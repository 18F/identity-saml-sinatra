# frozen_string_literal: true

ENV['APP_ENV'] = 'test'

require_relative '../app'
require 'rspec'
require 'rack/test'
require 'jwe'

RSpec.describe 'Attempts API viewer (agency role)' do
  include Rack::Test::Methods

  let(:factory) { DelegatedAssertionFactory }
  let(:poll_url) { 'http://localhost:3000/api/attempts/poll' }
  let(:event_type_base) { 'https://schemas.login.gov/secevent/attempts-api/event-type' }

  def app
    RelyingParty
  end

  # A Security Event Token encrypted the way the IdP does it (RSA-OAEP / A256GCM)
  # to the agency's registered public key.
  def encrypted_event(type, payload, jti: SecureRandom.uuid, iat: Time.now.to_i)
    set = {
      jti:,
      iat:,
      iss: 'http://localhost:3000/',
      aud: ResourceServerConfig::DEFAULT_ISSUER,
      events: {
        "#{event_type_base}/#{type}" => {
          'subject' => { 'subject_type' => 'session', 'session_id' => 'sp-session-1' },
          'occurred_at' => Time.now.to_f,
        }.merge(payload),
      },
    }
    [jti, JWE.encrypt(set.to_json, factory.rs_cert.public_key, alg: 'RSA-OAEP', enc: 'A256GCM', zip: 'DEF')]
  end

  def stub_poll(*events)
    stub_request(:post, poll_url).with(query: hash_including('maxEvents' => '100')).
      to_return(status: 200, body: { sets: events.to_h }.to_json)
  end

  before do
    ENV['issuer'] = ResourceServerConfig::DEFAULT_ISSUER
    ENV['idp_url'] = 'http://localhost:3000'
    ENV.delete('IDP_METADATA_URL')
    ENV['SAML_METADATA_YEAR'] = '2026'
    ENV['RESOURCE_IDENTIFIER'] = factory::RESOURCE
    ENV.delete('signed_events')
    ENV.delete('allow_all_events_plaintext')
    stub_request(:get, factory::METADATA_URL).to_return(status: 200, body: factory.metadata_xml)
    RelyingParty.reset_idp_metadata!
    RelyingParty.settings.replay_cache.clear
    RelyingParty.settings.decision_log.clear
  end

  describe 'GET /attempts-api' do
    it 'polls once with the agency credentials and lists decrypted events' do
      stub_poll(
        encrypted_event('login-email-and-password-auth', {'success' => true, 'delegation_id' => 'del-1'}),
        encrypted_event('delegated-access-consented', {'actor_issuer' => factory::ACTOR, 'scopes' => %w[token_exchange:benefits_read],
                        'resources' => [factory::RESOURCE], 'remembered' => true, 'delegation_id' => 'del-1',}),
      )

      get '/attempts-api'

      expect(last_response).to be_ok, last_response.body
      expect(a_request(:post, poll_url).with(
        query: { 'maxEvents' => '100' },
        headers: { 'Authorization' => "Bearer #{ResourceServerConfig::DEFAULT_ISSUER} benefits-agency-attempts-secret" },
      )).to have_been_made.once
      expect(last_response.body).to include('delegated-access-consented')
      expect(last_response.body).to include('login-email-and-password-auth')
      expect(last_response.body).to include('del-1')
      expect(last_response.body).to include(factory::ACTOR)
    end

    it 'redacts fields that are not allow-listed and keeps the delegated-access fields' do
      stub_poll(
        encrypted_event('delegated-access-token-issued', {'actor_issuer' => factory::ACTOR, 'resource' => factory::RESOURCE,
                        'scopes' => %w[token_exchange:benefits_read], 'ial' => 2, 'aal' => 2,
                        'token_format' => 'saml2', 'delegation_id' => 'del-2', 'secret_thing' => 'hide-me',}),
      )

      get '/attempts-api'

      expect(last_response.body).to include('saml2')
      expect(last_response.body).to include('REDACTED')
      expect(last_response.body).not_to include('hide-me')
    end

    it 'shows an error alert instead of failing when the poll is refused' do
      stub_request(:post, poll_url).with(query: hash_including({})).to_return(status: 401, body: '{"error":"Unauthorized"}')

      get '/attempts-api'

      expect(last_response).to be_ok
      expect(last_response.body).to include('Attempts API error')
      expect(last_response.body).to include('401')
    end

    it 'verifies signed event payloads with the IdP Attempts key when signed_events is set' do
      ENV['signed_events'] = 'true'
      AttemptsConfiguration.reset!
      signing_key = OpenSSL::PKey::EC.generate('prime256v1')
      jwk = JWT::JWK.new(signing_key)
      stub_request(:get, 'http://localhost:3000/.well-known/ssf-configuration').
        to_return(status: 200, body: { jwks_uri: 'http://localhost:3000/api/attempts-certs' }.to_json)
      stub_request(:get, 'http://localhost:3000/api/attempts-certs').
        to_return(status: 200, body: { keys: [jwk.export] }.to_json)

      set = {
        jti: 'signed-1', iat: Time.now.to_i,
        events: { "#{event_type_base}/delegated-access-revoked" => {
          'subject' => { 'subject_type' => 'session', 'session_id' => 's' }, 'occurred_at' => Time.now.to_f,
          'reason' => 'user_revoked', 'delegation_id' => 'del-3',
        } },
      }
      jwt = JWT.encode(set, signing_key, 'ES256')
      jwe = JWE.encrypt(jwt, factory.rs_cert.public_key, alg: 'RSA-OAEP', enc: 'A256GCM')
      stub_poll(['signed-1', jwe])

      get '/attempts-api'

      expect(last_response).to be_ok, last_response.body
      expect(last_response.body).to include('delegated-access-revoked')
      expect(last_response.body).to include('user_revoked')
    ensure
      AttemptsConfiguration.reset!
    end
  end

  describe 'GET /attempts-api?tab=delegated' do
    it 'groups events by delegation_id and lists the API decisions with the same delegation_id' do
      stub_poll(
        encrypted_event('delegated-access-consented', {'actor_issuer' => factory::ACTOR, 'scopes' => %w[token_exchange:benefits_read],
                        'resources' => [factory::RESOURCE], 'remembered' => false, 'delegation_id' => 'del-join',}),
        encrypted_event('delegated-access-token-issued', {'actor_issuer' => factory::ACTOR, 'resource' => factory::RESOURCE,
                        'scopes' => %w[token_exchange:benefits_read], 'token_format' => 'saml2', 'delegation_id' => 'del-join',}),
        encrypted_event('delegated-access-token-issued', {'actor_issuer' => factory::ACTOR, 'resource' => factory::RESOURCE,
                        'scopes' => %w[token_exchange:benefits_write], 'token_format' => 'saml2', 'delegation_id' => 'del-other',}),
        encrypted_event('login-email-and-password-auth', {'success' => true}),
      )

      read_only = factory::DEFAULT_ATTRIBUTES.merge(
        'delegation_id' => 'del-join', 'delegation_scopes' => 'token_exchange:benefits_read',
      )
      header 'Authorization', "Bearer #{factory.token(attributes: read_only)}"
      get '/api/benefits'
      expect(last_response.status).to eq(200)
      # A fresh assertion (the service provider refreshed) with the same delegation_id.
      header 'Authorization', "Bearer #{factory.token(attributes: read_only)}"
      post '/api/benefits', { preferred_contact: 'email' }.to_json, 'CONTENT_TYPE' => 'application/json'
      expect(last_response.status).to eq(403)
      header 'Authorization', "Bearer #{factory.token(attributes: factory::DEFAULT_ATTRIBUTES.merge('delegation_id' => 'del-unrelated'))}"
      get '/api/benefits'
      expect(last_response.status).to eq(200)
      header 'Authorization', nil

      get '/attempts-api?tab=delegated'

      expect(last_response).to be_ok, last_response.body
      body = last_response.body
      join_section = body[/delegation_id <code>del-join<\/code>.*?<\/section>/m]
      other_section = body[/delegation_id <code>del-other<\/code>.*?<\/section>/m]

      expect(join_section).to include('delegated-access-consented')
      expect(join_section).to include('delegated-access-token-issued')
      expect(join_section).to include('GET /api/benefits')
      expect(join_section).to include('POST /api/benefits')
      expect(join_section).to include('insufficient_scope').or include('does not include token_exchange:benefits_write')
      expect(join_section).not_to include('del-unrelated')

      expect(other_section).to include('None yet.')
      expect(body).not_to include('login-email-and-password-auth')
    end
  end

  describe 'POST /ack-events' do
    it 'acknowledges the given JTIs with ack[] params and redirects back' do
      stub_request(:post, poll_url).with(query: hash_including('ack' => %w[a b])).
        to_return(status: 200, body: { sets: {} }.to_json)

      post '/ack-events', jtis: 'a,b', tab: 'delegated'

      expect(last_response).to be_redirect
      expect(URI(last_response.location).request_uri).to eq('/attempts-api?tab=delegated')
      expect(a_request(:post, poll_url).with(query: hash_including('ack' => %w[a b]))).to have_been_made.once
    end
  end
end
