# frozen_string_literal: true

ENV['APP_ENV'] = 'test'

require_relative '../app'
require 'rspec'
require 'rack/test'

F = DelegatedAssertionFactory unless defined?(F)

RSpec.describe 'delegated-access API (/api/benefits)' do
  include Rack::Test::Methods

  def app
    RelyingParty
  end

  def bearer(token)
    header 'Authorization', "Bearer #{token}"
  end

  def body_json
    JSON.parse(last_response.body)
  end

  before do
    ENV['idp_url'] = 'http://localhost:3000'
    ENV.delete('IDP_METADATA_URL')
    ENV['SAML_METADATA_YEAR'] = '2026'
    ENV['RESOURCE_IDENTIFIER'] = F::RESOURCE
    ENV['REPLAY_PROTECTION'] = 'true'
    stub_request(:get, F::METADATA_URL).to_return(status: 200, body: F.metadata_xml)
    RelyingParty.reset_idp_metadata!
    RelyingParty.settings.replay_cache.clear
    RelyingParty.settings.decision_log.clear
    RelyingParty.settings.benefits.clear
  end

  describe 'GET /api/benefits' do
    it 'accepts a valid signed assertion and returns fictional benefits plus the delegation context' do
      bearer F.token(name_id: 'user-1')
      get '/api/benefits'

      expect(last_response.status).to eq(200), last_response.body
      expect(body_json['benefits']['case_number']).to start_with('DEMO-')
      expect(body_json['delegated_access']).to eq(
        'actor' => F::ACTOR,
        'delegation_id' => 'del-0001',
        'delegation_scopes' => %w[token_exchange:benefits_read token_exchange:benefits_write],
      )
      expect(body_json['_assertion']['name_id']).to eq('user-1')
      expect(body_json['_assertion']['issuer']).to eq(F::IDP_ENTITY_ID)
      expect(body_json['_assertion']['attributes']).to include('email' => 'test.user@example.com', 'uuid' => 'agency-uuid-1234')
    end

    it 'fetches IdP metadata once and never calls Login.gov per request' do
      3.times do
        bearer F.token
        get '/api/benefits'
        expect(last_response.status).to eq(200)
      end

      expect(a_request(:get, F::METADATA_URL)).to have_been_made.once
      expect(a_request(:any, %r{localhost:3000/api/openid_connect})).not_to have_been_made
    end

    it 'accepts an EncryptedAssertion encrypted to the resource server certificate' do
      bearer F.encrypted_token(name_id: 'user-enc')
      get '/api/benefits'

      expect(last_response.status).to eq(200), last_response.body
      expect(body_json['_assertion']['name_id']).to eq('user-enc')
    end

    it 'returns 401 with a bare challenge when there is no bearer token' do
      get '/api/benefits'

      expect(last_response.status).to eq(401)
      expect(last_response.headers['WWW-Authenticate']).to start_with('Bearer realm="benefits-api"')
      expect(last_response.headers['WWW-Authenticate']).not_to include('error=')
    end

    it 'returns 401 invalid_token when the token is not base64url' do
      bearer 'not+base64url/at+all'
      get '/api/benefits'

      expect(last_response.status).to eq(401)
      expect(body_json['error']).to eq('invalid_token')
    end

    it 'returns 400 invalid_request when the Bearer header is malformed' do
      bearer 'has spaces="and quotes"'
      get '/api/benefits'

      expect(last_response.status).to eq(400)
      expect(body_json['error']).to eq('invalid_request')
    end

    it 'returns 401 with a bare challenge for a non-Bearer scheme' do
      header 'Authorization', 'Basic dXNlcjpwYXNz'
      get '/api/benefits'

      expect(last_response.status).to eq(401)
      expect(last_response.headers['WWW-Authenticate']).not_to include('error=')
    end

    it 'rejects an assertion issued to another audience' do
      bearer F.token(audience: 'https://records-api.agency.localdev')
      get '/api/benefits'

      expect(last_response.status).to eq(401)
      expect(last_response.headers['WWW-Authenticate']).to include('error="invalid_token"')
      expect(body_json['error_description']).to match(/Audience/)
    end

    it 'rejects a Recipient that is not this resource server' do
      bearer F.token(recipient: 'https://records-api.agency.localdev')
      get '/api/benefits'

      expect(last_response.status).to eq(401)
      expect(body_json['error_description']).to match(/Recipient/)
    end

    it 'rejects an assertion whose subject-confirmation window has passed, even inside Conditions' do
      bearer F.token(subject_not_on_or_after: Time.now.utc - 61)
      get '/api/benefits'

      expect(last_response.status).to eq(401)
      expect(body_json['error_description']).to match(/subject confirmation window/)
    end

    it 'tolerates 60 seconds of clock drift on the subject-confirmation window' do
      bearer F.token(subject_not_on_or_after: Time.now.utc - 30)
      get '/api/benefits'

      expect(last_response.status).to eq(200), last_response.body
    end

    it 'rejects an expired Conditions window' do
      bearer F.token(not_on_or_after: Time.now.utc - 120, subject_not_on_or_after: Time.now.utc + 60)
      get '/api/benefits'

      expect(last_response.status).to eq(401)
      expect(body_json['error_description']).to match(/expired/)
    end

    it 'rejects an assertion that is not yet valid' do
      bearer F.token(not_before: Time.now.utc + 600)
      get '/api/benefits'

      expect(last_response.status).to eq(401)
      expect(body_json['error_description']).to match(/not yet valid/)
    end

    it 'rejects a signature from a key that is not in the IdP metadata' do
      bearer F.encode(F.sign(F.assertion_xml, key: F.rogue_key, cert: F.rogue_cert))
      get '/api/benefits'

      expect(last_response.status).to eq(401)
      expect(body_json['error_description']).to match(/signature/i)
    end

    it 'rejects an assertion whose content was altered after signing' do
      signed = F.sign(F.assertion_xml(name_id: 'victim'))
      tampered = signed.sub('<NameID', '<NameID xmlns:x="urn:x" x:tampered="1"')
      bearer F.encode(tampered)
      get '/api/benefits'

      expect(last_response.status).to eq(401)
      expect(body_json['error_description']).to match(/signature invalid/)
    end

    it 'rejects an unsigned assertion' do
      bearer F.encode(F.assertion_xml)
      get '/api/benefits'

      expect(last_response.status).to eq(401)
      expect(body_json['error_description']).to match(/not signed/)
    end

    it 'rejects an assertion carrying InResponseTo (an ordinary sign-in assertion)' do
      bearer F.token(in_response_to: '_authn-request-1')
      get '/api/benefits'

      expect(last_response.status).to eq(401)
      expect(body_json['error_description']).to match(/InResponseTo/)
    end

    it 'accepts an assertion that carries the delegation but not the actor attribute' do
      bearer F.token(attributes: F::DEFAULT_ATTRIBUTES.except('actor'))
      get '/api/benefits'
      expect(last_response.status).to eq 200
    end

    it 'rejects an assertion without the delegation attributes' do
      bearer F.token(attributes: F::DEFAULT_ATTRIBUTES.except('delegation_scopes', 'delegation_id', 'actor'))
      get '/api/benefits'

      expect(last_response.status).to eq(401)
      expect(body_json['error_description']).to match(/not a delegated assertion/)
    end

    it 'rejects an Issuer that is not the IdP metadata entityID' do
      bearer F.token(issuer: 'http://evil.example/saml')
      get '/api/benefits'

      expect(last_response.status).to eq(401)
      expect(body_json['error_description']).to match(/Issuer/)
    end

    it 'rejects a replayed assertion ID while remembering the first use' do
      token = F.token
      bearer token
      get '/api/benefits'
      expect(last_response.status).to eq(200)

      bearer token
      get '/api/benefits'
      expect(last_response.status).to eq(401)
      expect(body_json['error_description']).to match(/already been presented/)
    end

    it 'allows repeat presentation when REPLAY_PROTECTION=false' do
      ENV['REPLAY_PROTECTION'] = 'false'
      token = F.token
      2.times do
        bearer token
        get '/api/benefits'
        expect(last_response.status).to eq(200)
      end
    end

    it 'returns 403 insufficient_scope when benefits_read was not approved' do
      bearer F.token(attributes: F::DEFAULT_ATTRIBUTES.merge('delegation_scopes' => 'token_exchange:benefits_write'))
      get '/api/benefits'

      expect(last_response.status).to eq(403)
      expect(last_response.headers['WWW-Authenticate']).to include('error="insufficient_scope"')
      expect(last_response.headers['WWW-Authenticate']).to include('scope="token_exchange:benefits_read"')
    end

    it 'fails closed with 503 when IdP metadata cannot be fetched' do
      stub_request(:get, F::METADATA_URL).to_return(status: 500)
      bearer F.token
      get '/api/benefits'

      expect(last_response.status).to eq(503)
      expect(body_json['error_description']).not_to include('localhost:3000')
      expect(RelyingParty.settings.decision_log.entries.first.reason).to include('500')
    end

    it 're-fetches metadata once when the signing key rotated' do
      new_key = OpenSSL::PKey::RSA.new(2048)
      new_cert = F.self_signed_cert(new_key, 'CN=Rotated IdP')
      stub_request(:get, F::METADATA_URL).
        to_return({ status: 200, body: F.metadata_xml }, { status: 200, body: F.metadata_xml(cert: new_cert) })

      # Warm the cache with the old certificate, then age it past the refresh rate limit.
      bearer F.token
      get '/api/benefits'
      expect(last_response.status).to eq(200)
      RelyingParty.idp_metadata.instance_variable_set(:@fetched_at, Time.now - 120)

      bearer F.encode(F.sign(F.assertion_xml, key: new_key, cert: new_cert))
      get '/api/benefits'

      expect(last_response.status).to eq(200), last_response.body
      expect(a_request(:get, F::METADATA_URL)).to have_been_made.twice
    end
  end

  describe 'POST /api/benefits' do
    it 'requires benefits_write in delegation_scopes' do
      bearer F.token(attributes: F::DEFAULT_ATTRIBUTES.merge('delegation_scopes' => 'token_exchange:benefits_read'))
      post '/api/benefits', { preferred_contact: 'email' }.to_json, 'CONTENT_TYPE' => 'application/json'

      expect(last_response.status).to eq(403)
      expect(body_json['error']).to eq('insufficient_scope')
    end

    it 'applies the change and records the acting service provider' do
      bearer F.token(name_id: 'writer-1')
      post '/api/benefits', { preferred_contact: 'email' }.to_json, 'CONTENT_TYPE' => 'application/json'

      expect(last_response.status).to eq(200), last_response.body
      expect(body_json['benefits']['preferred_contact']).to eq('email')
      expect(body_json['benefits']['last_updated']).to include('by_actor' => F::ACTOR, 'delegation_id' => 'del-0001')
    end

    it 'rejects fields that are not editable' do
      bearer F.token
      post '/api/benefits', { status: 'closed' }.to_json, 'CONTENT_TYPE' => 'application/json'

      expect(last_response.status).to eq(400)
      expect(body_json['error']).to eq('invalid_request')
    end
  end
end
