# frozen_string_literal: true

# CORS on the delegated-access API (Fetch standard, https://fetch.spec.whatwg.org/#http-cors-protocol).
# The reference broker is a browser public client, so the browser enforces these headers.

ENV['APP_ENV'] = 'test'

require_relative '../app'
require 'rspec'
require 'rack/test'

RSpec.describe 'CORS on /api/benefits' do
  include Rack::Test::Methods

  def app
    RelyingParty
  end

  let(:sp_origin) { 'http://localhost:9292' }

  before do
    ENV.delete('CORS_ALLOWED_ORIGINS')
    ENV['idp_url'] = 'http://localhost:3000'
    ENV.delete('IDP_METADATA_URL')
    ENV['SAML_METADATA_YEAR'] = '2026'
    ENV['RESOURCE_IDENTIFIER'] = DelegatedAssertionFactory::RESOURCE
    stub_request(:get, DelegatedAssertionFactory::METADATA_URL).
      to_return(status: 200, body: DelegatedAssertionFactory.metadata_xml)
    RelyingParty.reset_idp_metadata!
    RelyingParty.settings.replay_cache.clear
    RelyingParty.settings.dpop_jti_cache.clear
    RelyingParty.settings.decision_log.clear
    RelyingParty.settings.benefits.clear
  end

  describe 'preflight (OPTIONS)' do
    it 'allows GET (no POST: the application is read-only) with Authorization, DPoP and Content-Type' do
      header 'Origin', sp_origin
      header 'Access-Control-Request-Method', 'GET'
      header 'Access-Control-Request-Headers', 'authorization, dpop'
      options '/api/benefits'

      expect(last_response.status).to eq 204
      expect(last_response.headers['Access-Control-Allow-Origin']).to eq sp_origin
      expect(last_response.headers['Access-Control-Allow-Methods']).to eq 'GET, OPTIONS'
      expect(last_response.headers['Access-Control-Allow-Headers']).to eq 'Authorization, DPoP, Content-Type'
      expect(last_response.headers['Vary']).to include 'Origin'
    end

    it 'answers an origin that is not allowed without any CORS headers' do
      header 'Origin', 'https://evil.example'
      options '/api/benefits'

      expect(last_response.status).to eq 204
      expect(last_response.headers).not_to have_key('Access-Control-Allow-Origin')
    end

    it 'reads additional origins from CORS_ALLOWED_ORIGINS' do
      ENV['CORS_ALLOWED_ORIGINS'] = 'https://sp.example.gov, http://localhost:9292'
      header 'Origin', 'https://sp.example.gov'
      options '/api/benefits'

      expect(last_response.headers['Access-Control-Allow-Origin']).to eq 'https://sp.example.gov'
    end
  end

  describe 'actual requests' do
    it 'carries the CORS headers and exposes WWW-Authenticate on a 401 challenge' do
      header 'Origin', sp_origin
      get '/api/benefits'

      expect(last_response.status).to eq 401
      expect(last_response.headers['WWW-Authenticate']).to start_with('Bearer realm=')
      expect(last_response.headers['Access-Control-Allow-Origin']).to eq sp_origin
      expect(last_response.headers['Access-Control-Expose-Headers']).to eq 'WWW-Authenticate'
    end

    it 'carries the CORS headers on a successful call from the allowed origin' do
      header 'Origin', sp_origin
      header 'Authorization', "Bearer #{DelegatedAssertionFactory.token(name_id: 'user-1')}"
      get '/api/benefits'

      expect(last_response.status).to eq(200), last_response.body
      expect(last_response.headers['Access-Control-Allow-Origin']).to eq sp_origin
    end

    it 'adds no CORS headers to routes outside /api/' do
      header 'Origin', sp_origin
      get '/decisions.json'

      expect(last_response.headers).not_to have_key('Access-Control-Allow-Origin')
    end
  end
end
