require 'cgi'
# frozen_string_literal: true

ENV['APP_ENV'] = 'test'

require_relative '../app'
require 'rspec'
require 'rack/test'

RSpec.describe RelyingParty do
  include Rack::Test::Methods

  def app
    RelyingParty
  end

  before do
    ENV['issuer'] = 'urn:gov:gsa:SAML:2.0.profiles:sp:sso:localhost'
    ENV['assertion_consumer_service_url'] = 'http://sp.example.com/consume'
    ENV['idp_sso_target_url'] = 'http://idp.example.com/api/saml/auth'
    ENV['idp_slo_target_url'] = 'http://idp.example.com/api/saml/logout'
    ENV['semantic_ial_values_enabled'] = 'false'
    allow(STDOUT).to receive(:puts)
    allow(OneLogin::RubySaml::Logging).to receive(:debug)
  end

  describe '/' do
    it 'renders a link to the authorize endpoint' do
      get '/'

      expect(last_response).to be_ok
      expect(last_response.body).to include('<form action="/login_get?aal=2&ial=1" method="GET" id="login-form">')
    end

    context 'when the request tries to exploit XSS' do
      it 'protects against the attack' do
        get '/?ial=%22%20onmouseover=%22alert(document.domain)%22%20k=%22'

        expect(last_response.body).not_to include('alert(document.domain)')
      end
    end
  end

  describe '/success' do
    it 'redirects to the root' do
      get '/success'

      expect(last_response).to be_redirect
      expect(URI(last_response.location).path).to eq('/')
    end
  end

  describe '/logout' do
    before do
      stub_request(:get, ENV['idp_slo_target_url'])
    end

    it 'redirects to the IDP' do
      post '/logout'

      expect(last_response).to be_redirect
      expect(URI(last_response.location).path).to eq('/api/saml/logout')
    end
  end

  describe '/slo_logout' do
    let(:logout_response) do
      instance_double(
        OneLogin::RubySaml::Logoutresponse,
      )
    end

    before do
      allow(OneLogin::RubySaml::Logoutresponse).to receive(:new).and_return(logout_response)
      allow(logout_response).to receive(:validate).and_return(valid_logout_response)

      get '/'
      env 'rack.session', {
        userid: 'SOME_USERID',
        email: 'subscriber@example.com',
        attributes: 'SOME_ATTRIBUTES',
        step_up_enabled: false,
        step_up_aal: 2,
      }
    end

    context 'when the logout response is valid' do
      let(:valid_logout_response) { true }

      it 'terminates the session' do
        post '/slo_logout?SAMLResponse=anything'

        expect(last_response).to be_redirect
        expect(URI(last_response.location).path).to eq('/')
        expect(last_request.session[:logout]).to eq('ok')
        expect(last_request.session.keys).to_not include('userid')
        expect(last_request.session.keys).to_not include('email')
        expect(last_request.session.keys).to_not include('attributes')
        expect(last_request.session.keys).to_not include('step_up_enabled')
        expect(last_request.session.keys).to_not include('step_up_aal')
      end
    end

    context 'when the logout response is invalid' do
      let(:valid_logout_response) { false }

      it 'redirects to root with a failure' do
        post '/slo_logout?SAMLResponse=anything'

        expect(last_response).to be_redirect
        expect(URI(last_response.location).path).to eq('/')
        expect(last_request.session[:logout]).to eq('fail')
        expect(last_request.session.keys).to include('userid')
        expect(last_request.session.keys).to include('email')
        expect(last_request.session.keys).to include('attributes')
        expect(last_request.session.keys).to include('step_up_enabled')
        expect(last_request.session.keys).to include('step_up_aal')
      end
    end
  end

  describe 'login_get' do
    let(:params) { { requested_attributes: ['x509_presented', 'email'] } }

    before do
      allow(OneLogin::RubySaml::Settings).to receive(:new).
        and_call_original
    end

    describe 'force_authn' do
      let(:params) { super().merge(force_authn: expected_force_authn) }
      let(:expected_force_authn) { nil }

      context 'when force_authn is true' do
        let(:expected_force_authn) { 'true' }

        it 'calls Saml::Settings with the correct value for force_authn' do
          get '/login_get', **params

          expect(OneLogin::RubySaml::Settings).to have_received(:new).
            with(hash_including('force_authn' => expected_force_authn))
        end
      end

      context 'when force_authn is false' do
        let(:expected_force_authn) { 'false' }

        it 'calls Saml::Settings with the correct value for force_authn' do
          get '/login_get', **params

          expect(OneLogin::RubySaml::Settings).to have_received(:new).
            with(hash_including('force_authn' => expected_force_authn))
        end
      end
    end

    context 'when running in production' do
      before do
        ENV['idp_sso_target_url'] = 'http://idp.login.gov/api/saml/auth2024'
        ENV['sp_cert'] = File.read('config/demo_sp.crt')
        ENV['sp_private_key'] = 'SOME_PRIVATE_KEY'
      end

      it 'requires expicit env var sp_cert' do
        ENV.delete('sp_cert')

        expect { get '/login_get', **params }.to raise_error(NotImplementedError)
      end

      it 'requires expicit env var sp_private_key' do
        ENV.delete('sp_private_key')

        expect { get '/login_get', **params }.to raise_error(NotImplementedError)
      end
    end

    describe 'authn_context' do
      let(:expected_authn_context) { nil }
      context 'when the default parameters are used' do
        let(:expected_authn_context) do
          ['http://idmanagement.gov/ns/assurance/ial/1',
          'http://idmanagement.gov/ns/assurance/aal/2',
          'http://idmanagement.gov/ns/requested_attributes?ReqAttr=x509_presented,email',]
        end

        it 'sets the correct authn_context' do
          get '/login_get', **params

          expect(OneLogin::RubySaml::Settings).to have_received(:new).
            with(hash_including(authn_context: expected_authn_context))
        end

        context 'when semantic ial values are enabled' do
          before do
            ENV['semantic_ial_values_enabled'] = 'true'
          end

          let(:expected_authn_context) do
            [
              'urn:acr.login.gov:auth-only',
              'http://idmanagement.gov/ns/assurance/aal/2',
              'http://idmanagement.gov/ns/requested_attributes?ReqAttr=x509_presented,email',
            ]
          end

          it 'sets the correct authn_context' do
            get 'login_get', **params

            expect(OneLogin::RubySaml::Settings).to have_received(:new).
              with(hash_including(authn_context: expected_authn_context))
          end
        end
      end

      context 'when facial-match-preferred is selected' do
        let(:params) { super().merge(ial: 'facial-match-preferred') }
        let(:expected_authn_context) do
          ['http://idmanagement.gov/ns/assurance/ial/2?bio=preferred',
          'http://idmanagement.gov/ns/assurance/aal/2',
          'http://idmanagement.gov/ns/requested_attributes?ReqAttr=x509_presented,email',]
        end

        it 'sets the correct authn_context' do
          get '/login_get', **params

          expect(OneLogin::RubySaml::Settings).to have_received(:new).
            with(hash_including(authn_context: expected_authn_context))
        end

        context 'when semantic ial values are enabled' do
          before do
            ENV['semantic_ial_values_enabled'] = 'true'
          end

          let(:expected_authn_context) do
            [
              'urn:acr.login.gov:verified-facial-match-preferred',
              'http://idmanagement.gov/ns/assurance/aal/2',
              'http://idmanagement.gov/ns/requested_attributes?ReqAttr=x509_presented,email',
            ]
          end

          it 'sets the correct authn_context' do
            get '/login_get', **params

            expect(OneLogin::RubySaml::Settings).to have_received(:new).
              with(hash_including(authn_context: expected_authn_context))
          end
        end
      end

      context 'when facial-match-required is selected' do
        let(:params) { super().merge(ial: 'facial-match-required') }
        let(:expected_authn_context) do
          ['http://idmanagement.gov/ns/assurance/ial/2?bio=required',
          'http://idmanagement.gov/ns/assurance/aal/2',
          'http://idmanagement.gov/ns/requested_attributes?ReqAttr=x509_presented,email',]
        end

        it 'sets the correct authn_context' do
          get '/login_get', **params

          expect(OneLogin::RubySaml::Settings).to have_received(:new).
            with(hash_including(authn_context: expected_authn_context))
        end

        context 'when semantic ial values are enabled' do
          before do
            ENV['semantic_ial_values_enabled'] = 'true'
          end

          let(:expected_authn_context) do
            [
              'urn:acr.login.gov:verified-facial-match-required',
              'http://idmanagement.gov/ns/assurance/aal/2',
              'http://idmanagement.gov/ns/requested_attributes?ReqAttr=x509_presented,email',
            ]
          end

          it 'sets the correct authn_context' do
            get '/login_get', **params

            expect(OneLogin::RubySaml::Settings).to have_received(:new).
              with(hash_including(authn_context: expected_authn_context))
          end
        end
      end
    end

    context 'when Initiate User Registration checkbox is checked' do
      let(:params) { {initiate_registration: 'true' }}
      it 'sends prompt=create param' do
        get '/login_get', **params

        expect(last_response).to be_redirect

        prompt = CGI.parse(URI(last_response.location).query)['prompt'][0]
        expect(prompt).to eq 'create'
      end 
    end
  end

  describe 'login_post' do
    let(:params) { { requested_attributes: ['x509_presented', 'email'] } }

    before do
      allow(OneLogin::RubySaml::Settings).to receive(:new).
        and_call_original
    end

    let(:expected_authn_context) do
      [
        'http://idmanagement.gov/ns/assurance/ial/1',
        'http://idmanagement.gov/ns/assurance/aal/2',
        'http://idmanagement.gov/ns/requested_attributes?ReqAttr=x509_presented,email',
      ]
    end

     context 'when Initiate User Registration checkbox is checked' do
      let(:params) { { initiate_registration: 'true' }}
      it 'there is a hidden value of prompt=create that gets created' do
        get '/login_post', **params

        expect(last_response).to be_ok
        expect(last_response.body).to include('<input name="prompt" type="hidden" value="create">')
      end 
    end

    it 'sets the correct authn_context' do
      get 'login_post', **params

      expect(OneLogin::RubySaml::Settings).to have_received(:new).
        with(hash_including(authn_context: expected_authn_context))
    end

    context 'when 2-phishing_resistant aal is requested' do
      let(:params) { super().merge(aal: '2-phishing_resistant') }
      let(:expected_authn_context) do
        [
          'http://idmanagement.gov/ns/assurance/ial/1',
          'http://idmanagement.gov/ns/assurance/aal/2?phishing_resistant=true',
          'http://idmanagement.gov/ns/requested_attributes?ReqAttr=x509_presented,email',
        ]
      end

      it 'sets the correct authn_context' do
        get 'login_post', **params

        expect(OneLogin::RubySaml::Settings).to have_received(:new).
          with(hash_including(authn_context: expected_authn_context))
      end
    end

    context 'when 2-hspd12 aal is requested' do
      let(:params) { super().merge(aal: '2-hspd12') }
      let(:expected_authn_context) do
        [
          'http://idmanagement.gov/ns/assurance/ial/1',
          'http://idmanagement.gov/ns/assurance/aal/2?hspd12=true',
          'http://idmanagement.gov/ns/requested_attributes?ReqAttr=x509_presented,email',
        ]
      end

      it 'sets the correct authn_context' do
        get 'login_post', **params

        expect(OneLogin::RubySaml::Settings).to have_received(:new).
          with(hash_including(authn_context: expected_authn_context))
      end
    end
  end

  describe 'consume' do
    let(:expected_name_id) { 'DUMMY_NAME_ID' }
    let(:expected_email) { 'subscriber@example.com' }
    let(:expected_attributes) { { 'email' => expected_email, 'name' => 'John Doe' } }
    let(:response) do
      instance_double(
        OneLogin::RubySaml::Response,
        name_id: expected_name_id,
        attributes: expected_attributes,
        errors: [],
      )
    end
    let(:authn_instant) { Time.now.utc }

    before do
      allow(OneLogin::RubySaml::Response).to receive(:new).and_return(response)
      allow(response).to receive(:is_valid?).and_return(valid_response)
      allow(response).to receive(:authn_instant).and_return(authn_instant)
    end

    context 'when the response is valid' do
      let(:valid_response) { true }

      it 'saves the correct values in the session' do
        post 'consume?SAMLResponse=something'
        follow_redirect!

        expect(last_request.session[:userid]).to eq(expected_name_id)
        expect(last_request.session[:email]).to eq(expected_email)
        expect(last_request.session[:authn_instant]).to eq(authn_instant)
        expect(JSON.parse(last_request.session[:attributes])).to eq(expected_attributes)
      end
    end

    context 'when the response is invalid' do
      let(:valid_response) { false }

      it 'shows an authentication failure page' do
        post 'consume?SAMLResponse=something'
        follow_redirect!

        expect(last_response).to be_ok
        expect(last_response.body).to include('Authentication failure')
      end
    end
  end

  describe 'third-party-initiated login (OpenID Connect Core 1.0 §4)' do
    let(:login_hint) { '7a0b9b3e-6b2a-4a7f-9c3d-2f1e8d5c4b6a' }
    let(:target_link_uri) { 'http://localhost:9292/third_party/return?agency=benefits' }

    before do
      ENV['idp_url'] = 'http://idp.example.com'
      ENV.delete('THIRD_PARTY_TARGET_LINK_ALLOWLIST')
    end

    # The return page carries the third party's URL in its refresh directive and its link.
    def return_location(body)
      match = body.match(/content="0;url=([^"]+)"/)
      expect(match).not_to be_nil
      URI(CGI.unescapeHTML(match[1]))
    end

    def initiate(overrides = {})
      query = {
        iss: 'http://idp.example.com',
        login_hint: login_hint,
        target_link_uri: target_link_uri,
      }.merge(overrides).compact
      get "/initiate_login?#{URI.encode_www_form(query)}"
    end

    it 'refuses a request without iss' do
      initiate(iss: nil)
      expect(last_response.status).to eq(400)
      expect(JSON.parse(last_response.body)['error']).to eq('invalid_request')
      expect(last_request.session[:third_party_login]).to be_nil
    end

    it 'refuses an iss that is not the Login.gov this app trusts' do
      initiate(iss: 'https://evil.example.com')
      expect(last_response.status).to eq(400)
      expect(last_response.body).to include('iss must name the Login.gov issuer')
    end

    it 'refuses a target_link_uri whose origin is not allow-listed (open redirect)' do
      initiate(target_link_uri: 'https://attacker.example.com/steal')
      expect(last_response.status).to eq(400)
      expect(last_response.body).to include('target_link_uri is not an allowed return address')
    end

    it 'refuses a plain-http target that is not a local development host' do
      ENV['THIRD_PARTY_TARGET_LINK_ALLOWLIST'] = 'http://america.example.gov'
      initiate(target_link_uri: 'http://america.example.gov/return')
      expect(last_response.status).to eq(400)
    end

    it 'refuses an oversized login_hint' do
      initiate(login_hint: 'x' * 129)
      expect(last_response.status).to eq(400)
    end

    it 'starts the ordinary SAML sign-in and remembers the hand-off' do
      initiate
      expect(last_response).to be_redirect
      expect(URI(last_response.location).path).to eq('/api/saml/auth')
      expect(URI(last_response.location).query).to include('SAMLRequest=')
      handoff = last_request.session[:third_party_login]
      expect(handoff['login_hint']).to eq(login_hint)
      expect(handoff['target_link_uri']).to eq(target_link_uri)
    end

    it 'ignores a trailing slash on iss and accepts a configured https origin' do
      ENV['THIRD_PARTY_TARGET_LINK_ALLOWLIST'] = 'https://america.example.gov http://localhost:9292'
      initiate(iss: 'http://idp.example.com/', target_link_uri: 'https://america.example.gov/return')
      expect(last_response).to be_redirect
    end

    describe 'completing the hand-off at /consume' do
      let(:response) do
        instance_double(
          OneLogin::RubySaml::Response,
          name_id: 'DUMMY_NAME_ID',
          # Real ruby-saml attributes are multi-valued; the index page iterates each value.
          attributes: { 'email' => ['subscriber@example.com'] },
          errors: ['bad signature'],
          authn_instant: Time.now.utc,
        )
      end

      before do
        allow(OneLogin::RubySaml::Response).to receive(:new).and_return(response)
        allow(response).to receive(:is_valid?).and_return(valid_response)
        initiate
      end

      context 'when the SAML response is valid' do
        let(:valid_response) { true }

        # Not a redirect: Login.gov's POST-binding page carries form-action 'self' <ACS>, which
        # Chrome enforces on the redirects after the submission, so the return is a page that
        # continues to the third party (see views/third_party_return.erb).
        it 'answers with a page that sends the user to target_link_uri with the same hint, this issuer and status' do
          post 'consume?SAMLResponse=something'

          expect(last_response.status).to eq(200)
          location = return_location(last_response.body)
          expect("#{location.scheme}://#{location.host}:#{location.port}#{location.path}").
            to eq('http://localhost:9292/third_party/return')
          expect(last_response.body).to include('http-equiv="refresh"')
          expect(last_response.body).to include('id="third-party-return-link"')
          returned = URI.decode_www_form(location.query).to_h
          expect(returned).to include(
            'agency' => 'benefits',
            'login_hint' => login_hint,
            'iss' => 'urn:gov:gsa:SAML:2.0.profiles:sp:sso:localhost',
            'status' => 'signed_in',
          )
          # Identity came from the assertion; the hand-off is consumed and only the notice remains.
          expect(last_request.session[:userid]).to eq('DUMMY_NAME_ID')
          expect(last_request.session[:third_party_login]).to be_nil
          expect(last_request.session[:third_party_initiated_hint]).to eq(login_hint)
        end

        it 'does not redirect to the third party again on a later sign-in' do
          post 'consume?SAMLResponse=something'
          post 'consume?SAMLResponse=something'
          expect(URI(last_response.location).path).to eq('/success')
        end

        it 'shows the third-party notice on the signed-in page' do
          post 'consume?SAMLResponse=something'
          get '/success'
          follow_redirect!
          expect(last_response.body).to include('third-party-initiated login')
          expect(last_response.body).to include(login_hint)
        end
      end

      context 'when the SAML response is invalid' do
        let(:valid_response) { false }

        it 'sends the user back with status=failed and clears the hand-off' do
          post 'consume?SAMLResponse=something'

          expect(last_response.status).to eq(200)
          returned = URI.decode_www_form(return_location(last_response.body).query).to_h
          expect(returned['status']).to eq('failed')
          expect(returned['login_hint']).to eq(login_hint)
          expect(last_request.session[:third_party_login]).to be_nil
          expect(last_request.session[:userid]).to be_nil
        end
      end
    end
  end

  describe 'failure_to_proof' do
    it 'shows the failure to proof page' do
      get '/failure_to_proof'
      follow_redirect!

      expect(last_response).to be_ok
      expect(last_response.body).to include('Proofing failure')
      expect(last_response.body).to include('We were unable to verify your identity')
    end
  end
end
