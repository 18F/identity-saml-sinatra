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
      expect(last_response.body).to include('<form action="/login" method="POST">')
    end

    context 'when the request tries to exploit XSS' do
      it 'protects agains the attack' do
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
      allow(OneLogin::RubySaml::Settings).to receive(:new)
        .and_call_original
    end

    describe 'force_authn' do
      let(:params) { super().merge(force_authn: expected_force_authn) }
      let(:expected_force_authn) { nil }

      context 'when force_authn is true' do
        let(:expected_force_authn) { 'true' }

        it 'calls Saml::Settings with the correct value for force_authn' do
          get '/login_get', **params

          expect(OneLogin::RubySaml::Settings).to have_received(:new)
            .with(hash_including('force_authn' => expected_force_authn))
        end
      end

      context 'when force_authn is false' do
        let(:expected_force_authn) { 'false' }

        it 'calls Saml::Settings with the correct value for force_authn' do
          get '/login_get', **params

          expect(OneLogin::RubySaml::Settings).to have_received(:new)
            .with(hash_including('force_authn' => expected_force_authn))
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
      context 'with vtr_disabled' do
        before do
          ENV['vtr_disabled'] = 'true'
        end

        context 'when the default parameters are used' do
          let(:expected_authn_context) do
            ['http://idmanagement.gov/ns/assurance/ial/1',
            'http://idmanagement.gov/ns/assurance/aal/2',
            'http://idmanagement.gov/ns/requested_attributes?ReqAttr=x509_presented,email']
          end

          it 'sets the correct authn_context' do
            get '/login_get', **params

            expect(OneLogin::RubySaml::Settings).to have_received(:new)
              .with(hash_including(authn_context: expected_authn_context))
          end

          context 'when semantic ial values are enabled' do
            before do
              ENV['semantic_ial_values_enabled'] = 'true'
            end

            let(:expected_authn_context) do
              [
                'urn:acr.login.gov:auth-only',
                'http://idmanagement.gov/ns/assurance/aal/2',
                'http://idmanagement.gov/ns/requested_attributes?ReqAttr=x509_presented,email'
              ]
            end

            it 'sets the correct authn_context' do
              get 'login_get', **params

              expect(OneLogin::RubySaml::Settings).to have_received(:new)
                .with(hash_including(authn_context: expected_authn_context))
            end
          end
        end

        context 'when facial-match-preferred is selected' do
          let(:params) { super().merge(ial: 'facial-match-preferred') }
          let(:expected_authn_context) do
            ['http://idmanagement.gov/ns/assurance/ial/2?bio=preferred',
            'http://idmanagement.gov/ns/assurance/aal/2',
            'http://idmanagement.gov/ns/requested_attributes?ReqAttr=x509_presented,email']
          end

          it 'sets the correct authn_context' do
            get '/login_get', **params

            expect(OneLogin::RubySaml::Settings).to have_received(:new)
              .with(hash_including(authn_context: expected_authn_context))
          end

          context 'when semantic ial values are enabled' do
            before do
              ENV['semantic_ial_values_enabled'] = 'true'
            end

            let(:expected_authn_context) do
              [
                'urn:acr.login.gov:verified-facial-match-preferred',
                'http://idmanagement.gov/ns/assurance/aal/2',
                'http://idmanagement.gov/ns/requested_attributes?ReqAttr=x509_presented,email'
              ]
            end

            it 'sets the correct authn_context' do
              get '/login_get', **params

              expect(OneLogin::RubySaml::Settings).to have_received(:new)
                .with(hash_including(authn_context: expected_authn_context))
            end
          end
        end

        context 'when facial-match-required is selected' do
          let(:params) { super().merge(ial: 'facial-match-required') }
          let(:expected_authn_context) do
            ['http://idmanagement.gov/ns/assurance/ial/2?bio=required',
            'http://idmanagement.gov/ns/assurance/aal/2',
            'http://idmanagement.gov/ns/requested_attributes?ReqAttr=x509_presented,email']
          end

          it 'sets the correct authn_context' do
            get '/login_get', **params

            expect(OneLogin::RubySaml::Settings).to have_received(:new)
              .with(hash_including(authn_context: expected_authn_context))
          end

          context 'when semantic ial values are enabled' do
            before do
              ENV['semantic_ial_values_enabled'] = 'true'
            end

            let(:expected_authn_context) do
              [
                'urn:acr.login.gov:verified-facial-match-required',
                'http://idmanagement.gov/ns/assurance/aal/2',
                'http://idmanagement.gov/ns/requested_attributes?ReqAttr=x509_presented,email'
              ]
            end

            it 'sets the correct authn_context' do
              get '/login_get', **params

              expect(OneLogin::RubySaml::Settings).to have_received(:new)
                .with(hash_including(authn_context: expected_authn_context))
            end
          end
        end
      end

      context 'with vtr enabled' do
        before do
          ENV['vtr_disabled'] = 'false'
        end

        context 'when the default parameters are used' do
          let(:expected_authn_context) do
            [
              'http://idmanagement.gov/ns/assurance/ial/1',
              'http://idmanagement.gov/ns/assurance/aal/2',
              'http://idmanagement.gov/ns/requested_attributes?ReqAttr=x509_presented,email'
            ]
          end

          it 'sets the correct authn_context' do
            get '/login_get', **params

            expect(OneLogin::RubySaml::Settings).to have_received(:new)
              .with(hash_including(authn_context: expected_authn_context))
          end

          context 'when semantic ial values are enabled' do
            before do
              ENV['semantic_ial_values_enabled'] = 'true'
            end

            let(:expected_authn_context) do
              [
                'urn:acr.login.gov:auth-only',
                'http://idmanagement.gov/ns/assurance/aal/2',
                'http://idmanagement.gov/ns/requested_attributes?ReqAttr=x509_presented,email'
              ]
            end

            it 'sets the correct authn_context' do
              get 'login_get', **params

              expect(OneLogin::RubySaml::Settings).to have_received(:new)
                .with(hash_including(authn_context: expected_authn_context))
            end
          end
        end

        context 'when the facial match is requested' do
          let(:params) { super().merge(ial: 'facial-match-vot') }
          let(:expected_authn_context) do
            [
              'C1.C2.P1.Pb',
              'http://idmanagement.gov/ns/requested_attributes?ReqAttr=x509_presented,email'
            ]
          end

          it 'sets the correct authn_context' do
            get '/login_get', **params

            expect(OneLogin::RubySaml::Settings).to have_received(:new)
              .with(hash_including(authn_context: expected_authn_context))
          end
        end
      end
    end
  end

  describe 'login_post' do
    let(:params) { { requested_attributes: ['x509_presented', 'email'] } }

    before do
      allow(OneLogin::RubySaml::Settings).to receive(:new)
        .and_call_original
    end

    let(:expected_authn_context) do
      [
        'http://idmanagement.gov/ns/assurance/ial/1',
        'http://idmanagement.gov/ns/assurance/aal/2',
        'http://idmanagement.gov/ns/requested_attributes?ReqAttr=x509_presented,email'
      ]
    end

    it 'sets the correct authn_context' do
      get 'login_post', **params

      expect(OneLogin::RubySaml::Settings).to have_received(:new)
        .with(hash_including(authn_context: expected_authn_context))
    end

    context 'when 2-phishing_resistant aal is requested' do
      let(:params) { super().merge(aal: '2-phishing_resistant') }
      let(:expected_authn_context) do
        [
          'http://idmanagement.gov/ns/assurance/ial/1',
          'http://idmanagement.gov/ns/assurance/aal/2?phishing_resistant=true',
          'http://idmanagement.gov/ns/requested_attributes?ReqAttr=x509_presented,email'
        ]
      end

      it 'sets the correct authn_context' do
        get 'login_post', **params

        expect(OneLogin::RubySaml::Settings).to have_received(:new)
          .with(hash_including(authn_context: expected_authn_context))
      end
    end

    context 'when 2-hspd12 aal is requested' do
      let(:params) { super().merge(aal: '2-hspd12') }
      let(:expected_authn_context) do
        [
          'http://idmanagement.gov/ns/assurance/ial/1',
          'http://idmanagement.gov/ns/assurance/aal/2?hspd12=true',
          'http://idmanagement.gov/ns/requested_attributes?ReqAttr=x509_presented,email'
        ]
      end

      it 'sets the correct authn_context' do
        get 'login_post', **params

        expect(OneLogin::RubySaml::Settings).to have_received(:new)
          .with(hash_including(authn_context: expected_authn_context))
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
        errors: []
      )
    end

    before do
      allow(OneLogin::RubySaml::Response).to receive(:new).and_return(response)
      allow(response).to receive(:is_valid?).and_return(valid_response)
    end

    context 'when the response is valid' do
      let(:valid_response) { true }

      it 'saves the correct values in the session' do
        post 'consume?SAMLResponse=something'
        follow_redirect!

        expect(last_request.session[:userid]).to eq(expected_name_id)
        expect(last_request.session[:email]).to eq(expected_email)
        expect(JSON.parse(last_request.session[:attributes])).to eq(expected_attributes)
      end
    end

    context 'when the response is invalid' do
      let(:valid_response) { false }

      it 'shows an authentication failure page' do
        post 'consume?SAMLResponse=something'

        expect(last_response).to be_ok
        expect(last_response.body).to include('Authentication Failure!')
      end
    end
  end

  describe 'failure_to_proof' do
    it 'shows the failure to proof page' do
      get '/failure_to_proof'
      expect(last_response).to be_ok
      expect(last_response.body).to include('We were unable to verify your identity')
    end
  end
end
