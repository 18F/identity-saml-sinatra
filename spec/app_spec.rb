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
    ENV['assertion_consumer_service_url'] = 'http://localhost:4567/consume'
    ENV['idp_sso_target_url'] = 'http://localhost:3000/api/saml/auth2024'
    ENV['idp_slo_target_url'] = 'http://localhost:3000/api/saml/logout2024'
    ENV['idp_host'] = 'localhost:3000'
    ENV['idp_cert_fingerprint'] = 'EF:54:67:D4:32:C7:52:E9:8C:25:22:EF:4D:65:4D:08:C9:9A:D8:DC'
    ENV['new_ial_values_enabled'] = 'false'
  end

  context '/' do
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

    context 'when the agency parameter is used with a supported agency' do
      it "uses the agency's logo" do
        get '/?agency=uscis'

        expect(last_response.body).to include('img/uscis/logo.png')
        expect(last_response.body).not_to include('img/seal.png')
      end
    end

    context 'when the agency parameter is used with an unsupported agency' do
      it 'uses the default logo' do
        get '/?agency=foo'

        expect(last_response.body).not_to include('img/uscis/logo.png')
        expect(last_response.body).to include('us-flag.png')
      end
    end
  end

  context '/success' do
    it 'redirects to the root' do
      get '/success'

      expect(last_response).to be_redirect
      expect(URI(last_response.location).path).to eq('/')
    end
  end

  describe 'login_get' do
    let(:expected_authn_context) { nil }
    context 'with vtr_disabled' do
      before do
        ENV['vtr_disabled'] = 'true'
        expect(OneLogin::RubySaml::Settings).to receive(:new)
          .with(hash_including(authn_context: expected_authn_context)).and_call_original
      end

      context 'when the default parameters are used' do
        let(:expected_authn_context) do
          ['http://idmanagement.gov/ns/assurance/ial/1',
           'http://idmanagement.gov/ns/assurance/aal/2',
           'http://idmanagement.gov/ns/requested_attributes?ReqAttr=x509_presented,email']
        end

        it 'sets the correct authn_context' do
          get '/login_get'
        end

        context 'when new ial values are enabled' do
          before do
            ENV['new_ial_values_enabled'] = 'true'
          end

          let(:expected_authn_context) do
            [
              'urn:acr.login.gov:auth-only',
              'http://idmanagement.gov/ns/assurance/aal/2',
              'http://idmanagement.gov/ns/requested_attributes?ReqAttr=x509_presented,email'
            ]
          end

          it 'sets the correct authn_context' do
            get 'login_get'
          end
        end
      end

      context 'when biometric-comparison-preferred is selected' do
        let(:expected_authn_context) do
          ['http://idmanagement.gov/ns/assurance/ial/2?bio=preferred',
           'http://idmanagement.gov/ns/assurance/aal/2',
           'http://idmanagement.gov/ns/requested_attributes?ReqAttr=x509_presented,email']
        end

        it 'sets the correct authn_context' do
          get '/login_get?ial=biometric-comparison-preferred'
        end

        context 'when new ial values are enabled' do
          before do
            ENV['new_ial_values_enabled'] = 'true'
          end

          let(:expected_authn_context) do
            [
              'urn:acr.login.gov:verified-facial-match-preferred',
              'http://idmanagement.gov/ns/assurance/aal/2',
              'http://idmanagement.gov/ns/requested_attributes?ReqAttr=x509_presented,email'
            ]
          end

          it 'sets the correct authn_context' do
            get '/login_get?ial=biometric-comparison-preferred'
          end
        end
      end

      context 'when biometric-comparison-required is selected' do
        let(:expected_authn_context) do
          ['http://idmanagement.gov/ns/assurance/ial/2?bio=required',
           'http://idmanagement.gov/ns/assurance/aal/2',
           'http://idmanagement.gov/ns/requested_attributes?ReqAttr=x509_presented,email']
        end

        it 'sets the correct authn_context' do
          get '/login_get?ial=biometric-comparison-required'
        end

        context 'when new ial values are enabled' do
          before do
            ENV['new_ial_values_enabled'] = 'true'
          end

          after do
            ENV['new_ial_values_enabled'] = 'false'
          end

          let(:expected_authn_context) do
            [
              'urn:acr.login.gov:verified-facial-match-required',
              'http://idmanagement.gov/ns/assurance/aal/2',
              'http://idmanagement.gov/ns/requested_attributes?ReqAttr=x509_presented,email'
            ]
          end

          it 'sets the correct authn_context' do
            get '/login_get?ial=biometric-comparison-required'
          end
        end
      end
    end

    context 'with vtr enabled' do
      before do
        ENV['vtr_disabled'] = 'false'
        expect(OneLogin::RubySaml::Settings).to receive(:new)
          .with(hash_including(authn_context: expected_authn_context)).and_call_original
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
          get '/login_get'
        end

        context 'when new ial values is enabled' do
          before do
            ENV['new_ial_values_enabled'] = 'true'
          end

          let(:expected_authn_context) do
            [
              'urn:acr.login.gov:auth-only',
              'http://idmanagement.gov/ns/assurance/aal/2',
              'http://idmanagement.gov/ns/requested_attributes?ReqAttr=x509_presented,email'
            ]
          end

          it 'sets the correct authn_context' do
            get 'login_get'
          end
        end
      end

      context 'when the biometric comparison is requested' do
        let(:expected_authn_context) do
          [
            'C1.C2.P1.Pb',
            'http://idmanagement.gov/ns/requested_attributes?ReqAttr=x509_presented,email'
          ]
        end

        it 'sets the correct authn_context' do
          get '/login_get/?ial=biometric-comparison-vot'
        end
      end
    end
  end
end
