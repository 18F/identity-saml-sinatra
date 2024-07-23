ENV['APP_ENV'] = 'test'

require_relative '../app'
require 'rspec'
require 'rack/test'
require 'spec_helper'
require 'pry'

RSpec.describe RelyingParty do
  include Rack::Test::Methods

  def app
    RelyingParty
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
end
