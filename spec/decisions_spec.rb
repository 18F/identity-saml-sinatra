# frozen_string_literal: true

ENV['APP_ENV'] = 'test'

require_relative '../app'
require 'rspec'
require 'rack/test'

RSpec.describe 'decision log (/decisions)' do
  include Rack::Test::Methods

  let(:factory) { DelegatedAssertionFactory }

  def app
    RelyingParty
  end

  before do
    ENV['idp_url'] = 'http://localhost:3000'
    ENV.delete('IDP_METADATA_URL')
    ENV['SAML_METADATA_YEAR'] = '2026'
    ENV['RESOURCE_IDENTIFIER'] = factory::RESOURCE
    stub_request(:get, factory::METADATA_URL).to_return(status: 200, body: factory.metadata_xml)
    RelyingParty.reset_idp_metadata!
    RelyingParty.settings.replay_cache.clear
    RelyingParty.settings.decision_log.clear
  end

  it 'records allow and deny decisions with the delegation context, newest first' do
    header 'Authorization', "Bearer #{factory.token(attributes: factory::DEFAULT_ATTRIBUTES.merge('delegation_id' => 'del-A'))}"
    get '/api/benefits'
    expect(last_response.status).to eq(200)

    header 'Authorization', "Bearer #{factory.token(audience: 'https://other.example')}"
    get '/api/benefits'
    expect(last_response.status).to eq(401)

    header 'Authorization', nil
    get '/decisions.json'
    decisions = JSON.parse(last_response.body)['decisions']

    expect(decisions.size).to eq(2)
    expect(decisions[0]).to include('decision' => 'deny', 'route' => 'GET /api/benefits', 'delegation_id' => nil)
    expect(decisions[0]['reason']).to match(/Audience/)
    expect(decisions[1]).to include(
      'decision' => 'allow',
      'actor' => factory::ACTOR,
      'delegation_id' => 'del-A',
      'required_scope' => 'token_exchange:benefits_read',
      'delegation_scopes' => %w[token_exchange:benefits_read token_exchange:benefits_write],
      'uuid' => 'agency-uuid-1234',
    )
  end

  it 'renders the HTML table with escaping' do
    header 'Authorization', "Bearer #{factory.token(attributes: factory::DEFAULT_ATTRIBUTES.merge('actor' => '<script>x</script>'))}"
    get '/api/benefits'

    header 'Authorization', nil
    get '/decisions'

    expect(last_response).to be_ok
    expect(last_response.body).to include('API authorization decisions')
    expect(last_response.body).to include('&lt;script&gt;x&lt;/script&gt;')
    expect(last_response.body).not_to include('<script>x</script>')
  end

  it 'keeps only the most recent entries' do
    log = DecisionLog.new(max_size: 2)
    3.times { |i| log.record(route: "GET /#{i}", decision: 'allow') }

    expect(log.entries.map(&:route)).to eq(['GET /2', 'GET /1'])
  end
end
