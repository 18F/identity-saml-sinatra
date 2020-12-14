ENV['RACK_ENV'] = 'test'

require_relative '../app'
require 'test/unit'
require 'rack/test'
require 'mocha/test_unit'

class FakeIdvaasTest < Test::Unit::TestCase
  include Rack::Test::Methods

  def app
    RelyingParty
  end

  def test_it_shows_main_page
    get '/'
    assert last_response.ok?
    assert last_response.body.include? '<form action="/login" method="POST">'
  end

  def test_main_page_xss
    get '/?ial=%22%20onmouseover=%22alert(document.domain)%22%20k=%22'
    assert !last_response.body.include?('alert(document.domain)')
  end

  def test_agency_template_override
    get '/?agency=uscis'
    assert last_response.body.include? 'img/uscis/logo.png'
    assert !(last_response.body.include? 'img/seal.png')
  end

  def test_agency_template_no_override
    get '/?agency=foo'
    assert !(last_response.body.include? 'img/uscis/logo.png')
    assert last_response.body.include? 'us-flag.png'
  end

  def test_it_shows_success
    get '/success/'
    assert last_response.redirect?
  end
end
