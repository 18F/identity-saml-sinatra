require 'dotenv'
require 'erb'
require 'net/http'
require 'sinatra/base'
require 'onelogin/ruby-saml'
require 'yaml'

Dotenv.load

class RelyingParty < Sinatra::Base
  use Rack::Session::Cookie, :key => 'sinatra_sp'

  if ENV['SP_NAME'] && ENV['SP_PASS']
    use Rack::Auth::Basic, "Restricted" do |username, password|
      username == ENV['SP_NAME'] && password == ENV['SP_PASS']
    end
  end

  def init(uri)
    @auth_server_uri = uri
  end

  def auth_server_uri
    @auth_server_uri ||= URI('https://localhost:1234')
  end

  get '/' do
    agency = params[:agency]
    whitelist = ['uscis', 'sba', 'ed']

    if whitelist.include?(agency)
      session[:agency] = agency
      erb :"agency/#{agency}/index", :layout => false
    else
      session.delete(:agency)
      erb :index
    end
  end

  post '/login/?' do
    puts 'Login received'
    request = OneLogin::RubySaml::Authrequest.new
    puts "Request: #{request}"
    redirect to(request.create(saml_settings))
  end

  get '/success/?' do
    agency = session[:agency]
    if !agency.nil?
      erb :"agency/#{agency}/success", :layout => false
    else
      erb :success
    end
  end

  post '/consume/?' do
    response = OneLogin::RubySaml::Response.new(params[:SAMLResponse])

    # insert identity provider discovery logic here
    response.settings = saml_settings
    puts "Got SAMLResponse from NAMEID: #{response.name_id}"

    if response.is_valid?
      session[:userid] = response.name_id
      session[:email] = response.attributes['email']
      puts 'SAML Success!'
      redirect to('/success')
    else
      puts 'SAML Fail :('
      @errors = response.errors
      erb :failure
    end
  end

  private

  def saml_settings
    if ENV['SAML_ENV'] == 'local'
      settings_file = 'config/saml_settings_local.yml'
    elsif ENV['SAML_ENV'] == 'dev'
      settings_file = 'config/saml_settings_dev.yml'
    else
      settings_file = 'config/saml_settings_demo.yml'
    end
    settings = OneLogin::RubySaml::Settings.new(YAML.load_file settings_file)
    settings.certificate = File.read('config/demo_sp.crt')
    settings.private_key = File.read('config/demo_sp.key')
    settings
  end

  run! if app_file == $0
end
