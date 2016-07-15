require 'dotenv'
require 'erb'
require 'hashie/mash'
require 'net/http'
require 'pp'
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

    @logout_msg = session.delete(:logout)
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

  post '/logout/?' do
    puts 'Logout received'
    settings = saml_settings.dup
    settings.name_identifier_value = session[:userid]
    redirect to(OneLogin::RubySaml::Logoutrequest.new.create(settings))
  end

  post '/slo_logout/?' do
    puts 'SLO response received'
    slo_response = OneLogin::RubySaml::Logoutresponse.new(
      params[:SAMLResponse],
      saml_settings
    )
    if slo_response.validate
      puts 'Logout OK'
      logout_session
      session[:logout] = 'ok'
      redirect to(home_page)
    else
      puts 'Logout failed'
      session[:logout] = 'fail'
      redirect to(home_page)
    end
  end

  get '/success/?' do
    agency = session[:agency]
    puts "Success!"
    if !agency.nil?
      erb :"agency/#{agency}/success", :layout => false
    else
      erb :success
    end
  end

  post '/consume/?' do
    response = OneLogin::RubySaml::Response.new(params[:SAMLResponse])

    user_uuid = response.name_id.gsub(/^_/, '')

    # insert identity provider discovery logic here
    response.settings = saml_settings
    puts "Got SAMLResponse from NAMEID: #{user_uuid}"

    if response.is_valid?
      session[:userid] = user_uuid
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

  def logout_session
    session.delete(:userid)
    session.delete(:email)
  end

  def home_page
    if session[:agency]
      "/?agency=#{session[:agency]}"
    else
      '/'
    end
  end

  def saml_settings
    if ENV['SAML_ENV'] == 'local'
      settings_file = 'config/saml_settings_local.yml'
    elsif ENV['SAML_ENV'] == 'dev'
      settings_file = 'config/saml_settings_dev.yml'
    else
      settings_file = 'config/saml_settings_demo.yml'
    end
    base_config = Hashie::Mash.new(YAML.load_file(settings_file))
    base_config.certificate = File.read('config/demo_sp.crt')
    base_config.private_key = File.read('config/demo_sp.key')
    OneLogin::RubySaml::Settings.new(base_config)
  end

  run! if app_file == $0
end
