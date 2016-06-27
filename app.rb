require 'dotenv'
require 'erb'
require 'net/http'
require 'sinatra/base'
require 'onelogin/ruby-saml'
require 'yaml'

Dotenv.load

class RelyingParty < Sinatra::Base
  enable :sessions

  use Rack::Auth::Basic, "Restricted" do |username, password|
    username == ENV['SP_NAME'] and password == ENV['SP_PASS']
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
    puts "params: #{params}"
    response = OneLogin::RubySaml::Response.new(params[:SAMLResponse])

    # insert identity provider discovery logic here
    response.settings = saml_settings
    puts "NAMEID: #{response.name_id}"

    if response.is_valid?
      session[:userid] = response.name_id
      session[:email] = response.attributes['email']
      puts 'Success!'
      redirect to('/success')
    else
      puts 'Fail :('
      puts response.errors
      # session[:email] = "fail fail fail"
      redirect to('/success')
    end
  end

  private

  def saml_settings
    if ENV['SAML_ENV'] == 'local'
      settings_file = 'config/saml_settings_local.yml'
    else
      settings_file = 'config/saml_settings.yml'
    end
    settings = OneLogin::RubySaml::Settings.new(YAML.load_file settings_file)
    settings.certificate = File.read('config/demo_sp.crt')
    settings.private_key = File.read('config/demo_sp.key')
    settings
  end

  run! if app_file == $0
end
