require 'erb'
require 'net/http'
require 'sinatra/base'
require 'onelogin/ruby-saml'
require 'yaml'


class RelyingParty < Sinatra::Base
  enable :sessions

  def init(uri)
    @auth_server_uri = uri
  end

  def auth_server_uri
    @auth_server_uri ||= URI('https://localhost:1234')
  end

  get '/' do
    agency = params[:agency]
    whitelist = ['uscis']

    if whitelist.include?(agency)
      erb :"agency/#{agency}/index", :layout => false
    else
      erb :index
    end
  end

  post '/login/?' do
    puts 'Login received'
    request = OneLogin::RubySaml::Authrequest.new
    puts "Request: #{request}"
    x = saml_settings
    redirect to(request.create(saml_settings))
  end

  get '/success/?' do
    # default to uscis success page for now
    erb :"agency/uscis/success", :layout => false
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
      session[:email] = "fail fail fail"
      redirect to('/success')
    end
  end

  private

  def saml_settings
    settings = OneLogin::RubySaml::Settings.new(YAML.load_file 'config/saml_settings.yml')
    settings.certificate = File.read('config/server.crt')
    settings.private_key = File.read('config/server.key')
    settings.idp_cert =  File.read('config/idp.crt')
    settings
  end

  run! if app_file == $0
end
