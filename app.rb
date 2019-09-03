require 'erb'
require 'hashie/mash'
require 'login_gov/hostdata'
require 'net/http'
require 'onelogin/ruby-saml'
require 'pp'
require 'sinatra/base'
require 'yaml'

class RelyingParty < Sinatra::Base
  use Rack::Session::Cookie, key: 'sinatra_sp', secret: SecureRandom.uuid

  def init(uri)
    @auth_server_uri = uri
  end

  def auth_server_uri
    @auth_server_uri ||= URI('https://localhost:1234')
  end

  get '/' do
    agency = params[:agency]
    whitelist = ['uscis', 'sba', 'ed']

    logout_msg = session.delete(:logout)
    login_msg = session.delete(:login)
    if whitelist.include?(agency)
      session[:agency] = agency
      erb :"agency/#{agency}/index", layout: false, locals: { logout_msg: logout_msg }
    else
      session.delete(:agency)
      erb :index, locals: { logout_msg: logout_msg, login_msg: login_msg }
    end
  end

  post '/login_get/?' do
    puts "Logging in via GET"
    request = OneLogin::RubySaml::Authrequest.new
    puts "Request: #{request}"
    redirect to(request.create(saml_settings))
  end

  post '/login_post/?' do
    puts "Logging in via POST"
    saml_request = OneLogin::RubySaml::Authrequest.new
    puts "Request: #{saml_request}"
    post_params = saml_request.create_params(saml_settings, 'RelayState' => params[:id])
    login_url   = saml_settings.idp_sso_target_url
    erb :login_post, locals: { login_url: login_url, post_params: post_params }
  end

  post '/logout/?' do
    puts 'Logout received'
    settings = saml_settings.dup
    settings.name_identifier_value = session[:userid]
    redirect to(OneLogin::RubySaml::Logoutrequest.new.create(settings))
  end

  post '/slo_logout/?' do
    if params[:SAMLRequest]
      puts 'SLO request came from IdP'
      idp_logout_request
    elsif params[:SAMLResponse]
      puts 'SLO response received'
      validate_slo_response
    else
      sp_logout_request
    end
  end

  get '/success/?' do
    agency = session[:agency]
    puts "Success!"
    if !agency.nil?
      erb :"agency/#{agency}/success", :layout => false
    else
      session[:login] = 'ok'
      redirect to('/')
    end
  end

  post '/consume/?' do
    response = OneLogin::RubySaml::Response.new(
      params.fetch('SAMLResponse'), settings: saml_settings
    )

    user_uuid = response.name_id.gsub(/^_/, '')

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
    template = File.read('config/saml_settings.yml')
    base_config = Hashie::Mash.new(YAML.safe_load(ERB.new(template).result(binding)))

    # TODO: don't use the demo cert and key in EC2 environments
    if LoginGov::Hostdata.in_datacenter? && (
      LoginGov::Hostdata.domain == 'login.gov' ||
      LoginGov::Hostdata.env == 'prod'
    )
      raise NotImplementedError.new('Refusing to use demo cert in production')
    end
    base_config.certificate = File.read('config/demo_sp.crt')
    base_config.private_key = File.read('config/demo_sp.key')

    OneLogin::RubySaml::Settings.new(base_config)
  end

  def idp_logout_request
    logout_request = OneLogin::RubySaml::SloLogoutrequest.new(
      params[:SAMLRequest],
      settings: saml_settings
    )
    if logout_request.is_valid?
      redirect_to_logout(logout_request)
    else
      render_logout_error(logout_request)
    end
  end

  def redirect_to_logout(logout_request)
    puts "IdP initiated Logout for #{logout_request.nameid}"
    logout_session
    logout_response = OneLogin::RubySaml::SloLogoutresponse.new.create(
      saml_settings,
      logout_request.id,
      nil,
      RelayState: params[:RelayState]
    )
    redirect to(logout_response)
  end

  def render_logout_error(logout_request)
    error_msg = "IdP initiated LogoutRequest was not valid: #{logout_request.errors}"
    puts error_msg
    @errors = error_msg
    erb :failure
  end

  def validate_slo_response
    slo_response = idp_logout_response
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

  def idp_logout_response
    OneLogin::RubySaml::Logoutresponse.new(params[:SAMLResponse], saml_settings)
  end

  def sp_logout_request
    settings = saml_settings.dup
    settings.name_identifier_value = session[:user_id]
    logout_request = OneLogin::RubySaml::Logoutrequest.new.create(settings)
    redirect to(logout_request)
  end

  run! if app_file == $0
end
