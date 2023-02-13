require 'dotenv/load'
require 'erb'
require 'hashie/mash'
require 'net/http'
require 'onelogin/ruby-saml'
require 'pp'
require 'sinatra/base'
require 'uri'
require 'yaml'
require 'active_support/core_ext/object/to_query'
require 'active_support/core_ext/object/blank'

class RelyingParty < Sinatra::Base
  use Rack::Session::Cookie, key: 'sinatra_sp', secret: SecureRandom.uuid

  def init(uri)
    @auth_server_uri = uri
  end

  def auth_server_uri
    @auth_server_uri ||= URI('https://localhost:1234')
  end

  def get_param(key, acceptable_values)
    value = params[key]
    value if acceptable_values.include?(value)
  end

  get '/' do
    agency = get_param(:agency, %w[uscis sba ed])

    logout_msg = session.delete(:logout)
    login_msg = session.delete(:login)
    if agency
      session[:agency] = agency
      erb :"agency/#{agency}/index", layout: false, locals: { logout_msg: logout_msg }
    else
      ial = get_param(:ial, %w[sp 1 2 0 step-up]) || '1'
      aal = get_param(:aal, %w[sp 1 2 2-phishing_resistant 2-hspd12]) || '2'
      ial = prepare_step_up_flow(session: session, ial: ial, aal: aal)
      force_authn = get_param(:force_authn, %w[true false])
      skip_encryption = get_param(:skip_encryption, %w[true false])

      login_path = '/login_get?' + {
        ial: ial,
        aal: aal,
      }.to_query

      session.delete(:agency)
      erb :index, locals: {
        ial: ial,
        aal: aal,
        force_authn: force_authn,
        skip_encryption: skip_encryption,
        logout_msg: logout_msg,
        login_msg: login_msg,
        login_path: login_path,
        method: 'get',
      }
    end
  end

  get '/login_get/?' do
    puts 'Logging in via GET'
    request = OneLogin::RubySaml::Authrequest.new
    puts "Request: #{request}"
    ial = get_param(:ial, %w[sp 1 2 0 step-up]) || '1'
    aal = get_param(:aal, %w[sp 1 2 2-phishing_resistant 2-hspd12]) || '2'
    ial = prepare_step_up_flow(session: session, ial: ial, aal: aal)
    force_authn = get_param(:force_authn, %w[true false])
    skip_encryption = get_param(:skip_encryption, %w[true false])
    request_url = request.create(saml_settings(ial: ial, aal: aal, force_authn: force_authn))
    request_url += "&#{ { skip_encryption: skip_encryption }.to_query }" if skip_encryption
    redirect to(request_url)
  end

  get '/login_post/?' do
    puts 'Logging in via POST'
    saml_request = OneLogin::RubySaml::Authrequest.new
    puts "Request: #{saml_request}"
    ial = get_param(:ial, %w[sp 1 2 0 step-up]) || '1'
    aal = get_param(:aal, %w[sp 1 2 2-phishing_resistant 2-hspd12]) || '2'
    ial = prepare_step_up_flow(session: session, ial: ial, aal: aal)
    force_authn = get_param(:force_authn, %w[true false])
    skip_encryption = get_param(:skip_encryption, %w[true false])
    settings = saml_settings(ial: ial, aal: aal, force_authn: force_authn)
    post_params = saml_request.create_params(settings, skip_encryption: skip_encryption, 'RelayState' => params[:id])
    login_url   = settings.idp_sso_target_url
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
    puts 'Success!'
    if !agency.nil?
      erb :"agency/#{agency}/success", layout: false
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
      if session.delete(:step_up_enabled)
        aal = session.delete(:step_up_aal)

        redirect to("/login_get/?aal=#{aal}&ial=2")
      else
        session[:userid] = user_uuid
        session[:email] = response.attributes['email']
        session[:attributes] = response.attributes.to_h.to_json

        puts 'SAML Success!'
        redirect to('/success')
      end
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
    session.delete(:attributes)
    session.delete(:step_up_enabled)
    session.delete(:step_up_aal)
  end

  def home_page
    if session[:agency]
      '/?' + { agency: session[:agency] }.to_query
    else
      '/'
    end
  end

  def saml_settings(ial: nil, aal: nil, force_authn: false)
    template = File.read('config/saml_settings.yml')
    base_config = Hashie::Mash.new(YAML.safe_load(ERB.new(template).result(binding)))

    ial_context = case ial
    when '1'
      'http://idmanagement.gov/ns/assurance/ial/1'
    when '2'
      'http://idmanagement.gov/ns/assurance/ial/2'
    when '0'
      'http://idmanagement.gov/ns/assurance/ial/0'
    else
      nil
    end

    aal_context = case aal
    when '2'
      'http://idmanagement.gov/ns/assurance/aal/2'
    when '2-phishing_resistant'
      'http://idmanagement.gov/ns/assurance/aal/2?phishing_resistant=true'
    when '2-hspd12'
      'http://idmanagement.gov/ns/assurance/aal/2?hspd12=true'
    else
      nil
    end

    base_config.ial_context = ial_context if ial_context
    base_config.aal_context = aal_context if aal_context
    base_config.authn_context = [base_config.ial_context, base_config.aal_context].compact
    base_config.force_authn = force_authn

    base_config.certificate = saml_sp_certificate
    base_config.private_key = saml_sp_private_key

    OneLogin::RubySaml::Settings.new(base_config)
  end

  def saml_sp_certificate
    return @saml_sp_certificate if defined?(@saml_sp_certificate)

    if running_in_prod_env? && !ENV['sp_cert']
      raise NotImplementedError, 'Refusing to use demo cert in production'
    end

    @saml_sp_certificate = ENV['sp_cert'] || File.read('config/demo_sp.crt')
  end

  def saml_sp_private_key
    return @saml_sp_private_key if defined?(@saml_sp_private_key)

    if running_in_prod_env? && !ENV['sp_private_key']
      raise NotImplementedError, 'Refusing to use demo private key in production'
    end

    @saml_sp_private_key = ENV['sp_private_key'] || File.read('config/demo_sp.key')
  end

  def running_in_prod_env?
    @running_in_prod_env ||= URI.parse(ENV['idp_sso_target_url']).hostname.match?(/login\.gov/)
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

  def prepare_step_up_flow(session:, ial:, aal: nil)
    if ial == 'step-up'
      ial = '1'
      session[:step_up_enabled] = 'true'
      session[:step_up_aal] = aal if %r{^\d$}.match?(aal)
    else
      session.delete(:step_up_enabled)
      session.delete(:step_up_aal)
    end

    ial
  end

  def maybe_redact_ssn(ssn)
    ssn&.gsub(/\d/, '#')
  end

  run! if app_file == $0
end
