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
      ial = get_param(:ial, %w[sp 1 2 2-strict 0 step-up]) || '1'
      aal = get_param(:aal, %w[sp 1 2 3 3-hspd12]) || '2'
      ial = prepare_step_up_flow(session: session, ial: ial, aal: aal)
      skip_encryption = get_param(:skip_encryption, %w[true false])

      login_path = '/login_get?' + {
        ial: ial,
        aal: aal,
      }.to_query

      session.delete(:agency)
      erb :index, locals: {
        ial: ial,
        aal: aal,
        skip_encryption: skip_encryption,
        logout_msg: logout_msg,
        login_msg: login_msg,
        login_path: login_path,
      }
    end
  end

  get '/login_get/?' do
    puts 'Logging in via GET'
    request = OneLogin::RubySaml::Authrequest.new
    puts "Request: #{request}"
    ial = get_param(:ial, %w[sp 1 2 2-strict 0 step-up]) || '1'
    aal = get_param(:aal, %w[sp 1 2 3 3-hspd12]) || '2'
    ial = prepare_step_up_flow(session: session, ial: ial, aal: aal)
    skip_encryption = get_param(:skip_encryption, %w[true false])
    request_url = request.create(saml_settings(ial: ial, aal: aal))
    request_url += "&#{ { skip_encryption: skip_encryption }.to_query }" if skip_encryption
    redirect to(request_url)
  end

  post '/login_post/?' do
    puts 'Logging in via POST'
    saml_request = OneLogin::RubySaml::Authrequest.new
    puts "Request: #{saml_request}"
    ial = get_param(:ial, %w[sp 1 2 2-strict 0 step-up]) || '1'
    aal = get_param(:aal, %w[sp 1 2 3 3-hspd12]) || '2'
    ial = prepare_step_up_flow(session: session, ial: ial, aal: aal)
    skip_encryption = get_param(:skip_encryption, %w[true false])
    settings = saml_settings(ial: ial, aal: aal)
    post_params = saml_request.create_params(settings, skip_encryption: skip_encryption, 'RelayState' => params[:id])
    login_url   = settings.idp_sso_target_url
    # erb :login_post, locals: { login_url: login_url, post_params: post_params }
    erb :login_post, locals: { login_url: login_url, post_params: { SAMLRequest: "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"} }
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
    # require 'pry'
    # binding.pry

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

  def saml_settings(ial: nil, aal: nil)
    template = File.read('config/saml_settings.yml')
    base_config = Hashie::Mash.new(YAML.safe_load(ERB.new(template).result(binding)))

    ial_context = case ial
    when '1'
      'http://idmanagement.gov/ns/assurance/ial/1'
    when '2'
      'http://idmanagement.gov/ns/assurance/ial/2'
    when '2-strict'
      'http://idmanagement.gov/ns/assurance/ial/2?strict=true'
    when '0'
      'http://idmanagement.gov/ns/assurance/ial/0'
    else
      nil
    end

    aal_context = case aal
    when '2'
      'http://idmanagement.gov/ns/assurance/aal/2'
    when '3'
      'http://idmanagement.gov/ns/assurance/aal/3'
    when '3-hspd12'
      'http://idmanagement.gov/ns/assurance/aal/3?hspd12=true'
    else
      nil
    end

    base_config.ial_context = ial_context if ial_context
    base_config.aal_context = aal_context if aal_context
    base_config.authn_context = [base_config.ial_context, base_config.aal_context].compact

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
