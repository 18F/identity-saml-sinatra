require 'dotenv/load'
require 'erb'
require 'hashie/mash'
require 'net/http'
require 'onelogin/ruby-saml'
require 'sinatra/base'
require 'uri'
require 'yaml'
require 'active_support/core_ext/object/to_query'

class RelyingParty < Sinatra::Base
  use Rack::Session::Cookie, key: 'sinatra_sp', secret: SecureRandom.hex(32)

  helpers do
    def ial_select_options
      options = [
        ['sp', 'Service Provider setting'],
        ['1', 'Authentication only (default)'],
        ['2', 'Identity-verified'],
        ['0', 'IALMax'],
        ['facial-match-preferred', 'Facial Match Preferred (ACR)'],
        ['facial-match-required', 'Facial Match Required (ACR)'],
        ['step-up', 'Step-up Flow'],
      ]

      if !ENV['vtr_disabled']
        options.push ['facial-match-vot', 'Facial Match (VOT)']
      end

      options
    end

    def requested_attributes_options
      # https://developers.login.gov/attributes/
      %w[
        uuid
        email
        all_emails
        ial
        aal
        first_name
        last_name
        address1
        address2
        city
        state
        zipcode
        phone
        dob
        ssn
        verified_at
        x509_issuer
        x509_subject
        x509_presented
      ]
    end

    def default_requested_attributes_by_ial
      ial2_options = [
        '2',
        'facial-match-preferred',
        'facial-match-required',
        'facial-match-vot',
        'enhanced-ipp-required',
      ]

      default_requested_attributes_by_ial = {
        nil => %w[email x509_presented],
        '0' => %w[email ssn x509_presented],
        '1' => %w[email x509_presented],
      }

      ial2_options.each do |ial2_option|
        default_requested_attributes_by_ial[ial2_option] = %w[
          email
          ssn
          phone
          address1
          address2
          city
          state
          zipcode
          x509_presented
        ]
      end

      default_requested_attributes_by_ial
    end
  end

  get '/' do
    logout_msg = session.delete(:logout)
    login_msg = session.delete(:login)
    ial, aal, force_authn, skip_encryption = extract_params

    login_path = '/login_get?' + {
      ial:,
      aal:,
    }.to_query

    erb :index, locals: {
      ial:,
      aal:,
      force_authn:,
      skip_encryption:,
      logout_msg:,
      login_msg:,
      login_path:,
      method: 'get',
    }
  end

  get '/login_get/?' do
    puts 'Logging in via GET'
    saml_auth_request = OneLogin::RubySaml::Authrequest.new
    puts "Request: #{saml_auth_request}"
    ial, aal, force_authn, skip_encryption, requested_attributes = extract_params
    settings = saml_settings(ial:, aal:, force_authn:, requested_attributes:)
    request_url = saml_auth_request.create(settings)
    request_url += "&#{ { skip_encryption: }.to_query }" if skip_encryption
    redirect to(request_url)
  end

  get '/login_post/?' do
    puts 'Logging in via POST'
    saml_auth_request = OneLogin::RubySaml::Authrequest.new
    puts "Request: #{saml_auth_request}"
    ial, aal, force_authn, skip_encryption, requested_attributes = extract_params
    settings = saml_settings(ial:, aal:, force_authn:, requested_attributes:)
    post_params = saml_auth_request.create_params(settings, skip_encryption:, 'RelayState' => params[:id])
    login_url   = settings.idp_sso_target_url
    erb :login_post, locals: { login_url:, post_params: }
  end

  post '/logout/?' do
    puts 'Logout received'
    settings = saml_settings.dup
    settings.name_identifier_value = session[:userid]
    redirect to(OneLogin::RubySaml::Logoutrequest.new.create(settings))
  end

  post '/slo_logout/?' do
    puts 'Logout response received'

    logout_response = OneLogin::RubySaml::Logoutresponse.new(params[:SAMLResponse], saml_settings)

    if logout_response.validate # ruby-saml uses is_valid? for some and validate for others inconsistently
      puts 'Logout OK'
      logout_session
      session[:logout] = 'ok'
    else
      puts 'Logout failed'
      session[:logout] = 'fail'
    end

    redirect to('/')
  end

  get '/success/?' do
    puts 'Success!'
    session[:login] = 'ok'
    redirect to('/')
  end

  post '/consume/?' do
    response = OneLogin::RubySaml::Response.new(
      params.fetch('SAMLResponse'), settings: saml_settings
    )

    if response.is_valid? # ruby-saml uses is_valid? for some and validate for others inconsistently
      user_uuid = response.name_id.gsub(/^_/, '')
      puts "Got SAMLResponse from NAMEID: #{user_uuid}"

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

  get '/failure_to_proof' do
    puts 'Failure to Proof :('
    erb :failure_to_proof
  end

  private

  def get_param(key, acceptable_values)
    value = params[key]
    case value
    when String
      value if acceptable_values.include?(value)
    when Array
      value & acceptable_values
    end
  end

  def logout_session
    session.delete(:userid)
    session.delete(:email)
    session.delete(:attributes)
    session.delete(:step_up_enabled)
    session.delete(:step_up_aal)
  end

  def saml_settings(ial: nil, aal: nil, requested_attributes: [], force_authn: false)
    template = File.read('config/saml_settings.yml')
    base_config = Hashie::Mash.new(YAML.safe_load(ERB.new(template).result(binding)))

    base_config.authn_context = [
      ial_authn_context(ial),
      aal_authn_context(aal, ial),
      *vtr_authn_context(ial:, aal:),
      "http://idmanagement.gov/ns/requested_attributes?ReqAttr=#{requested_attributes.join(',')}",
    ].compact
    base_config.force_authn = force_authn

    base_config.certificate = saml_sp_certificate
    base_config.private_key = saml_sp_private_key

    OneLogin::RubySaml::Settings.new(base_config)
  end

  def ial_authn_context(ial)
    return nil if vtr_needed?(ial)

    if semantic_ial_values_enabled?
      semantic_ial_values[ial]
    else
      legacy_ial_values[ial]
    end
  end

  def aal_authn_context(aal, ial)
    return nil if vtr_needed?(ial)

    case aal
    when '2'
      'http://idmanagement.gov/ns/assurance/aal/2'
    when '2-phishing_resistant'
      'http://idmanagement.gov/ns/assurance/aal/2?phishing_resistant=true'
    when '2-hspd12'
      'http://idmanagement.gov/ns/assurance/aal/2?hspd12=true'
    end
  end

  def vtr_authn_context(ial:, aal:)
    return nil unless vtr_needed?(ial)

    values = ['C1']

    values << {
      '2' => 'C2',
      '2-phishing_resistant' => 'C2.Ca',
      '2-hspd12' => 'C2.Cb',
    }[aal]

    values << {
      '2' => 'P1',
      'facial-match-vot' => 'P1.Pb',
    }[ial]

    vtr_list = [values.compact.join('.')]
    if ial == '0'
      proofing_vector = values.dup + ['P1']
      vtr_list = [proofing_vector.compact.join('.'), *vtr_list]
    end
    vtr_list
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

  def vtr_needed?(ial)
    vtr_enabled? && ial == 'facial-match-vot'
  end

  def vtr_enabled?
    !vtr_disabled?
  end

  def vtr_disabled?
    ENV['vtr_disabled'] == 'true'
  end

  def semantic_ial_values_enabled?
    ENV['semantic_ial_values_enabled'] == 'true'
  end

  def legacy_ial_values
    {
      '0' => 'http://idmanagement.gov/ns/assurance/ial/0',
      '1' => 'http://idmanagement.gov/ns/assurance/ial/1',
      '2' => 'http://idmanagement.gov/ns/assurance/ial/2',
      'facial-match-preferred' => 'http://idmanagement.gov/ns/assurance/ial/2?bio=preferred',
      'facial-match-required' => 'http://idmanagement.gov/ns/assurance/ial/2?bio=required',
    }
  end

  def semantic_ial_values
    {
      '0' => 'http://idmanagement.gov/ns/assurance/ial/0',
      '1' => 'urn:acr.login.gov:auth-only',
      '2' => 'urn:acr.login.gov:verified',
      'facial-match-required' => 'urn:acr.login.gov:verified-facial-match-required',
      'facial-match-preferred' => 'urn:acr.login.gov:verified-facial-match-preferred',
    }
  end

  def extract_params
    aal = get_param(:aal, %w[sp 1 2 2-phishing_resistant 2-hspd12]) || '2'
    ial = get_param(:ial, %w[sp 1 2 0 facial-match-vot facial-match-preferred facial-match-required step-up]) || '1'
    ial = prepare_step_up_flow(session:, ial:, aal:)
    force_authn = get_param(:force_authn, %w[true false])
    skip_encryption = get_param(:skip_encryption, %w[true false])
    requested_attributes = get_param(:requested_attributes, requested_attributes_options) || []
    [ial, aal, force_authn, skip_encryption, requested_attributes]
  end

  run! if app_file == $0
end
