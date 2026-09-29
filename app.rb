require 'dotenv/load'
require 'erb'
require 'hashie/mash'
require 'net/http'
require 'onelogin/ruby-saml'
require 'sinatra/base'
require 'uri'
require 'yaml'
require 'active_support/core_ext/object/to_query'
require 'json'

require_relative './resource_server_config'
require_relative './idp_metadata'
require_relative './delegated_assertion'
require_relative './assertion_replay_cache'
require_relative './decision_log'
require_relative './demo_benefits'

class RelyingParty < Sinatra::Base
  use Rack::Session::Cookie, key: 'sinatra_sp', secret: SecureRandom.hex(32)

  # --- Delegated-access resource server state (requirements §15.7, Appendix D step 19) ---
  # These live on the class so every request shares them within the process.
  set :rs_config, ResourceServerConfig.new
  set :decision_log, DecisionLog.new(max_size: rs_config.decision_log_size)
  set :replay_cache, AssertionReplayCache.new
  set :benefits, DemoBenefits.new

  # IdP metadata is fetched lazily on the first API call so the app boots
  # without the IdP and so tests can point IDP_METADATA_URL at a stub.
  def self.idp_metadata
    @idp_metadata ||= IdpMetadata.new(
      url: rs_config.idp_metadata_url,
      cache_seconds: rs_config.idp_metadata_cache_seconds,
    )
  end

  def self.reset_idp_metadata!
    @idp_metadata = nil
  end

  # Scopes as they appear on the wire: the full `token_exchange:` form. The
  # exchange response `scope`, introspection and the SAML `delegation_scopes`
  # attribute all carry it, and resource servers compare whole strings.
  BENEFITS_READ = 'token_exchange:benefits_read'
  BENEFITS_WRITE = 'token_exchange:benefits_write'

  # Raised by #bearer_token when the request carries no Bearer credentials.
  class MissingToken < StandardError; end
  # Raised by #bearer_token when there is a Bearer header but it is malformed.
  class MalformedToken < StandardError; end

  # Raised by #enforce_scope; carries the validated assertion for the decision log.
  class InsufficientScope < StandardError
    attr_reader :assertion, :required_scope

    def initialize(assertion, required_scope)
      @assertion = assertion
      @required_scope = required_scope
      super("delegation_scopes does not include #{required_scope}")
    end
  end

  # rubocop:disable Metrics/BlockLength
  helpers do
    # HTML-escape values that came from assertions or Attempts events.
    def h(text)
      Rack::Utils.escape_html(text.to_s)
    end

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
  # rubocop:enable Metrics/BlockLength

  get '/' do
    logout_msg = session.delete(:logout)
    login_msg = session.delete(:login)
    errors = session.delete(:errors)
    error_type = session.delete(:error_type)
    ial, aal, force_authn, skip_encryption = extract_params

    login_path = '/login_get?' + {
      ial:,
      aal:,
    }.to_query

    erb :index, locals: {
      aal:,
      error_type:,
      errors:,
      force_authn:,
      ial:,
      login_msg:,
      login_path:,
      logout_msg:,
      method: 'get',
      skip_encryption:,
    }
  end

  get '/login_get/?' do
    puts 'Logging in via GET'
    puts "Request: #{saml_auth_request}"
    request_url = saml_auth_request.create(
      saml_request_data('GET'),
      {
        skip_encryption:,
        prompt:,
      }.compact,
    )
    redirect to(request_url)
  end

  get '/login_post/?' do
    puts 'Logging in via POST'
    puts "Request: #{saml_auth_request}"
    settings =  saml_request_data('POST')
    post_params = saml_auth_request.create_params(
     settings,
      skip_encryption:,
      prompt:,
      'RelayState' => params[:id],
    )
    login_url = settings.idp_sso_target_url
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

    # ruby-saml uses is_valid? for some and validate for others inconsistently
    if logout_response.validate
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
        session[:authn_instant] = response.authn_instant
        session[:attributes] = response.attributes.to_h.to_json

        puts 'SAML Success!'
        redirect to('/success')
      end
    else
      puts 'SAML Fail :('
      session[:error_type] = 'Authentication failure'
      session[:errors] = response.errors || ['Something unknown went wrong.']

      redirect to('/')
    end
  end


  # ===========================================================================
  # Delegated-access API (§15.7). The service provider calls these with the
  # SAML assertion Login.gov's token exchange issued for this resource server.
  # ===========================================================================

  # Reads require the read capability the user approved for this API.
  get '/api/benefits' do
    assertion = authorize!(BENEFITS_READ)
    record = settings.benefits.record_for(assertion.name_id)
    json_response(benefits_payload(assertion, record))
  end

  # Writes require the read_write capability. The scope check *is* the policy:
  # a delegation with only benefits_read gets 403 insufficient_scope here.
  post '/api/benefits' do
    assertion = authorize!(BENEFITS_WRITE)
    changes = parse_json_body
    record = settings.benefits.update(
      assertion.name_id,
      changes,
      actor: assertion.actor,
      delegation_id: assertion.delegation_id,
    )
    json_response(benefits_payload(assertion, record))
  rescue DemoBenefits::InvalidChange => e
    halt_json(400, 'invalid_request', e.message)
  end

  # Every decision the API made (REF-IMPL-2), newest first.
  get '/decisions' do
    erb :decisions, locals: { decisions: settings.decision_log.entries }
  end

  get '/decisions.json' do
    json_response(decisions: settings.decision_log.entries.map(&:to_h))
  end

  get '/failure_to_proof' do
    puts 'Failure to Proof :('
    session[:error_type] = 'Proofing failure'
    session[:errors] = ['We were unable to verify your identity.']
    redirect to('/')
  end

  private


  # ---------------------------------------------------------------------------
  # Authorization for delegated API calls: one method per protocol step.
  # ---------------------------------------------------------------------------

  # Authorize the current request for `required_scope`, or halt with an
  # RFC 6750 §3 error response. Steps, in order:
  #
  #   bearer_token                RFC 6750 §2.1  Authorization: Bearer <access_token>
  #   DelegatedAssertion.decode   RFC 8693 §3    base64url SAML 2.0 assertion
  #   validate_assertion          §15.7 items 2, 3, 5  signature, Issuer, Recipient,
  #                               Audience, both time windows, no InResponseTo;
  #                               no call to Login.gov
  #   enforce_scope               §15.7 item 4   delegation_scopes per endpoint
  #   log_decision                REF-IMPL-2     record what was decided
  #
  # @return [DelegatedAssertion] the validated assertion
  def authorize!(required_scope)
    token = bearer_token
    assertion = validate_assertion(DelegatedAssertion.decode(token))
    enforce_scope(assertion, required_scope)
    log_decision(assertion, required_scope:, decision: 'allow')
    assertion
  rescue MissingToken
    log_decision(nil, required_scope:, decision: 'deny', reason: 'no bearer token')
    # RFC 6750 §3.1: a request with no credentials gets the challenge and no error code.
    halt_bearer_error(401, nil, 'Authorization: Bearer <delegated SAML assertion> required')
  rescue MalformedToken => e
    log_decision(nil, required_scope:, decision: 'deny', reason: e.message)
    halt_bearer_error(400, 'invalid_request', e.message)
  rescue DelegatedAssertion::InvalidAssertion => e
    log_decision(nil, required_scope:, decision: 'deny', reason: e.message)
    halt_bearer_error(401, 'invalid_token', e.message)
  rescue InsufficientScope => e
    log_decision(e.assertion, required_scope:, decision: 'deny', reason: e.message)
    halt_bearer_error(403, 'insufficient_scope', e.message, scope: required_scope)
  rescue IdpMetadata::FetchError => e
    # Fail closed: without the IdP's certificate nothing can be verified.
    log_decision(nil, required_scope:, decision: 'deny', reason: e.message)
    halt_json(503, 'temporarily_unavailable', e.message)
  end

  # RFC 6750 §2.1: the access token is sent in the Authorization header with
  # the Bearer scheme (scheme name case-insensitive) in b64token syntax. The
  # form-body (§2.2) and query (§2.3) methods are not accepted.
  #
  # @return [String] the token exactly as the service provider received it
  def bearer_token
    header = request.env['HTTP_AUTHORIZATION'].to_s
    raise MissingToken unless header.match?(/\ABearer(\s|\z)/i)

    match = header.match(%r{\ABearer\s+([A-Za-z0-9\-._~+/]+=*)\z}i)
    raise MalformedToken.new('Bearer token is not b64token syntax (RFC 6750 §2.1)') if match.nil?

    match[1]
  end

  # Validate the decoded XML locally against Login.gov's published metadata.
  # See DelegatedAssertion for the individual checks.
  #
  # If the signature fails, Login.gov may have rotated its signing key (a new
  # year's metadata); refresh the cached metadata once (rate limited) and retry.
  def validate_assertion(xml)
    build_assertion(xml).validate!
  rescue DelegatedAssertion::SignatureError
    raise unless self.class.idp_metadata.refresh_if_stale!

    build_assertion(xml).validate!
  end

  def build_assertion(xml)
    metadata = self.class.idp_metadata
    config = settings.rs_config
    DelegatedAssertion.new(
      xml,
      resource_identifier: config.resource_identifier,
      idp_certificates: metadata.signing_certificates,
      idp_entity_id: metadata.entity_id,
      private_key: config.rs_private_key,
      clock_drift: config.allowed_clock_drift,
      replay_cache: config.replay_protection? ? settings.replay_cache : nil,
    )
  end

  # §15.7 item 4: the `delegation_scopes` attribute lists exactly the
  # capabilities the user approved for this resource. Compare full strings.
  def enforce_scope(assertion, required_scope)
    return if assertion.delegation_scopes.include?(required_scope)

    raise InsufficientScope.new(assertion, required_scope)
  end

  # Record the decision (REF-IMPL-2 "shows every decision it made"). When the
  # assertion did not validate, only the reason is recorded: nothing read from
  # an unverified assertion is trusted enough to log as fact.
  def log_decision(assertion, required_scope:, decision:, reason: nil)
    settings.decision_log.record(
      route: "#{request.request_method} #{request.path_info}",
      decision:,
      reason:,
      required_scope:,
      name_id: assertion&.name_id,
      uuid: assertion&.attributes&.fetch('uuid', nil),
      actor: assertion&.actor,
      delegation_id: assertion&.delegation_id,
      delegation_scopes: assertion&.delegation_scopes,
      assertion_id: assertion&.assertion_id,
    )
  end

  # RFC 6750 §3: WWW-Authenticate: Bearer with realm, error, error_description
  # and (for insufficient_scope) the scope the route needs.
  def halt_bearer_error(status, error, description, scope: nil)
    challenge = ['Bearer realm="benefits-api"']
    challenge << "error=\"#{error}\"" if error
    challenge << "error_description=\"#{description.to_s.tr('"', "'")}\"" if description
    challenge << "scope=\"#{scope}\"" if scope
    headers['WWW-Authenticate'] = challenge.join(', ')
    halt_json(status, error || 'unauthorized', description)
  end

  def halt_json(status, error, description)
    content_type :json
    halt status, { error:, error_description: description }.to_json
  end

  def json_response(payload)
    content_type :json
    payload.to_json
  end

  def parse_json_body
    body = request.body.read
    raise DemoBenefits::InvalidChange.new('request body must be JSON') if body.to_s.strip.empty?

    JSON.parse(body)
  rescue JSON::ParserError
    raise DemoBenefits::InvalidChange.new('request body must be JSON')
  end

  # Response body for both routes. `delegated_access` is what a
  # delegation-aware API reads (§15.7 item 4): the acting service provider,
  # the delegation_id that joins to Attempts API events, and the approved
  # scopes. `_assertion` is a demo affordance so the service provider's demo
  # page can show what the API saw; a production API would not echo it.
  def benefits_payload(assertion, record)
    {
      benefits: record,
      delegated_access: {
        actor: assertion.actor,
        delegation_id: assertion.delegation_id,
        delegation_scopes: assertion.delegation_scopes,
      },
      _assertion: {
        id: assertion.assertion_id,
        issuer: assertion.issuer,
        name_id: assertion.name_id,
        name_id_format: assertion.name_id_format,
        subject_confirmation_not_on_or_after: assertion.subject_not_on_or_after.iso8601,
        not_before: assertion.not_before.iso8601,
        not_on_or_after: assertion.not_on_or_after.iso8601,
        authn_instant: assertion.authn_instant,
        authn_context_class_ref: assertion.authn_context_class_ref,
        attributes: assertion.attributes,
      },
    }
  end

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
      "http://idmanagement.gov/ns/requested_attributes?ReqAttr=#{requested_attributes.join(',')}",
    ].compact
    base_config.force_authn = force_authn

    base_config.certificate = saml_sp_certificate
    base_config.private_key = saml_sp_private_key

    OneLogin::RubySaml::Settings.new(base_config)
  end

  def ial_authn_context(ial)
    if semantic_ial_values_enabled?
      semantic_ial_values[ial]
    else
      legacy_ial_values[ial]
    end
  end

  def aal_authn_context(aal, ial)
    case aal
    when '2'
      'http://idmanagement.gov/ns/assurance/aal/2'
    when '2-phishing_resistant'
      'http://idmanagement.gov/ns/assurance/aal/2?phishing_resistant=true'
    when '2-hspd12'
      'http://idmanagement.gov/ns/assurance/aal/2?hspd12=true'
    end
  end

  def prompt
    params[:initiate_registration] == 'true' ? 'create' : nil
  end

  def saml_auth_request
    @saml_auth_request ||= OneLogin::RubySaml::Authrequest.new
  end

  def saml_request_data(action)
    ial, aal, force_authn, requested_attributes = extract_params
    saml_settings(ial:, aal:, force_authn:, requested_attributes:)
  end

  def skip_encryption
    get_param(:skip_encryption, %w[true false])
  end

  def saml_sp_certificate
    return @saml_sp_certificate if defined?(@saml_sp_certificate)

    if running_in_prod_env? && !ENV['sp_cert']
      raise NotImplementedError.new('Refusing to use demo cert in production')
    end

    @saml_sp_certificate = ENV['sp_cert'] || File.read('config/demo_sp.crt')
  end

  def saml_sp_private_key
    return @saml_sp_private_key if defined?(@saml_sp_private_key)

    if running_in_prod_env? && !ENV['sp_private_key']
      raise NotImplementedError.new('Refusing to use demo private key in production')
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
    ial = get_param(:ial, %w[sp 1 2 0  facial-match-preferred facial-match-required step-up]) || '1'
    ial = prepare_step_up_flow(session:, ial:, aal:)
    force_authn = get_param(:force_authn, %w[true false])
    requested_attributes = get_param(:requested_attributes, requested_attributes_options) || []
    [ial, aal, force_authn, requested_attributes]
  end

  run! if app_file == $0
end
