# Sample agency application for Login.gov in two roles:
#
# 1. Direct SAML sign-in (the original sample): /login_get, /login_post,
#    /consume, /logout, /slo_logout. Unchanged.
# 2. SAML resource server for delegated access: a third-party client broker
#    obtains a SAML 2.0 assertion for this API from Login.gov's token exchange
#    (RFC 8693) and presents it as a bearer token (RFC 6750), or, when the
#    assertion is bound to the broker's key, with the DPoP scheme and
#    a proof of possession (RFC 9449). GET /api/benefits validates it locally
#    (DelegatedAssertion, DpopVerifier) and requires this application's one
#    delegation scope; the application is registered read-only, so there is
#    no write route. /decisions shows every decision.
# 3. Third-Party-Initiated Login, the relying-party side of OpenID Connect Core
#    1.0 §4 (https://openid.net/specs/openid-connect-core-1_0.html#ThirdPartyInitiatedLogin)
#    applied to this SAML service provider: a third party (the broker)
#    sends the user's browser to GET /initiate_login naming Login.gov as the
#    issuer; this app verifies the issuer and the return address, then runs
#    its ordinary SAML sign-in and, when it completes, sends the user back to
#    the third party. Nothing is delegated: the agency signs the user in itself.
#
# Supporting files: resource_server_config.rb (env vars), idp_metadata.rb
# (IdP signing certificates), delegated_assertion.rb (validation steps),
# dpop_verifier.rb (proof checks), assertion_replay_cache.rb, decision_log.rb,
# demo_benefits.rb.
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
require_relative './dpop_verifier'
require_relative './assertion_replay_cache'
require_relative './decision_log'
require_relative './demo_benefits'

class RelyingParty < Sinatra::Base
  use Rack::Session::Cookie, key: 'sinatra_sp', secret: SecureRandom.hex(32)

  # --- Delegated-access resource server state ---
  # These live on the class so every request shares them within the process.
  set :rs_config, ResourceServerConfig.new
  set :decision_log, DecisionLog.new(max_size: rs_config.decision_log_size)
  set :replay_cache, AssertionReplayCache.new
  # DPoP proof `jti` values seen so far (RFC 9449 §11.1); same shape as the
  # assertion replay cache, kept separate so the two policies stay independent.
  set :dpop_jti_cache, AssertionReplayCache.new
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

  # Raised by #presented_token when the request carries no Bearer or DPoP credentials.
  class MissingToken < StandardError; end

  # Longest `login_hint` accepted on a third-party-initiated login request. The hint is an opaque
  # correlation value the third party minted (a UUID is 36 characters); it carries no identity and
  # is only echoed back, so a generous but bounded length keeps it out of session-size trouble.
  THIRD_PARTY_LOGIN_HINT_MAX_LENGTH = 128
  # Raised by #presented_token when there is a Bearer or DPoP header but it is malformed.
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
    # HTML-escape values that came from assertions.
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

  # ===========================================================================
  # Third-Party-Initiated Login (relying-party side)
  # OpenID Connect Core 1.0 §4,
  # https://openid.net/specs/openid-connect-core-1_0.html#ThirdPartyInitiatedLogin
  #
  # §4 defines the request a third party sends to a relying party's login
  # initiation endpoint: `iss` (the issuer the RP should authenticate the user
  # with), `login_hint` (an opaque hint the RP may use), and `target_link_uri`
  # (where to send the user afterwards). The section is written for OpenID
  # Connect RPs; this app is a SAML service provider, and the pattern applies
  # unchanged because the initiation request says nothing about the sign-in
  # protocol. What this endpoint starts is the same SAML AuthnRequest that
  # /login_get sends today. Because the user already holds a Login.gov session
  # from the broker, Login.gov completes the sign-in without re-prompting.
  # ===========================================================================

  # GET /initiate_login?iss=...&login_hint=...&target_link_uri=...
  get '/initiate_login/?' do
    # §4: "The RP MUST verify that the iss ... is an issuer that it trusts."
    # A forged iss could point this app at an attacker's IdP, so anything but the
    # one Login.gov this app is configured for is refused before any redirect.
    verify_third_party_issuer!(params['iss'])
    # §4: the RP MUST verify target_link_uri "to prevent being used as an open
    # redirector to external sites." Only an allow-listed origin is accepted.
    target_link_uri = verify_target_link_uri!(params['target_link_uri'])
    login_hint = third_party_login_hint(params['login_hint'])

    # Remember the hand-off for this one sign-in. The hint is opaque to this app:
    # it is never used to identify the user (the SAML assertion does that) and is
    # only echoed back so the third party can match the return to its request.
    session[:third_party_login] = {
      'login_hint' => login_hint,
      # The validated URL, kept as text so it serializes cleanly into the cookie session.
      'target_link_uri' => target_link_uri.to_s,
      'started_at' => Time.now.utc.iso8601,
    }

    # Start the ordinary SAML sign-in. The hint is deliberately not forwarded to
    # Login.gov: §4 only permits it as a hint to the RP, and Login.gov identifies
    # the user by its own session, not by anything a third party supplies.
    puts 'Third-party-initiated login: starting SAML sign-in'
    request_url = saml_auth_request.create(
      saml_request_data('GET'),
      { skip_encryption:, prompt: }.compact,
    )
    redirect to(request_url)
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

        # A pending third-party hand-off (session[:third_party_login]) survives
        # the step-up round trip: the second /consume completes it below.
        redirect to("/login_get/?aal=#{aal}&ial=2")
      else
        session[:userid] = user_uuid
        session[:email] = response.attributes['email']
        session[:authn_instant] = response.authn_instant
        session[:attributes] = response.attributes.to_h.to_json

        puts 'SAML Success!'
        # §4 flow, last step: when this sign-in was started by a third party,
        # send the user back to the address verified at initiation. The identity
        # established above came from the assertion alone; the hint is only echoed.
        handoff = session.delete(:third_party_login)
        if handoff
          session[:third_party_initiated_hint] = handoff['login_hint']
          return third_party_return_page(handoff, status: 'signed_in')
        end
        redirect to('/success')
      end
    else
      puts 'SAML Fail :('
      session[:error_type] = 'Authentication failure'
      session[:errors] = response.errors || ['Something unknown went wrong.']

      # A failed sign-in also ends a third-party hand-off: the user goes back to
      # the third party with status=failed rather than landing on this app's
      # error page, and the hand-off is cleared so it cannot be completed later.
      handoff = session.delete(:third_party_login)
      return third_party_return_page(handoff, status: 'failed') if handoff

      redirect to('/')
    end
  end


  # ===========================================================================
  # Delegated-access API. The broker calls these with the
  # SAML assertion Login.gov's token exchange issued for this resource server.
  # ===========================================================================

  # CORS (Fetch standard, https://fetch.spec.whatwg.org/#http-cors-protocol).
  # The reference broker is a browser-based public client: its pages
  # call this API with fetch from another origin. Before a request that carries
  # an Authorization or DPoP header the browser sends a preflight OPTIONS naming
  # the method and headers it intends to use; the real request follows only if
  # the preflight answer allows them. Both answers must carry the CORS headers,
  # including error answers (401/403), or the page cannot read the status or the
  # WWW-Authenticate challenge and sees only a network error.
  before %r{/api/.*} do
    cors_headers!
  end

  # Preflight: no credentials are checked here. The browser only asks whether
  # the origin, method and headers are acceptable; the token arrives with the
  # request that follows.
  options %r{/api/.*} do
    halt 204
  end

  # The application's one delegation scope, as it appears on the wire in the
  # exchange response `scope` and the assertion's `delegation_scopes`
  # attribute. The application is registered read-only, so a read is all this
  # API offers; there is no write route.
  get '/api/benefits' do
    assertion = authorize!(settings.rs_config.delegation_scope)
    record = settings.benefits.record_for(assertion.name_id)
    json_response(benefits_payload(assertion, record))
  end

  # Every decision the API made, newest first.
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
  # RFC 6750 §3 / RFC 9449 §7.1 error response. Steps, in order:
  #
  #   presented_token             RFC 6750 §2.1, RFC 9449 §7.1  Authorization: Bearer|DPoP <token>
  #   DelegatedAssertion.decode   RFC 8693 §3    base64url SAML 2.0 assertion
  #   validate_assertion          SAML Core §2.4.1.2, §2.5.1, §5.4  signature, Issuer,
  #                               Recipient, Audience, both time windows, no
  #                               InResponseTo; no call to Login.gov; then, for
  #                               a key-bound assertion, the DPoP proof
  #                               (RFC 9449 §4.3)
  #   enforce_scope               delegation_scopes carries this application's scope
  #   log_decision                record what was decided
  #
  # @return [DelegatedAssertion] the validated assertion
  def authorize!(required_scope)
    # The scheme is read here but judged later: whether Bearer or DPoP is the
    # right one depends on the assertion's `dpop_jkt`, which can only be trusted
    # after its signature has been verified inside validate_assertion.
    token, scheme = presented_token
    assertion = validate_assertion(DelegatedAssertion.decode(token), token:, scheme:)
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
  rescue DelegatedAssertion::InvalidProof => e
    # RFC 9449 §7.1: the assertion is bound to a key but the proof of possession
    # was missing or wrong. The challenge names the DPoP scheme and the
    # algorithms this API accepts.
    log_decision(nil, required_scope:, decision: 'deny', reason: e.message, key_bound: true)
    halt_dpop_error(401, 'invalid_dpop_proof', e.message)
  rescue DelegatedAssertion::SchemeMismatch => e
    # Either a bound assertion arrived as Bearer or an unbound one arrived as
    # DPoP (RFC 9449 §7.1). Both are `invalid_token`: the credential as
    # presented is not acceptable, though the assertion itself may be fine.
    # The reason text starts with "key-bound" only in the first case, which is
    # what the decision log's key_bound column records.
    log_decision(nil, required_scope:, decision: 'deny', reason: e.message,
                      key_bound: e.message.start_with?('key-bound'))
    halt_dpop_error(401, 'invalid_token', e.message)
  rescue DelegatedAssertion::InvalidAssertion => e
    log_decision(nil, required_scope:, decision: 'deny', reason: e.message)
    halt_bearer_error(401, 'invalid_token', e.message)
  rescue InsufficientScope => e
    log_decision(e.assertion, required_scope:, decision: 'deny', reason: e.message)
    halt_bearer_error(403, 'insufficient_scope', e.message, scope: required_scope)
  rescue IdpMetadata::FetchError => e
    # Fail closed: without the IdP's certificate nothing can be verified. The
    # detail (URL, socket error) goes to the decision log, not to the caller.
    log_decision(nil, required_scope:, decision: 'deny', reason: e.message)
    halt_json(503, 'temporarily_unavailable', 'IdP metadata is not available; try again later')
  end

  # RFC 6750 §2.1 / RFC 9449 §7.1: the token is sent in the Authorization
  # header with the Bearer scheme, or the DPoP scheme when it is key-bound
  # (scheme names case-insensitive, RFC 9110 §11.1), in b64token syntax. The
  # form-body (RFC 6750 §2.2) and query (§2.3) methods are not accepted. Which
  # scheme is correct is decided once the assertion has been validated and its
  # `dpop_jkt` attribute can be trusted (DelegatedAssertion#check_key_binding).
  #
  # @return [Array(String, String)] the token exactly as presented, and the scheme
  def presented_token
    header = request.env['HTTP_AUTHORIZATION'].to_s
    # No recognized scheme at all: the challenge-only 401 (RFC 6750 §3.1).
    raise MissingToken unless header.match?(/\A(Bearer|DPoP)(\s|\z)/i)

    # b64token (RFC 6750 §2.1): one run of token characters, optional padding.
    match = header.match(%r{\A(Bearer|DPoP)\s+([A-Za-z0-9\-._~+/]+=*)\z}i)
    raise MalformedToken.new('token is not b64token syntax (RFC 6750 §2.1)') if match.nil?

    # match[2] is the token exactly as sent; the DPoP `ath` check hashes this
    # string, so it must not be normalized or decoded here.
    [match[2], match[1]]
  end

  # Validate the decoded XML locally against Login.gov's published metadata.
  # See DelegatedAssertion for the individual checks.
  #
  # If the signature fails, Login.gov may have rotated its signing key (a new
  # year's metadata); refresh the cached metadata once (rate limited) and retry.
  def validate_assertion(xml, token:, scheme:)
    build_assertion(xml, token:, scheme:).validate!
  rescue DelegatedAssertion::SignatureError
    raise unless self.class.idp_metadata.refresh_if_stale!

    build_assertion(xml, token:, scheme:).validate!
  end

  # How the token reached this request, for the key-binding check: the scheme,
  # the token as presented (what `ath` hashes), the DPoP header, and the method
  # and URL the proof must name. `request.base_url` reflects X-Forwarded-Proto
  # and X-Forwarded-Host, so `htu` is compared against the URL the service
  # provider called, not an internal one behind a gateway.
  def build_assertion(xml, token:, scheme:)
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
      presentation: {
        scheme:,
        token:,
        # Rack exposes the DPoP header as HTTP_DPOP; nil when absent.
        dpop_proof: request.env['HTTP_DPOP'],
        method: request.request_method,
        # `htu` must equal the URL the broker called, without query
        # or fragment (RFC 9449 §4.3 (9)). Behind a TLS-terminating proxy or
        # gateway the app sees http://internal-host, but Rack's base_url
        # follows X-Forwarded-Proto and X-Forwarded-Host, so this rebuilds the
        # public URL. request.path excludes the query string.
        url: request.base_url + request.path,
      },
      dpop_verifier: dpop_verifier,
    )
  end

  # One verifier per request, sharing the process-wide jti cache. The cache is
  # a second AssertionReplayCache instance rather than the assertion one: both
  # remember "seen until <time>" values, but they are separate policies (the
  # assertion replay check is optional agency policy; the jti check is required
  # by RFC 9449 §11.1) and must be clearable and configurable independently.
  def dpop_verifier
    config = settings.rs_config
    DpopVerifier.new(
      allowed_algs: config.dpop_allowed_algs,
      iat_leeway: config.dpop_iat_leeway_seconds,
      replay_cache: settings.dpop_jti_cache,
    )
  end

  # The `delegation_scopes` attribute carries the one delegation scope of the
  # application the assertion was issued for, in its full `token_exchange:<value>`
  # form (space-delimited per RFC 6749 §3.3 should there ever be more than
  # one). An assertion for another application is refused. Compare full
  # strings; never match on a prefix or substring.
  def enforce_scope(assertion, required_scope)
    return if assertion.delegation_scopes.include?(required_scope)

    raise InsufficientScope.new(assertion, required_scope)
  end

  # Record the decision so the API can show every decision it made. When the
  # assertion did not validate, only the reason is recorded: nothing read from
  # an unverified assertion is trusted enough to log as fact.
  def log_decision(assertion, required_scope:, decision:, reason: nil, key_bound: nil)
    settings.decision_log.record(
      route: "#{request.request_method} #{request.path_info}",
      decision:,
      reason:,
      required_scope:,
      # With a validated assertion the binding is read from it; on a denial
      # before validation finished, the caller says what it knows (may be nil).
      key_bound: assertion ? assertion.bound? : key_bound,
      name_id: assertion&.name_id,
      uuid: assertion&.attributes&.fetch('uuid', nil),
      actor: assertion&.actor,
      delegation_id: assertion&.delegation_id,
      delegation_scopes: assertion&.delegation_scopes,
      assertion_id: assertion&.assertion_id,
    )
  end

  # RFC 6750 §3: WWW-Authenticate: Bearer with realm, error, error_description
  # and (for insufficient_scope) the scope the route needs. A second, DPoP
  # challenge advertises that key-bound tokens are accepted here and which
  # algorithms the proof may use (RFC 9449 §7.1).
  def halt_bearer_error(status, error, description, scope: nil)
    challenge = ['Bearer realm="benefits-api"']
    challenge << "error=\"#{error}\"" if error
    challenge << "error_description=\"#{description.to_s.tr('"', "'")}\"" if description
    challenge << "scope=\"#{scope}\"" if scope
    headers['WWW-Authenticate'] = "#{challenge.join(', ')}, #{dpop_challenge}"
    halt_json(status, error || 'unauthorized', description)
  end

  # RFC 9449 §7.1: WWW-Authenticate: DPoP with the accepted algorithms and the
  # error (`invalid_dpop_proof` for a bad or missing proof; `invalid_token`
  # when the scheme does not fit the token).
  def halt_dpop_error(status, error, description)
    # Quotes inside the description would end the quoted-string early, so they
    # are swapped for apostrophes, as the Bearer challenge does.
    detail = description.to_s.tr('"', "'")
    headers['WWW-Authenticate'] =
      "#{dpop_challenge}, error=\"#{error}\", error_description=\"#{detail}\""
    halt_json(status, error, description)
  end

  def dpop_challenge
    "DPoP algs=\"#{settings.rs_config.dpop_allowed_algs.join(' ')}\""
  end

  # Add the CORS response headers when the request comes from an allowed origin.
  # `Access-Control-Allow-Origin` echoes the one matching origin (never `*`:
  # the responses carry per-user data), `Vary: Origin` keeps caches from
  # serving one origin's answer to another, and the allow lists name exactly
  # what the broker sends: GET with `Authorization` (Bearer or DPoP
  # scheme) and the `DPoP` proof header. There is no POST: the application is
  # registered read-only.
  # `WWW-Authenticate` is exposed so the page can read the challenge
  # (RFC 6750 §3, RFC 9449 §7.1) on a 401 or 403. A request from any other
  # origin gets no CORS headers and the browser withholds the response.
  def cors_headers!
    origin = request.env['HTTP_ORIGIN'].to_s.chomp('/').downcase
    return if origin.empty? || !settings.rs_config.cors_allowed_origins.include?(origin)

    headers 'Access-Control-Allow-Origin' => request.env['HTTP_ORIGIN'],
            'Vary' => 'Origin',
            'Access-Control-Allow-Methods' => 'GET, OPTIONS',
            'Access-Control-Allow-Headers' => 'Authorization, DPoP, Content-Type',
            'Access-Control-Expose-Headers' => 'WWW-Authenticate',
            'Access-Control-Max-Age' => '600'
  end

  def halt_json(status, error, description)
    content_type :json
    halt status, { error:, error_description: description }.to_json
  end

  def json_response(payload)
    content_type :json
    payload.to_json
  end

  # Response body for the API. `delegated_access` is what a
  # delegation-aware API reads: the acting broker,
  # the delegation_id that identifies the grant, the application's
  # scope, whether the assertion was key-bound (so the call carried a DPoP
  # proof) and the bound key's thumbprint. `_assertion` is a demo affordance so
  # the broker's demo page can show what the API saw; a production
  # API would not echo it.
  def benefits_payload(assertion, record)
    {
      benefits: record,
      delegated_access: {
        actor: assertion.actor,
        delegation_id: assertion.delegation_id,
        delegation_scopes: assertion.delegation_scopes,
        key_bound: assertion.bound?,
        # The thumbprint the assertion is bound to (nil when unbound), so the
        # broker's demo page can confirm which key was checked.
        dpop_jkt: assertion.dpop_jkt,
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

  # ---------------------------------------------------------------------------
  # Third-Party-Initiated Login helpers (OpenID Connect Core 1.0 §4)
  # ---------------------------------------------------------------------------

  # §4: the RP MUST verify that `iss` is an issuer it trusts. The third party
  # (an OpenID Connect client of Login.gov) knows Login.gov by its OpenID
  # Connect issuer identifier, which is the IdP's root URL. This app knows the
  # same IdP by `idp_url`, the root from which its SAML endpoints and metadata
  # URL are derived, so the two are compared directly (trailing slash ignored).
  # Any other value, or a missing one, is refused with 400 before anything else
  # happens: a redirect to an attacker-chosen "issuer" is exactly what §4 is
  # guarding against.
  def verify_third_party_issuer!(iss)
    expected = settings.rs_config.idp_url.to_s.chomp('/')
    return if iss.is_a?(String) && iss.chomp('/') == expected && !expected.empty?

    puts "Third-party-initiated login refused: iss #{iss.inspect} is not #{expected}"
    halt 400, third_party_error('iss must name the Login.gov issuer this service trusts')
  end

  # §4: the RP MUST verify `target_link_uri` to avoid being an open redirector.
  # The value must be an absolute http(s) URL whose origin (scheme, host, port)
  # exactly matches one entry of the configured allow-list. There are no
  # wildcards, and a plain-http origin is honored only for the local
  # development hosts, so a production allow-list is https-only.
  # @return [URI::HTTP] the parsed, accepted URI
  def verify_target_link_uri!(value)
    uri = begin
      URI.parse(value.to_s)
    rescue URI::InvalidURIError
      nil
    end
    allowed = uri.is_a?(URI::HTTP) && uri.host &&
              settings.rs_config.third_party_target_link_allowlist.include?(origin_of(uri))
    return uri if allowed

    puts "Third-party-initiated login refused: target_link_uri #{value.inspect} not allow-listed"
    halt 400, third_party_error('target_link_uri is not an allowed return address')
  end

  # scheme://host[:port], the unit the allow-list is expressed in. Default ports
  # are dropped so "https://example.gov" and "https://example.gov:443" compare equal.
  def origin_of(uri)
    port = uri.port == uri.default_port ? '' : ":#{uri.port}"
    "#{uri.scheme.downcase}://#{uri.host.downcase}#{port}"
  end

  # The hint is optional in §4 and opaque here. It is bounded in length and
  # stripped so an oversized or whitespace-padded value cannot bloat the session
  # or produce a mismatched echo.
  def third_party_login_hint(value)
    hint = value.to_s.strip
    return nil if hint.empty?
    return hint if hint.length <= THIRD_PARTY_LOGIN_HINT_MAX_LENGTH

    halt 400, third_party_error('login_hint is too long')
  end

  # Builds the return redirect from the hand-off recorded at initiation. The
  # URI was validated then, so it is reused as stored; this app only appends
  # its own parameters (keeping any query the third party put on the URL):
  #   login_hint  the third party's correlation value, echoed unchanged
  #   iss         this agency's SAML issuer, so the third party knows who returned the user
  #   status      signed_in or failed
  # §4, last step, for a SAML relying party: hand the user back to the third party from a page of
  # this app's own rather than with a redirect. The assertion arrived by a form POST from
  # Login.gov's page, served with `form-action 'self' <our ACS>`; Chrome applies that policy to the
  # redirects that follow the submission, so a 303 to the third party's origin is silently blocked
  # (found in the live end-to-end run). A refresh from this document is a new navigation under this
  # app's own policy. The hand-off was already removed from the session by the caller (single use).
  def third_party_return_page(handoff, status:)
    return_url = third_party_return_url(handoff, status:)
    # The one place the hand-off leaves this app: the line to look for when a third party reports
    # that the user never came back. The hint is a correlation value, not identity.
    puts "Third-party-initiated login: returning the user to #{return_url}"
    erb :third_party_return, locals: { return_url:, status: }
  end

  def third_party_return_url(handoff, status:)
    uri = URI.parse(handoff['target_link_uri'])
    returned = {
      'login_hint' => handoff['login_hint'],
      'iss' => settings.rs_config.issuer,
      'status' => status,
    }.compact
    existing = uri.query ? URI.decode_www_form(uri.query) : []
    uri.query = URI.encode_www_form(existing + returned.to_a)
    uri.to_s
  end

  def third_party_error(message)
    content_type :json
    { error: 'invalid_request', error_description: message }.to_json
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
    session.delete(:third_party_login)
    session.delete(:third_party_initiated_hint)
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
