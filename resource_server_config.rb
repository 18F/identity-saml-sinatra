# frozen_string_literal: true

require 'openssl'
require 'uri'

# Configuration for the agency resource-server role of this sample app.
#
# Every value comes from an environment variable with a local-development
# default, so the same code runs against a local IdP and against the sandbox by
# changing environment variables only. Defaults match the local-development
# fixtures shared by the Login.gov IdP and the other delegated-access sample apps.
class ResourceServerConfig
  DEFAULT_ISSUER = 'urn:gov:gsa:SAML:2.0.profiles:sp:sso:benefits_agency'
  DEFAULT_RESOURCE_IDENTIFIER = 'https://benefits-api.agency.localdev'
  DEFAULT_IDP_URL = 'http://localhost:3000'
  DEFAULT_SAML_METADATA_YEAR = '2026'
  DEFAULT_PRIVATE_KEY_PATH = './config/demo_sp.key'

  # The agency's SAML issuer (entityID). The IdP registers this SP as the owner
  # of the resource server below.
  def issuer
    ENV.fetch('issuer', DEFAULT_ISSUER)
  end

  # The resource server identifier registered with Login.gov. It is the
  # `resource` value the service provider sends to the token exchange and the
  # value this app requires in the assertion's Audience and Recipient.
  def resource_identifier
    ENV.fetch('RESOURCE_IDENTIFIER', DEFAULT_RESOURCE_IDENTIFIER)
  end

  def idp_url
    ENV.fetch('idp_url', DEFAULT_IDP_URL)
  end

  # Login.gov publishes SAML metadata at a year-suffixed path
  # (/api/saml/metadata<YYYY>). Set IDP_METADATA_URL to override the whole
  # URL, or SAML_METADATA_YEAR to change only the year.
  def idp_metadata_url
    ENV.fetch('IDP_METADATA_URL') do
      "#{idp_url}/api/saml/metadata#{ENV.fetch('SAML_METADATA_YEAR', DEFAULT_SAML_METADATA_YEAR)}"
    end
  end

  # How long fetched IdP metadata is reused before re-fetching.
  def idp_metadata_cache_seconds
    ENV.fetch('IDP_METADATA_CACHE_SECONDS', '3600').to_i
  end

  # Tolerance applied to every NotBefore / NotOnOrAfter comparison.
  def allowed_clock_drift
    ENV.fetch('ALLOWED_CLOCK_DRIFT', '60').to_i
  end

  # Whether to remember assertion IDs and refuse a second presentation.
  # Optional agency policy; see README ("Replay protection").
  def replay_protection?
    ENV.fetch('REPLAY_PROTECTION', 'true') == 'true'
  end

  # JWS algorithms accepted in a DPoP proof (RFC 9449 §4.2); asymmetric only,
  # since a MAC algorithm would let anyone holding the "public" key forge
  # proofs. Space-separated, in the form the WWW-Authenticate `algs` parameter
  # uses (§7.1), so the same list is enforced and advertised.
  def dpop_allowed_algs
    ENV.fetch('DPOP_ALLOWED_ALGS', 'ES256 RS256').split
  end

  # Seconds a DPoP proof's iat may differ from this server's clock, in either
  # direction (RFC 9449 §4.3 (10)). Also sizes the jti cache: an entry is kept
  # for twice this, after which the proof would be too old to pass anyway.
  def dpop_iat_leeway_seconds
    ENV.fetch('DPOP_IAT_LEEWAY_SECONDS', '60').to_i
  end

  # Origins a Third-Party-Initiated Login request may name in `target_link_uri`
  # (OpenID Connect Core 1.0 §4,
  # https://openid.net/specs/openid-connect-core-1_0.html#ThirdPartyInitiatedLogin).
  # §4 requires the relying party to verify this value so it cannot be used as
  # an open redirector; this app accepts only an exact origin match against
  # this list. Space-separated `scheme://host[:port]` values, no wildcards.
  # Plain http is honored only for local development hosts; anything else must
  # be https. The default is the MyBenefits Assistant reference app (identity-sts-sinatra).
  #
  # @return [Array<String>] normalized origins
  def third_party_target_link_allowlist
    entries = ENV.fetch('THIRD_PARTY_TARGET_LINK_ALLOWLIST', 'http://localhost:9292').split
    entries.filter_map do |entry|
      uri = URI.parse(entry)
      next unless uri.is_a?(URI::HTTP) && uri.host
      # http is a development convenience, never a production return address.
      next if uri.scheme == 'http' && !%w[localhost 127.0.0.1].include?(uri.host.downcase)

      port = uri.port == uri.default_port ? '' : ":#{uri.port}"
      "#{uri.scheme.downcase}://#{uri.host.downcase}#{port}"
    rescue URI::InvalidURIError
      nil
    end
  end

  # Number of authorization decisions kept in memory for GET /decisions.
  def decision_log_size
    ENV.fetch('DECISION_LOG_SIZE', '200').to_i
  end

  # The resource server's private key. Delegated assertions are encrypted to
  # the matching certificate registered with Login.gov (`certs: [sp_sinatra_demo]`
  # locally); this key decrypts them.
  #
  # @return [OpenSSL::PKey::RSA]
  def rs_private_key
    @rs_private_key ||= OpenSSL::PKey::RSA.new(
      ENV['sp_private_key'] ||
        File.read(ENV.fetch('RS_PRIVATE_KEY_PATH', DEFAULT_PRIVATE_KEY_PATH)),
    )
  end
end
