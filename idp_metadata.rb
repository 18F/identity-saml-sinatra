# frozen_string_literal: true

require 'base64'
require 'faraday'
require 'onelogin/ruby-saml'
require 'openssl'

# Fetches and caches Login.gov's SAML metadata so delegated assertions can be
# validated against the IdP's published signing certificate(s) with no
# per-request call to Login.gov (§15.5, SAML-8).
#
# Login.gov publishes metadata at a year-suffixed path (/api/saml/metadata<YYYY>)
# and rotates signing keys by publishing a new year. The metadata is fetched
# over the IdP URL (TLS in any real deployment; that is where trust in the
# certificate comes from), parsed with ruby-saml's IdpMetadataParser and reused
# for `cache_seconds`. A signature failure may trigger one early refresh, rate
# limited by `min_refresh_interval`, so a just-rotated key is picked up without
# letting bad tokens turn into a flood of metadata requests.
class IdpMetadata
  class FetchError < StandardError; end

  attr_reader :url

  def initialize(url:, cache_seconds: 3600, min_refresh_interval: 60, http: Faraday)
    @url = url
    @cache_seconds = cache_seconds
    @min_refresh_interval = min_refresh_interval
    @http = http
    @mutex = Mutex.new
    @fetched_at = nil
    @parsed = nil
  end

  # The IdP's entityID; the assertion's <saml:Issuer> must equal it
  # (SAML Core §2.2.3, Profiles §4.1.4.2).
  #
  # @return [String]
  def entity_id
    parsed[:idp_entity_id]
  end

  # Certificates from <md:KeyDescriptor use="signing"> (or with no `use`,
  # which SAML Metadata §2.4.1.1 defines as usable for signing).
  #
  # @return [Array<OpenSSL::X509::Certificate>]
  def signing_certificates
    certs = Array(parsed.dig(:idp_cert_multi, :signing))
    certs = [parsed[:idp_cert]].compact if certs.empty?
    raise FetchError.new("no signing certificate in IdP metadata at #{url}") if certs.empty?

    certs.map { |c| OpenSSL::X509::Certificate.new(Base64.decode64(c.gsub(/\s+/, ''))) }
  end

  # Re-fetch if the cached copy is older than `min_refresh_interval`.
  # Returns true when a fetch happened.
  def refresh_if_stale!
    @mutex.synchronize do
      return false if @fetched_at && Time.now - @fetched_at < @min_refresh_interval

      fetch!
      true
    end
  end

  # Drop the cache (used by tests and by an operator-triggered reload).
  def reset!
    @mutex.synchronize do
      @parsed = nil
      @fetched_at = nil
    end
  end

  private

  def parsed
    @mutex.synchronize do
      fetch! if @parsed.nil? || Time.now - @fetched_at > @cache_seconds
      @parsed
    end
  end

  def fetch!
    response = @http.get(url)
    unless response.status == 200
      raise FetchError.new("IdP metadata request to #{url} returned #{response.status}")
    end

    @parsed = OneLogin::RubySaml::IdpMetadataParser.new.parse_to_hash(response.body)
    @fetched_at = Time.now
  rescue Faraday::Error => e
    raise FetchError.new("IdP metadata request to #{url} failed: #{e.message}")
  end
end
