# frozen_string_literal: true

require 'faraday'
require 'json'
require 'jwt'
require 'active_support/core_ext/hash/indifferent_access'

# Login.gov's Attempts API configuration (Shared Signals Framework discovery)
# and the public key that verifies signed event payloads. Ported from the
# identity-oidc-sinatra sample (907fc7f attempts_configuration.rb); the agency
# role is the same, only the credentials differ.
class AttemptsConfiguration
  class Error < StandardError; end

  def self.cached
    @cached ||= live
  end

  def self.reset!
    @cached = nil
    @cached_attempts_public_key = nil
  end

  def self.live(idp_url: ResourceServerConfig.new.idp_url)
    response = Faraday.get("#{idp_url}/.well-known/ssf-configuration")
    unless response.status == 200
      raise Error.new(
        "Unable to retrieve Attempts API configuration from IdP: #{idp_url} responded " \
        "with #{response.status}.",
      )
    end

    JSON.parse(response.body).with_indifferent_access
  end

  def self.cached_attempts_public_key(attempts_config)
    @cached_attempts_public_key ||= live_attempts_public_key(attempts_config)
  end

  # The IdP's event-signing key (ES256) from its JWKS.
  def self.live_attempts_public_key(attempts_config)
    jwks = JSON.parse(Faraday.get(attempts_config[:jwks_uri]).body).with_indifferent_access
    JWT::JWK.import(jwks[:keys].first).keypair
  end
end
