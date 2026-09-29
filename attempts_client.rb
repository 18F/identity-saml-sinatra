# frozen_string_literal: true

require 'faraday'
require 'json'
require 'jwe'
require 'jwt'

# Polls Login.gov's Attempts API in the agency role and decrypts the events.
#
# Ported from identity-oidc-sinatra's `#attempts_events` helper (907fc7f), with
# one fix: the original posted twice and discarded the first response's
# `sets`; this posts once.
#
# Protocol (Login.gov Attempts API):
#   POST {idp_url}/api/attempts/poll?maxEvents=N&ack[]=<jti>...
#   Authorization: Bearer <agency issuer> <shared secret>
#   -> { "sets": { "<jti>": "<JWE>", ... } }
# Each set is a JWE (RSA-OAEP / A256GCM, typ secevent+jwe) encrypted to the
# agency's registered public key. The plaintext is the Security Event Token
# JSON, or an ES256 JWT of it when the IdP signs events.
#
# The events a target agency receives for delegated access are the ordinary
# sign-in events re-mapped with `delegation_id`, plus
# delegated-access-consented, delegated-access-token-issued,
# delegated-access-token-refreshed and delegated-access-revoked.
class AttemptsClient
  class Error < StandardError; end

  def initialize(config, signing_key: nil)
    @config = config
    @signing_key = signing_key
  end

  # One poll request. Acknowledging JTIs deletes those events on the IdP so
  # they are not delivered again; unacknowledged events are redelivered until
  # their TTL. Returns the events in the response (not the acknowledged ones).
  #
  # @param ack [Array<String>, nil] JTIs to acknowledge (delete) on the IdP
  # @param max_events [Integer]
  # @return [Array<Hash>] decrypted Security Event Tokens
  def poll(ack: nil, max_events: 100)
    params = { maxEvents: max_events }
    params[:ack] = ack if ack && !ack.empty?

    response = Faraday.post(@config.attempts_url) do |req|
      req.params = params
      req.headers['Authorization'] = "Bearer #{@config.issuer} #{@config.attempts_shared_secret}"
    end
    unless response.status == 200
      raise Error.new("Attempts API poll returned #{response.status}: #{response.body}")
    end

    sets = JSON.parse(response.body).fetch('sets', {})
    sets.values.map { |jwe| decrypt_event(jwe) }
  end

  private

  # JWE (RFC 7516) encrypted to the agency's registered public key; the
  # plaintext is the Security Event Token (RFC 8417) JSON, or an ES256 JWT of
  # it when the IdP signs events, verified with the key from its JWKS.
  def decrypt_event(jwe)
    plaintext = JWE.decrypt(jwe, @config.attempts_private_key)
    if @config.signed_events?
      JWT.decode(plaintext, @signing_key, true, { algorithm: 'ES256' }).first
    else
      JSON.parse(plaintext)
    end
  end
end
