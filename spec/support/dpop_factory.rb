# frozen_string_literal: true

require 'base64'
require 'digest'
require 'jwt'
require 'openssl'
require 'securerandom'

# Builds RFC 9449 DPoP proofs for tests, with runtime-generated keys that are
# never written to disk.
module DpopFactory
  module_function

  # The broker's key: ES256 (EC P-256) by default.
  def ec_key
    @ec_key ||= OpenSSL::PKey::EC.generate('prime256v1')
  end

  def rsa_key
    @rsa_key ||= OpenSSL::PKey::RSA.new(2048)
  end

  # A different key, to model a stolen token presented by someone else.
  def other_ec_key
    @other_ec_key ||= OpenSSL::PKey::EC.generate('prime256v1')
  end

  # RFC 7638 thumbprint, the value Login.gov places in the `dpop_jkt` attribute.
  def jkt(key = ec_key)
    JWT::JWK::Thumbprint.new(JWT::JWK.new(key)).to_s
  end

  # Public JWK for the proof header (RFC 9449 §4.2).
  def public_jwk(key = ec_key)
    JWT::JWK.new(key).export.reject { |k, _| k == :kid }
  end

  # RFC 9449 §4.3 (12): base64url SHA-256 of the token as presented.
  def ath(token)
    Base64.urlsafe_encode64(Digest::SHA256.digest(token), padding: false)
  end

  # A proof for `token` presented to `method url`.
  #
  # @param key [OpenSSL::PKey::PKey] signing key (ES256 for EC, RS256 for RSA)
  # @param header [Hash] overrides merged into the JWS header
  # @param claims [Hash] overrides merged into the claims; nil values are removed
  def proof(token:, method: 'GET', url: 'http://example.org/api/benefits', key: ec_key,
            alg: nil, header: {}, claims: {}, now: Time.now.to_i)
    alg ||= key.is_a?(OpenSSL::PKey::EC) ? 'ES256' : 'RS256'
    payload = {
      jti: SecureRandom.urlsafe_base64(16),
      htm: method,
      htu: url,
      iat: now,
      ath: ath(token),
    }.merge(claims).compact
    jws_header = { typ: 'dpop+jwt', jwk: public_jwk(key) }.merge(header)
    JWT.encode(payload, key, alg, jws_header)
  end

  # An unsigned proof (alg none), for the "none" rejection case.
  def unsigned_proof(token:, method: 'GET', url: 'http://example.org/api/benefits')
    payload = { jti: SecureRandom.hex, htm: method, htu: url, iat: Time.now.to_i, ath: ath(token) }
    header = { typ: 'dpop+jwt', alg: 'none', jwk: public_jwk }
    [header, payload].map { |part| Base64.urlsafe_encode64(part.to_json, padding: false) }.join('.') + '.'
  end

  # An HS256 proof, for the symmetric-algorithm rejection case.
  def hmac_proof(token:, method: 'GET', url: 'http://example.org/api/benefits')
    payload = { jti: SecureRandom.hex, htm: method, htu: url, iat: Time.now.to_i, ath: ath(token) }
    JWT.encode(payload, 'shared-secret', 'HS256', { typ: 'dpop+jwt', jwk: public_jwk })
  end
end
