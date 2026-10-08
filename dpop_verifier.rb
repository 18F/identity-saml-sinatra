# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'
require 'jwt'
require 'uri'

# Verifies an RFC 9449 DPoP proof presented with a key-bound delegated
# assertion.
#
# A key-bound assertion carries a `dpop_jkt` attribute: the RFC 7638 JWK
# thumbprint of the key the service provider proved possession of when
# Login.gov issued the assertion. Every request that presents such an
# assertion must also carry a `DPoP` header holding a proof JWT signed with
# that key, so a copy of the assertion is useless to anyone who does not hold
# the key. This class performs the resource-server checks of RFC 9449 §4.3,
# one method per check, in the order the section lists them:
#
#   decode              RFC 9449 §4.3 (1)       exactly one proof, well-formed JWS
#   check_typ           RFC 9449 §4.3 (2)(3)    typ is dpop+jwt
#   check_alg           RFC 9449 §4.3 (4)       asymmetric alg from the allow-list
#   check_jwk           RFC 9449 §4.3 (5)       public key only, matching the alg
#   verify_signature    RFC 9449 §4.3 (6)       signature with the embedded key
#   check_htm           RFC 9449 §4.3 (8)       HTTP method of this request
#   check_htu           RFC 9449 §4.3 (9)       URL of this request, no query/fragment
#   check_iat           RFC 9449 §4.3 (10)      created recently
#   check_ath           RFC 9449 §4.3 (12)      hash of the presented token
#   check_thumbprint    RFC 9449 §4.3 (13)      key matches the assertion's dpop_jkt
#   check_jti           RFC 9449 §11.1          not seen before
#
# Any failure raises InvalidProof with a reason suitable for an RFC 9449 §7.1
# `error_description`. The `jti` is recorded last so a rejected proof never
# burns a value a later, valid proof might legitimately reuse.
class DpopVerifier
  class InvalidProof < StandardError; end

  PROOF_TYPE = 'dpop+jwt'
  DEFAULT_ALLOWED_ALGS = %w[ES256 RS256].freeze
  # JWK members that would make the embedded key a private key (RFC 7518 §6.2.2, §6.3.2).
  PRIVATE_MEMBERS = %w[d p q dp dq qi oth k].freeze
  KEY_TYPE_FOR_ALG = { 'ES256' => 'EC', 'RS256' => 'RSA' }.freeze
  CURVE_FOR_ALG = { 'ES256' => 'P-256' }.freeze

  # @param allowed_algs [Array<String>] JWS algorithms accepted in the proof header
  # @param iat_leeway [Integer] seconds the proof's iat may differ from now
  # @param replay_cache [#first_use?] remembers jti values (AssertionReplayCache shape)
  # @param now [Time]
  def initialize(allowed_algs: DEFAULT_ALLOWED_ALGS, iat_leeway: 60, replay_cache: nil,
                 now: Time.now.utc)
    @allowed_algs = allowed_algs
    @iat_leeway = iat_leeway
    @replay_cache = replay_cache
    @now = now
  end

  attr_reader :allowed_algs

  # @param proof [String, nil] the DPoP header value
  # @param method [String] the HTTP method of the request being authorized
  # @param url [String] the request URL as this server saw it
  # @param access_token [String] the token exactly as presented in Authorization
  # @param expected_jkt [String] the assertion's dpop_jkt attribute
  # @return [String] the verified key's thumbprint
  def verify!(proof:, method:, url:, access_token:, expected_jkt:)
    header, payload = decode(proof)
    check_typ(header)
    alg = check_alg(header)
    jwk = check_jwk(header, alg)
    payload = verify_signature(proof, jwk, alg)
    check_htm(payload, method)
    check_htu(payload, url)
    check_iat(payload)
    check_ath(payload, access_token)
    thumbprint = check_thumbprint(jwk, expected_jkt)
    check_jti(payload)
    thumbprint
  end

  private

  # RFC 9449 §4.3 (1): exactly one DPoP header. Rack joins repeated headers
  # with ", ", so a comma means more than one was sent.
  def decode(proof)
    raise InvalidProof.new('DPoP header is required for a key-bound token') if proof.to_s.strip.empty?
    raise InvalidProof.new('more than one DPoP header') if proof.include?(',')

    payload, header = JWT.decode(proof, nil, false)
    raise InvalidProof.new('DPoP proof is not a JWT') unless header.is_a?(Hash) && payload.is_a?(Hash)

    [header, payload]
  rescue JWT::DecodeError
    raise InvalidProof.new('DPoP proof is not a JWT')
  end

  # RFC 9449 §4.3 (2)(3): the typ header must be dpop+jwt.
  def check_typ(header)
    return if header['typ'] == PROOF_TYPE

    raise InvalidProof.new("DPoP proof typ must be #{PROOF_TYPE}")
  end

  # RFC 9449 §4.3 (4): an asymmetric algorithm the server supports; "none" and
  # MAC algorithms are refused.
  def check_alg(header)
    alg = header['alg']
    return alg if allowed_algs.include?(alg)

    raise InvalidProof.new("DPoP proof alg must be one of #{allowed_algs.join(' ')}")
  end

  # RFC 9449 §4.3 (5): the jwk header is the public key, with no private
  # members, and its type matches the algorithm.
  def check_jwk(header, alg)
    jwk = header['jwk']
    raise InvalidProof.new('DPoP proof has no jwk header') unless jwk.is_a?(Hash)

    private_members = jwk.keys.map(&:to_s) & PRIVATE_MEMBERS
    unless private_members.empty?
      raise InvalidProof.new("DPoP proof jwk carries private key members (#{private_members.join(', ')})")
    end
    unless jwk['kty'] == KEY_TYPE_FOR_ALG[alg]
      raise InvalidProof.new("DPoP proof jwk kty #{jwk['kty'].inspect} does not match #{alg}")
    end
    if CURVE_FOR_ALG[alg] && jwk['crv'] != CURVE_FOR_ALG[alg]
      raise InvalidProof.new("DPoP proof jwk crv must be #{CURVE_FOR_ALG[alg]} for #{alg}")
    end

    JWT::JWK.import(jwk)
  rescue JWT::JWKError, ArgumentError, OpenSSL::PKey::PKeyError
    raise InvalidProof.new('DPoP proof jwk is not a usable public key')
  end

  # RFC 9449 §4.3 (6): the signature verifies with the embedded key under the
  # algorithm the header named (pinned here, not taken from the token again).
  def verify_signature(proof, jwk, alg)
    payload, = JWT.decode(proof, jwk.verify_key, true, algorithm: alg, verify_expiration: false)
    payload
  rescue JWT::DecodeError
    raise InvalidProof.new('DPoP proof signature is invalid')
  end

  # RFC 9449 §4.3 (8): htm equals the method of the request.
  def check_htm(payload, method)
    return if payload['htm'].is_a?(String) && payload['htm'].upcase == method.to_s.upcase

    raise InvalidProof.new('DPoP proof htm does not match the request method')
  end

  # RFC 9449 §4.3 (9): htu equals the request URL without query or fragment.
  # Scheme and host compare case-insensitively (RFC 3986 §6.2.2.1); default
  # ports are dropped (§6.2.3).
  def check_htu(payload, url)
    htu = payload['htu']
    raise InvalidProof.new('DPoP proof has no htu') unless htu.is_a?(String)
    return if normalize_url(htu) == normalize_url(url)

    raise InvalidProof.new('DPoP proof htu does not match the request URL')
  end

  # RFC 9449 §4.3 (10): iat is present and within the acceptable window on
  # either side of now (the client's clock may be slightly off).
  def check_iat(payload)
    iat = payload['iat']
    raise InvalidProof.new('DPoP proof iat must be an integer') unless iat.is_a?(Integer)
    return if (iat - @now.to_i).abs <= @iat_leeway

    raise InvalidProof.new('DPoP proof iat is outside the acceptable window')
  end

  # RFC 9449 §4.3 (12): ath is the base64url SHA-256 of the token exactly as
  # presented, binding the proof to this token and not just to this key.
  def check_ath(payload, access_token)
    expected = Base64.urlsafe_encode64(Digest::SHA256.digest(access_token.to_s), padding: false)
    return if payload['ath'].is_a?(String) && secure_compare(payload['ath'], expected)

    raise InvalidProof.new('DPoP proof ath does not match the presented token')
  end

  # RFC 9449 §4.3 (13): the proof key's RFC 7638 thumbprint equals the one
  # Login.gov bound the assertion to.
  def check_thumbprint(jwk, expected_jkt)
    thumbprint = JWT::JWK::Thumbprint.new(jwk).to_s
    return thumbprint if expected_jkt.is_a?(String) && secure_compare(thumbprint, expected_jkt)

    raise InvalidProof.new('DPoP proof key does not match the key the token is bound to')
  end

  # RFC 9449 §11.1: a proof is accepted once. The entry can be forgotten once
  # the proof's iat could no longer pass check_iat.
  def check_jti(payload)
    jti = payload['jti']
    raise InvalidProof.new('DPoP proof has no jti') unless jti.is_a?(String) && !jti.empty?
    return if @replay_cache.nil?
    return if @replay_cache.first_use?("dpop:#{jti}", expires_at: @now + (2 * @iat_leeway))

    raise InvalidProof.new('DPoP proof has already been used')
  end

  def normalize_url(value)
    uri = URI.parse(value.to_s)
    raise InvalidProof.new('DPoP proof htu is not an absolute URL') unless uri.scheme && uri.host

    port = uri.port == uri.default_port ? nil : uri.port
    URI::Generic.build(
      scheme: uri.scheme.downcase, host: uri.host.downcase, port: port,
      path: uri.path.empty? ? '/' : uri.path,
    ).to_s
  rescue URI::InvalidURIError
    raise InvalidProof.new('DPoP proof htu is not a valid URL')
  end

  def secure_compare(a, b)
    a.bytesize == b.bytesize && OpenSSL.fixed_length_secure_compare(a, b)
  end
end
