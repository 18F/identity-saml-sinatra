# frozen_string_literal: true

require 'base64'
require 'nokogiri'
require 'onelogin/ruby-saml'
require 'rexml/document'
require 'time'
require 'xml_security'
require_relative './dpop_verifier'

# Validates a delegated SAML 2.0 assertion that a service provider presents to
# this API as a bearer token, and exposes what the API needs from it.
#
# The token is what Login.gov's token exchange returned for an API registered
# for SAML assertions (the response's `issued_token_type` is
# `urn:ietf:params:oauth:token-type:saml2`): per RFC 8693 §3 a base64url-encoded
# SAML 2.0 *assertion* -- not a <samlp:Response> -- and,
# because this resource server registered a certificate, wrapped in a
# <saml:EncryptedAssertion>.
#
# Validation is local: the signature is checked against the
# certificate(s) in Login.gov's SAML metadata, and Audience, Recipient and the
# two validity windows are enforced here. Nothing calls Login.gov per request.
#
# Every protocol step is one method, in the order `#validate!` runs them, so an
# agency can copy the class or lift a single step:
#
#   decode               RFC 8693 §3; RFC 4648 §5 (base64url, no padding)
#   decrypt_if_encrypted XML Encryption; SAML Core §2.3.4 (EncryptedAssertion)
#   parse_assertion      SAML Core §2.3.3 (Assertion, Version, ID)
#   verify_signature     SAML Core §5.4 (enveloped XML Signature)
#   check_issuer         SAML Core §2.2.5; Profiles §4.1.4.2
#   check_subject        SAML Core §2.4.1.2 (bearer SubjectConfirmationData)
#   check_conditions     SAML Core §2.5.1 (NotBefore/NotOnOrAfter), §2.5.1.4 (AudienceRestriction)
#   read_attributes      delegation_scopes, delegation_id, actor, dpop_jkt attributes
#   check_key_binding    RFC 9449 §4.3, §7.1 (key-bound assertions: scheme and DPoP proof)
#   check_replay         optional agency policy (see AssertionReplayCache)
#
# On any failure `InvalidAssertion` is raised with a reason suitable for
# RFC 6750 §3.1 `error_description`. Attribute values are never trusted before
# `verify_signature` has passed.
class DelegatedAssertion
  class InvalidAssertion < StandardError; end
  # Raised only for a signature that does not verify with the current IdP
  # certificates; the caller may refresh metadata once and retry.
  class SignatureError < InvalidAssertion; end
  # A key-bound assertion was presented with the Bearer scheme, or an unbound
  # one with the DPoP scheme (RFC 9449 §7.1): the token is refused as invalid.
  class SchemeMismatch < InvalidAssertion; end
  # The DPoP proof for a key-bound assertion was missing or did not verify
  # (RFC 9449 §7.1 `invalid_dpop_proof`).
  class InvalidProof < InvalidAssertion; end

  NAMESPACES = {
    'saml' => 'urn:oasis:names:tc:SAML:2.0:assertion',
    'ds' => 'http://www.w3.org/2000/09/xmldsig#',
    'xenc' => 'http://www.w3.org/2001/04/xmlenc#',
  }.freeze

  BEARER = 'urn:oasis:names:tc:SAML:2.0:cm:bearer'

  # Login.gov signs with RSA-SHA256 (saml_idp `config.algorithm = SHA256`).
  # Accept the SHA-2 family only; RSA-SHA1 is refused.
  ALLOWED_SIGNATURE_METHODS = [
    XMLSecurity::Document::RSA_SHA256,
    XMLSecurity::Document::RSA_SHA384,
    XMLSecurity::Document::RSA_SHA512,
  ].freeze
  ALLOWED_DIGEST_METHODS = [
    XMLSecurity::Document::SHA256,
    XMLSecurity::Document::SHA384,
    XMLSecurity::Document::SHA512,
  ].freeze

  # The token exchange appends delegation attributes to the agency's normal
  # bundle. `delegation_scopes` (what the user approved) and `delegation_id`
  # (the join key to Attempts events) are what make an assertion a delegated
  # one and are required. `actor` names the service provider acting for the
  # user (the SAML counterpart of the OAuth `act` claim, RFC 8693 §4.1); it is
  # observed and logged, never a reason to reject on its own, so an API that
  # also accepts assertions without it keeps working. `dpop_jkt`, when present,
  # is the RFC 7638 thumbprint of the key the assertion is bound to (RFC 9449):
  # the service provider must then prove possession of that key on every
  # request, and a copy of the assertion alone is useless.
  REQUIRED_DELEGATION_ATTRIBUTES = %w[delegation_scopes delegation_id].freeze
  DELEGATION_ATTRIBUTES = (REQUIRED_DELEGATION_ATTRIBUTES + %w[actor dpop_jkt]).freeze

  # Base64url-decode the `access_token` value (RFC 8693 §3: "a base64url-encoded
  # SAML 2.0 assertion"; RFC 4648 §5, no padding). Padding is tolerated.
  #
  # @return [String] XML
  def self.decode(token)
    unless token.is_a?(String) && token.match?(/\A[A-Za-z0-9_-]+={0,2}\z/)
      raise InvalidAssertion.new('token is not base64url')
    end

    Base64.urlsafe_decode64(token)
  rescue ArgumentError
    raise InvalidAssertion.new('token is not base64url')
  end

  attr_reader :xml, :assertion_id, :issuer, :name_id, :name_id_format,
              :subject_not_on_or_after, :not_before, :not_on_or_after,
              :authn_instant, :authn_context_class_ref, :attributes

  # @param xml [String] the decoded token: a <saml:Assertion> or <saml:EncryptedAssertion>
  # @param resource_identifier [String] this API's registered identifier
  # @param idp_certificates [Array<OpenSSL::X509::Certificate>] signing certs from IdP metadata
  # @param idp_entity_id [String, nil] the IdP entityID; Issuer must match when given
  # @param private_key [OpenSSL::PKey::RSA, nil] decrypts EncryptedAssertion
  # @param clock_drift [Integer] seconds of tolerance on every time comparison
  # @param replay_cache [AssertionReplayCache, nil] nil disables replay protection
  # @param presentation [Hash, nil] how the token reached this API, for the
  #   key-binding check: `scheme` (`Bearer` or `DPoP`), `token` (exactly as
  #   presented), `dpop_proof` (the DPoP header, may be nil), `method`, `url`.
  #   nil skips the check (unit tests of the assertion alone).
  # @param dpop_verifier [DpopVerifier, nil] verifies the proof of a bound assertion
  # @param now [Time]
  def initialize(xml, resource_identifier:, idp_certificates:, idp_entity_id: nil,
                 private_key: nil, clock_drift: 60, replay_cache: nil, presentation: nil,
                 dpop_verifier: nil, now: Time.now.utc)
    @xml = xml
    @resource_identifier = resource_identifier
    @idp_certificates = idp_certificates
    @idp_entity_id = idp_entity_id
    @private_key = private_key
    @clock_drift = clock_drift
    @replay_cache = replay_cache
    @presentation = presentation
    @dpop_verifier = dpop_verifier
    @now = now
    @attributes = {}
  end

  # Runs every step in order. Returns self so callers can read the accessors.
  def validate!
    decrypt_if_encrypted
    parse_assertion
    verify_signature
    check_issuer
    check_subject
    check_conditions
    read_attributes
    # Key binding comes after the signature (so `dpop_jkt` is trusted) and
    # before replay (so a bad proof does not consume this assertion's one
    # presentation; the service provider can retry with a correct proof).
    check_key_binding
    check_replay
    self
  end

  # The delegation scope of the application the assertion was issued for, e.g.
  # ["token_exchange:retirement_benefits"]: one value per application, split on
  # spaces per RFC 6749 §3.3. Compared as full strings.
  def delegation_scopes
    Array(attributes['delegation_scopes']).join(' ').split
  end

  def delegation_id
    attributes['delegation_id']
  end

  # The service provider acting for the user: SAML counterpart of the OAuth
  # `act` claim (RFC 8693 §4.1).
  def actor
    attributes['actor']
  end

  # RFC 7638 thumbprint of the key this assertion is bound to (RFC 9449), or
  # nil for an ordinary bearer assertion.
  def dpop_jkt
    value = attributes['dpop_jkt']
    value.is_a?(String) && !value.strip.empty? ? value.strip : nil
  end

  # Whether presenting this assertion requires a DPoP proof.
  def bound?
    !dpop_jkt.nil?
  end

  # The latest instant at which any validator would still accept this
  # assertion, used to size the replay cache entry.
  def expires_at
    [subject_not_on_or_after, not_on_or_after].compact.min + @clock_drift
  end

  private

  # --- step: decrypt --------------------------------------------------------

  # If the token is a <saml:EncryptedAssertion> (SAML Core §2.3.4), decrypt it
  # with the resource server's private key. Login.gov encrypts to the
  # certificate the resource server registered, so only this app can read the
  # attributes. Login.gov's saml_idp gem emits XML Encryption 1.0
  # with a block cipher named in EncryptedData/EncryptionMethod (aes256-cbc for
  # this app) and the symmetric key wrapped with RSA-OAEP in
  # EncryptedData/ds:KeyInfo/xenc:EncryptedKey. ruby-saml's Utils.decrypt_data
  # handles exactly that layout (it is what OneLogin::RubySaml::Response uses).
  def decrypt_if_encrypted
    root = XMLSecurity::BaseDocument.new(@xml).root
    raise InvalidAssertion.new('token is not XML') if root.nil?
    return unless root.name == 'EncryptedAssertion'

    if @private_key.nil?
      raise InvalidAssertion.new('encrypted assertion but no private key configured')
    end

    plaintext = OneLogin::RubySaml::Utils.decrypt_data(root, @private_key)
    # AES-CBC leaves the XML Encryption padding bytes on the plaintext; keep
    # the element and drop the trailing noise, as ruby-saml's Response does.
    match = plaintext.match(%r{(.*</(\w+:)?Assertion>)}m)
    raise InvalidAssertion.new('decrypted content is not an Assertion') if match.nil?

    @xml = match[1]
  rescue OpenSSL::PKey::PKeyError, OpenSSL::Cipher::CipherError, REXML::ParseException => e
    raise InvalidAssertion.new("decryption failed: #{e.class}")
  end

  # --- step: parse ----------------------------------------------------------

  # Parse the (now plaintext) XML with DTDs and network access disabled, and
  # require the root to be a SAML 2.0 <saml:Assertion> with an ID
  # (SAML Core §2.3.3).
  def parse_assertion
    @doc = XMLSecurity::BaseDocument.safe_load_xml(@xml)
    root = @doc.root
    unless root && root.name == 'Assertion' && root.namespace&.href == NAMESPACES['saml']
      raise InvalidAssertion.new('root element is not saml:Assertion')
    end
    raise InvalidAssertion.new('unsupported SAML version') unless root['Version'] == '2.0'

    @assertion_id = root['ID']
    raise InvalidAssertion.new('assertion has no ID') if @assertion_id.to_s.empty?
  rescue StandardError => e
    raise e if e.is_a?(InvalidAssertion)

    raise InvalidAssertion.new("token is not well-formed XML: #{e.message}")
  end

  # --- step: signature ------------------------------------------------------

  # Verify the enveloped XML Signature over the assertion against a certificate
  # from the IdP's metadata, which SAML relying parties already trust (SAML Core §5.4).
  #
  # Choice of API: ruby-saml's XMLSecurity::SignedDocument is used directly on
  # the bare assertion rather than wrapping it in a synthetic <samlp:Response>
  # for OneLogin::RubySaml::Response. Response#is_valid? checks things a
  # delegated assertion does not have (a Response ID, Status, Destination,
  # InResponseTo handling) and would validate XML this app fabricated;
  # SignedDocument verifies exactly the bytes Login.gov signed:
  # `validate_document_with_cert` canonicalizes the referenced element, checks
  # the digest, and verifies SignatureValue over SignedInfo with the given
  # certificate's public key. The checks around it defend against signature
  # wrapping: exactly one Signature, a direct child of the Assertion, whose
  # Reference URI is the Assertion's own ID, which is unique in the document.
  def verify_signature
    signatures = @doc.xpath('/saml:Assertion/ds:Signature', NAMESPACES)
    raise SignatureError.new('assertion is not signed') if signatures.empty?
    if signatures.size != 1 || @doc.xpath('//ds:Signature', NAMESPACES).size != 1
      raise SignatureError.new('assertion must carry exactly one signature')
    end

    check_signature_algorithms(signatures.first)

    signed = XMLSecurity::SignedDocument.new(@xml)
    unless signed.signed_element_id == @assertion_id
      raise SignatureError.new('signature does not reference the assertion')
    end
    if @doc.xpath('//*[@ID=$id]', NAMESPACES, { 'id' => @assertion_id }).size != 1
      raise SignatureError.new('assertion ID is not unique in the document')
    end

    verified = @idp_certificates.any? do |cert|
      signed.reset_errors!
      signed.validate_document_with_cert(cert, true)
    end
    return if verified

    raise SignatureError.new("signature invalid: #{signed.errors.uniq.join('; ')}")
  end

  # Only SHA-2 signature and digest algorithms (XML Signature 1.1 / RFC 6931
  # identifiers). RSA-SHA1 and SHA-1 digests are refused because they are
  # deprecated and Login.gov never uses them.
  def check_signature_algorithms(signature)
    sig_method = signature.at_xpath(
      './ds:SignedInfo/ds:SignatureMethod/@Algorithm', NAMESPACES
    )&.value
    unless ALLOWED_SIGNATURE_METHODS.include?(sig_method)
      raise SignatureError.new("unsupported SignatureMethod #{sig_method.inspect}")
    end

    digest_method = signature.at_xpath(
      './ds:SignedInfo/ds:Reference/ds:DigestMethod/@Algorithm', NAMESPACES
    )&.value
    unless ALLOWED_DIGEST_METHODS.include?(digest_method)
      raise SignatureError.new("unsupported DigestMethod #{digest_method.inspect}")
    end
  end

  # --- step: issuer ---------------------------------------------------------

  # <saml:Issuer> must be Login.gov's SAML entityID, the same value that is the
  # metadata's entityID (SAML Core §2.2.5; Profiles §4.1.4.2).
  def check_issuer
    @issuer = text('/saml:Assertion/saml:Issuer')
    raise InvalidAssertion.new('assertion has no Issuer') if @issuer.to_s.empty?
    return if @idp_entity_id.nil? || @issuer == @idp_entity_id

    raise InvalidAssertion.new('Issuer does not match the IdP metadata entityID')
  end

  # --- step: subject --------------------------------------------------------

  # The Subject must carry a NameID and a bearer SubjectConfirmation whose
  # SubjectConfirmationData names this API as Recipient and has not expired
  # (SAML Core §2.4.1.2; Profiles §4.1.4.3). Login.gov sets NotOnOrAfter to
  # five minutes after issuance for delegated assertions.
  #
  # InResponseTo is refused. Login.gov omits it from delegated assertions; its
  # presence means the assertion answered a browser AuthnRequest, i.e. an
  # ordinary sign-in, which is never delegation.
  def check_subject
    @name_id = text('/saml:Assertion/saml:Subject/saml:NameID')
    @name_id_format = @doc.at_xpath(
      '/saml:Assertion/saml:Subject/saml:NameID/@Format', NAMESPACES
    )&.value
    raise InvalidAssertion.new('assertion has no Subject/NameID') if @name_id.to_s.empty?

    confirmation = @doc.at_xpath(
      "/saml:Assertion/saml:Subject/saml:SubjectConfirmation[@Method='#{BEARER}']", NAMESPACES
    )
    raise InvalidAssertion.new('no bearer SubjectConfirmation') if confirmation.nil?

    data = confirmation.at_xpath('./saml:SubjectConfirmationData', NAMESPACES)
    raise InvalidAssertion.new('no SubjectConfirmationData') if data.nil?

    if data['InResponseTo']
      raise InvalidAssertion.new('InResponseTo present: sign-in assertions are not delegation')
    end
    unless data['Recipient'] == @resource_identifier
      raise InvalidAssertion.new('Recipient does not match this resource server')
    end

    @subject_not_on_or_after = parse_time(
      data['NotOnOrAfter'], 'SubjectConfirmationData/@NotOnOrAfter'
    )
    if @now >= @subject_not_on_or_after + @clock_drift
      raise InvalidAssertion.new('subject confirmation window has passed')
    end
  end

  # --- step: conditions -----------------------------------------------------

  # Conditions: the validity window and the audience (SAML Core §2.5.1).
  #
  # - NotBefore / NotOnOrAfter are enforced with the configured drift
  #   (SAML Core §2.5.1.2). Login.gov sets them to issuance -5 s and +1 h.
  # - Every AudienceRestriction must list this API's identifier (SAML Core §2.5.1.4:
  #   multiple AudienceRestriction elements are independent and all must be
  #   satisfied). An assertion with no AudienceRestriction was not issued to
  #   this API and is refused; an assertion issued to another audience must
  #   never be accepted.
  # - Any other Condition type is not understood by this consumer, which per
  #   SAML Core §2.5.1 makes the assertion Invalid.
  def check_conditions
    conditions = @doc.at_xpath('/saml:Assertion/saml:Conditions', NAMESPACES)
    raise InvalidAssertion.new('assertion has no Conditions') if conditions.nil?

    @not_before = parse_time(conditions['NotBefore'], 'Conditions/@NotBefore')
    @not_on_or_after = parse_time(conditions['NotOnOrAfter'], 'Conditions/@NotOnOrAfter')
    raise InvalidAssertion.new('assertion is not yet valid') if @now < @not_before - @clock_drift
    raise InvalidAssertion.new('assertion has expired') if @now >= @not_on_or_after + @clock_drift

    restrictions = conditions.xpath('./saml:AudienceRestriction', NAMESPACES)
    raise InvalidAssertion.new('assertion has no AudienceRestriction') if restrictions.empty?

    restrictions.each do |restriction|
      audiences = restriction.xpath('./saml:Audience', NAMESPACES).map { |a| a.text.strip }
      next if audiences.include?(@resource_identifier)

      raise InvalidAssertion.new('Audience does not include this resource server')
    end

    other = conditions.element_children.reject { |c| c.name == 'AudienceRestriction' }
    return if other.empty?

    raise InvalidAssertion.new("unsupported Condition #{other.first.name}")
  end

  # --- step: attributes -----------------------------------------------------

  # Read the AttributeStatement. Login.gov keys each <saml:Attribute> by Name
  # (FriendlyName carries the same value). The agency SP's bundle (uuid, ial,
  # aal, email, name...) is exactly what this agency receives at direct sign-in;
  # the three delegation attributes are appended by the token exchange.
  # An assertion without them is not a delegated assertion and is refused.
  def read_attributes
    @doc.xpath('/saml:Assertion/saml:AttributeStatement/saml:Attribute', NAMESPACES).each do |attr|
      name = attr['Name'] || attr['FriendlyName']
      next if name.nil?

      values = attr.xpath('./saml:AttributeValue', NAMESPACES).map { |v| v.text }
      @attributes[name] = values.size == 1 ? values.first : values
    end

    missing = REQUIRED_DELEGATION_ATTRIBUTES.reject { |k| @attributes[k].to_s.strip != '' }
    unless missing.empty?
      raise InvalidAssertion.new("not a delegated assertion: missing #{missing.join(', ')}")
    end

    @authn_instant = @doc.at_xpath(
      '/saml:Assertion/saml:AuthnStatement/@AuthnInstant', NAMESPACES
    )&.value
    @authn_context_class_ref = text(
      '/saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthnContextClassRef',
    )
  end

  # --- step: key binding ----------------------------------------------------

  # RFC 9449 §7.1: a key-bound assertion (one carrying `dpop_jkt`) must arrive
  # with the DPoP scheme and a proof signed by the bound key; presented as a
  # plain Bearer token it is invalid, because whoever holds it has not shown
  # they hold the key. An unbound assertion presented with the DPoP scheme is
  # equally wrong: there is no key to check against. Runs after the signature
  # has verified (so `dpop_jkt` can be trusted) and before the replay check (so
  # a bad proof does not burn the assertion for a later, correct retry).
  def check_key_binding
    # Unit tests of the assertion alone pass no presentation; the app always does.
    return if @presentation.nil?

    scheme = @presentation[:scheme].to_s.downcase
    if bound?
      # `dpop_jkt` was read in #read_attributes, which runs after
      # #verify_signature, so by this point it is a value Login.gov signed, not
      # one an attacker could have inserted to steer the check.
      #
      # A bound assertion sent as Bearer is refused outright (RFC 9449 §7.1):
      # the holder has not shown they hold the key, and accepting it would make
      # the binding optional, which is the same as having none.
      unless scheme == 'dpop'
        raise SchemeMismatch.new('key-bound assertion must be presented with the DPoP scheme')
      end
      raise InvalidProof.new('no DPoP verifier configured') if @dpop_verifier.nil?

      begin
        # The verifier checks the proof against this exact request (method,
        # URL, token) and against the thumbprint in the assertion (§4.3).
        @dpop_verifier.verify!(
          proof: @presentation[:dpop_proof],
          method: @presentation[:method],
          url: @presentation[:url],
          access_token: @presentation[:token],
          expected_jkt: dpop_jkt,
        )
      rescue DpopVerifier::InvalidProof => e
        # Re-raised as an assertion error so the caller maps it to the
        # `invalid_dpop_proof` challenge (§7.1) alongside the other outcomes.
        raise InvalidProof.new(e.message)
      end
    elsif scheme == 'dpop'
      # An unbound assertion sent as DPoP is also refused: there is no
      # thumbprint to verify a proof against, so the DPoP scheme would be
      # claiming a binding that does not exist (RFC 9449 §7.1).
      raise SchemeMismatch.new('assertion is not key-bound; present it with the Bearer scheme')
    end
  end

  # --- step: replay ---------------------------------------------------------

  # Optional: accept each assertion ID once (see AssertionReplayCache). Runs
  # last so a rejected assertion is never remembered.
  def check_replay
    return if @replay_cache.nil?
    return if @replay_cache.first_use?(@assertion_id, expires_at: expires_at)

    raise InvalidAssertion.new('assertion has already been presented')
  end

  # --- helpers --------------------------------------------------------------

  def text(xpath)
    @doc.at_xpath(xpath, NAMESPACES)&.text&.strip
  end

  def parse_time(value, label)
    raise InvalidAssertion.new("#{label} is missing") if value.to_s.empty?

    Time.iso8601(value).utc
  rescue ArgumentError
    raise InvalidAssertion.new("#{label} is not an xs:dateTime")
  end
end
