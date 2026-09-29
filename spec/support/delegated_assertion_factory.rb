# frozen_string_literal: true

require 'base64'
require 'nokogiri'
require 'openssl'
require 'securerandom'
require 'time'
require 'xml_security'
require 'xmlenc'

# Builds delegated SAML assertions shaped like the ones Login.gov's token
# exchange mints with a throwaway IdP
# key pair, signs them the way ruby-saml does, and (optionally) encrypts them
# with xmlenc using the same template as the IdP's saml_idp Encryptor.
module DelegatedAssertionFactory
  IDP_ENTITY_ID = 'http://localhost:3000/api/saml'
  RESOURCE = 'https://benefits-api.agency.localdev'
  ACTOR = 'urn:gov:gsa:openidconnect:sp:sinatra_sts'
  METADATA_URL = 'http://localhost:3000/api/saml/metadata2026'

  module_function

  def idp_key
    @idp_key ||= OpenSSL::PKey::RSA.new(2048)
  end

  def idp_cert
    @idp_cert ||= self_signed_cert(idp_key, 'CN=Test IdP')
  end

  # A second, untrusted key pair for "bad signature" cases.
  def rogue_key
    @rogue_key ||= OpenSSL::PKey::RSA.new(2048)
  end

  def rogue_cert
    @rogue_cert ||= self_signed_cert(rogue_key, 'CN=Rogue IdP')
  end

  # The resource server's own key pair (what the app decrypts with).
  def rs_key
    @rs_key ||= OpenSSL::PKey::RSA.new(File.read(File.expand_path('../../config/demo_sp.key', __dir__)))
  end

  def rs_cert
    @rs_cert ||= OpenSSL::X509::Certificate.new(
      File.read(File.expand_path('../../config/demo_sp.crt', __dir__)),
    )
  end

  def self_signed_cert(key, subject)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = SecureRandom.random_number(2**64)
    cert.subject = cert.issuer = OpenSSL::X509::Name.parse(subject)
    cert.public_key = key.public_key
    cert.not_before = Time.now - 60
    cert.not_after = Time.now + (365 * 24 * 3600)
    cert.sign(key, OpenSSL::Digest.new('SHA256'))
    cert
  end

  def pem_body(cert)
    Base64.strict_encode64(cert.to_der)
  end

  # Minimal IdP metadata with one signing KeyDescriptor, as ruby-saml's
  # IdpMetadataParser expects it.
  def metadata_xml(cert: idp_cert, entity_id: IDP_ENTITY_ID)
    <<~XML
      <?xml version="1.0"?>
      <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
          xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="#{entity_id}">
        <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
          <md:KeyDescriptor use="signing">
            <ds:KeyInfo><ds:X509Data><ds:X509Certificate>#{pem_body(cert)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
          </md:KeyDescriptor>
          <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
          <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
              Location="http://localhost:3000/api/saml/auth2026"/>
        </md:IDPSSODescriptor>
      </md:EntityDescriptor>
    XML
  end

  DEFAULT_ATTRIBUTES = {
    'uuid' => 'agency-uuid-1234',
    'ial' => 'http://idmanagement.gov/ns/assurance/ial/2',
    'aal' => 'http://idmanagement.gov/ns/assurance/aal/2',
    'email' => 'test.user@example.com',
    'first_name' => 'Test',
    'last_name' => 'User',
    'delegation_scopes' => 'token_exchange:benefits_read token_exchange:benefits_write',
    'delegation_id' => 'del-0001',
    'actor' => ACTOR,
  }.freeze

  # Unsigned assertion XML in the saml_idp AssertionBuilder layout: Issuer,
  # (Signature goes here), Subject, Conditions, AttributeStatement, AuthnStatement.
  #
  # @param attributes [Hash] replaces DEFAULT_ATTRIBUTES entirely when given
  # @param in_response_to [String, nil] added to SubjectConfirmationData when given
  # @param extra_conditions [String] raw XML appended inside <Conditions>
  def assertion_xml(
    id: "_#{SecureRandom.uuid}",
    issuer: IDP_ENTITY_ID,
    name_id: 'pairwise-name-id-abc',
    audience: RESOURCE,
    recipient: RESOURCE,
    now: Time.now.utc,
    subject_not_on_or_after: now + 300,
    not_before: now - 5,
    not_on_or_after: now + 3600,
    in_response_to: nil,
    attributes: DEFAULT_ATTRIBUTES,
    extra_conditions: '',
    audience_restriction: true
  )
    scd = {
      'NotOnOrAfter' => subject_not_on_or_after.utc.iso8601,
      'Recipient' => recipient,
    }
    scd['InResponseTo'] = in_response_to if in_response_to
    scd_attrs = scd.map { |k, v| "#{k}=\"#{v}\"" }.join(' ')

    attr_xml = attributes.map do |name, value|
      values = Array(value).map { |v| "<AttributeValue>#{v.to_s.encode(xml: :text)}</AttributeValue>" }.join
      "<Attribute Name=\"#{name}\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\" " \
        "FriendlyName=\"#{name}\">#{values}</Attribute>"
    end.join

    restriction = audience_restriction ? "<AudienceRestriction><Audience>#{audience}</Audience></AudienceRestriction>" : ''

    <<~XML.gsub(/\n\s*/, '')
      <Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="#{id}" IssueInstant="#{now.iso8601}" Version="2.0">
        <Issuer>#{issuer}</Issuer>
        <Subject>
          <NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">#{name_id}</NameID>
          <SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <SubjectConfirmationData #{scd_attrs}/>
          </SubjectConfirmation>
        </Subject>
        <Conditions NotBefore="#{not_before.utc.iso8601}" NotOnOrAfter="#{not_on_or_after.utc.iso8601}">
          #{restriction}#{extra_conditions}
        </Conditions>
        <AttributeStatement>#{attr_xml}</AttributeStatement>
        <AuthnStatement AuthnInstant="#{(now - 120).iso8601}" SessionIndex="#{id}">
          <AuthnContext><AuthnContextClassRef>http://idmanagement.gov/ns/assurance/ial/2</AuthnContextClassRef></AuthnContext>
        </AuthnStatement>
      </Assertion>
    XML
  end

  # Enveloped signature over the Assertion (RSA-SHA256 / SHA-256, exclusive c14n),
  # inserted after Issuer as ruby-saml and saml_idp both do.
  def sign(xml, key: idp_key, cert: idp_cert,
           signature_method: XMLSecurity::Document::RSA_SHA256,
           digest_method: XMLSecurity::Document::SHA256)
    doc = XMLSecurity::Document.new(xml)
    doc.sign_document(key, cert, signature_method, digest_method)
    doc.to_s
  end

  # The saml_idp Encryptor template (aes256-cbc + rsa-oaep-mgf1p) wrapped in
  # <EncryptedAssertion>, produced with the same xmlenc gem.
  def encrypt(signed_xml, cert: rs_cert, block_encryption: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc')
    template = <<~XML
      <EncryptedData Id="ED" Type="http://www.w3.org/2001/04/xmlenc#Element" xmlns="http://www.w3.org/2001/04/xmlenc#">
        <EncryptionMethod Algorithm="#{block_encryption}"/>
        <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
          <EncryptedKey Id="EK" xmlns="http://www.w3.org/2001/04/xmlenc#">
            <EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
              <ds:X509Data><ds:X509Certificate>#{pem_body(cert)}</ds:X509Certificate></ds:X509Data>
            </ds:KeyInfo>
            <CipherData><CipherValue/></CipherData>
            <ReferenceList><DataReference URI="ED"/></ReferenceList>
          </EncryptedKey>
        </ds:KeyInfo>
        <CipherData><CipherValue/></CipherData>
      </EncryptedData>
    XML
    node = Nokogiri::XML::Document.parse(template).root
    encrypted_data = Xmlenc::EncryptedData.new(node)
    key = encrypted_data.encrypt(signed_xml)
    encrypted_key_node = encrypted_data.node.at_xpath(
      '//xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey', Xmlenc::NAMESPACES
    )
    Xmlenc::EncryptedKey.new(encrypted_key_node).encrypt(cert.public_key, key)
    "<EncryptedAssertion xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\">#{encrypted_data.node}</EncryptedAssertion>"
  end

  # RFC 8693 §3: base64url, no padding.
  def encode(xml)
    Base64.urlsafe_encode64(xml, padding: false)
  end

  # Signed, encoded assertion ready for `Authorization: Bearer`.
  def token(**overrides)
    encode(sign(assertion_xml(**overrides)))
  end

  def encrypted_token(**overrides)
    encode(encrypt(sign(assertion_xml(**overrides))))
  end
end
