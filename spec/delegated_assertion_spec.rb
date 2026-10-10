# frozen_string_literal: true

require 'spec_helper'
require_relative '../delegated_assertion'
require_relative '../dpop_verifier'
require_relative '../assertion_replay_cache'
require_relative '../idp_metadata'

RSpec.describe DelegatedAssertion do
  let(:factory) { DelegatedAssertionFactory }
  let(:rs_key) { factory.rs_key }
  let(:certs) { [factory.idp_cert] }

  def validate(xml, **opts)
    described_class.new(
      xml,
      resource_identifier: factory::RESOURCE,
      idp_certificates: certs,
      idp_entity_id: factory::IDP_ENTITY_ID,
      private_key: rs_key,
      clock_drift: 60,
      **opts,
    ).validate!
  end

  describe '.decode' do
    it 'accepts unpadded and padded base64url' do
      xml = '<a/>'
      expect(described_class.decode(Base64.urlsafe_encode64(xml, padding: false))).to eq(xml)
      expect(described_class.decode(Base64.urlsafe_encode64(xml))).to eq(xml)
    end

    it 'rejects anything else' do
      expect { described_class.decode('a b') }.to raise_error(DelegatedAssertion::InvalidAssertion)
      expect { described_class.decode(nil) }.to raise_error(DelegatedAssertion::InvalidAssertion)
    end
  end

  it 'exposes the subject, windows, attributes and delegation values' do
    now = Time.now.utc
    assertion = validate(factory.sign(factory.assertion_xml(now:)))

    expect(assertion.issuer).to eq(factory::IDP_ENTITY_ID)
    expect(assertion.name_id).to eq('pairwise-name-id-abc')
    expect(assertion.name_id_format).to eq('urn:oasis:names:tc:SAML:2.0:nameid-format:persistent')
    expect(assertion.subject_not_on_or_after).to be_within(1).of(now + 300)
    expect(assertion.not_on_or_after).to be_within(1).of(now + 3600)
    expect(assertion.delegation_scopes).to eq(%w[token_exchange:retirement_benefits])
    expect(assertion.delegation_id).to eq('del-0001')
    expect(assertion.actor).to eq(factory::ACTOR)
    expect(assertion.attributes).to include('first_name' => 'Test', 'last_name' => 'User')
    expect(assertion.authn_context_class_ref).to eq('http://idmanagement.gov/ns/assurance/ial/2')
    expect(assertion.expires_at).to be_within(1).of(now + 300 + 60)
  end

  it 'accepts an identifiers-only assertion (refresh after the service provider session ended)' do
    attrs = factory::DEFAULT_ATTRIBUTES.slice('uuid', 'ial', 'aal', 'delegation_scopes', 'delegation_id', 'actor')
    assertion = validate(factory.sign(factory.assertion_xml(attributes: attrs)))

    expect(assertion.attributes.keys).to match_array(attrs.keys)
  end

  describe 'signature' do
    it 'refuses RSA-SHA1 signatures' do
      xml = factory.sign(factory.assertion_xml, signature_method: XMLSecurity::Document::RSA_SHA1,
                                                digest_method: XMLSecurity::Document::SHA1)
      expect { validate(xml) }.to raise_error(DelegatedAssertion::SignatureError, /SignatureMethod/)
    end

    it 'refuses a signature whose Reference points at a nested element' do
      xml = factory.assertion_xml.sub('<Issuer>', '<Issuer ID="_inner">')
      doc = XMLSecurity::Document.new(xml)
      doc.uuid = '_inner'
      doc.sign_document(factory.idp_key, factory.idp_cert, XMLSecurity::Document::RSA_SHA256, XMLSecurity::Document::SHA256)

      expect { validate(doc.to_s) }.to raise_error(DelegatedAssertion::SignatureError, /does not reference the assertion/)
    end

    it 'accepts a signature from any of several metadata signing certificates' do
      other = factory.self_signed_cert(OpenSSL::PKey::RSA.new(2048), 'CN=Other')
      assertion = described_class.new(
        factory.sign(factory.assertion_xml),
        resource_identifier: factory::RESOURCE,
        idp_certificates: [other, factory.idp_cert],
      ).validate!

      expect(assertion.name_id).to eq('pairwise-name-id-abc')
    end
  end

  describe 'conditions' do
    it 'refuses an assertion with no AudienceRestriction' do
      xml = factory.sign(factory.assertion_xml(audience_restriction: false))
      expect { validate(xml) }.to raise_error(DelegatedAssertion::InvalidAssertion, /no AudienceRestriction/)
    end

    it 'requires every AudienceRestriction to name this resource server (SAML Core §2.5.1.4)' do
      extra = '<AudienceRestriction><Audience>https://someone-else.example</Audience></AudienceRestriction>'
      xml = factory.sign(factory.assertion_xml(extra_conditions: extra))
      expect { validate(xml) }.to raise_error(DelegatedAssertion::InvalidAssertion, /Audience/)
    end

    it 'treats an unknown Condition type as invalid (SAML Core §2.5.1)' do
      xml = factory.sign(factory.assertion_xml(extra_conditions: '<OneTimeUse/>'))
      expect { validate(xml) }.to raise_error(DelegatedAssertion::InvalidAssertion, /unsupported Condition OneTimeUse/)
    end
  end

  describe 'encryption' do
    it 'decrypts aes256-cbc (the registered block_encryption) and aes128-cbc' do
      %w[aes256-cbc aes128-cbc].each do |alg|
        xml = factory.encrypt(factory.sign(factory.assertion_xml), block_encryption: "http://www.w3.org/2001/04/xmlenc##{alg}")
        expect(validate(xml).name_id).to eq('pairwise-name-id-abc')
      end
    end

    it 'fails cleanly when encrypted to a different key' do
      other_cert = factory.self_signed_cert(OpenSSL::PKey::RSA.new(2048), 'CN=Not Us')
      xml = factory.encrypt(factory.sign(factory.assertion_xml), cert: other_cert)
      expect { validate(xml) }.to raise_error(DelegatedAssertion::InvalidAssertion, /decryption failed/)
    end

    it 'refuses an encrypted assertion when no private key is configured' do
      xml = factory.encrypt(factory.sign(factory.assertion_xml))
      expect { validate(xml, private_key: nil) }.to raise_error(DelegatedAssertion::InvalidAssertion, /no private key/)
    end
  end

  describe 'replay cache' do
    it 'accepts the first presentation and refuses the second until expiry' do
      cache = AssertionReplayCache.new
      xml = factory.sign(factory.assertion_xml)

      validate(xml, replay_cache: cache)
      expect { validate(xml, replay_cache: cache) }.to raise_error(DelegatedAssertion::InvalidAssertion, /already been presented/)
      expect(cache.size).to eq(1)
    end

    it 'forgets IDs once they can no longer be valid' do
      cache = AssertionReplayCache.new
      expect(cache.first_use?('x', expires_at: Time.now - 1)).to be(true)
      expect(cache.first_use?('x', expires_at: Time.now - 1)).to be(true)
    end
  end


  describe 'key binding (RFC 9449)' do
    let(:dpop) { DpopFactory }
    let(:bound_attrs) { factory::DEFAULT_ATTRIBUTES.merge('dpop_jkt' => dpop.jkt) }
    let(:url) { 'https://benefits-api.agency.localdev/api/benefits' }

    def present(xml, token:, scheme:, proof:, method: 'GET', verifier: DpopVerifier.new)
      validate(
        xml,
        presentation: { scheme:, token:, dpop_proof: proof, method:, url: },
        dpop_verifier: verifier,
      )
    end

    it 'exposes dpop_jkt and bound? and skips the check when no presentation is given' do
      bound = validate(factory.sign(factory.assertion_xml(attributes: bound_attrs)))
      expect(bound.dpop_jkt).to eq(dpop.jkt)
      expect(bound).to be_bound

      plain = validate(factory.sign(factory.assertion_xml))
      expect(plain.dpop_jkt).to be_nil
      expect(plain).not_to be_bound
    end

    it 'accepts a bound assertion with the DPoP scheme and a matching proof' do
      xml = factory.sign(factory.assertion_xml(attributes: bound_attrs))
      token = factory.encode(xml)
      assertion = present(xml, token:, scheme: 'DPoP', proof: dpop.proof(token:, url:))
      expect(assertion).to be_bound
    end

    it 'refuses a bound assertion presented as Bearer' do
      xml = factory.sign(factory.assertion_xml(attributes: bound_attrs))
      expect { present(xml, token: factory.encode(xml), scheme: 'Bearer', proof: nil) }.
        to raise_error(DelegatedAssertion::SchemeMismatch, /DPoP scheme/)
    end

    it 'refuses an unbound assertion presented as DPoP' do
      xml = factory.sign(factory.assertion_xml)
      token = factory.encode(xml)
      expect { present(xml, token:, scheme: 'DPoP', proof: dpop.proof(token:, url:)) }.
        to raise_error(DelegatedAssertion::SchemeMismatch, /not key-bound/)
    end

    it 'maps verifier failures to InvalidProof' do
      xml = factory.sign(factory.assertion_xml(attributes: bound_attrs))
      token = factory.encode(xml)
      expect { present(xml, token:, scheme: 'DPoP', proof: dpop.proof(token:, url:, key: dpop.other_ec_key)) }.
        to raise_error(DelegatedAssertion::InvalidProof, /does not match the key/)
    end

    it 'does not trust dpop_jkt before the signature verifies' do
      xml = factory.sign(factory.assertion_xml(attributes: bound_attrs), key: factory.rogue_key, cert: factory.rogue_cert)
      token = factory.encode(xml)
      expect { present(xml, token:, scheme: 'DPoP', proof: dpop.proof(token:, url:)) }.
        to raise_error(DelegatedAssertion::SignatureError)
    end

    it 'checks the proof before recording the assertion ID for replay' do
      cache = AssertionReplayCache.new
      xml = factory.sign(factory.assertion_xml(attributes: bound_attrs))
      token = factory.encode(xml)
      expect do
        validate(xml, replay_cache: cache,
                      presentation: { scheme: 'DPoP', token:, dpop_proof: 'garbage', method: 'GET', url: },
                      dpop_verifier: DpopVerifier.new)
      end.to raise_error(DelegatedAssertion::InvalidProof)
      expect(cache.size).to eq(0)
    end
  end

  describe 'malformed input' do
    it 'rejects non-XML, a non-Assertion root, and DOCTYPEs' do
      expect { validate('not xml') }.to raise_error(DelegatedAssertion::InvalidAssertion)
      expect { validate('<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol"/>') }.
        to raise_error(DelegatedAssertion::InvalidAssertion, /root element/)
      expect { validate("<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///etc/passwd'>]>#{factory.assertion_xml}") }.
        to raise_error(DelegatedAssertion::InvalidAssertion)
    end
  end
end

RSpec.describe IdpMetadata do
  let(:factory) { DelegatedAssertionFactory }

  it 'reads the entityID and signing certificates, fetching once within the cache window' do
    stub_request(:get, factory::METADATA_URL).to_return(status: 200, body: factory.metadata_xml)
    metadata = described_class.new(url: factory::METADATA_URL)

    expect(metadata.entity_id).to eq(factory::IDP_ENTITY_ID)
    expect(metadata.signing_certificates.map(&:to_pem)).to eq([factory.idp_cert.to_pem])
    expect(a_request(:get, factory::METADATA_URL)).to have_been_made.once
  end

  it 'raises FetchError on a non-200 or connection failure' do
    stub_request(:get, factory::METADATA_URL).to_return(status: 404)
    expect { described_class.new(url: factory::METADATA_URL).signing_certificates }.
      to raise_error(IdpMetadata::FetchError, /404/)

    stub_request(:get, factory::METADATA_URL).to_raise(Faraday::ConnectionFailed.new('refused'))
    expect { described_class.new(url: factory::METADATA_URL).signing_certificates }.
      to raise_error(IdpMetadata::FetchError, /refused/)
  end

  it 'rate-limits early refreshes' do
    stub_request(:get, factory::METADATA_URL).to_return(status: 200, body: factory.metadata_xml)
    metadata = described_class.new(url: factory::METADATA_URL, min_refresh_interval: 60)
    metadata.signing_certificates

    expect(metadata.refresh_if_stale!).to be(false)
    metadata.instance_variable_set(:@fetched_at, Time.now - 120)
    expect(metadata.refresh_if_stale!).to be(true)
    expect(a_request(:get, factory::METADATA_URL)).to have_been_made.twice
  end
end
