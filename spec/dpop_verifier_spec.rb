# frozen_string_literal: true

require 'spec_helper'
require_relative '../dpop_verifier'
require_relative '../assertion_replay_cache'

RSpec.describe DpopVerifier do
  let(:dpop) { DpopFactory }
  let(:token) { 'dGhlLXRva2Vu' }
  let(:url) { 'https://benefits-api.agency.localdev/api/benefits' }
  let(:cache) { AssertionReplayCache.new }
  let(:verifier) { described_class.new(replay_cache: cache) }

  def verify(proof, method: 'GET', request_url: url, expected_jkt: dpop.jkt)
    verifier.verify!(proof:, method:, url: request_url, access_token: token, expected_jkt:)
  end

  it 'returns the key thumbprint for a valid proof and records its jti' do
    expect(verify(dpop.proof(token:, url:))).to eq(dpop.jkt)
    expect(cache.size).to eq(1)
  end

  it 'normalizes htu: scheme and host case, default port, trailing query and fragment' do
    proof = dpop.proof(token:, url: 'HTTPS://Benefits-API.agency.localdev:443/api/benefits')
    expect(verify(proof, request_url: "#{url}?x=1#frag")).to eq(dpop.jkt)
  end

  it 'requires an absolute htu' do
    expect { verify(dpop.proof(token:, url: '/api/benefits')) }.
      to raise_error(described_class::InvalidProof, /absolute URL/)
  end

  it 'accepts iat within the leeway on either side and refuses beyond it' do
    expect { verify(dpop.proof(token:, url:, now: Time.now.to_i - 59)) }.not_to raise_error
    expect { verify(dpop.proof(token:, url:, now: Time.now.to_i + 59)) }.not_to raise_error
    expect { verify(dpop.proof(token:, url:, now: Time.now.to_i - 61)) }.
      to raise_error(described_class::InvalidProof, /iat/)
  end

  it 'honors a configured alg allow-list' do
    strict = described_class.new(allowed_algs: %w[ES256])
    expect do
      strict.verify!(proof: dpop.proof(token:, url:, key: dpop.rsa_key), method: 'GET', url:,
                     access_token: token, expected_jkt: dpop.jkt(dpop.rsa_key))
    end.to raise_error(described_class::InvalidProof, /alg must be one of ES256/)
  end

  it 'refuses a jwk whose type does not match the alg' do
    proof = dpop.proof(token:, url:, key: dpop.ec_key, header: { jwk: dpop.public_jwk(dpop.rsa_key) })
    expect { verify(proof) }.to raise_error(described_class::InvalidProof, /kty/)
  end

  it 'refuses a proof whose jti was already used, and forgets it after the window' do
    proof = dpop.proof(token:, url:)
    verify(proof)
    expect { verify(proof) }.to raise_error(described_class::InvalidProof, /already been used/)
  end

  it 'does not record the jti of a proof that failed another check' do
    expect { verify(dpop.proof(token:, url:, method: 'POST')) }.to raise_error(described_class::InvalidProof)
    expect(cache.size).to eq(0)
  end
end
