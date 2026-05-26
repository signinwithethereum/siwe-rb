# frozen_string_literal: true

# Build a Siwe::Message from a JSON test vector hash.
def build_message_from_vector(vec)
  Siwe::Message.new(
    domain: vec["domain"],
    address: vec["address"],
    uri: vec["uri"],
    chain_id: vec["chainId"],
    nonce: vec["nonce"],
    version: vec["version"],
    statement: vec["statement"],
    issued_at: vec["issuedAt"],
    expiration_time: vec["expirationTime"],
    not_before: vec["notBefore"],
    request_id: vec["requestId"],
    resources: vec["resources"]
  )
end

def verify_kwargs_for(vec)
  {
    signature: vec["signature"],
    domain: vec["domainBinding"] || vec["domain"],
    nonce: vec["matchNonce"] || vec["nonce"],
    time: vec["time"]
  }.compact
end

RSpec.describe "EOA signature verification" do
  describe "verification_positive vectors" do
    load_vectors("verification", "verification_positive").each do |name, vec|
      it name do
        msg = build_message_from_vector(vec)
        expect { msg.verify!(**verify_kwargs_for(vec)) }.not_to raise_error
      end
    end
  end

  describe "verification_negative vectors" do
    load_vectors("verification", "verification_negative").each do |name, vec|
      it name do
        expect do
          msg = build_message_from_vector(vec)
          msg.verify!(**verify_kwargs_for(vec))
        end.to raise_error(Siwe::Error)
      end
    end
  end

  describe "Siwe.configure" do
    after { Siwe.reset_config! }

    it "sets a global config" do
      Siwe.configure do |c|
        c.rpc_url = "https://example.com"
      end
      expect(Siwe.config.rpc_url).to eq("https://example.com")
    end

    it "uses custom adapter via per-call config" do
      fake_adapter = Class.new do
        def verify_message(_msg, _sig) = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
      end.new
      cfg = Siwe::Config.new(adapter: fake_adapter)

      msg = Siwe::Message.new(
        domain: "example.com",
        address: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
        uri: "https://example.com",
        chain_id: 1,
        nonce: "abcd1234",
        issued_at: "2024-01-01T00:00:00Z"
      )
      expect do
        msg.verify!(signature: "0xdeadbeef", domain: "example.com", nonce: "abcd1234", config: cfg)
      end.not_to raise_error
    end
  end

  describe "parameter validation" do
    let(:msg) do
      Siwe::Message.new(
        domain: "example.com",
        address: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
        uri: "https://example.com",
        chain_id: 1,
        nonce: "abcd1234",
        issued_at: "2024-01-01T00:00:00Z"
      )
    end

    it "raises :invalid_params for a nil signature (not :invalid_signature)" do
      expect do
        msg.verify!(signature: nil, domain: "example.com", nonce: "abcd1234")
      end.to raise_error(Siwe::Error) { |e| expect(e.type).to eq(:invalid_params) }
    end

    it "raises :invalid_params for an empty signature" do
      expect do
        msg.verify!(signature: "", domain: "example.com", nonce: "abcd1234")
      end.to raise_error(Siwe::Error) { |e| expect(e.type).to eq(:invalid_params) }
    end

    it "raises :missing_domain when domain is omitted" do
      expect do
        msg.verify!(signature: "0xdeadbeef", domain: "", nonce: "abcd1234")
      end.to raise_error(Siwe::Error) { |e| expect(e.type).to eq(:missing_domain) }
    end

    it "raises :missing_nonce when nonce is omitted" do
      expect do
        msg.verify!(signature: "0xdeadbeef", domain: "example.com", nonce: "")
      end.to raise_error(Siwe::Error) { |e| expect(e.type).to eq(:missing_nonce) }
    end

    it "raises :missing_uri in strict mode without a uri arg" do
      expect do
        msg.verify!(signature: "0xdeadbeef", domain: "example.com", nonce: "abcd1234", strict: true)
      end.to raise_error(Siwe::Error) { |e| expect(e.type).to eq(:missing_uri) }
    end

    it "raises :missing_chain_id in strict mode without a chain_id arg" do
      expect do
        msg.verify!(signature: "0xdeadbeef", domain: "example.com", nonce: "abcd1234",
                    uri: "https://example.com", strict: true)
      end.to raise_error(Siwe::Error) { |e| expect(e.type).to eq(:missing_chain_id) }
    end
  end

  describe "expiration boundary" do
    let(:msg) do
      Siwe::Message.new(
        domain: "example.com",
        address: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
        uri: "https://example.com",
        chain_id: 1,
        nonce: "abcd1234",
        issued_at: "2024-01-01T00:00:00Z",
        expiration_time: "2024-06-01T00:00:00Z"
      )
    end

    it "rejects at the exact expiration instant (matches TS/Python/Rust)" do
      expect do
        msg.verify!(signature: "0xdeadbeef", domain: "example.com",
                    nonce: "abcd1234", time: "2024-06-01T00:00:00Z")
      end.to raise_error(Siwe::Error) { |e| expect(e.type).to eq(:expired_message) }
    end

    it "rejects after the expiration instant" do
      expect do
        msg.verify!(signature: "0xdeadbeef", domain: "example.com",
                    nonce: "abcd1234", time: "2024-06-01T00:00:00.001Z")
      end.to raise_error(Siwe::Error) { |e| expect(e.type).to eq(:expired_message) }
    end
  end
end
