# frozen_string_literal: true

# Live-RPC integration tests for smart-wallet verification.
# Gated on `:live_rpc` filter — only runs when SIWE_RPC_URL is set
# (see spec_helper.rb). Defaults to https://ethereum-rpc.publicnode.com,
# which is the same endpoint the discourse plugin's integration test uses.

RSpec.describe "Smart-wallet verification (live RPC)", :live_rpc do
  let(:rpc_url) { ENV.fetch("SIWE_RPC_URL", "https://ethereum-rpc.publicnode.com") }
  let(:rpc) { Siwe::Rpc::HttpClient.new(rpc_url) }
  let(:vectors) { load_vectors("verification", "eip1271") }

  describe "EIP-1271 vectors" do
    it "verifies the Argent smart-wallet signature" do
      v = vectors.fetch("argent")
      msg = Siwe::Message.parse(v["message"])
      cfg = Siwe::Config.new(rpc: rpc)

      expect do
        msg.verify!(signature: v["signature"], domain: msg.domain, nonce: msg.nonce, config: cfg)
      end.not_to raise_error
    end

    it "verifies the Loopring smart-wallet signature" do
      v = vectors.fetch("loopring")
      msg = Siwe::Message.parse(v["message"])
      cfg = Siwe::Config.new(rpc: rpc)

      expect do
        msg.verify!(signature: v["signature"], domain: msg.domain, nonce: msg.nonce, config: cfg)
      end.not_to raise_error
    end
  end

  describe "EOA via universal validator" do
    it "verifies a fresh EOA signature even when forced through the smart-wallet path" do
      key = Eth::Key.new
      msg = Siwe::Message.new(
        domain: "example.com",
        address: key.address.to_s,
        uri: "https://example.com",
        chain_id: 1,
        nonce: "abcd1234",
        issued_at: "2024-01-01T00:00:00Z"
      )
      sig = key.personal_sign(msg.prepare_message)

      # Verify directly via the universal validator (bypassing the EOA short-circuit).
      result = Siwe::SmartWallet.verify(rpc: rpc, address: msg.address, message: msg.prepare_message, signature: sig)
      expect(result).to be(true)
    end
  end
end
