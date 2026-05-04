# frozen_string_literal: true

# Unit tests for the smart-wallet verify path.
# Uses mocked RPC. Live integration cases live in smart_wallet_integration_spec.rb
# and run only when SIWE_RPC_URL is set.

class FakeRpc
  attr_reader :calls, :chain_id

  def initialize(result: nil, raise_error: nil, chain_id: nil)
    @result = result
    @raise_error = raise_error
    @chain_id = chain_id
    @calls = []
  end

  def eth_call(to:, data:, block: "latest")
    @calls << { to: to, data: data, block: block }
    raise @raise_error if @raise_error

    @result
  end
end

RSpec.describe Siwe::Eip6492 do
  describe ".signature?" do
    it "detects the magic suffix with or without 0x prefix" do
      sig = "0xdeadbeef#{Siwe::Eip6492::MAGIC_SUFFIX}"
      expect(described_class.signature?(sig)).to be(true)
      expect(described_class.signature?(sig.delete_prefix("0x"))).to be(true)
    end

    it "rejects normal EOA signatures" do
      expect(described_class.signature?("0x#{"ab" * 65}")).to be(false)
    end

    it "rejects nil and short inputs" do
      expect(described_class.signature?(nil)).to be(false)
      expect(described_class.signature?("0xff")).to be(false)
    end
  end

  describe "VALIDATOR_BYTECODE" do
    it "matches the TS reference byte-for-byte" do
      ts_path = File.expand_path("../../ts/packages/siwe/lib/eip6492.ts", __dir__)
      skip "TS reference not available" unless File.exist?(ts_path)

      m = File.read(ts_path).match(/EIP6492_VALIDATOR_BYTECODE\s*=\s*['"](0x[0-9a-fA-F]+)['"]/)
      ts_bytecode = m[1].sub(/^0x/, "")
      expect(described_class::VALIDATOR_BYTECODE).to eq(ts_bytecode)
    end
  end
end

# Test vectors from discourse-siwe-auth/test/smart_wallet_unit_test.rb,
# known-correct against viem.
module SmartWalletVectors
  ADDRESS_HEX = "0x05616f5E0B9a600D4D51DE3D0D24C5D6dD638BE0"
  EXPECTED_HASH = "f9e0abaf53d39c5b7e8122276cb46f6cf5b100d32ba23bd095889568c79a4d95"
  SIGNATURE_HEX = "0xea337e906e34f485e054c5999ae2c97a8d346474633798a5c88fcb3e6a3f3964" \
                  "44f685fc1a43a743c54d6037dd6f3c0b516d35229c24fe2a8d03c7783cbc2d2b1c"
  SIWE_MESSAGE = "test.example.com wants you to sign in with your Ethereum account:\n" \
                 "0x05616f5E0B9a600D4D51DE3D0D24C5D6dD638BE0\n" \
                 "\n" \
                 "Sign in with Ethereum\n" \
                 "\n" \
                 "URI: https://test.example.com\n" \
                 "Version: 1\n" \
                 "Chain ID: 1\n" \
                 "Nonce: test123\n" \
                 "Issued At: 2024-01-01T00:00:00Z"
end

RSpec.describe Siwe::SmartWallet do
  include SmartWalletVectors

  describe ".eip191_hash" do
    it "matches viem.hashMessage byte-for-byte" do
      hash = described_class.eip191_hash(SmartWalletVectors::SIWE_MESSAGE)
      expect(hash.unpack1("H*")).to eq(SmartWalletVectors::EXPECTED_HASH)
    end
  end

  describe ".verify" do
    let(:rpc) { FakeRpc.new(result: "0x01") }

    it "issues exactly one eth_call, with to: nil (deploy-and-call)" do
      described_class.verify(rpc: rpc, address: SmartWalletVectors::ADDRESS_HEX,
                             message: SmartWalletVectors::SIWE_MESSAGE,
                             signature: SmartWalletVectors::SIGNATURE_HEX)
      expect(rpc.calls.length).to eq(1)
      expect(rpc.calls[0][:to]).to be_nil
    end

    it "ABI-encodes (address,bytes32,bytes) constructor args matching viem" do
      described_class.verify(rpc: rpc, address: SmartWalletVectors::ADDRESS_HEX,
                             message: SmartWalletVectors::SIWE_MESSAGE,
                             signature: SmartWalletVectors::SIGNATURE_HEX)
      data = rpc.calls[0][:data]
      args_hex = data.delete_prefix("0x")[Siwe::Eip6492::VALIDATOR_BYTECODE.length..]

      expected_args = "00000000000000000000000005616f5e0b9a600d4d51de3d0d24c5d6dd638be0" \
                      "f9e0abaf53d39c5b7e8122276cb46f6cf5b100d32ba23bd095889568c79a4d95" \
                      "0000000000000000000000000000000000000000000000000000000000000060" \
                      "0000000000000000000000000000000000000000000000000000000000000041" \
                      "ea337e906e34f485e054c5999ae2c97a8d346474633798a5c88fcb3e6a3f3964" \
                      "44f685fc1a43a743c54d6037dd6f3c0b516d35229c24fe2a8d03c7783cbc2d2b" \
                      "1c00000000000000000000000000000000000000000000000000000000000000"
      expect(args_hex).to eq(expected_args)
    end

    it "returns true when validator yields 0x01 (padded form)" do
      rpc = FakeRpc.new(result: "0x#{"0" * 62}01")
      result = described_class.verify(rpc: rpc, address: SmartWalletVectors::ADDRESS_HEX,
                                      message: SmartWalletVectors::SIWE_MESSAGE,
                                      signature: SmartWalletVectors::SIGNATURE_HEX)
      expect(result).to be(true)
    end

    it "returns false when validator yields 0x00" do
      rpc = FakeRpc.new(result: "0x#{"0" * 64}")
      result = described_class.verify(rpc: rpc, address: SmartWalletVectors::ADDRESS_HEX,
                                      message: SmartWalletVectors::SIWE_MESSAGE,
                                      signature: SmartWalletVectors::SIGNATURE_HEX)
      expect(result).to be(false)
    end

    it "propagates Siwe::Error :rpc_error from the RPC client" do
      rpc = FakeRpc.new(raise_error: Siwe::Error.new(Siwe::ErrorType::RPC_ERROR))
      expect do
        described_class.verify(rpc: rpc, address: SmartWalletVectors::ADDRESS_HEX,
                               message: SmartWalletVectors::SIWE_MESSAGE,
                               signature: SmartWalletVectors::SIGNATURE_HEX)
      end.to raise_error(Siwe::Error) { |e| expect(e.type).to eq(:rpc_error) }
    end
  end
end

RSpec.describe Siwe::Message do
  describe "EOA → smart-wallet dispatch" do
    let(:address) { "0xa5b3A53800cD49669F34DE80f2C569c6D4Ca3009" }
    let(:msg) do
      Siwe::Message.new(
        domain: "localhost:4361", address: address, uri: "http://localhost:4361",
        chain_id: 1, nonce: "FbYd6TNB4m0IUHDG7", issued_at: "2022-04-19T18:55:04.444Z",
        statement: "SIWE Notepad Example"
      )
    end

    it "skips RPC entirely when EOA recovery succeeds (matches signer)" do
      key = Eth::Key.new
      eoa_msg = Siwe::Message.new(
        domain: "example.com", address: key.address.to_s, uri: "https://example.com",
        chain_id: 1, nonce: "abcd1234", issued_at: "2024-01-01T00:00:00Z"
      )
      sig = key.personal_sign(eoa_msg.prepare_message)
      rpc = FakeRpc.new(result: "0x01")
      cfg = Siwe::Config.new(rpc: rpc)

      eoa_msg.verify!(signature: sig, domain: "example.com", nonce: "abcd1234", config: cfg)
      expect(rpc.calls).to be_empty
    end

    it "falls through to smart-wallet path when EOA recovery returns the wrong address" do
      rpc = FakeRpc.new(result: "0x01")
      cfg = Siwe::Config.new(rpc: rpc)

      msg.verify!(signature: "0x#{"ab" * 65}", domain: "localhost:4361", nonce: "FbYd6TNB4m0IUHDG7", config: cfg)
      expect(rpc.calls.length).to eq(1)
      expect(rpc.calls[0][:to]).to be_nil
    end

    it "raises :invalid_signature when smart-wallet validator returns 0x00" do
      rpc = FakeRpc.new(result: "0x#{"0" * 64}")
      cfg = Siwe::Config.new(rpc: rpc)

      expect do
        msg.verify!(signature: "0x#{"ab" * 65}", domain: "localhost:4361", nonce: "FbYd6TNB4m0IUHDG7", config: cfg)
      end.to raise_error(Siwe::Error) { |e| expect(e.type).to eq(:invalid_signature) }
    end

    it "raises :invalid_signature when no RPC is configured and EOA recovery fails" do
      Siwe.reset_config!
      expect do
        msg.verify!(signature: "0x#{"ab" * 65}", domain: "localhost:4361", nonce: "FbYd6TNB4m0IUHDG7")
      end.to raise_error(Siwe::Error) { |e| expect(e.type).to eq(:invalid_signature) }
    end

    it "raises :invalid_signature_chain_id when RPC chain doesn't match message chain" do
      rpc = FakeRpc.new(result: "0x01", chain_id: 137)
      cfg = Siwe::Config.new(rpc: rpc)

      expect do
        msg.verify!(signature: "0x#{"ab" * 65}", domain: "localhost:4361", nonce: "FbYd6TNB4m0IUHDG7", config: cfg)
      end.to raise_error(Siwe::Error) { |e| expect(e.type).to eq(:invalid_signature_chain_id) }
    end
  end
end
