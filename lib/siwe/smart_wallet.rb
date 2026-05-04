# frozen_string_literal: true

require "eth"

require_relative "eip6492"
require_relative "error"
require_relative "error_type"

module Siwe
  # Smart-wallet signature verification via the EIP-6492 off-chain universal
  # validator. A single eth_call (deploy-and-call) covers both deployed ERC-1271
  # wallets (e.g. Safe) and counterfactual EIP-6492-wrapped signatures
  # (e.g. Coinbase Smart Wallet).
  module SmartWallet
    module_function

    # Verify a smart-wallet signature.
    # rpc       — anything responding to `eth_call(to:, data:, block:)`
    # address   — claimed signer (smart contract or factory-deployed address)
    # message   — EIP-4361 message string (will be EIP-191 hashed internally)
    # signature — hex-encoded signature, may or may not include 0x prefix,
    #             may include the EIP-6492 magic-suffix wrapper
    # Returns true (valid) or false (validator returned non-1).
    # Re-raises Siwe::Error from the rpc client on transport errors.
    def verify(rpc:, address:, message:, signature:) # rubocop:disable Naming/PredicateMethod
      hash_hex = bin_to_hex(eip191_hash(message))
      sig_hex = strip_hex_prefix(signature)

      args = Eth::Abi.encode(
        %w[address bytes32 bytes],
        [address, Eth::Util.hex_to_bin(hash_hex), Eth::Util.hex_to_bin(sig_hex)]
      )
      data = "0x#{Eip6492::VALIDATOR_BYTECODE}#{Eth::Util.bin_to_hex(args)}"

      result = rpc.eth_call(to: nil, data: data)
      result_indicates_valid?(result)
    end

    # Hash a message per EIP-191 (`personal_sign`). Returns binary keccak256.
    def eip191_hash(message)
      prefixed = Eth::Signature.prefix_message(message)
      Eth::Util.keccak256(prefixed)
    end

    # Validator returns 0x01 (possibly zero-padded to 32 bytes) for valid,
    # 0x00 for invalid. The default RPC client strips the 0x prefix; for
    # callers that don't, normalize here.
    def result_indicates_valid?(hex)
      return false if hex.nil?

      hex = strip_hex_prefix(hex.to_s)
      hex.gsub(/\A0+/, "") == "1"
    end

    def strip_hex_prefix(hex)
      hex.start_with?("0x") ? hex[2..] : hex
    end

    def bin_to_hex(bin)
      bin.unpack1("H*")
    end
  end
end
