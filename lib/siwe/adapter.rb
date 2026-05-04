# frozen_string_literal: true

require "eth"

require_relative "error"
require_relative "error_type"

module Siwe
  module Adapter
    # Default crypto adapter using the eth gem.
    # Implements the SiweConfig interface from the TS reference implementation:
    # verify_message → recover signer address from EIP-191 signed message
    # hash_message → EIP-191 personal_sign hash
    # get_address → normalize to EIP-55 checksum address
    class EthGem
      def verify_message(message, signature)
        public_key = Eth::Signature.personal_recover(message, signature)
        Eth::Util.public_key_to_address(public_key).to_s
      end

      def hash_message(message)
        prefixed = Eth::Signature.prefix_message(message)
        Eth::Util.keccak256(prefixed)
      end

      def get_address(addr)
        Eth::Address.new(addr).to_s
      end
    end

    DEFAULT = EthGem.new
  end
end
