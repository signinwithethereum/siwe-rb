# frozen_string_literal: true

require "eth"

require_relative "error"
require_relative "error_type"

module Siwe
  module Adapter
    # Default crypto adapter using the eth gem. The verification path only needs
    # signer recovery — any object implementing `#verify_message(message, signature)`
    # returning the recovered EIP-55 address can be plugged in via Config.new(adapter:).
    class EthGem
      def verify_message(message, signature)
        public_key = Eth::Signature.personal_recover(message, signature)
        Eth::Util.public_key_to_address(public_key).to_s
      end
    end

    DEFAULT = EthGem.new
  end
end
