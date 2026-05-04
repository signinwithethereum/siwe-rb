# frozen_string_literal: true

require_relative "siwe/version"

module Siwe
  autoload :Error,       "siwe/error"
  autoload :ErrorType,   "siwe/error_type"
  autoload :Response,    "siwe/response"
  autoload :Util,        "siwe/util"
  autoload :Parser,      "siwe/parser"
  autoload :Message,     "siwe/message"
  autoload :Config,      "siwe/config"
  autoload :Adapter,     "siwe/adapter"
  autoload :Rpc,         "siwe/rpc"
  autoload :SmartWallet, "siwe/smart_wallet"
  autoload :Eip6492,     "siwe/eip6492"

  class << self
    def configure
      builder = Config::Builder.new(**config.to_h)
      yield(builder) if block_given?
      @config = builder.build.freeze
    end

    def config
      @config ||= Config.new.freeze
    end

    def reset_config!
      @config = nil
    end

    def generate_nonce
      Util.generate_nonce
    end

    # Top-level alias for Siwe::Message.parse — mirrors how the TS package
    # exposes parsing at the package root.
    def parse(str)
      Message.parse(str)
    end

    # Top-level alias for Siwe::Eip6492.signature? — mirrors TS isEIP6492Signature.
    def eip6492_signature?(hex)
      Eip6492.signature?(hex)
    end
  end
end
