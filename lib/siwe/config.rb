# frozen_string_literal: true

require_relative "adapter"

module Siwe
  # Verification config — pluggable adapter (crypto) plus RPC URL or RPC client
  # for the smart-wallet (ERC-1271 / ERC-6492) verification path.
  #
  # Set globally via Siwe.configure { |c| ... } or per-call as `verify(config: ...)`.
  class Config
    attr_reader :rpc_url, :rpc, :adapter

    def initialize(rpc_url: nil, rpc: nil, adapter: nil)
      @rpc_url = rpc_url
      @rpc = rpc
      @adapter = adapter || Siwe::Adapter::DEFAULT
    end

    def to_h
      { rpc_url: @rpc_url, rpc: @rpc, adapter: @adapter }
    end

    # Mutable struct used inside Siwe.configure { |c| c.rpc_url = ... }.
    # Caller mutates fields, then build returns a frozen Config.
    class Builder
      attr_accessor :rpc_url, :rpc, :adapter

      def initialize(rpc_url: nil, rpc: nil, adapter: nil)
        @rpc_url = rpc_url
        @rpc = rpc
        @adapter = adapter
      end

      def build
        Config.new(rpc_url: @rpc_url, rpc: @rpc, adapter: @adapter)
      end
    end
  end
end
