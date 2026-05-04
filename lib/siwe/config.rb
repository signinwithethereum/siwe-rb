# frozen_string_literal: true

require_relative "adapter"

module Siwe
  # Verification config — pluggable adapter (crypto), RPC URL or RPC client (smart wallet),
  # and optional verification fallback.
  #
  # Set globally via Siwe.configure { |c| ... } or per-call as `verify(config: ...)`.
  class Config
    attr_reader :rpc_url, :rpc, :adapter, :verification_fallback

    def initialize(rpc_url: nil, rpc: nil, adapter: nil, verification_fallback: nil)
      @rpc_url = rpc_url
      @rpc = rpc
      @adapter = adapter || Siwe::Adapter::DEFAULT
      @verification_fallback = verification_fallback
    end

    def to_h
      {
        rpc_url: @rpc_url,
        rpc: @rpc,
        adapter: @adapter,
        verification_fallback: @verification_fallback
      }
    end

    # Mutable struct used inside Siwe.configure { |c| c.rpc_url = ... }.
    # Caller mutates fields, then build returns a frozen Config.
    class Builder
      attr_accessor :rpc_url, :rpc, :adapter, :verification_fallback

      def initialize(rpc_url: nil, rpc: nil, adapter: nil, verification_fallback: nil)
        @rpc_url = rpc_url
        @rpc = rpc
        @adapter = adapter
        @verification_fallback = verification_fallback
      end

      def build
        Config.new(
          rpc_url: @rpc_url,
          rpc: @rpc,
          adapter: @adapter,
          verification_fallback: @verification_fallback
        )
      end
    end
  end
end
