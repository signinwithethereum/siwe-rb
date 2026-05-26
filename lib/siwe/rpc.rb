# frozen_string_literal: true

require "json"
require "net/http"
require "uri"

require_relative "error"
require_relative "error_type"

module Siwe
  module Rpc
    # Minimal JSON-RPC client for eth_call. Default implementation used when
    # Siwe.configure { |c| c.rpc_url = ... } is set. Anything that responds to
    # `eth_call(to:, data:, block:)` (and optionally `chain_id`) can be plugged
    # in via `c.rpc = ...` to use a different transport (web3.rb, eth-rpc, etc.).
    class HttpClient
      attr_reader :url, :timeout

      def initialize(url, chain_id: nil, timeout: 10)
        raise ArgumentError, "rpc url is required" if url.nil? || url.empty?

        @url = url
        @uri = URI(url)
        @chain_id = chain_id
        @timeout = timeout
      end

      # Returns the chain id (Integer). Lazy-fetched via eth_chainId on first call and
      # cached for the lifetime of this client. Raises Siwe::Error :rpc_error on probe
      # failure rather than returning nil — callers in the smart-wallet path rely on
      # this to enforce ERC-4361's chain binding (a silent nil could otherwise validate
      # a signature against the wrong chain).
      def chain_id
        @chain_id ||= fetch_chain_id
      end

      # Send eth_call. Returns the result as a hex string WITHOUT the 0x prefix.
      # When +to+ is nil, omits it from params (used by EIP-6492 deploy-and-call).
      # Raises Siwe::Error :rpc_error on transport / HTTP / JSON-RPC failure.
      def eth_call(to:, data:, block: "latest")
        call_params = { data: data }
        call_params[:to] = to if to
        rpc_request("eth_call", [call_params, block])
      end

      private

      def fetch_chain_id
        rpc_request("eth_chainId", []).to_i(16)
      end

      def rpc_request(method, params)
        body = { jsonrpc: "2.0", id: 1, method: method, params: params }.to_json
        response = post(body)
        parse_response(response)
      end

      def post(body)
        http = Net::HTTP.new(@uri.host, @uri.port)
        http.use_ssl = (@uri.scheme == "https")
        http.open_timeout = @timeout
        http.read_timeout = @timeout

        path = @uri.request_uri
        path = "/" if path.empty?
        request = Net::HTTP::Post.new(path, "Content-Type" => "application/json")
        request.body = body
        http.request(request)
      rescue StandardError => e
        raise Error.new(ErrorType::RPC_ERROR, message: "RPC transport error: #{e.class}: #{e.message}")
      end

      def parse_response(response)
        unless response.is_a?(Net::HTTPSuccess)
          raise Error.new(ErrorType::RPC_ERROR, message: "RPC HTTP #{response.code}: #{response.message}")
        end

        body = JSON.parse(response.body)
        raise Error.new(ErrorType::RPC_ERROR, message: "RPC error: #{body["error"].inspect}") if body["error"]

        result = body["result"]
        raise Error.new(ErrorType::RPC_ERROR, message: "RPC returned no result") if result.nil?

        strip_hex_prefix(result.to_s)
      rescue JSON::ParserError => e
        raise Error.new(ErrorType::RPC_ERROR, message: "Invalid RPC JSON: #{e.message}")
      end

      def strip_hex_prefix(hex)
        hex.start_with?("0x") ? hex[2..] : hex
      end
    end
  end
end
