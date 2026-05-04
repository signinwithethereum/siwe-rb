# frozen_string_literal: true

require "json"
require "time"

require_relative "error"
require_relative "error_type"
require_relative "parser"
require_relative "response"
require_relative "util"

module Siwe
  # An EIP-4361 Sign-In with Ethereum message.
  # Construct via `Siwe::Message.new(**fields)` or parse via `Siwe::Message.parse(string)`.
  # Render via `#prepare_message` (alias `#to_eip4361`, `#to_s`).
  class Message
    FIELDS = %i[
      scheme domain address statement uri version chain_id nonce
      issued_at expiration_time not_before request_id resources
    ].freeze

    attr_reader(*FIELDS, :warnings)

    def self.parse(str)
      result = Parser.parse(str)
      msg = allocate
      msg.send(:init_from_parser, result)
      msg
    end

    def self.from_json(json_str)
      data = JSON.parse(json_str, symbolize_names: true)
      new(**data.slice(*FIELDS))
    rescue JSON::ParserError => e
      raise Error.new(ErrorType::UNABLE_TO_PARSE, message: "Invalid JSON: #{e.message}")
    end

    def initialize(domain:, address:, uri:, chain_id:, nonce: nil, version: "1",
                   scheme: nil, statement: nil, issued_at: nil,
                   expiration_time: nil, not_before: nil, request_id: nil, resources: nil)
      @warnings = []
      @scheme = scheme
      @domain = domain
      @address = normalize_address(address)
      @statement = statement
      @uri = uri
      @version = version
      @chain_id = coerce_chain_id(chain_id)
      @nonce = nonce || Util.generate_nonce
      @issued_at = issued_at || Time.now.utc.iso8601
      @expiration_time = expiration_time
      @not_before = not_before
      @request_id = request_id
      @resources = resources

      validate_required!
      roundtrip_validate!
      freeze
    end

    def prepare_message
      header_prefix = @scheme ? "#{@scheme}://#{@domain}" : @domain
      header = "#{header_prefix} wants you to sign in with your Ethereum account:"

      prefix = "#{header}\n#{@address}"
      prefix = if @statement.nil?
                 "#{prefix}\n\n"
               else
                 "#{prefix}\n\n#{@statement}\n"
               end

      suffix = "URI: #{@uri}\nVersion: #{@version}\nChain ID: #{@chain_id}"
      suffix << "\nNonce: #{@nonce}"
      suffix << "\nIssued At: #{@issued_at}" if @issued_at
      suffix << "\nExpiration Time: #{@expiration_time}" if @expiration_time
      suffix << "\nNot Before: #{@not_before}" if @not_before
      suffix << "\nRequest ID: #{@request_id}" unless @request_id.nil?
      if @resources
        suffix << "\nResources:"
        @resources.each { |r| suffix << "\n- #{r}" }
      end

      "#{prefix}\n#{suffix}"
    end

    alias to_eip4361 prepare_message
    alias to_s prepare_message

    # Verify a signature against this message and the verification params.
    # Returns Siwe::Response — never raises on verification failure.
    def verify(signature:, domain:, nonce:, scheme: nil, uri: nil, chain_id: nil,
               request_id: nil, time: nil, config: nil, strict: false)
      cfg = config || Siwe.config

      check_param_mismatches!(domain: domain, nonce: nonce, scheme: scheme,
                              uri: uri, chain_id: chain_id, request_id: request_id, strict: strict)
      check_temporal!(time)
      check_signature!(signature, cfg)

      Response.new(success: true, error: nil, data: self)
    rescue Error => e
      Response.new(success: false, error: e, data: self)
    end

    # Verify a signature; raises Siwe::Error on failure, returns self on success.
    def verify!(**)
      response = verify(**)
      raise response.error if response.failure?

      self
    end

    def to_h
      FIELDS.to_h { |f| [f, instance_variable_get("@#{f}")] }
    end

    def to_json(*)
      to_h.to_json(*)
    end

    def ==(other)
      other.is_a?(Message) && to_h == other.to_h
    end
    alias eql? ==

    def hash
      to_h.hash
    end

    private

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity, Metrics/AbcSize
    def check_param_mismatches!(domain:, nonce:, scheme:, uri:, chain_id:, request_id:, strict:)
      raise Error.new(ErrorType::MISSING_DOMAIN) if domain.nil? || domain.empty?
      raise Error.new(ErrorType::MISSING_NONCE) if nonce.nil? || nonce.empty?

      raise Error.new(ErrorType::DOMAIN_MISMATCH, expected: @domain, received: domain) if @domain != domain
      if scheme && @scheme != scheme
        raise Error.new(ErrorType::SCHEME_MISMATCH, expected: @scheme.to_s, received: scheme)
      end
      raise Error.new(ErrorType::NONCE_MISMATCH, expected: @nonce, received: nonce) if @nonce != nonce

      raise Error.new(ErrorType::MISSING_URI) if strict && uri.nil?
      raise Error.new(ErrorType::URI_MISMATCH, expected: @uri, received: uri) if uri && @uri != uri

      raise Error.new(ErrorType::MISSING_CHAIN_ID) if strict && chain_id.nil?
      if chain_id && @chain_id != chain_id
        raise Error.new(ErrorType::CHAIN_ID_MISMATCH, expected: @chain_id.to_s, received: chain_id.to_s)
      end

      return unless request_id && @request_id != request_id

      raise Error.new(ErrorType::REQUEST_ID_MISMATCH, expected: @request_id.to_s, received: request_id.to_s)
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity, Metrics/AbcSize

    def check_temporal!(time_str)
      check_at = time_str ? Time.iso8601(time_str) : Time.now.utc
      if @expiration_time && Time.iso8601(@expiration_time) < check_at
        raise Error.new(ErrorType::EXPIRED_MESSAGE, expected: @expiration_time, received: check_at.iso8601)
      end
      return unless @not_before && Time.iso8601(@not_before) > check_at

      raise Error.new(ErrorType::NOT_YET_VALID_MESSAGE, expected: @not_before, received: check_at.iso8601)
    rescue ArgumentError => e
      raise Error.new(ErrorType::INVALID_TIME_FORMAT, message: e.message)
    end

    def check_signature!(signature, cfg)
      if signature.nil? || signature.empty?
        raise Error.new(ErrorType::INVALID_SIGNATURE, expected: "non-empty signature", received: signature.inspect)
      end

      recovered = recover_eoa(signature, cfg)
      return if recovered && recovered.downcase == @address.downcase

      # EOA recovery failed or address mismatch — try smart-wallet path if configured.
      return if smart_wallet_valid?(signature, cfg)

      raise Error.new(ErrorType::INVALID_SIGNATURE, expected: @address, received: recovered.to_s)
    end

    def recover_eoa(signature, cfg)
      cfg.adapter.verify_message(prepare_message, signature)
    rescue StandardError
      nil
    end

    def smart_wallet_valid?(signature, cfg)
      rpc = resolve_rpc(cfg)
      return false if rpc.nil?

      check_chain_id_match!(rpc)
      SmartWallet.verify(rpc: rpc, address: @address, message: prepare_message, signature: signature)
    end

    def resolve_rpc(cfg)
      return cfg.rpc if cfg.rpc
      return Rpc::HttpClient.new(cfg.rpc_url) if cfg.rpc_url

      nil
    end

    def check_chain_id_match!(rpc)
      return unless rpc.respond_to?(:chain_id)

      rpc_chain = rpc.chain_id
      return if rpc_chain.nil? || rpc_chain == @chain_id

      raise Error.new(ErrorType::INVALID_SIGNATURE_CHAIN_ID,
                      expected: @chain_id.to_s, received: rpc_chain.to_s)
    end

    def init_from_parser(result)
      result[:fields].each { |k, v| instance_variable_set("@#{k}", v) }
      @warnings = result[:warnings]
      freeze
    end

    def normalize_address(addr)
      raise Error.new(ErrorType::INVALID_ADDRESS, expected: "valid EIP-55 address", received: addr.to_s) if addr.nil?

      case Util.address_case(addr)
      when :checksum
        addr
      when :lower, :upper
        @warnings << "address is not EIP-55 checksummed - #{addr}"
        Util.checksum_address(addr) || addr
      when :invalid_checksum
        raise Error.new(ErrorType::INVALID_ADDRESS, expected: "valid EIP-55 address", received: addr)
      else
        raise Error.new(ErrorType::INVALID_ADDRESS, expected: "0x + 40 hex chars", received: addr.to_s)
      end
    end

    def coerce_chain_id(value)
      case value
      when Integer then value
      when String
        unless value.match?(/\A\d+\z/)
          raise Error.new(ErrorType::UNABLE_TO_PARSE, expected: "integer chain ID", received: value)
        end

        value.to_i
      else
        raise Error.new(ErrorType::UNABLE_TO_PARSE, expected: "integer chain ID", received: value.inspect)
      end
    end

    def validate_required!
      if @domain.nil? || @domain.to_s.empty?
        raise Error.new(ErrorType::INVALID_DOMAIN, expected: "non-empty domain",
                                                   received: @domain.inspect)
      end
      if @uri.nil? || @uri.to_s.empty?
        raise Error.new(ErrorType::INVALID_URI, expected: "non-empty URI",
                                                received: @uri.inspect)
      end
      unless @version == "1"
        raise Error.new(ErrorType::INVALID_MESSAGE_VERSION, expected: "1",
                                                            received: @version.to_s)
      end
      return if Parser::NONCE_REGEX.match?(@nonce.to_s)

      raise Error.new(ErrorType::INVALID_NONCE, expected: "alphanumeric 8+ chars",
                                                received: @nonce.to_s)
    end

    def roundtrip_validate!
      Parser.parse(prepare_message)
    rescue Error => e
      raise Error.new(e.type, expected: e.expected, received: e.received,
                              message: "Constructed message fails to parse: #{e.message}")
    end
  end
end
