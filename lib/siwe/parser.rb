# frozen_string_literal: true

require_relative "error"
require_relative "error_type"
require_relative "util"

module Siwe
  # Parser for the EIP-4361 Sign-In with Ethereum message format.
  # Validates structure line-by-line and per-field via ABNF-aligned regexes.
  # Returns a hash of typed fields plus an array of non-fatal warnings.
  class Parser
    HEADER_SUFFIX = " wants you to sign in with your Ethereum account:"
    SCHEME_REGEX  = /\A([A-Za-z][A-Za-z0-9+\-.]*)\z/
    # RFC 3986 authority (without scheme://) — userinfo, host (reg-name/IPv4/IP-literal), port.
    DOMAIN_REGEX  = /\A[A-Za-z0-9\-._~%!$&'()*+,;=:@\[\]]+\z/
    ADDRESS_REGEX = /\A0x[0-9a-fA-F]{40}\z/
    NONCE_REGEX   = /\A[A-Za-z0-9]{8,}\z/
    CHAIN_REGEX   = /\A[0-9]+\z/
    # Statement chars per ABNF: %d32-33 %d35-36 %d38-59 %d61 %d63-64 %d91 %d93 %d95 %d126.
    # Note: explicitly excludes %d34 (") and %d37 (%). Built via Regexp.new to avoid
    # accidental string interpolation of `#$&` inside a regex literal.
    STATEMENT_REGEX = Regexp.new('\A[a-zA-Z0-9 !\x23\x24\x26-\x3B\x3D\x3F\x40\x5B\x5D\x5F\x7E]*\z')
    REQUEST_ID_REGEX = %r{\A[A-Za-z0-9\-._~%!$&'()*+,;=:@/?]*\z}
    URI_REGEX = /\A[A-Za-z][A-Za-z0-9+\-.]*:[^\s]*\z/

    def self.parse(str)
      new(str).parse
    end

    def initialize(str)
      @str = str
      @warnings = []
    end

    def parse # rubocop:disable Metrics/AbcSize, Metrics/MethodLength, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
      raise unable_to_parse("message is not a string") unless @str.is_a?(String)

      lines = @str.split("\n", -1)
      raise unable_to_parse("message too short") if lines.length < 6

      scheme, domain = parse_header(lines[0])
      address = parse_address(lines[1])

      uri_idx = lines.index { |l| l.start_with?("URI: ") }
      raise unable_to_parse("URI: line not found") if uri_idx.nil? || uri_idx < 3

      statement = parse_statement_block(lines[2...uri_idx])

      uri        = parse_field(lines[uri_idx],     "URI: ",       :invalid_uri,             URI_REGEX)
      version    = parse_field(lines[uri_idx + 1], "Version: ",   :invalid_message_version, /\A1\z/)
      chain_str  = parse_field(lines[uri_idx + 2], "Chain ID: ",  :unable_to_parse,         CHAIN_REGEX)
      nonce      = parse_field(lines[uri_idx + 3], "Nonce: ",     :invalid_nonce,           NONCE_REGEX)
      issued_at  = parse_iso_field(lines[uri_idx + 4], "Issued At: ", "issuedAt")

      cursor = uri_idx + 5
      expiration_time = nil
      not_before = nil
      request_id = nil
      resources = nil

      if cursor < lines.length && lines[cursor]&.start_with?("Expiration Time: ")
        expiration_time = parse_iso_field(lines[cursor], "Expiration Time: ", "expirationTime")
        cursor += 1
      end
      if cursor < lines.length && lines[cursor]&.start_with?("Not Before: ")
        not_before = parse_iso_field(lines[cursor], "Not Before: ", "notBefore")
        cursor += 1
      end
      if cursor < lines.length && lines[cursor]&.start_with?("Request ID: ")
        request_id = parse_field(lines[cursor], "Request ID: ", :unable_to_parse, REQUEST_ID_REGEX)
        cursor += 1
      end
      if cursor < lines.length && lines[cursor] == "Resources:"
        cursor += 1
        resources = parse_resources(lines, cursor)
        cursor += resources.length
      end

      validate_trailing(lines, cursor)
      classify_address!(address)

      {
        fields: {
          scheme: scheme,
          domain: domain,
          address: address,
          statement: statement,
          uri: uri,
          version: version,
          chain_id: chain_str.to_i,
          nonce: nonce,
          issued_at: issued_at,
          expiration_time: expiration_time,
          not_before: not_before,
          request_id: request_id,
          resources: resources
        },
        warnings: @warnings
      }
    end

    private

    def parse_header(line) # rubocop:disable Metrics/AbcSize
      raise unable_to_parse("missing header") if line.nil? || line.empty?
      raise unable_to_parse("malformed header") unless line.end_with?(HEADER_SUFFIX)

      prefix = line[0...(line.length - HEADER_SUFFIX.length)]
      raise unable_to_parse("empty domain") if prefix.empty?

      if prefix.include?("://")
        scheme, _, domain = prefix.partition("://")
        raise unable_to_parse("invalid scheme: #{scheme.inspect}") unless SCHEME_REGEX.match?(scheme)
        raise unable_to_parse("empty domain") if domain.empty?
        unless DOMAIN_REGEX.match?(domain)
          raise Error.new(ErrorType::INVALID_DOMAIN, expected: "RFC 3986 authority",
                                                     received: domain)
        end

        [scheme, domain]
      else
        unless DOMAIN_REGEX.match?(prefix)
          raise Error.new(ErrorType::INVALID_DOMAIN, expected: "RFC 3986 authority",
                                                     received: prefix)
        end

        [nil, prefix]
      end
    end

    def parse_address(line)
      raise unable_to_parse("missing address line") if line.nil?
      unless ADDRESS_REGEX.match?(line)
        raise Error.new(ErrorType::INVALID_ADDRESS, expected: "0x + 40 hex chars",
                                                    received: line)
      end

      line
    end

    def classify_address!(address)
      case Util.address_case(address)
      when :checksum, :lower, :upper
        @warnings << "address is not EIP-55 checksummed - #{address}" if Util.address_case(address) != :checksum
      when :invalid_checksum
        raise Error.new(ErrorType::INVALID_ADDRESS, expected: "EIP-55 checksum address",
                                                    received: address)
      else
        raise Error.new(ErrorType::INVALID_ADDRESS, expected: "0x + 40 hex chars",
                                                    received: address)
      end
    end

    def parse_statement_block(stmt_lines)
      case stmt_lines.length
      when 2
        raise unable_to_parse("malformed statement block") unless stmt_lines.all?(&:empty?)

        nil
      when 3
        first, stmt, last = stmt_lines
        raise unable_to_parse("statement must be enclosed by blank lines") unless first.empty? && last.empty?
        raise unable_to_parse("statement must not contain LF") if stmt.include?("\n")
        raise unable_to_parse("statement contains disallowed characters") unless STATEMENT_REGEX.match?(stmt)

        stmt
      else
        raise unable_to_parse("malformed statement block (#{stmt_lines.length} lines)")
      end
    end

    def parse_field(line, prefix, error_type, regex)
      raise unable_to_parse("missing #{prefix.strip}") if line.nil?
      raise unable_to_parse("expected #{prefix.strip} line") unless line.start_with?(prefix)

      value = line[prefix.length..]
      raise Error.new(error_type, expected: prefix.strip, received: value) unless regex.match?(value)

      value
    end

    def parse_iso_field(line, prefix, name)
      value = parse_field(line, prefix, :invalid_time_format, /.+/)
      unless Util.valid_iso8601?(value)
        raise Error.new(ErrorType::INVALID_TIME_FORMAT, expected: "ISO 8601 #{name}", received: value)
      end

      value
    end

    def parse_resources(lines, start_idx)
      idx = start_idx
      out = []
      while idx < lines.length && lines[idx].start_with?("- ")
        uri = lines[idx][2..]
        unless URI_REGEX.match?(uri)
          raise Error.new(ErrorType::INVALID_URI, expected: "RFC 3986 resource URI", received: uri)
        end

        out << uri
        idx += 1
      end
      out
    end

    def validate_trailing(lines, cursor)
      while cursor < lines.length
        unless lines[cursor].empty?
          raise unable_to_parse("trailing content at line #{cursor + 1}: #{lines[cursor].inspect}")
        end

        cursor += 1
      end
    end

    def unable_to_parse(detail)
      Error.new(ErrorType::UNABLE_TO_PARSE, message: "Unable to parse the message: #{detail}")
    end
  end
end
