# frozen_string_literal: true

require "ipaddr"
require "securerandom"
require "time"
require "date"
require "eth"

module Siwe
  module Util
    module_function

    NONCE_LENGTH = 17

    ISO8601_REGEX = /
      \A
      (?<date>\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01]))
      [Tt]
      (?:[01]\d|2[0-3]):
      [0-5]\d:
      (?:[0-5]\d|60)
      (?:\.\d+)?
      (?:[Zz]|[+-](?:[01]\d|2[0-3]):[0-5]\d)
      \z
    /x

    # Character classes per RFC 3986. Anything outside these is rejected.
    # unreserved + sub-delims + pct-encoded marker, used in reg-name.
    HOST_CHAR_REGEX     = /\A(?:[A-Za-z0-9\-._~!$&'()*+,;=]|%[0-9A-Fa-f]{2})*\z/
    USERINFO_CHAR_REGEX = /\A(?:[A-Za-z0-9\-._~!$&'()*+,;=:]|%[0-9A-Fa-f]{2})*\z/
    # pchar = unreserved / pct-encoded / sub-delims / ":" / "@". Used for request-id
    # (ABNF "request-id = *pchar") and segments within a path.
    PCHAR_REGEX = /\A(?:[A-Za-z0-9\-._~!$&'()*+,;=:@]|%[0-9A-Fa-f]{2})*\z/
    # path = *( pchar / "/" ). No "?" or "#".
    PATH_REGEX = %r{\A(?:[A-Za-z0-9\-._~!$&'()*+,;=:@/]|%[0-9A-Fa-f]{2})*\z}
    # query / fragment = *( pchar / "/" / "?" ).
    QUERY_FRAGMENT_REGEX = %r{\A(?:[A-Za-z0-9\-._~!$&'()*+,;=:@/?]|%[0-9A-Fa-f]{2})*\z}
    PORT_REGEX   = /\A\d*\z/
    SCHEME_REGEX = /\A[A-Za-z][A-Za-z0-9+\-.]*\z/

    def generate_nonce
      SecureRandom.alphanumeric(NONCE_LENGTH)
    end

    def valid_iso8601?(str)
      return false if str.nil? || str.empty?

      m = ISO8601_REGEX.match(str)
      return false if m.nil?

      year, month, day = m[:date].split("-").map(&:to_i)
      return false unless Date.valid_date?(year, month, day)

      Time.iso8601(str)
      true
    rescue ArgumentError
      false
    end

    def valid_address?(addr)
      return false if addr.nil? || addr.empty?

      Eth::Address.new(addr)
      true
    rescue StandardError
      false
    end

    def address_case(addr)
      return :invalid unless addr.is_a?(String) && addr.match?(/\A0x[0-9a-fA-F]{40}\z/)

      hex = addr[2..]
      return :lower if hex == hex.downcase
      return :upper if hex == hex.upcase

      eip55 = checksum_address(addr)
      eip55 == addr ? :checksum : :invalid_checksum
    end

    def checksum_address(addr)
      Eth::Address.new(addr).to_s
    rescue StandardError
      nil
    end

    # Validate an RFC 3986 authority: [userinfo "@"] host [":" port].
    # Used for both the SIWE `domain` field and any URI's authority component.
    # Empty authority is valid (empty reg-name).
    def valid_authority?(str)
      return false if str.nil?
      return true if str.empty?

      userinfo, host_port = str.include?("@") ? str.split("@", 2) : [nil, str]
      return false if userinfo && !USERINFO_CHAR_REGEX.match?(userinfo)

      host, port = split_host_port(host_port)
      return false if host.nil?
      return false if port && !PORT_REGEX.match?(port)

      valid_host?(host)
    end

    # Validate an absolute RFC 3986 URI: scheme ":" hier-part [ "?" query ] [ "#" fragment ].
    def valid_uri?(str)
      return false if str.nil? || str.empty?

      scheme, rest = str.split(":", 2)
      return false if rest.nil?
      return false unless SCHEME_REGEX.match?(scheme)

      m = rest.match(/\A(?<hier>[^?#]*)(?:\?(?<query>[^#]*))?(?:\#(?<frag>.*))?\z/)
      return false if m.nil?
      return false unless valid_hier_part?(m[:hier])
      return false if m[:query] && !QUERY_FRAGMENT_REGEX.match?(m[:query])
      return false if m[:frag]  && !QUERY_FRAGMENT_REGEX.match?(m[:frag])

      true
    end

    # host = IP-literal / IPv4address / reg-name. Distinguishes by leading "[".
    def valid_host?(host)
      if host.start_with?("[") && host.end_with?("]")
        valid_ip_literal?(host[1..-2])
      else
        HOST_CHAR_REGEX.match?(host)
      end
    end

    # IP-literal = IPv6address / IPvFuture (latter is rare and unused in SIWE — reject).
    def valid_ip_literal?(content)
      return false if content.nil? || content.empty?
      return false if content.start_with?("v", "V") # IPvFuture not supported

      ipv6 = content
      if content.include?(".")
        last_colon = content.rindex(":")
        return false if last_colon.nil?

        ipv4 = content[(last_colon + 1)..]
        return false unless valid_dotted_ipv4?(ipv4)

        # IPAddr rejects leading zeros in IPv4 octets ("zero-filled ambiguous"), but the
        # SIWE test vectors treat them as valid. Rewrite the IPv4 tail as two h16 groups.
        octets = ipv4.split(".").map(&:to_i)
        g1 = format("%x", (octets[0] << 8) | octets[1])
        g2 = format("%x", (octets[2] << 8) | octets[3])
        ipv6 = "#{content[0..last_colon]}#{g1}:#{g2}"
      end

      IPAddr.new(ipv6).ipv6?
    rescue IPAddr::InvalidAddressError
      false
    end

    def valid_dotted_ipv4?(addr)
      octets = addr.split(".", -1)
      return false unless octets.length == 4

      octets.all? { |o| o.match?(/\A\d{1,3}\z/) && o.to_i <= 255 }
    end

    def split_host_port(str)
      if str.start_with?("[")
        close = str.index("]")
        return [nil, nil] if close.nil?

        host = str[0..close]
        rest = str[(close + 1)..]
        if rest.empty?
          [host, nil]
        elsif rest.start_with?(":")
          [host, rest[1..]]
        else
          [nil, nil]
        end
      elsif (colon = str.rindex(":"))
        [str[0...colon], str[(colon + 1)..]]
      else
        [str, nil]
      end
    end

    def valid_hier_part?(hier)
      if hier.start_with?("//")
        rest = hier[2..]
        authority_end = rest.index("/") || rest.length
        valid_authority?(rest[0...authority_end]) && PATH_REGEX.match?(rest[authority_end..])
      else
        PATH_REGEX.match?(hier)
      end
    end
  end
end
