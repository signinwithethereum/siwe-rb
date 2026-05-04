# frozen_string_literal: true

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
  end
end
