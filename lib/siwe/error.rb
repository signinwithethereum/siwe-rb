# frozen_string_literal: true

require_relative "error_type"

module Siwe
  class Error < StandardError
    attr_reader :type, :expected, :received

    def initialize(type, expected: nil, received: nil, message: nil)
      raise ArgumentError, "unknown SIWE error type: #{type.inspect}" unless ErrorType::MESSAGES.key?(type)

      @type = type
      @expected = expected
      @received = received
      super(message || ErrorType::MESSAGES.fetch(type))
    end

    def to_h
      { type: @type, expected: @expected, received: @received, message: message }
    end
  end
end
