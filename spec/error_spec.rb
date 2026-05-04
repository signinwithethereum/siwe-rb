# frozen_string_literal: true

RSpec.describe Siwe::Error do
  it "is a StandardError" do
    expect(described_class.ancestors).to include(StandardError)
  end

  it "constructs from a known type" do
    err = described_class.new(Siwe::ErrorType::EXPIRED_MESSAGE)
    expect(err.type).to eq(:expired_message)
    expect(err.message).to eq("Expired message.")
    expect(err.expected).to be_nil
    expect(err.received).to be_nil
  end

  it "carries expected and received" do
    err = described_class.new(Siwe::ErrorType::DOMAIN_MISMATCH, expected: "a.com", received: "b.com")
    expect(err.expected).to eq("a.com")
    expect(err.received).to eq("b.com")
  end

  it "rejects unknown types" do
    expect { described_class.new(:bogus) }.to raise_error(ArgumentError)
  end

  it "supports custom messages" do
    err = described_class.new(Siwe::ErrorType::INVALID_SIGNATURE, message: "custom")
    expect(err.message).to eq("custom")
  end

  it "exposes to_h" do
    err = described_class.new(Siwe::ErrorType::INVALID_NONCE, expected: "alphanumeric", received: "$$")
    expect(err.to_h).to eq(
      type: :invalid_nonce,
      expected: "alphanumeric",
      received: "$$",
      message: "Nonce size smaller than 8 characters or is not alphanumeric."
    )
  end
end

RSpec.describe Siwe::ErrorType do
  it "defines 27 error types" do
    expect(described_class::ALL.length).to eq(27)
  end

  it "has a message for every type" do
    described_class::ALL.each do |type|
      expect(described_class::MESSAGES[type]).to be_a(String)
    end
  end
end
