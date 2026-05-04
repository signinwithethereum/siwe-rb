# frozen_string_literal: true

RSpec.describe Siwe::Response do
  it "is a Data class with success/error/data" do
    r = described_class.new(success: true, error: nil, data: :stub)
    expect(r.success).to be(true)
    expect(r.error).to be_nil
    expect(r.data).to eq(:stub)
  end

  it "exposes success? and failure?" do
    ok = described_class.new(success: true, error: nil, data: nil)
    bad = described_class.new(success: false, error: :err, data: nil)
    expect(ok).to be_success
    expect(ok).not_to be_failure
    expect(bad).to be_failure
    expect(bad).not_to be_success
  end

  it "is value-equal" do
    a = described_class.new(success: true, error: nil, data: 1)
    b = described_class.new(success: true, error: nil, data: 1)
    expect(a).to eq(b)
  end
end
