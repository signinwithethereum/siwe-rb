# frozen_string_literal: true

RSpec.describe Siwe::Util do
  describe ".generate_nonce" do
    it "returns a 17-char alphanumeric string" do
      n = described_class.generate_nonce
      expect(n).to match(/\A[a-zA-Z0-9]{17}\z/)
    end

    it "produces unique values across calls" do
      nonces = Array.new(50) { described_class.generate_nonce }
      expect(nonces.uniq.length).to eq(50)
    end
  end

  describe ".valid_iso8601?" do
    it "accepts canonical UTC timestamps" do
      expect(described_class.valid_iso8601?("2022-03-17T12:45:13.610Z")).to be(true)
      expect(described_class.valid_iso8601?("2022-03-17T12:45:13Z")).to be(true)
    end

    it "accepts non-UTC timezones" do
      expect(described_class.valid_iso8601?("2021-09-30T16:25:24-02:00")).to be(true)
    end

    it "rejects non-ISO formats" do
      expect(described_class.valid_iso8601?("Wed Oct 05 2011 16:48:00 GMT+0200 (CEST)")).to be(false)
      expect(described_class.valid_iso8601?("not a date")).to be(false)
      expect(described_class.valid_iso8601?("")).to be(false)
      expect(described_class.valid_iso8601?(nil)).to be(false)
    end

    it "rejects impossible dates" do
      expect(described_class.valid_iso8601?("2022-13-01T00:00:00Z")).to be(false)
      expect(described_class.valid_iso8601?("2022-02-30T00:00:00Z")).to be(false)
    end
  end

  describe ".valid_address?" do
    it "accepts valid checksum addresses" do
      expect(described_class.valid_address?("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")).to be(true)
    end

    it "accepts all-lowercase and all-uppercase" do
      expect(described_class.valid_address?("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2")).to be(true)
      expect(described_class.valid_address?("0xC02AAA39B223FE8D0A0E5C4F27EAD9083C756CC2")).to be(true)
    end

    it "rejects invalid checksums" do
      expect(described_class.valid_address?("0xC02aaa39b223FE8D0A0e5C4F27eAD9083C756Cc2")).to be(false)
    end

    it "rejects bad shapes" do
      expect(described_class.valid_address?("not an address")).to be(false)
      expect(described_class.valid_address?("")).to be(false)
      expect(described_class.valid_address?(nil)).to be(false)
    end
  end

  describe ".address_case" do
    it "classifies all-lowercase" do
      expect(described_class.address_case("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2")).to eq(:lower)
    end

    it "classifies all-uppercase" do
      expect(described_class.address_case("0xC02AAA39B223FE8D0A0E5C4F27EAD9083C756CC2")).to eq(:upper)
    end

    it "classifies valid EIP-55 checksum" do
      expect(described_class.address_case("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")).to eq(:checksum)
    end

    it "classifies invalid checksum" do
      expect(described_class.address_case("0xC02aaa39b223FE8D0A0e5C4F27eAD9083C756Cc2")).to eq(:invalid_checksum)
    end

    it "rejects bad shapes" do
      expect(described_class.address_case("nope")).to eq(:invalid)
    end
  end

  describe ".checksum_address" do
    it "normalizes to EIP-55" do
      checksummed = described_class.checksum_address("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2")
      expect(checksummed).to eq("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
    end

    it "returns nil for invalid input" do
      expect(described_class.checksum_address("nope")).to be_nil
    end
  end
end
