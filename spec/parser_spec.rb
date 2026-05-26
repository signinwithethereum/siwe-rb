# frozen_string_literal: true

RSpec.describe Siwe::Parser do
  describe "parsing_positive vectors" do
    load_vectors("parsing", "parsing_positive").each do |name, vec|
      it name do
        result = described_class.parse(vec["message"])
        f = result[:fields]
        expected = vec["fields"]

        expect(f[:domain]).to eq(expected["domain"])
        expect(f[:address]).to eq(expected["address"])
        expect(f[:statement]).to eq(expected["statement"])
        expect(f[:uri]).to eq(expected["uri"])
        expect(f[:version]).to eq(expected["version"])
        expect(f[:chain_id]).to eq(expected["chainId"])
        expect(f[:nonce]).to eq(expected["nonce"])
        expect(f[:issued_at]).to eq(expected["issuedAt"])
        expect(f[:expiration_time]).to eq(expected["expirationTime"])
        expect(f[:not_before]).to eq(expected["notBefore"])
        expect(f[:request_id]).to eq(expected["requestId"])
        expect(f[:resources]).to eq(expected["resources"])
        expect(f[:scheme]).to eq(expected["scheme"])
        expect(result[:warnings]).to be_empty
      end
    end
  end

  describe "parsing_negative vectors" do
    load_vectors("parsing", "parsing_negative").each do |name, message|
      it name do
        expect { described_class.parse(message) }.to raise_error(Siwe::Error)
      end
    end
  end

  describe "parsing_warnings vectors" do
    load_vectors("parsing", "parsing_warnings").each do |name, vec|
      it name do
        result = described_class.parse(vec["message"])
        f = result[:fields]
        expected = vec["fields"]

        expect(f[:address]).to eq(expected["address"])
        expect(result[:warnings].length).to eq(vec["expectedWarnings"])
      end
    end
  end
end

RSpec.describe Siwe::Message do
  describe "round-trip" do
    it "constructs, formats, and re-parses" do
      msg = described_class.new(
        domain: "example.com",
        address: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
        uri: "https://example.com/login",
        chain_id: 1,
        nonce: "abcd1234",
        issued_at: "2024-01-01T00:00:00Z",
        statement: "Hello there"
      )
      reparsed = described_class.parse(msg.prepare_message)
      expect(reparsed).to eq(msg)
    end

    it "supports scheme prefix" do
      msg = described_class.new(
        scheme: "https",
        domain: "example.com",
        address: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
        uri: "https://example.com/login",
        chain_id: 1,
        nonce: "abcd1234",
        issued_at: "2024-01-01T00:00:00Z"
      )
      expect(msg.prepare_message).to start_with("https://example.com wants you to sign in")
      expect(described_class.parse(msg.prepare_message).scheme).to eq("https")
    end

    it "supports resources" do
      msg = described_class.new(
        domain: "example.com",
        address: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
        uri: "https://example.com/login",
        chain_id: 1,
        nonce: "abcd1234",
        issued_at: "2024-01-01T00:00:00Z",
        resources: ["ipfs://Qm123", "https://example.com/r"]
      )
      reparsed = described_class.parse(msg.prepare_message)
      expect(reparsed.resources).to eq(["ipfs://Qm123", "https://example.com/r"])
    end

    it "json round-trip" do
      msg = described_class.new(
        domain: "example.com",
        address: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
        uri: "https://example.com",
        chain_id: 1,
        nonce: "abcd1234",
        issued_at: "2024-01-01T00:00:00Z"
      )
      json = msg.to_json
      restored = described_class.from_json(json)
      expect(restored).to eq(msg)
    end
  end

  describe "objects vectors" do
    load_vectors("objects", "message_objects").each do |name, vec|
      it name do
        msg_data = vec["msg"]
        kwargs = {
          domain: msg_data["domain"],
          address: msg_data["address"],
          uri: msg_data["uri"],
          chain_id: msg_data["chainId"],
          nonce: msg_data["nonce"],
          version: msg_data["version"],
          statement: msg_data["statement"],
          issued_at: msg_data["issuedAt"],
          expiration_time: msg_data["expirationTime"],
          not_before: msg_data["notBefore"],
          request_id: msg_data["requestId"],
          resources: msg_data["resources"]
        }.compact

        if vec["error"] == "none"
          msg = Siwe::Message.new(**kwargs)
          expect(msg.warnings.length).to eq(vec["expectedWarnings"]) if vec["expectedWarnings"]
        else
          expect { Siwe::Message.new(**kwargs) }.to raise_error(Siwe::Error)
        end
      end
    end
  end

  describe "grammar vectors (full-message)" do
    # NOTE: valid_chars / invalid_chars test individual ABNF rules, not full
    # SIWE messages — they're for ABNF-level parsers (the TS siwe-parser package
    # exposes per-rule entry points). Our parser only parses whole messages, so
    # those vectors are out of scope here.
    %w[valid_uris valid_resources valid_specification].each do |file|
      describe file do
        load_vectors("grammar", file).each do |name, vec|
          it name do
            expect { Siwe::Message.parse(vec["msg"]) }.not_to raise_error
          end
        end
      end
    end

    # NOTE: in the shared vector suite, invalid_uris / invalid_resources are stored as
    # `{name: raw_string}` rather than `{name: {msg: ..., ...}}` like the valid ones.
    %w[invalid_uris invalid_resources].each do |file|
      describe file do
        load_vectors("grammar", file).each do |name, msg|
          it name do
            expect { Siwe::Message.parse(msg) }.to raise_error(Siwe::Error)
          end
        end
      end
    end
  end
end
