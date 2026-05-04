# frozen_string_literal: true

require "webmock/rspec"

# `require "webmock/rspec"` calls `WebMock.disable_net_connect!` at load time;
# undo that immediately so live_rpc specs (loaded as siblings) can still hit
# real RPC endpoints. We re-enable WebMock per-example below.
WebMock.allow_net_connect!

RSpec.describe Siwe::Rpc::HttpClient do
  before { WebMock.disable_net_connect! }
  after  { WebMock.allow_net_connect! }
  let(:url) { "https://rpc.example.com/api" }
  let(:client) { described_class.new(url) }

  describe "#eth_call" do
    it "sends a valid JSON-RPC eth_call and returns hex without 0x prefix" do
      stub_request(:post, url)
        .with(body: hash_including(method: "eth_call"))
        .to_return(body: '{"jsonrpc":"2.0","id":1,"result":"0x1626ba7e"}')

      expect(client.eth_call(to: "0xabc", data: "0xdef")).to eq("1626ba7e")
    end

    it "omits `to` for deploy-and-call (EIP-6492 universal validator)" do
      stub_request(:post, url)
        .with do |req|
          parsed = JSON.parse(req.body)
          parsed["method"] == "eth_call" &&
            parsed["params"][0].key?("data") &&
            !parsed["params"][0].key?("to")
        end
        .to_return(body: '{"jsonrpc":"2.0","id":1,"result":"0x01"}')

      expect(client.eth_call(to: nil, data: "0xdeadbeef")).to eq("01")
    end

    it "passes the block parameter (default 'latest')" do
      stub_request(:post, url)
        .with do |req|
          parsed = JSON.parse(req.body)
          parsed["params"][1] == "latest"
        end
        .to_return(body: '{"jsonrpc":"2.0","id":1,"result":"0x1"}')

      client.eth_call(to: "0xabc", data: "0xdef")
    end

    it "raises Siwe::Error :rpc_error on JSON-RPC error field" do
      stub_request(:post, url)
        .to_return(body: '{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"execution reverted"}}')

      expect { client.eth_call(to: "0xabc", data: "0xdef") }
        .to raise_error(Siwe::Error) { |e| expect(e.type).to eq(:rpc_error) }
    end

    it "raises Siwe::Error :rpc_error on non-2xx HTTP response" do
      stub_request(:post, url).to_return(status: 503, body: "Service Unavailable")

      expect { client.eth_call(to: "0xabc", data: "0xdef") }
        .to raise_error(Siwe::Error) { |e| expect(e.type).to eq(:rpc_error) }
    end

    it "raises Siwe::Error :rpc_error on transport failure" do
      stub_request(:post, url).to_raise(Errno::ECONNREFUSED)

      expect { client.eth_call(to: "0xabc", data: "0xdef") }
        .to raise_error(Siwe::Error) { |e| expect(e.type).to eq(:rpc_error) }
    end

    it "raises Siwe::Error :rpc_error on invalid JSON" do
      stub_request(:post, url).to_return(body: "not-json")

      expect { client.eth_call(to: "0xabc", data: "0xdef") }
        .to raise_error(Siwe::Error) { |e| expect(e.type).to eq(:rpc_error) }
    end

    it "preserves the path and query string of the configured URL (e.g. Alchemy)" do
      alchemy_url = "https://eth-mainnet.g.alchemy.com/v2/some-api-key?foo=bar"
      stub_request(:post, alchemy_url)
        .to_return(body: '{"jsonrpc":"2.0","id":1,"result":"0xff"}')

      result = described_class.new(alchemy_url).eth_call(to: "0xabc", data: "0xde")
      expect(result).to eq("ff")
    end
  end

  describe "#chain_id" do
    it "returns the constructor-provided chain_id without making a call" do
      expect(described_class.new(url, chain_id: 137).chain_id).to eq(137)
    end

    it "fetches chain_id lazily via eth_chainId" do
      stub_request(:post, url)
        .with(body: hash_including(method: "eth_chainId"))
        .to_return(body: '{"jsonrpc":"2.0","id":1,"result":"0x1"}')

      expect(client.chain_id).to eq(1)
    end

    it "returns nil when the RPC fails (best-effort)" do
      stub_request(:post, url).to_raise(Errno::ECONNREFUSED)

      expect(client.chain_id).to be_nil
    end
  end

  describe "constructor" do
    it "rejects empty URLs" do
      expect { described_class.new("") }.to raise_error(ArgumentError)
      expect { described_class.new(nil) }.to raise_error(ArgumentError)
    end
  end
end
