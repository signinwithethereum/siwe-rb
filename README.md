# siwe-rb

Sign-In with Ethereum (EIP-4361) for Ruby — message construction, parsing, and signature verification, with built-in support for ERC-1271 and EIP-6492 smart contract wallets.

`siwe-rb` is the Ruby companion to the [TypeScript](https://github.com/signinwithethereum/siwe), [Python](https://github.com/signinwithethereum/siwe-py), and [Rust](https://github.com/signinwithethereum/siwe-rs) implementations under the [@signinwithethereum](https://github.com/signinwithethereum) organisation. It runs against the same shared test-vector suite.

## Installation

```ruby
# Gemfile
gem "siwe-rb", "~> 0.1"
```

```ruby
require "siwe"
```

Requires Ruby ≥ 3.3.

## Usage

### Construct and sign a message

```ruby
require "siwe"
require "eth"

key = Eth::Key.new

message = Siwe::Message.new(
  domain:     "example.com",
  address:    key.address.to_s,
  uri:        "https://example.com/login",
  chain_id:   1,
  nonce:      Siwe.generate_nonce,
  issued_at:  Time.now.utc.iso8601,
  statement:  "Sign in to example.com"
)

text      = message.prepare_message  # → EIP-4361 message string
signature = key.personal_sign(text)
```

### Parse a message

```ruby
message = Siwe::Message.parse(text)
message.domain    # => "example.com"
message.address   # => "0x..."
message.warnings  # => [] (e.g. ["address is not EIP-55 checksummed - 0x…"])
```

### Verify a signature

`verify` returns a `Siwe::Response`; `verify!` raises a `Siwe::Error` on failure.

```ruby
response = message.verify(
  signature: signature,
  domain:    "example.com",
  nonce:     message.nonce
)

if response.success?
  # signed in
else
  Rails.logger.warn("siwe failed: #{response.error.type}")
end

# or, idiomatic Ruby:
message.verify!(signature: signature, domain: "example.com", nonce: message.nonce)
```

### Smart-wallet support (ERC-1271, EIP-6492)

Configure an Ethereum RPC URL once at boot, and `verify` will automatically fall through to a single deploy-and-call against the EIP-6492 universal validator when EOA recovery fails. This handles both deployed ERC-1271 wallets (e.g. Safe) and counterfactual EIP-6492-wrapped signatures (e.g. Coinbase Smart Wallet) in one call.

```ruby
Siwe.configure do |c|
  c.rpc_url = ENV["ETH_RPC_URL"]   # e.g. https://ethereum-rpc.publicnode.com
end

message.verify!(signature: sig, domain: "example.com", nonce: message.nonce)
```

You can also pass an RPC client per call, or inject your own client (anything responding to `eth_call(to:, data:, block:)`):

```ruby
custom_rpc = MyOwnRpcClient.new(...)
config     = Siwe::Config.new(rpc: custom_rpc)
message.verify!(signature: sig, domain: domain, nonce: nonce, config: config)
```

### Error handling

All failures raise (or, for `verify`, surface as `response.error`) a single `Siwe::Error` carrying a `type` symbol from `Siwe::ErrorType`:

```ruby
begin
  message.verify!(signature: sig, domain: domain, nonce: nonce)
rescue Siwe::Error => e
  case e.type
  when :expired_message       then render_expired
  when :nonce_mismatch        then render_replay
  when :invalid_signature     then render_unauthorized
  when :rpc_error             then retry_or_fail
  else                             render_generic_error
  end
end
```

The full set of error types mirrors `SiweErrorType` in the TypeScript reference (27 codes including the Ruby-specific `:rpc_error`). See `lib/siwe/error_type.rb`.

## Comparison with the TypeScript implementation

| Feature                            | TS            | Ruby           |
| ---------------------------------- | ------------- | -------------- |
| EIP-4361 v1 parsing & rendering    | ✓             | ✓              |
| Optional `scheme` field            | ✓             | ✓              |
| EIP-55 checksum + warning          | ✓             | ✓              |
| 17-char alphanumeric nonce         | ✓             | ✓              |
| `verify` / response object         | Promise       | sync `Response`|
| EOA verification                   | ✓             | ✓              |
| ERC-1271 verification              | ✓ (via viem)  | ✓ (built-in)   |
| EIP-6492 verification              | ✓ (via viem)  | ✓ (built-in)   |
| Pluggable provider                 | viem / ethers | duck-typed RPC |
| Shared test-vector suite           | ✓             | ✓              |
| CI matrix                          | -             | Ruby 3.3 / 3.4 |

## Development

```bash
git submodule update --init    # pulls in the shared test-vectors repo
bundle install
bundle exec rake               # runs rspec + rubocop

# Live RPC integration tests (Argent, Loopring, EIP-6492 universal validator):
SIWE_RPC_URL=https://ethereum-rpc.publicnode.com bundle exec rspec --tag live_rpc
```

## License

MIT.
