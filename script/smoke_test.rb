# frozen_string_literal: true

# End-to-end smoke test: runs against the gem as installed from the .gem file
# (no Bundler, no bundle exec). Exits non-zero on any failure.
# Used by the `package` CI job.

require "siwe"

def assert(label, condition, detail = nil)
  if condition
    puts "ok    #{label}"
  else
    suffix = detail ? " — #{detail}" : ""
    puts "FAIL  #{label}#{suffix}"
    exit 1
  end
end

assert "Siwe::VERSION is a string", Siwe::VERSION.is_a?(String)
assert "Siwe.generate_nonce", Siwe.generate_nonce.match?(/\A[a-zA-Z0-9]{17}\z/)

require "eth"
key = Eth::Key.new
msg = Siwe::Message.new(
  domain: "example.com",
  address: key.address.to_s,
  uri: "https://example.com/login",
  chain_id: 1,
  nonce: Siwe.generate_nonce,
  issued_at: Time.now.utc.iso8601,
  statement: "smoke test"
)

text = msg.prepare_message
assert "prepare_message returns String", text.is_a?(String)
assert "prepare_message starts with header", text.start_with?("example.com wants you to sign in")

reparsed = Siwe::Message.parse(text)
assert "parse round-trip equality", reparsed == msg

top_level_parse = Siwe.parse(text)
assert "Siwe.parse top-level alias", top_level_parse == msg

sig = key.personal_sign(text)
response = msg.verify(signature: sig, domain: msg.domain, nonce: msg.nonce)
assert "verify returns Siwe::Response", response.is_a?(Siwe::Response)
assert "verify success", response.success?

bad = msg.verify(signature: sig, domain: "wrong.com", nonce: msg.nonce)
assert "verify mismatch returns failure", bad.failure?
assert "verify mismatch carries Siwe::Error", bad.error.is_a?(Siwe::Error)
assert "verify mismatch type", bad.error.type == :domain_mismatch

eip6492_sig = "0xdead#{Siwe::Eip6492::MAGIC_SUFFIX}"
assert "Siwe::Eip6492.signature?", Siwe::Eip6492.signature?(eip6492_sig)
assert "Siwe.eip6492_signature? top-level alias", Siwe.eip6492_signature?(eip6492_sig)

puts "all smoke tests passed"
