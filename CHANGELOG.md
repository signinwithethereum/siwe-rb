# Changelog

## [0.2.0] — 2026-05-26

Spec-conformance pass. Several behaviour changes; the only one that breaks API contract is the strict chain-id requirement on the smart-wallet path (3).

1. **RFC 3986 enforcement for `domain`, `URI`, and resource URIs.** The previous regexes accepted malformed authorities (`example.com:abc`), IP-literal hosts with invalid IPv4 octets (`uri://[::0.0.0.256]/p`), and URI characters outside RFC 3986 (`https://example.com/path?q=one|two`). The shared test-vector suite's `invalid_uris` / `invalid_resources` grammar cases were silently passing because the spec wrapper called `vec["msg"]` on raw-string entries; both the parser and the spec are fixed.
2. **Expiration boundary now matches sibling implementations.** A message is rejected at the exact `Expiration Time` (not one instant after), aligning with TypeScript / Python / Rust.
3. **Smart-wallet chain binding is enforced, not best-effort.** ERC-4361 requires ERC-1271 verification to happen on the chain matching the message's `Chain ID`. Previously, an RPC that lacked `chain_id` or whose `eth_chainId` probe failed would silently skip the check. Now `:invalid_signature_chain_id` is raised in either case. **Breaking** for callers using a custom RPC client without a `chain_id` method, or relying on `chain_id` returning `nil` on probe failure.
4. **`request-id` field tightened to `*pchar`.** The parser previously accepted `/` and `?` (ABNF query/fragment characters) which are not pchar.
5. **Empty / nil signatures now raise `:invalid_params`** instead of `:invalid_signature` — same `Siwe::Error` class, more specific type.
6. **Narrower `rescue` in EOA recovery.** Adapter misconfiguration no longer disappears behind `:invalid_signature`; only `eth`-gem signature/chain errors and arg/type errors are swallowed.
7. **Removed unused public surface.** `Config#verification_fallback`, `Eip6492::EIP1271_MAGIC_VALUE`, and `Adapter::EthGem#{hash_message,get_address}` are gone. None were called anywhere.

## [0.1.2] — 2026-05-04

- Add top-level convenience methods `Siwe.parse(str)` (alias for `Siwe::Message.parse`) and `Siwe.eip6492_signature?(hex)` (alias for `Siwe::Eip6492.signature?`), mirroring the TS package's root-level exports.
- New CI `package` job: builds and installs the gem from a `.gem` file, then runs `script/smoke_test.rb` in a fresh Ruby process. Catches packaging issues (missing files, autoload typos) that in-tree specs miss.
- Wire up SimpleCov in `spec_helper.rb` (branch coverage enabled). Set `SIWE_SKIP_COVERAGE=1` to disable.
- Bump GitHub Actions `actions/checkout` v4 → v5 to silence Node.js 20 deprecation warnings.
- Update gemspec author metadata.

## [0.1.1] — 2026-05-04

- Bump minimum Ruby to 3.3. RuboCop's transitive dep `parallel` 2.1+ requires Ruby ≥ 3.3, so 3.2 can no longer pass the gem's own CI; Ruby 3.2 went EOL in March 2026 anyway. Runtime users on 3.2 can stay on 0.1.0 — the only runtime dep (`eth`) still supports 3.2.
- CI matrix dropped 3.2; now runs on Ruby 3.3 and 3.4.

## [0.1.0] — 2026-05-04

Initial release of `siwe-rb`. Hard fork of the abandoned `siwe` gem (last published 0.1.0, 2021).

- Modern Ruby (≥ 3.3), no Ruby 2.x cruft.
- ABNF-aligned EIP-4361 parser; passes the shared `@signinwithethereum/test-vectors` suite (parsing, grammar, objects, verification).
- 17-character alphanumeric nonce, matching the TypeScript reference (`Siwe.generate_nonce`).
- Optional `scheme` field for `https://`-prefixed messages (ERC-4361 erratum).
- Single structured `Siwe::Error` with 27 typed error codes (`Siwe::ErrorType`) and `expected:` / `received:` context, replacing the legacy one-class-per-error layout.
- `Siwe::Response` value object returned by `Message#verify`; `Message#verify!` raises on failure for the common Rails-controller path.
- ERC-1271 + EIP-6492 smart-wallet support via the off-chain universal validator (single `eth_call` covers deployed wallets like Safe and counterfactual wallets like Coinbase Smart Wallet).
- Built-in `Siwe::Rpc::HttpClient` (Net::HTTP-based JSON-RPC) plus a duck-typed plug-in surface — drop in `web3.rb`, `eth-rpc`, or any object responding to `eth_call(to:, data:, block:)`.
- Pluggable `Siwe::Adapter` (defaults to the `eth` gem) for crypto / signature recovery.
- Modern toolchain: RuboCop, RSpec, WebMock, GitHub Actions matrix on Ruby 3.3 / 3.4, optional gated live-RPC integration job.
