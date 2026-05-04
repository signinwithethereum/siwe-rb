# Changelog

## [0.1.0] — 2026-05-04

Initial release of `siwe-rb`. Hard fork of the abandoned `siwe` gem (last published 0.1.0, 2021).

- Modern Ruby (≥ 3.2), no Ruby 2.x cruft.
- ABNF-aligned EIP-4361 parser; passes the shared `@signinwithethereum/test-vectors` suite (parsing, grammar, objects, verification).
- 17-character alphanumeric nonce, matching the TypeScript reference (`Siwe.generate_nonce`).
- Optional `scheme` field for `https://`-prefixed messages (ERC-4361 erratum).
- Single structured `Siwe::Error` with 27 typed error codes (`Siwe::ErrorType`) and `expected:` / `received:` context, replacing the legacy one-class-per-error layout.
- `Siwe::Response` value object returned by `Message#verify`; `Message#verify!` raises on failure for the common Rails-controller path.
- ERC-1271 + EIP-6492 smart-wallet support via the off-chain universal validator (single `eth_call` covers deployed wallets like Safe and counterfactual wallets like Coinbase Smart Wallet).
- Built-in `Siwe::Rpc::HttpClient` (Net::HTTP-based JSON-RPC) plus a duck-typed plug-in surface — drop in `web3.rb`, `eth-rpc`, or any object responding to `eth_call(to:, data:, block:)`.
- Pluggable `Siwe::Adapter` (defaults to the `eth` gem) for crypto / signature recovery.
- Modern toolchain: RuboCop, RSpec, WebMock, GitHub Actions matrix on Ruby 3.2 / 3.3 / 3.4, optional gated live-RPC integration job.
