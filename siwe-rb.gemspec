# frozen_string_literal: true

require_relative "lib/siwe/version"

Gem::Specification.new do |spec|
  spec.name    = "siwe-rb"
  spec.version = Siwe::VERSION
  spec.authors = ["EthID.org"]
  spec.email   = ["jalil@ethfollow.xyz"]

  spec.summary = "Sign-In with Ethereum (EIP-4361) for Ruby"
  spec.description = "EIP-4361 message construction, parsing, and signature verification, " \
                     "with built-in support for ERC-1271 and EIP-6492 smart contract wallets."
  spec.homepage    = "https://github.com/signinwithethereum/siwe-rb"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.3"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").reject do |f|
      f == __FILE__ ||
        f.start_with?("spec/", "test/", "features/", "bin/", "gems/", "script/") ||
        f.match?(/\A\.(?:git|github|rubocop|ruby-version|rspec)/)
    end
  end
  spec.require_paths = ["lib"]

  spec.add_dependency "eth", ">= 0.5.11", "< 1.0"
end
