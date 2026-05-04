# frozen_string_literal: true

# SimpleCov must start before requiring the gem so its methods are instrumented.
unless ENV["SIWE_SKIP_COVERAGE"]
  require "simplecov"
  SimpleCov.start do
    enable_coverage :branch
    add_filter "/spec/"
  end
end

require "json"
require "siwe"

VECTORS_DIR = File.expand_path("test-vectors/vectors", __dir__)

def load_vectors(category, file)
  path = File.join(VECTORS_DIR, category, "#{file}.json")
  unless File.exist?(path)
    warn "[siwe] test vectors not found at #{path} — run `git submodule update --init`"
    return {}
  end
  JSON.parse(File.read(path))
end

RSpec.configure do |config|
  config.example_status_persistence_file_path = ".rspec_status"
  config.disable_monkey_patching!
  config.expect_with(:rspec) { |c| c.syntax = :expect }
  config.filter_run_excluding(:live_rpc) unless ENV["SIWE_RPC_URL"]
end
