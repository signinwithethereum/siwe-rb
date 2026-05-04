# frozen_string_literal: true

module Siwe
  Response = Data.define(:success, :error, :data) do
    def success?
      success == true
    end

    def failure?
      !success?
    end
  end
end
