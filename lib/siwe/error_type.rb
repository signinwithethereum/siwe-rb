# frozen_string_literal: true

module Siwe
  module ErrorType
    EXPIRED_MESSAGE            = :expired_message
    INVALID_DOMAIN             = :invalid_domain
    SCHEME_MISMATCH            = :scheme_mismatch
    DOMAIN_MISMATCH            = :domain_mismatch
    NONCE_MISMATCH             = :nonce_mismatch
    URI_MISMATCH               = :uri_mismatch
    CHAIN_ID_MISMATCH          = :chain_id_mismatch
    REQUEST_ID_MISMATCH        = :request_id_mismatch
    INVALID_ADDRESS            = :invalid_address
    INVALID_URI                = :invalid_uri
    INVALID_NONCE              = :invalid_nonce
    NOT_YET_VALID_MESSAGE      = :not_yet_valid_message
    INVALID_SIGNATURE          = :invalid_signature
    INVALID_SIGNATURE_CHAIN_ID = :invalid_signature_chain_id
    INVALID_TIME_FORMAT        = :invalid_time_format
    INVALID_MESSAGE_VERSION    = :invalid_message_version
    UNABLE_TO_PARSE            = :unable_to_parse
    MISSING_DOMAIN             = :missing_domain
    MISSING_NONCE              = :missing_nonce
    MISSING_URI                = :missing_uri
    MISSING_CHAIN_ID           = :missing_chain_id
    MISSING_CONFIG             = :missing_config
    MISSING_PROVIDER_LIBRARY   = :missing_provider_library
    NONCE_GENERATION_FAILED    = :nonce_generation_failed
    INVALID_PARAMS             = :invalid_params
    MALFORMED_MESSAGE          = :malformed_message
    RPC_ERROR                  = :rpc_error

    MESSAGES = {
      EXPIRED_MESSAGE => "Expired message.",
      INVALID_DOMAIN => "Invalid domain.",
      SCHEME_MISMATCH => "Scheme does not match provided scheme for verification.",
      DOMAIN_MISMATCH => "Domain does not match provided domain for verification.",
      NONCE_MISMATCH => "Nonce does not match provided nonce for verification.",
      URI_MISMATCH => "URI does not match provided URI for verification.",
      CHAIN_ID_MISMATCH => "Chain ID does not match provided chain ID for verification.",
      REQUEST_ID_MISMATCH => "Request ID does not match provided request ID for verification.",
      INVALID_ADDRESS => "Invalid address.",
      INVALID_URI => "URI does not conform to RFC 3986.",
      INVALID_NONCE => "Nonce size smaller than 8 characters or is not alphanumeric.",
      NOT_YET_VALID_MESSAGE => "Message is not valid yet.",
      INVALID_SIGNATURE => "Signature does not match address of the message.",
      INVALID_SIGNATURE_CHAIN_ID => "Contract wallet verification provider chain does not match message chain ID.",
      INVALID_TIME_FORMAT => "Invalid time format.",
      INVALID_MESSAGE_VERSION => "Invalid message version.",
      UNABLE_TO_PARSE => "Unable to parse the message.",
      MISSING_DOMAIN => "Domain is required for verification.",
      MISSING_NONCE => "Nonce is required for verification.",
      MISSING_URI => "URI is required in strict mode.",
      MISSING_CHAIN_ID => "Chain ID is required in strict mode.",
      MISSING_CONFIG => "No verification configuration found.",
      MISSING_PROVIDER_LIBRARY => "Required provider library is not installed.",
      NONCE_GENERATION_FAILED => "Nonce generation failed.",
      INVALID_PARAMS => "Invalid parameters passed to verify.",
      MALFORMED_MESSAGE => "Message could not be prepared for signing.",
      RPC_ERROR => "RPC call failed."
    }.freeze

    ALL = MESSAGES.keys.freeze
  end
end
