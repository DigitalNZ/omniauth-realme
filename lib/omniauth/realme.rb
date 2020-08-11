# frozen_string_literal: true

require 'omniauth/realme/version'
require 'omniauth/strategies/realme'

module OmniAuth
  module Realme # :nodoc:
    class Error < StandardError; end

    ##
    # Generates SAML SP metadata XML using the same settings you used to
    # configure the OmniAuth strategy. This XML is suitable for uploading to
    # Realme at https://mts.realme.govt.nz/logon-mts/metadataupdate
    #
    # @param [Hash] options - An optional Hash of options to configure the
    #                         strategy. This is convenient for testing but is
    #                         not required during normal operation because the
    #                         strategy will already be configured by the Rails
    #                         initializer.
    # @return [String] SP metadata serialized as an XML string
    #
    def self.generate_metadata_xml(options: {})
      meta = OneLogin::RubySaml::Metadata.new

      # OmniAuth strategies are Rack middlewares. When an instance of a rack
      # middleware is created it is given a reference to the next rack
      # app/middleware in the chain. We are only interested here in getting the
      # SAML settings out of the strategy. We don't hit any code paths which
      # would require a real rack app/middleware so `nil` works just fine.
      rack_app = nil

      # The Rails initializer calls `OmniAuth::Strategies::Realme.configure`
      # which merges the provided block into the default options for
      # `OmniAuth::Strategies::Realme` - use
      # `OmniAuth::Strategies::Realme.default_options` to inspect the current
      # state of these options.
      #
      # This means that the `options` we pass in here will be merged into (and
      # override) those default options.
      #
      # When this method is called by app code, we want to use the options set
      # by the Rails initializer so pass an empty hash as `options`. When this
      # method is called by its specs, no Rails initializer has run so we need
      # to pass in some options.
      #
      strategy = OmniAuth::Strategies::Realme.new(rack_app, options)

      meta.generate(strategy.saml_settings)
    end
  end
end
