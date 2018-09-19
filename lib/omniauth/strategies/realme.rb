# frozen_string_literal: true

require 'omniauth'
require 'ruby-saml'

module OmniAuth
  module Strategies
    class Realme
      include OmniAuth::Strategy
      autoload :AuthRequest, 'omniauth/strategies/realme/auth_request'

      # Fixed OmniAuth options
      option :provider, 'realme'

      def request_phase
        redirect OmniAuth::Strategies::Realme::AuthRequest.new(options).call
      end

      def callback_phase
        response = ::OneLogin::RubySaml::Response.new(request.params['SAMLResponse'], settings: saml_settings)

        if response.is_valid?
          session[:uid] = response.nameid
        else
          authorize_failure
        end

        @raw_info = response
        super
      end

      private

      def saml_settings
        settings = OneLogin::RubySaml::Settings.new
        settings.issuer                         = options.fetch('issuer')
        settings.idp_sso_target_url             = options.fetch('destination')
        settings.name_identifier_format         = options.fetch('format')
        settings.assertion_consumer_service_url = options.fetch('assertion_consumer_service_url')

        settings.idp_cert       = options.fetch('idp_cert')
        settings.idp_cert_multi = { signing: [settings.idp_cert] }
        settings.private_key    = options.fetch('private_key')

        settings.soft = false
        settings.security = {}
        settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA1
        settings.security[:digest_method]    = XMLSecurity::Document::SHA1

        settings
      end
    end
  end
end

OmniAuth.config.add_camelization 'realme', 'Realme'
