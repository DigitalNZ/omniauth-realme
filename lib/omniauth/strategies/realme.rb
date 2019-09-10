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
        req = OneLogin::RubySaml::Authrequest.new
        redirect req.create(saml_settings, 'SigAlg' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256')
      end

      def callback_phase
        response = ::OneLogin::RubySaml::Response.new(request.params['SAMLResponse'], settings: saml_settings)

        if response.is_valid?
          session[:uid] = response.nameid
        else
          session[:realme_error] = {
            error: response.errors.join()[/=> (\S+) ->/,1],
            message: default_error_messages(response.errors.join)
          }
        end

        @raw_info = response
        super
      end

      private

      def saml_settings
        idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new
        settings = idp_metadata_parser.parse(File.read(options.fetch('idp_service_metadata')))

          settings.issuer                         = options.fetch('issuer')
          settings.assertion_consumer_service_url = options.fetch('assertion_consumer_service_url')
          settings.private_key                    = options.fetch('private_key')
          settings.authn_context                  = options.fetch('auth_strength', 'urn:nzl:govt:ict:stds:authn:deployment:GLS:SAML:2.0:ac:classes:LowStrength')
          settings.protocol_binding                   = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
          settings.assertion_consumer_service_binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
          settings.soft = true

          settings.security[:authn_requests_signed] = true

          settings
      end

      def default_error_messages(error)
        case error
        when /Timeout/
          '<p>Your RealMe session has expired due to inactivity.</p>'
        when /NoAvailableIDP/
          "<p>RealMe reported that the TXT service, Google Authenticator or the RealMe token service is not available.</p>
           <p>You may try again later. If the problem persists, please contact RealMe Help <a href='tel:'0800664774>0800 664 774</a>.</p>"
        when /AuthnFailed/
          '<p>You have chosen to leave the RealMe login screen without completing the login process.</p>'
          when /InternalError/
            "<p>RealMe was unable to process your request due to a RealMe internal error.</p>
              <p>Please try again. If the problem persists, please contact RealMe Help Desk on <a href='tel:'0800664774>0800 664 774</a>.</p>"
          else
            "<p>RealMe reported a serious application error with the message:</p>
              <p>#{error}</p>
              <p>Please try again later. If the problem persists, please contact RealMe Help Desk on <a href='tel:'0800664774>0800 664 774</a>.</p>"
        end
      end
    end
  end
end

OmniAuth.config.add_camelization 'realme', 'Realme'
