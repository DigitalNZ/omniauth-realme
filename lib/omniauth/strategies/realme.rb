# frozen_string_literal: true

require 'omniauth'
require 'ruby-saml'

module OmniAuth
  module Strategies
    class Realme
      include OmniAuth::Strategy

      RCMS_LAT_NAME = 'urn:nzl:govt:ict:stds:authn:safeb64:logon_attributes_jwt'

      # Fixed OmniAuth options
      option :provider, 'realme'

      def request_phase
        req = OneLogin::RubySaml::Authrequest.new
        redirect req.create(saml_settings, 'SigAlg' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256')
      end

      def callback_phase # rubocop:disable Metrics/AbcSize
        response = ::OneLogin::RubySaml::Response.new(request.params['SAMLResponse'],
                                                      settings: saml_settings,
                                                      allowed_clock_drift: allowed_clock_drift)

        if response.is_valid?
          @uid = response.nameid
          session[:uid] = response.nameid

          ##
          # If the Realme Context Mapping Service (RCMS) is enabled in Realme
          # for our app then we will get a RCMS Login Access Token in the
          # SAMLResponse.
          #
          # We save the token if it exists. See
          # https://developers.realme.govt.nz/how-realme-works/whats-realme-rcms/
          #
          @realme_cms_lat = response.attributes[RCMS_LAT_NAME] if response.attributes[RCMS_LAT_NAME]
        else
          session[:realme_error] = {
            error: response.errors.join[/=> (\S+) ->/, 1],
            message: default_error_messages(response.errors.join)
          }
        end

        super
      end

      ##
      # The `credentials` Hash will be placed within the `request["omniauth.auth"]`
      # Hash that `OmniAuth::Strategy` builds. See
      # https://github.com/omniauth/omniauth/wiki/Auth-Hash-Schema
      #
      # `credentials` contains any extra credentials information about the user
      # that we received from the authentication service (Realme) e.g. an RCMS
      # token if it exists.
      #
      credentials do
        output = {}
        output[:realme_cms_lat] = @realme_cms_lat if @realme_cms_lat
        output
      end

      ##
      # Return the `uid` (User ID) value in a way that allows
      # OmniAuth::Strategy to place it in the `request["omniauth.auth"]` Hash
      # that it builds. See
      # https://github.com/omniauth/omniauth/wiki/Auth-Hash-Schema
      #
      uid do
        @uid
      end

      def saml_settings # rubocop:disable Metrics/AbcSize
        idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new
        settings = idp_metadata_parser.parse(File.read(options.fetch('idp_service_metadata')))

        settings.issuer                             = options.fetch('issuer')
        settings.assertion_consumer_service_url     = options.fetch('assertion_consumer_service_url')
        settings.attributes_index                   = options.fetch('attributes_index', '0')
        settings.private_key                        = options.fetch('private_key')
        settings.authn_context                      = options.fetch('auth_strength', 'urn:nzl:govt:ict:stds:authn:deployment:GLS:SAML:2.0:ac:classes:LowStrength')
        settings.protocol_binding                   = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
        settings.assertion_consumer_service_binding = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
        settings.soft                               = !options.fetch('raise_exceptions_for_saml_validation_errors', false)

        settings.security[:authn_requests_signed] = true

        ##
        # Realme error if this is missing from the metadata
        #
        #     WantAssertionsSigned must be true (MTS-002)
        #
        settings.security[:want_assertions_signed] = true

        ##
        # Realme MTS requires our Metadata XML to have both:
        #
        #     <md:KeyDescriptor use="signing">...</md:KeyDescriptor>
        #     <md:KeyDescriptor use="encryption">...</md:KeyDescriptor>
        #
        # in the metadata XML we submit. We need to set a certificate **and**
        # set `:want_assertions_encrypted` for ruby-saml to include these
        # elements.
        #
        settings.certificate = options.fetch('certificate')
        settings.security[:want_assertions_encrypted] = true

        settings
      end

      private

      def allowed_clock_drift
        options.fetch('allowed_clock_drift', 0)
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
