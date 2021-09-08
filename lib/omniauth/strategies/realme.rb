# frozen_string_literal: true

require 'omniauth'
require 'ruby-saml'

module OmniAuth
  module Strategies
    class Realme
      class Error < StandardError; end
      class RelayStateTooLongError < Error; end

      ##
      # Create an exception for each documented Realme error
      # (https://developers.realme.govt.nz/how-realme-works/realme-saml-exception-handling/).
      #
      # All the errors we raise inherit from `OmniAuth::Strategies::Realme::Error`
      # so a caller can rescue that if they want to rescue all exceptions from
      # this class.
      #
      class RealmeAuthnFailedError        < Error; end
      class RealmeInternalError           < Error; end
      class RealmeInternalError           < Error; end
      class RealmeNoAvailableIDPError     < Error; end
      class RealmeNoPassiveError          < Error; end
      class RealmeRequestDeniedError      < Error; end
      class RealmeRequestUnsupportedError < Error; end
      class RealmeTimeoutError            < Error; end
      class RealmeUnknownPrincipalError   < Error; end
      class RealmeUnrecognisedError       < Error; end
      class RealmeUnsupportedBindingError < Error; end

      include OmniAuth::Strategy

      RCMS_LAT_NAME = 'urn:nzl:govt:ict:stds:authn:safeb64:logon_attributes_jwt'

      # The SAML spec says the maximum length of the RelayState is 80
      # bytes. See section 3.4.3 of
      # http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf
      MAX_LENGTH_OF_RELAY_STATE = 80 # bytes

      # Fixed OmniAuth options
      option :provider, 'realme'

      def request_phase
        req_options = { 'SigAlg' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' }

        ##
        # If we recieved a `relay_state` param e.g. we were invoked like:
        #
        #   redirect_to user_realme_omniauth_authorize_path(relay_state: 'some_value')
        #
        # then we pass it to Realme (via RubySaml). Realme (as a SAML IdP)
        # should return that value unaltered when it redirects back to this
        # application and `#callback_phase` below is executed.
        #
        if request.params['relay_state']
          if limit_relay_state? && request.params['relay_state'].length > MAX_LENGTH_OF_RELAY_STATE
            ex = RelayStateTooLongError.new('RelayState exceeds SAML spec max length of 80 bytes')

            # fail!() returns a rack response which this callback must also
            # return if OmniAuth error handling is to work correctly.
            return fail!(create_label_for(ex), ex)
          end

          req_options['RelayState'] = request.params['relay_state']
        end

        req = OneLogin::RubySaml::Authrequest.new
        redirect req.create(saml_settings, req_options)
      end

      def callback_phase # rubocop:disable Metrics/PerceivedComplexity, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/AbcSize
        response = ::OneLogin::RubySaml::Response.new(request.params['SAMLResponse'],
                                                      settings: saml_settings,
                                                      allowed_clock_drift: allowed_clock_drift)

        ##
        # `RelayState` is an arbitrary string (length < 80 characters). If we
        # sent it to Realme with the SAMLRequest then Realme will return it unaltered.
        #
        # If we receive any relay state then we save it.
        #
        @relay_state = request.params['RelayState'] if request.params['RelayState']

        # If the Realme Context Mapping Service (RCMS) is enabled in Realme
        # for our app then we will get a RCMS Login Access Token in the
        # SAMLResponse.
        #
        # We save the token if it exists. See
        # https://developers.realme.govt.nz/how-realme-works/whats-realme-rcms/
        #
        if response.is_valid?
          @realme_cms_lat = response.attributes[RCMS_LAT_NAME] if response.attributes[RCMS_LAT_NAME]
        end

        if legacy_rails_session_behaviour_enabled?
          OmniAuth.logger.info "Deprecation: omniauth-realme will stop putting values via Rails `session` in a future version. Use request.env['omniauth.auth'] instead." # rubocop:disable Layout/LineLength

          if response.is_valid?
            session[:uid] = response.nameid
          else
            session[:realme_error] = {
              error: response.errors.join[/=> (\S+) ->/, 1],
              message: default_error_messages_for_rails_session(response.errors.join)
            }
          end
        else
          if response.is_valid? # rubocop:disable Style/IfInsideElse
            @uid = response.nameid
          else
            msg = response.status_message ? response.status_message.strip : ''
            ex = create_exception_for(status_code: response.status_code, message: msg)

            # fail!() returns a rack response which this callback must also
            # return if OmniAuth error handling is to work correctly.
            return fail!(create_label_for(ex), ex)
          end
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
      # The `extra` Hash will be placed within the `request["omniauth.auth"]`
      # Hash that `OmniAuth::Strategy` builds. See
      # https://github.com/omniauth/omniauth/wiki/Auth-Hash-Schema
      #
      # `extra` contains anything which isn't information about the user or a
      # user credential.
      #
      extra do
        output = {}
        output[:relay_state] = @relay_state if @relay_state
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

      ##
      # Realme documents the various error conditions it can return:
      #
      # https://developers.realme.govt.nz/how-realme-works/realme-saml-exception-handling/
      #
      def create_exception_for(status_code:, message:) # rubocop:disable Metrics/MethodLength, Metrics/CyclomaticComplexity
        case status_code
        when /status:Timeout\z/
          RealmeTimeoutError.new(message)
        when /status:InternalError\z/
          RealmeInternalError.new(message)
        when /status:AuthnFailed\z/
          RealmeAuthnFailedError.new(message)
        when /status:NoAvailableIDP\z/
          RealmeNoAvailableIDPError.new(message)
        when /status:NoPassive\z/
          RealmeNoPassiveError.new(message)
        when /status:RequestDenied\z/
          RealmeRequestDeniedError.new(message)
        when /status:RequestUnsupported\z/
          RealmeRequestUnsupportedError.new(message)
        when /status:UnknownPrincipal\z/
          RealmeUnknownPrincipalError.new(message)
        when /status:UnsupportedBinding\z/
          RealmeUnsupportedBindingError.new(message)
        else
          RealmeUnrecognisedError.new("Realme login service returned an unrecognised error. status_code=#{status_code} message=#{message}")
        end
      end

      ##
      # The OmniAuth failure endpoint requires us to pass an instance of an
      # Exception and a String|Symbol describing the error. This method builds
      # a simple description based on class of the exception.
      #
      # This gem can be used in any Rack environment so we don't use any Rails
      # specific text wrangling methods
      #
      # @param [Exception] exception The exception to describe
      # @return [String] The label describing the exception
      #
      def create_label_for(exception)
        exception.class.to_s.gsub('::', '_')
      end

      def allowed_clock_drift
        options.fetch('allowed_clock_drift', 0)
      end

      def legacy_rails_session_behaviour_enabled?
        options.fetch('legacy_rails_session_behaviour_enabled', true)
      end

      def limit_relay_state?
        options.fetch('limit_relay_state', true)
      end

      def default_error_messages_for_rails_session(error)
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
