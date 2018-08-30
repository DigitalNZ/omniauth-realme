require 'omniauth'

module OmniAuth
  module Strategies
    class Realme
      include OmniAuth::Strategy
      autoload :AuthRequest,  'omniauth/strategies/realme/auth_request'
      autoload :AuthResponse, 'omniauth/strategies/realme/auth_response'
      
      # Fixed OmniAuth options
      option :provider, 'realme'

      def request
        OmniAuth::Strategies::Realme::AuthRequest.new(self.class.default_options).call
      end

      def callback_phase
        response = OmniAuth::Strategies::Realme::AuthResponse.new(request.params['SAMLart'], self.class.default_options).call
        @name_id = response.name_id

        raise OmniAuth::Error.new('RealMe Bad request') unless response.successful?
        super

        uid { @name_id } # ??
      end
    end
  end
end

OmniAuth.config.add_camelization 'realme', 'Realme'

# Issuer
#
# NameIDPolicy
# - Allow Create => FLT requesting || AllowCreate TRUE for no distinct first time login processes
# - Format ( Value SHOULD be persistent, but unspecified allows the IdP to decide )
#
# RequestedAuthnContext
# - RequestedAuthnContextClassRef required => urn:nzl:govt:ict:stds:authn:deployment:GLS:SAML:2.0:ac:classes:ModStrength 
# - Comparison should be EXACT but supports (optinal: EXACT, MINIMUM, MAXIMUM or BETTER)
# 
# AssertionConsumerServiceIndex set in config for intergration
#
# Protocol Binding Use Post binding? should be default
#
# ForceAuthn => TRUE
#
# IsPassive => FALSE
#
# ProviderName Matches known issuer value. requires a pre-approved ProviderName before successfull intergration
#
# RelaySate
# - OASIS SAML V2.0 requirement is: MAY be provided. MUST NOT exceed 80 bytes in length and SHOULD be integrity protected by the Service Provider.
# - RealMe login service requirement is: MAY be provided and will be ignored.
# - Recommendation: Can use to meet service provider specific requirements.
