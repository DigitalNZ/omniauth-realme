# frozen_string_literal: true

require 'uuid'
require 'zlib'
require 'cgi'
require 'openssl'
require 'base64'

module OmniAuth
  module Strategies
    class Realme
      class AuthRequest
        BASE64_DIRECTIVE = 'm' # See Array#Pack for more details https://ruby-doc.org/core-2.5.0/Array.html#method-i-pack

        def initialize(options, relay_state = nil)
          begin
            @relay_state  = relay_state
            @destination  = options.fetch('destination')
            @provider     = options.fetch('provider')
            @issuer       = options.fetch('issuer')
            @allow_create = options.fetch('allow_create', 'true')
            @format       = options.fetch('format')
            @rsa_private_key = OpenSSL::PKey::RSA.new(options.fetch('private_key'))
            @request_authn_context_class_ref = options.fetch('auth_strenght')
            @idp_target_url = options.fetch('idp_target_url')

            # idp_cert is not getting used as its the public ssl cert
            # @idp_cert     = OpenSSL::X509::Certificate.new(options.fetch('idp_cert'))
            # @name_identifier_format = options.fetch('name_identifier_format')
            # @assertion_consumer_service_index = options.fetch('name_identifier_format')

            # TODO: check if this is creating a proper closure
          rescue Errno::ENOENT => e
            raise OmniAuth::Error, "RealMe ssl sp pem cannot be found #{e}"
          rescue KeyError => e
            raise OmniAuth::Error, "RealMe #{e} check that it is present in your RealMe configuration"
          end
        end

        def call
          req = <<~REQUEST
            <samlp:AuthnRequest xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            AssertionConsumerServiceIndex="0"
            Destination="#{@destination}"
            ID="_#{UUID.new.generate}"
            IssueInstant="#{Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ')}"
            Version="2.0">
            <saml:Issuer>#{@issuer}</saml:Issuer>
            <samlp:NameIDPolicy AllowCreate="#{@allow_create}" Format="#{@format}"></samlp:NameIDPolicy>
            <samlp:RequestedAuthnContext>
            <saml:AuthnContextClassRef>#{@request_authn_context_class_ref}</saml:AuthnContextClassRef>
            </samlp:RequestedAuthnContext>
            </samlp:AuthnRequest>
          REQUEST
          # ProviderName="#{@provider}" # from above Version

          puts req

          compress_request = Zlib.deflate(req, Zlib::BEST_COMPRESSION)[2..-5] # What are the magic indexs??

          base64_request = [compress_request].pack(BASE64_DIRECTIVE)
          encoded_request = CGI.escape(base64_request)

          request = "SAMLRequest=#{encoded_request}"
          request = "#{request}&RelayState=#{@relayState}" if @relayState
          request = "#{request}&SigAlg=#{CGI.escape('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256')}"

          sig = @rsa_private_key.sign(OpenSSL::Digest::SHA256.new, request)

          "#{@idp_target_url}?#{request}&Signature=#{CGI.escape(::Base64.encode64(sig))}"
        end
      end
    end
  end
end
