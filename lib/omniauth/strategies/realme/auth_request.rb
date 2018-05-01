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

        def initialize(options, relay_state=nil)
          begin
            @relay_state  = relay_state
            @destination  = options.fetch('destination')
            @provider     = options.fetch('provider')
            @allow_create = options.fetch('allow_create', 'true')
            @format       = options.fetch('format')
            @ssl_sp_pem   = File.open(options.fetch('ssl_sp_pem'))
            @issuer       = options.fetch('issuer')
            @idp_sso_target_url     = options.fetch('idp_sso_target_url')
            # @name_identifier_format = options.fetch('name_identifier_format')
            @request_authn_context_class_ref  = options.fetch('request_authn_context_class_ref')
            # @assertion_consumer_service_index = options.fetch('name_identifier_format')

            # TODO check if this is creating a proper closure
          rescue Errno::ENOENT => e
            raise OmniAuth::Error.new("RealMe ssl sp pem cannot be found #{e}")

          rescue KeyError => e
            raise OmniAuth::Error.new("RealMe #{e} check that it is present in your RealMe configuration")
          end
        end

        def call
          req = <<-REQUEST
<samlp:AuthnRequest xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
AssertionConsumerServiceIndex="0"
Destination="#{@destination}"
ID="_#{UUID.new.generate}"
IssueInstant="#{Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")}"
ProviderName="#{@provider}"
Version="2.0">
<saml:Issuer>#{@issuer}</saml:Issuer>
<samlp:NameIDPolicy AllowCreate="#{@allow_create}" Format="#{@format}"></samlp:NameIDPolicy>
<samlp:RequestedAuthnContext>
<saml:AuthnContextClassRef>#{@request_authn_context_class_ref}</saml:AuthnContextClassRef>
</samlp:RequestedAuthnContext>
</samlp:AuthnRequest>
          REQUEST
          
          compress_request = Zlib.deflate(req, Zlib::BEST_COMPRESSION)[2..-5] # What are the magic indexs??

          base64_request = [compress_request].pack(BASE64_DIRECTIVE)
          encoded_request = CGI.escape(base64_request)

          request = "SAMLRequest=#{encoded_request}"
          # request = "SAMLRequest=#{req}"
          # request.concat("&RelayState=#{@relayState}") if @relayState
          # request.concat('&RelayState=a63b1904850ec370d500447f13fba000')
          request.concat("&SigAlg=#{CGI.escape('http://www.w3.org/2000/09/xmldsig#rsa-sha1')}")

          sig = OpenSSL::PKey::RSA.new(@ssl_sp_pem).sign(OpenSSL::Digest::SHA1.new, request)
          request.concat("&Signature=#{CGI.escape(::Base64.encode64(sig))}")

          "#{@idp_sso_target_url}?#{request}"
        end

        private
      end
    end
  end
end
