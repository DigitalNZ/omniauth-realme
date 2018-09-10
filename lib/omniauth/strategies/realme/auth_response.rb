# frozen_string_literal: true

require 'savon'
require 'nokogiri'
require 'uuid'

module OmniAuth
  module Strategies
    class Realme
      class AuthResponse
        # xml selectors
        STATUS_CODE = 'StatusCode'
        ENCRYPTED_DATA = 'EncryptedData'

        def initialize(saml_response, options)
          @raw_response = saml_response
          @saml = parse_response(saml_response)
          @private_key = OpenSSL::PKey::RSA.new(options.fetch('private_key'))
          @options = options # TODO: extract out the options we need
        end

        def call
          # saml = Nokogiri::XML.parse(::Base64.decode64(@saml_response), &:noblanks).remove_namespaces!
          # @saml = saml
          valid?

          encrypted_data = @saml.css(ENCRYPTED_DATA).first
          algorithm = encrypted_data.children[0].values.first

          # these need to be decrypted
          encoded_key = encrypted_data.children[1].text
          encoded_data = encrypted_data.children[2].text

          # https://stackoverflow.com/questions/8556940/rails-encryption-decryption
          decoded_key = ::Base64.decode64(encoded_key)
          decoded_data = ::Base64.decode64(encoded_data)
          cipher_key = @private_key.private_decrypt(decoded_key) # decrypted 16 byte key from response

          # aes-128 -> 16 byte key | aes-265 -> 32 byte key
          c = OpenSSL::Cipher::AES.new(algorithm[/#[a-z]+(\d+)/, 1], :CBC) #OpenSSL::Cipher.new("aes-128-cbc")
          c.decrypt
          # c.padding = 0
          
          c.key = cipher_key
          # c.key = Digest::SHA1.hexdigest(cipher_key).unpack("B#{c.key_len}").first
          # c.iv = Digest::SHA1.hexdigest(@options.fetch('idp_cert')).unpack("B#{c.key_len}").first
          c.update(cipher_data)
          c.final
        end

        private

        def parse_response(saml)
          Nokogiri::XML.parse(::Base64.decode64(saml), &:noblanks).remove_namespaces!
        end

        def valid?
          status_code = @saml.css(STATUS_CODE).first.values.first
          raise OmniAuth::Error, "Unsuccessful Realme response: status code #{status_code}" unless status_code == 'urn:oasis:names:tc:SAML:2.0:status:Success'
          raise OmniAuth::Error, 'EncryptedData was not found.' if @saml.css(ENCRYPTED_DATA).empty?
        end
      end
    end
  end
end
