# frozen_string_literal: true

RSpec.describe OmniAuth::Realme do
  it 'has a version number' do
    expect(OmniAuth::Realme::VERSION).not_to be nil
  end

  describe '.generate_metadata_xml' do
    let(:idp_metadata_path) { File.join(__dir__, '../fixtures/realme_mts_idp_metadata.xml') }
    let(:assertion_consumer_service_url) { 'http://www.example.com/auth/anything' }
    let(:issuer) { 'Anything' }

    let(:p12) { OpenSSL::PKCS12.new(File.read(File.join(__dir__, '../fixtures/mts_saml_sp.p12')), 'password') }
    let(:sp_private_key) { p12.key.to_s }
    let(:sp_public_key) { p12.certificate.to_s }
    let(:sp_public_key_without_formatting) do
      sp_public_key
        .gsub!(/-----(BEGIN|END) CERTIFICATE-----/, '')
        .gsub!("\n", '')
    end

    let(:realme_strategy_options) do
      {
        idp_service_metadata: idp_metadata_path,
        issuer: issuer,
        private_key: sp_private_key,
        certificate: sp_public_key,
        assertion_consumer_service_url: assertion_consumer_service_url,
        allowed_clock_drift: 0
      }
    end

    let(:expected_xml) do
      <<~EO_XML
        <?xml version="1.0" encoding="UTF-8"?>
        <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" ID="PLACEHOLDER_ID" entityID="#{issuer}">
          <md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <md:KeyDescriptor use="signing">
              <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data>
                  <ds:X509Certificate>#{sp_public_key_without_formatting}</ds:X509Certificate>
                </ds:X509Data>
              </ds:KeyInfo>
            </md:KeyDescriptor>
            <md:KeyDescriptor use="encryption">
              <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data>
                  <ds:X509Certificate>#{sp_public_key_without_formatting}</ds:X509Certificate>
                </ds:X509Data>
              </ds:KeyInfo>
            </md:KeyDescriptor>
            <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
            <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="#{assertion_consumer_service_url}" index="0" isDefault="true"/>
          </md:SPSSODescriptor>
        </md:EntityDescriptor>
      EO_XML
    end

    let(:expected_xmldoc) { Nokogiri.XML(expected_xml) }

    it 'generates the expected XML string' do
      actual_xml = OmniAuth::Realme.generate_metadata_xml(options: realme_strategy_options)

      actual_xmldoc = Nokogiri.XML(actual_xml)

      # The ID is different every time so replace it with a known, predictable
      # value before comparing with the expected output
      actual_xmldoc.root.attributes['ID'].value = 'PLACEHOLDER_ID'

      expect(actual_xmldoc.to_s).to eq(expected_xmldoc.to_s)
    end
  end
end
