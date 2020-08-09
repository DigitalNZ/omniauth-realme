# frozen_string_literal: true

RSpec.describe OmniAuth::Realme do
  it 'has a version number' do
    expect(OmniAuth::Realme::VERSION).not_to be nil
  end

  describe '.generate_metadata_xml' do
    let(:idp_metadata_path) { File.join(__dir__, '../fixtures/realme_mts_idp_metadata.xml') }
    let(:assertion_consumer_service_url) { 'http://www.example.com/auth/anything' }
    let(:issuer) { 'Anything' }
    let(:realme_strategy_options) do
      p12 = OpenSSL::PKCS12.new(File.read(File.join(__dir__, '../fixtures/mts_saml_sp.p12')), 'password')

      {
        idp_service_metadata: idp_metadata_path,
        issuer: issuer,
        private_key: p12.key.to_s,
        certificate: p12.certificate.to_s,
        assertion_consumer_service_url: assertion_consumer_service_url,
        allowed_clock_drift: 0
      }
    end

    let(:expected_xml) do
      <<~EO_XML
        <?xml version="1.0" encoding="UTF-8"?>
        <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" ID="PLACEHOLDER_ID" entityID="#{issuer}">
          <md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
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
