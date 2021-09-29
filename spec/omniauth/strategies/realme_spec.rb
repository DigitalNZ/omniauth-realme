# frozen_string_literal: true

RSpec.describe OmniAuth::Strategies::Realme do
  let(:idp_metadata_path) { File.join(__dir__, '../../fixtures/realme_mts_idp_metadata.xml') }
  let(:expected_clock_drift) { 7 }
  let(:assertion_consumer_service_url) { 'http://www.example.com/auth/anything' }
  let(:issuer) { 'Anything' }
  let(:legacy_rails_session_behaviour_enabled) { nil } # use whatever the default is
  let(:realme_strategy_options) do
    p12 = OpenSSL::PKCS12.new(File.read(File.join(__dir__, '../../fixtures/mts_saml_sp.p12')), 'password')

    {
      idp_service_metadata: idp_metadata_path,
      issuer: issuer,
      private_key: p12.key.to_s,
      certificate: p12.certificate.to_s,
      assertion_consumer_service_url: assertion_consumer_service_url,
      allowed_clock_drift: expected_clock_drift,
      legacy_rails_session_behaviour_enabled: legacy_rails_session_behaviour_enabled
    }
  end
  # due to using post, we need an authenticity token
  let(:authenticity_token) do
    get '/token'
    last_response.body
  end

  # Rack::Test helper methods expect the Rack app they are testing to be in `app`
  let(:app) do
    # OmniAuth strategies are rack apps and they depend on their being a
    # Session middleware before them in the chain so we build a chain of rack
    # middlewares to enable testing:
    #
    #   session_middleware -> strategy_middleware -> dummy_welcome_app
    #
    options = realme_strategy_options
    Rack::Builder.new do
      use Rack::Session::Cookie, secret: 'abc123'
      use Rack::Protection::AuthenticityToken
      use OmniAuth::Strategies::Realme, options
      run(lambda do |env|
        body = Rack::Protection::AuthenticityToken.token(env['rack.session']) if env['PATH_INFO'] == '/token'
        [200, env, [body || 'Welcome']]
      end)
    end.to_app
  end

  around(:each) do |example|
    # Create a custom logger which ignores all but the most serious log
    # messages (we don't want to pollute our test output with log output)
    logger = Logger.new(STDOUT)
    logger.level = Logger::FATAL

    # Replace the default OmniAuth and RubySaml loggers with our custom logger.
    old_omniauth_logger = OmniAuth.config.logger
    OmniAuth.config.logger = logger

    old_ruby_saml_logger = OneLogin::RubySaml::Logging.logger
    OneLogin::RubySaml::Logging.logger = logger

    example.run

    # Reset the loggers after each test run
    OmniAuth.config.logger = old_omniauth_logger
    OneLogin::RubySaml::Logging.logger = old_ruby_saml_logger
  end

  describe '#request_phase' do
    let(:expected_saml_request) do
      <<~EO_XML
        <samlp:AuthnRequest
          AssertionConsumerServiceURL='#{assertion_consumer_service_url}'
          AttributeConsumingServiceIndex='0'
          Destination='https://mts.realme.govt.nz/logon-mts/mtsEntryPoint'
          ID='PLACEHOLDER_ID'
          IssueInstant='PLACEHOLDER_ISSUE_INSTANT'
          ProtocolBinding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST' Version='2.0'
          xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'
          xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol'>
          <saml:Issuer>#{issuer}</saml:Issuer>
          <samlp:NameIDPolicy AllowCreate='true' Format='urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'/>
          <samlp:RequestedAuthnContext Comparison='exact'>
            <saml:AuthnContextClassRef>urn:nzl:govt:ict:stds:authn:deployment:GLS:SAML:2.0:ac:classes:LowStrength</saml:AuthnContextClassRef>
          </samlp:RequestedAuthnContext>
        </samlp:AuthnRequest>
      EO_XML
    end

    it 'generates the expected HTTP 302 Redirect to Realme' do
      response = post('/auth/realme', authenticity_token: authenticity_token)

      expect(response.status).to eq(302)
      expect(response.headers['Location']).to match(Regexp.quote('https://mts.realme.govt.nz/logon-mts/mtsEntryPoint?SAMLRequest='))
    end

    it 'uses the expected signature algorithm to sign the SAMLRequest' do
      response = post('/auth/realme', authenticity_token: authenticity_token)

      # Extract the query params from the redirect URL generated
      query_params = CGI.parse(URI.parse(response.headers['Location']).query)

      expect(query_params.fetch('SigAlg').first).to eq('http://www.w3.org/2000/09/xmldsig#rsa-sha1')
    end

    it 'generates the expected SAMLRequest for Realme' do
      response = post('/auth/realme', authenticity_token: authenticity_token)

      # Extract the query params from the redirect URL generated
      query_params = CGI.parse(URI.parse(response.headers['Location']).query)

      # Retrieve and decode the SAML request and convert it to an Nokogiri XML doc
      raw_saml_request = query_params.fetch('SAMLRequest').first
      actual_saml_request = Zlib::Inflate.new(-Zlib::MAX_WBITS).inflate(Base64.decode64(raw_saml_request))
      actual_saml_request_xml = Nokogiri::XML(actual_saml_request, &:noblanks)

      # Replace the parts of the SAML Request which we know are different each
      # time with values that we can test
      actual_saml_request_xml.root.attributes['ID'].value = 'PLACEHOLDER_ID'
      actual_saml_request_xml.root.attributes['IssueInstant'].value = 'PLACEHOLDER_ISSUE_INSTANT'

      # Create a Nokogiri XML doc from the expected request
      expected_saml_request_xml = Nokogiri::XML(expected_saml_request, &:noblanks)

      # Serialize both the actual and expected requests docs to strings and
      # compare. We depend on Nokogiri serializing the same document the same
      # way each time (e.g. order of attributes is the same).
      expect(actual_saml_request_xml.to_s).to eq(expected_saml_request_xml.to_s)
    end

    context 'when valid Relay State value is provided' do
      let(:valid_relay_state) { 'aabbcc' }

      it 'sends the relay state to Realme' do
        response = post('/auth/realme', { authenticity_token: authenticity_token, relay_state: valid_relay_state })

        query_params = CGI.parse(URI(response.headers['Location']).query)
        actual_relay_state = query_params.fetch('RelayState').first

        expect(actual_relay_state).to eq(valid_relay_state)
      end
    end

    context 'when invalid Relay State value is provided' do
      let(:too_long_relay_state) { 'x' * 81 }

      it 'redirects to the OmniAuth failure rack app' do
        response = post('/auth/realme', { authenticity_token: authenticity_token, relay_state: too_long_relay_state })

        expect(response.headers['Location']).to eq('/auth/failure?message=OmniAuth_Strategies_Realme_RelayStateTooLongError&strategy=realme')
      end
    end
  end

  describe '#callback_phase' do
    let(:raw_saml_response) { 'value can be anything because we stub & mock the return value' }
    let(:fake_ruby_saml_response) do
      double('OneLogin::RubySaml::Response',
             is_valid?: true,
             nameid: expected_realme_flt,
             attributes: {})
    end
    let(:expected_realme_flt) { 'expectedrealmefltvalue' }

    it 'passes the received clock drift to ruby-saml' do
      expect(OneLogin::RubySaml::Response).to receive(:new).with(raw_saml_response,
                                                                 hash_including(allowed_clock_drift: expected_clock_drift))
                                                           .and_return(fake_ruby_saml_response)

      post('/auth/realme/callback', { authenticity_token: authenticity_token, SAMLResponse: raw_saml_response })
    end

    context 'when we receive a Realme Context Mapping Service (RCMS) Login Access Token' do
      let(:expected_realme_cms_lat) { 'some-long-token' }
      let(:fake_ruby_saml_response) do
        double('OneLogin::RubySaml::Response',
               is_valid?: true,
               nameid: expected_realme_flt,
               attributes: { OmniAuth::Strategies::Realme::RCMS_LAT_NAME => expected_realme_cms_lat })
      end
      let(:expected_omniauth_auth) do
        {
          'provider' => 'realme',
          'uid' => expected_realme_flt,
          'info' => {},
          'credentials' => {
            'realme_cms_lat' => expected_realme_cms_lat
          },
          'extra' => {}
        }
      end

      it 'Realme RCMS LAT is put in "credentials" within "omniauth.auth"' do
        allow(OneLogin::RubySaml::Response).to receive(:new).with(raw_saml_response,
                                                                  hash_including(allowed_clock_drift: expected_clock_drift))
                                                            .and_return(fake_ruby_saml_response)

        response = post('/auth/realme/callback', { authenticity_token: authenticity_token, SAMLResponse: raw_saml_response })

        expect(response['omniauth.auth']).to eq(expected_omniauth_auth)
      end
    end

    context 'when we send relay state to Realme' do
      let(:expected_relay_state) { 'some-relay-state' }
      let(:fake_ruby_saml_response) do
        double('OneLogin::RubySaml::Response',
               is_valid?: true,
               nameid: expected_realme_flt,
               attributes: { 'RelayState' => expected_relay_state })
      end

      let(:expected_omniauth_auth) do
        {
          'provider' => 'realme',
          'uid' => expected_realme_flt,
          'info' => {},
          'credentials' => {},
          'extra' => {
            'relay_state' => expected_relay_state
          }
        }
      end

      it 'relay state from Realme is put in "extra" within "omniauth.auth"' do
        allow(OneLogin::RubySaml::Response).to receive(:new).with(raw_saml_response,
                                                                  hash_including(allowed_clock_drift: expected_clock_drift))
                                                            .and_return(fake_ruby_saml_response)

        response = post('/auth/realme/callback', { authenticity_token: authenticity_token, SAMLResponse: raw_saml_response, RelayState: expected_relay_state })

        expect(response['omniauth.auth']).to eq(expected_omniauth_auth)
      end
    end

    context 'when legacy use of Rails session is enabled' do
      let(:legacy_rails_session_behaviour_enabled) { true }

      context 'when Realme can successfully authenticate the user' do
        let(:expected_omniauth_auth) do
          {
            'provider' => 'realme',
            'uid' => expected_realme_flt,
            'info' => {},
            'credentials' => {},
            'extra' => {}
          }
        end

        it 'puts the Realme FLT in session[:uid]' do
          allow(OneLogin::RubySaml::Response).to receive(:new).with(raw_saml_response,
                                                                    hash_including(allowed_clock_drift: expected_clock_drift))
                                                              .and_return(fake_ruby_saml_response)

          response = post('/auth/realme/callback', { authenticity_token: authenticity_token, SAMLResponse: raw_saml_response })

          expect(response['rack.session']['uid']).to eq(expected_realme_flt)
        end
      end

      context 'when Realme returns an error' do
        let(:error_ruby_saml_response) do
          double(is_valid?: false,
                 status_code: 'anything',
                 status_message: 'anything',
                 errors: %w[first_err second_err],
                 attributes: {})
        end

        it 'puts the errors Realme FLT in session[:realme_error]' do
          allow(OneLogin::RubySaml::Response).to receive(:new).with(raw_saml_response,
                                                                    hash_including(allowed_clock_drift: expected_clock_drift))
                                                              .and_return(error_ruby_saml_response)

          response = post('/auth/realme/callback', { authenticity_token: authenticity_token, SAMLResponse: raw_saml_response })

          expect(response['rack.session']['realme_error'][:error]).to eq(nil)
          expect(response['rack.session']['realme_error'][:message]).to match(/RealMe reported a serious application error with the message/)
        end
      end
    end

    context 'when legacy use of Rails session is disabled' do
      let(:legacy_rails_session_behaviour_enabled) { false }

      context 'when Realme can successfully authenticate the user' do
        let(:expected_omniauth_auth) do
          {
            'provider' => 'realme',
            'uid' => expected_realme_flt,
            'info' => {},
            'credentials' => {},
            'extra' => {}
          }
        end

        context 'when we receive a Realme FLT' do
          it 'puts the Realme FLT in "omniauth.auth"' do
            allow(OneLogin::RubySaml::Response).to receive(:new).with(raw_saml_response,
                                                                      hash_including(allowed_clock_drift: expected_clock_drift))
                                                                .and_return(fake_ruby_saml_response)

            response = post('/auth/realme/callback', { authenticity_token: authenticity_token, SAMLResponse: raw_saml_response })

            expect(response['omniauth.auth']).to eq(expected_omniauth_auth)
          end
        end
      end

      context 'when Realme returns a urn:oasis:names:tc:SAML:2.0:status:AuthnFailed error' do
        let(:error_ruby_saml_response) do
          double(is_valid?: false,
                 status_code: 'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed',
                 status_message: 'anything',
                 errors: %w[first_err second_err],
                 attributes: {})
        end

        it 'redirects to the OmniAuth failure rack app' do
          allow(OneLogin::RubySaml::Response).to receive(:new).with(raw_saml_response,
                                                                    hash_including(allowed_clock_drift: expected_clock_drift))
                                                              .and_return(error_ruby_saml_response)

          response = post('/auth/realme/callback', { authenticity_token: authenticity_token, SAMLResponse: raw_saml_response })

          expect(response.headers['Location']).to eq('/auth/failure?message=OmniAuth_Strategies_Realme_RealmeAuthnFailedError&strategy=realme')
        end
      end
    end
  end
end
