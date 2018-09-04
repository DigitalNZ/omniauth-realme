OmniAuth::Strategies::Realme.configure do |config|
  config.provider   = 'Sample Service Provider'
  onfig.destination = 'https://mts.realme.govt.nz/logon-mts/mtsEntryPoint'
  config.format = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'
  config.issuer = 'https://sample-service-provider.org.nz/mts2/sp'
  config.idp_cert = '' # REALME idp_cert
  config.private_key = '' # REALME private_key
  config.idp_metadata = nil
  config.idp_target_url = 'https://www.mts.logon.realme.govt.nz/sso/logon/metaAlias/logon/logonidp'
  config.auth_strenght = 'urn:nzl:govt:ict:stds:authn:deployment:GLS:SAML:2.0:ac:classes:ModStrength'
end
