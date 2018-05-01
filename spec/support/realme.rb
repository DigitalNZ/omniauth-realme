OmniAuth::Strategies::Realme.configure do |config|
  config.provider    = 'Sample Service Provider'
  config.issuer      = 'https://www.sample-client.co.nz/onlineservices/service1'
  # config.destination = 'https://realme.govt.nz/sso/SSORedirect/metaAlias/logon-idp'
  config.destination = 'https://www.ite.logon.realme.govt.nz/sso/logon/metaAlias/logon/logonidp'
  config.ssl_sp_pem  = 'spec/secrets/mts_mutual_ssl_sp.pem'
  config.idp_sso_target_url = 'https://mts.realme.govt.nz/logon-mts/mtsEntryPoint'
end
