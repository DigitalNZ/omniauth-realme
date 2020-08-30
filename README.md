# omniauth-realme

![CI](https://github.com/DigitalNZ/omniauth-realme/workflows/CI/badge.svg)

Omniauth strategy for New Zealand's secure online identity verification service.

This Gem has been developed for the intention of using [Devise](https://github.com/plataformatec/devise) as the account model with Realme SSO integration.
This gem covers all of the SAML client requirements for RealMe integrations including the RealMe's default error messages.

You will need to set up your frontend login pages to match [RealMe's branding guidelines](https://developers.realme.govt.nz/how-to-integrate/application-design-and-branding-guide/realme-page-elements/)
We suggest you use their assets in a zip file on their page.

Getting to Production:
You will need to complete the [RealMe Operational handover checklist](https://developers.realme.govt.nz/how-to-integrate/getting-to-production/operational-handover-checklist/) `login service` form to gain access to RealMe production environments.

Not using *Ruby* but need to integrate? Use this gem as a baseline and find a suitable Library on [onelogin's](https://github.com/onelogin) github account.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'devise'
gem 'omniauth-realme'
```

And then execute:

    $ bundle

### Realme
To test that you have installed the Gem correctly integrate with their message testing servies [RealMe MTS](https://mts.realme.govt.nz/logon-mts/home) first, followed by ITE then Production integrations.

You will need to set up your applications integration via their [developers website](https://developers.realme.govt.nz) for ITE and production.

### Devise

Setup

```ruby
# config/initializers/devise.rb
Devise.setup do |config|
  # ...
  config.omniauth :realme
end
```

Here we configure the [ruby-saml](https://github.com/onelogin/ruby-saml) gem.
Realme provides the necessary `service-metadata.xml` files for their side of the integration. They can be found on this [page](https://developers.realme.govt.nz/how-realme-works/technical-integration-steps#e75)

```ruby
# config/initializers/omniauth.rb

# Use OmniAuthCallbacksController#failure as the Rack app which OmniAuth will
# redirect to in the event of a failure
OmniAuth.config.on_failure = Proc.new { |env| OmniAuthCallbacksController.action(:failure).call(env) }

OmniAuth.configure do |config|
  # Always wedirect to the failure endpoint if there is an error. Normally the
  # exception would just be raised in development mode. This is useful for
  # testing your Realme error handling in development.
  config.failure_raise_out_environments = []

  # We want to see OmniAuth messages in the log
  config.logger = Rails.logger
end
```

```ruby
# config/initializers/realme_omniauth.rb
OmniAuth::Strategies::Realme.configure do |config|
  # Website issuer namespace
  config.issuer = 'http://myapp/<issuer>/<access>'

  # Callback url
  config.assertion_consumer_service_url = 'http://myapp.com/users/auth/realme/callback'

  # Sign the request saml and decrypt response

  # Read the public+private keypair from a file. This example demonstrates
  # using the .p12 file Realme provides to help you get up an running with their
  # MTS environment.
  p12 = OpenSSL::PKCS12.new(File.read(Rails.root.join("realme/Integration-Bundle-MTS-V3.2/mts_saml_sp.p12")), "password")

  # Give the strategy the public key that will identify your SP to Realme (the IdP)
  config.certificate = p12.certificate.to_s

  # Give the strategy the corresponding private key so it can decrypt messages
  # sent by Realme which are encrypted with the public key
  config.private_key = p12.key.to_s

  # Realme login service xml file.
  # You will need to download the different XML files for the different environments found here: https://developers.realme.govt.nz/how-realme-works/technical-integration-steps/
  config.idp_service_metadata = Rails.root.join('path', 'to', 'logon-service-metadata.xml')

  # default strength
  config.auth_strength = 'urn:nzl:govt:ict:stds:authn:deployment:GLS:SAML:2.0:ac:classes:LowStrength'

  # The allowed clock drift is added to the current time at which the response
  # is validated before it's tested against the NotBefore assertion. Its value
  # must be given in a number (and/or fraction) of seconds.
  #
  # Make sure to keep the value as comfortably small as possible to keep
  # security risks to a minimum.
  #
  # See: https://github.com/onelogin/ruby-saml#clock-drift
  #
  config.allowed_clock_drift = 5.seconds # default is 0.seconds

  # It can be very useful to fail noisily in development if there are SAML
  # validation errors. We recommend enabling this in Rails development env at
  # least.
  #
  config.raise_exceptions_for_saml_validation_errors = Rails.env.development? # default: false

  # Versions 0.1.0 and older of this gem return the FLT or any errors from
  # Realme in the Rails session. We are migrating away from this to a more
  # conventional OmniAuth approach of returning the FLT in
  # `request.env['omniauth.auth'] and errors redirect to the OmniAuth failure
  # Rack app.
  #
  # As of version 0.1.0, using the Rails session is enabled by default to not
  # break existing installations. If you are configuring this strategy in a new
  # application, you should set this behaviour to `false` to ensure your app
  # continues to work seamlessly in future versions of this gem.
  #
  config.legacy_rails_session_behaviour_enabled = false
end
```

Routes

```ruby
# config/routes.rb

# Add/edit the `devise_for` line in your routes file as shown here
devise_for :users, controllers: { omniauth_callbacks: 'users/omniauth_callbacks' }
```

Controllers
```ruby
# app/controllers/application_controller.rb
class ApplicationController < ActionController::Base
  before_action :configure_permitted_parameters, if: :devise_controller?
  # ...

  private

  def configure_permitted_parameters
    # :uid, :provider and any new fields need to be added here
    devise_parameter_sanitizer.permit(:sign_up, keys: [:password, :password_confirmation, :email, :uid, :provider])
  end

  # ...
end
```

The customer `uid` will come through in `request.env['omniauth.auth']['uid']`

```ruby
# app/controllers/users/omniauth_callbacks_controller.rb

module Users
  class OmniauthCallbacksController < ::Devise::OmniauthCallbacksController
    skip_before_action :verify_authenticity_token

    def realme
      realme_flt_token = request.env["omniauth.auth"]["uid"]
      @user = User.from_omniauth('realme', realme_flt_token)

      unless @user.valid?
        @user.errors.each { |err| @user.errors.delete(err) }

        flash.notice = 'RealMe login successful, please fill in your user details.'
        return render 'devise/registrations/new.html.haml'
      end

      flash.notice = 'RealMe login successful.'

      sign_in_and_redirect @user
    end

    def failure
      exception = request.env["omniauth.error"] # a reference to the exception instance class
      error_type = request.env["omniauth.error.type"] # the first symbol passed to fail!()
      erroring_strategy = request.env["omniauth.error.strategy"] # a reference to the strategy instance that threw the error

      flash.alert = "Realme login failed because #{exception.message}"
      redirect_to root_path
    end
  end
end
```

Views
  - You will need to update your registration `new` and `edit` views by adding the new fields as well as hidden fields for `provider` and `uid`.
  - User sign in view will also need to be updated so that it links to the OmniAuth realme pass through using the link helper `user_realme_omniauth_authorize_path`.

Model
```ruby
# app/models/user.rb
class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable,
         :omniauthable, omniauth_providers: [:realme]

  validates :provider, presence: true
  validates :uid,      presence: true, uniqueness: true
  validates :email,    presence: true, uniqueness: true

  def self.from_omniauth(provider, uid)
    where(provider: provider, uid: uid).first_or_create do |user|
      user.provider = provider
      user.uid      = uid
    end
  end
end
```

Migrations
  - You will need to add `provider` and `uid` to your model and index the `uid`
```ruby
# db/migrate/<timestamp>_devise_create_users.rb
class DeviseCreateUsers < ActiveRecord::Migration[5.2]
  def change
    create_table :users do |t|
      # ...

      t.string :provider, null: false
      t.string :uid,      null: false, unique: true

      # ...
    end
     # ...
    add_index :users, :uid, unique: true
  end
end
```

Remove SAMLResponse from Rails log
```ruby
#config/initializers/filter_parameter_logging.rb
Rails.application.config.filter_parameters += [:password, 'SAMLResponse']
```

## Metadata

This gem includes `OmniAuth::Realme.generate_metadata_xml` which will generate SAML SP metadata in a form suitable for uploading to the [Realme MTS Metadata upload](https://mts.realme.govt.nz/logon-mts/metadataupdate) endpoint using the same settings you used to configure this strategy.

Below is an example of using it to create a `/saml/metadata.xml` endpoint in your app. This can be convenient but might be unnecessary for your application, depending on your use case so this step is optional.

```ruby
# config/routes.rb

# Example: curl http://localhost:3000/saml/metadata.xml
get "saml/metadata", to: "saml_metadata#metadata"
```

```ruby
# app/controllers/saml_metadata_controller.rb
class SamlMetadataController < ApplicationController
  # Skip authentication on the metadata action (this line is only required if
  # you are using devise)
  skip_before_action :authenticate_user!, only: [:metadata]

  def metadata
    respond_to do |format|
      format.xml  { render xml: OmniAuth::Realme.generate_metadata_xml }
    end
  end
end
```

If you don't need an endpoint in your app you can just invoke the function from the console e.g.

```ruby
rails-console> puts OmniAuth::Realme.generate_metadata_xml
```

## Realme Context Mapping Service (RCMS)

[Realme Context Mapping Service](https://developers.realme.govt.nz/how-realme-works/whats-realme-rcms/) is an additional service which your app can optionally integrate with.

Most of the work of integrating with RCMS is outside of the scope of what OmniAuth does. If your app is using RCMS then you will receive a _Login Attributes Token_ as well as the normal Realme FLT with the SAMLResponse.

This strategy facilitates your use of RCMS by making that additional token (if
it exists) available in
`request.env['omniauth.auth']['credentials']['realme_cms_lat']` e.g.

```ruby
# app/controllers/users/omniauth_callbacks_controller.rb

module Users
  class OmniauthCallbacksController < ::Devise::OmniauthCallbacksController
    skip_before_action :verify_authenticity_token

    def realme
      realme_flt = request.env['omniauth.auth']['uid']
      realme_cms_lat = request.env['omniauth.auth']['credentials']['realme_cms_lat']

      # complete your RCMS integration here ...
    end
  end
end
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/DigitalNZ/omniauth-realme.

## License
  GNU GENERAL PUBLIC LICENSE
