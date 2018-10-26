# omniauth-realme
Omniauth strategy for New Zealands secure online identity verification service.

This Gem has been developed for the intension of using [devise](https://github.com/plataformatec/devise) as the account model with Realme SSO intergation.

Not Using *ruby* but need to itergrate? Use this gem is a baseline and find a suitable Library on [onelogin's](https://github.com/onelogin) github account.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'devise'
gem 'omniauth-realme'
```

And then execute:

    $ bundle

### Realme
To test that you have installed the Gem correctly intergrate with their message testing servies [RealMe MTS](https://mts.realme.govt.nz/logon-mts/home) first, followed by ITE then Production intergrations.

You will need to be setup your applications intergration via their [developers website](https://developers.realme.govt.nz) for ITE and production set up.

### Devise
Setup
```ruby
# config/initializers/devise.rb
Devise.setup do |d_config|
  d_config.omniauth :realme
end
```

Here we configure the [ruby-saml](https://github.com/onelogin/ruby-saml) gem.
Realme provides the nessassery `service-metadata.xml` files for their side of the intergation they can be found on this [page](https://developers.realme.govt.nz/how-realme-works/technical-integration-steps#e75)

```ruby
# config/initializers/realme_omniauth.rb
OmniAuth::Strategies::Realme.configure do |config|
  config.issuer = 'http://myapp/<issuer>'                                                               # Website issuer namespace
  config.assertion_consumer_service_url = 'http://myapp.com/users/auth/realme/callback'                 # Callback url
  config.private_key = 'Realme SLL private cert'                                                        # Sign the request saml and decrypt response
  config.idp_service_metadata = Rails.root.join('path', 'to', 'logon-service-metadata.xml')             # Realme login service xml file
  config.auth_strenght = 'urn:nzl:govt:ict:stds:authn:deployment:GLS:SAML:2.0:ac:classes:LowStrength'   # default Strenght
end
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

The customer uid will come through in their session as `session[:uid]`

```ruby
# app/controllers/users/omniauth_callbacks_controller.rb
require 'devise'

module Users
  class OmniauthCallbacksController < ::Devise::OmniauthCallbacksController
    skip_before_action :verify_authenticity_token

    def realme
      return redirect_to new_user_session_path, alert: session.delete(:realme_error) if session[:realme_error].present?

      @user = User.from_omniauth('realme', session.delete(:uid))

      unless @user.valid?
        @user.errors.each { |err| @user.errors.delete(err) }

        flash.notice = 'RealMe login successful, please fill in your user details.'
        return render 'devise/registrations/new.html.haml'
      end

      flash.notice = 'RealMe login successful.'

      sign_in_and_redirect @user
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

Migration
  - You will need to add these extra fields and an index
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

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/[USERNAME]/omniauth-realme.

## License
  GNU GENERAL PUBLIC LICENSE
