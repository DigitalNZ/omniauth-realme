# frozen_string_literal: true

require 'bundler/setup'
require 'omniauth'
require 'omniauth/realme'
require 'pry'

Dir["#{Dir.pwd}/spec/support/**/*.rb"].each { |f| require f }

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = '.rspec_status'

  config.extend OmniAuth::Test::StrategyMacros, type: :strategy
end
