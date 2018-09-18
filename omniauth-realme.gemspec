
# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'omniauth/realme/version'

Gem::Specification.new do |spec|
  spec.name          = 'omniauth-realme'
  spec.version       = Omniauth::Realme::VERSION
  spec.authors       = ['DanHenton']
  spec.email         = ['Dan.henton@live.com']

  spec.summary       = 'Omniauth strategy for New Zealands secure online identity verification service.'
  spec.description   = 'Omniauth strategy for New Zealands secure online identity verification service.'
  spec.homepage      = 'https://example.com'
  spec.license       = 'GNU'

  # Prevent pushing this gem to RubyGems.org. To allow pushes either set the 'allowed_push_host'
  # to allow pushing to a single host or delete this section to allow pushing to any host.
  if spec.respond_to?(:metadata)
    spec.metadata['allowed_push_host'] = "TODO: Set to 'http://mygemserver.com'"
  else
    raise 'RubyGems 2.0 or newer is required to protect against ' \
      'public gem pushes.'
  end

  spec.files = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  spec.add_dependency 'omniauth'
  spec.add_dependency 'savon'
  spec.add_dependency 'uuid'
  spec.add_dependency 'nokogiri'
  spec.add_dependency 'ruby-saml'

  spec.add_development_dependency 'bundler'
  spec.add_development_dependency 'rake'
  spec.add_development_dependency 'rspec'
end
