# frozen_string_literal: true

require 'spec_helper'

RSpec.describe OmniAuth::Strategies::Realme do
  it 'has a version number' do
    expect(Omniauth::Realme::VERSION).not_to be nil
  end
  
  it 'loads the Omnauth dependanices' do
    binding.pry
    expect(OmniAuth::Strategies).to_not be_nil
  end
end
