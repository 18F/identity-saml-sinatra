git_source(:github) { |repo_name| "https://github.com/#{repo_name}.git" }
source 'https://rubygems.org'

ruby "~> #{File.read(File.join(__dir__, '.ruby-version')).strip}"

gem 'aws-sdk-s3', '>= 1.208.0'
gem 'dotenv'
gem 'faraday'
gem 'hashie'
gem 'jwt', '~> 2.1'
gem 'rexml'
gem 'ruby-saml', '>= 1.9.0'
gem 'rack-test', '>= 2.0.0'
gem 'rake'
gem 'rackup'
gem 'sinatra', '>= 3.0.4'
gem 'test-unit'
gem 'activesupport'
gem 'puma'

group :development do
  gem 'pry'
end

group :test do
  gem 'bundler-audit', require: false
  gem 'simplecov', require: false
  gem 'webmock'
  # Used by the specs to build EncryptedAssertion fixtures the same way the
  # IdP's saml_idp gem does (SamlIdp::Encryptor wraps xmlenc).
  gem 'xmlenc'
end

group :development, :test do
  gem 'rspec'
  gem 'rubocop', require: false
  gem 'rubocop-rspec', require: false
end
