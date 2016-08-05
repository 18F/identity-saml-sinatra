setup:
	bundle install

test:
	bundle exec ruby test/app_test.rb

run:
	SAML_ENV=local bundle exec ruby app.rb

.PHONY: test run
