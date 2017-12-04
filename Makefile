setup:
	bundle install

test:
	bundle exec ruby test/app_test.rb

run:
	bundle exec ruby app.rb

.PHONY: test run
