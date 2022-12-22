HOST ?= localhost
PORT ?= 4567

.env: .env.example
	cp -n .env.example .env || true

setup: .env
	bundle install

test:
	bundle exec ruby test/app_test.rb

run:
	bundle exec rackup -p $(PORT) --host ${HOST}

.PHONY: test run
