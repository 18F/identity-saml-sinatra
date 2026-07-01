HOST ?= localhost
PORT ?= 4567

.env: .env.example
	cp .env.example .env

setup: .env install_dependencies

test:
	bundle exec rspec
	npm run test

lint:
	@echo "--- rubocop ---"
	bundle exec bundler-audit check --update
	npm audit --audit-level=high

run:
	bundle exec rackup -p $(PORT) --host ${HOST}

.PHONY: test run

public/vendor:
	mkdir -p public/vendor

install_dependencies:
	bundle check || bundle install
	npm install

