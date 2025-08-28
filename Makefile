HOST ?= localhost
PORT ?= 4567

.env: .env.example
	cp .env.example .env

setup: .env install_dependencies copy_vendor

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

copy_vendor: public/vendor
	cp -R node_modules/uswds/dist public/vendor/uswds
