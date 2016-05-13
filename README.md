Identity-RP
===========

Mock relying party (RP) app for validating IdP and IdV APIs.

May also function as reference RP implementation.

### Setup

    $ bundle install

### Testing

    $ bundle exec ruby test/app_test.rb

### Running

    $ bundle exec ruby app.rb

### Generating a new key + self-signed cert

    openssl req -newkey rsa:2048 -nodes -keyout config/server.key \
      -x509 -out config/server.crt -config config/openssl.conf
