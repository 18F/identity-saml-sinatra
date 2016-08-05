Sinatra-based Identity SP
=========================

Example service provide (SP) app for use with 18F's IdP.

### Setup

    $ make setup

### Testing

    $ make test

### Running (local development mode)

    $ make run
    
### Running (on cloud.gov)

    $ bin/cloud_deploy [dev or demo]
(Note: You'll need to be logged into cloud.gov first)

### Generating a new key + self-signed cert

    openssl req -newkey rsa:2048 -nodes -keyout config/demo_sp.key \
      -x509 -out config/demo_sp.crt -config config/openssl.conf

    openssl x509 -fingerprint -noout -in config/demo_sp.crt
