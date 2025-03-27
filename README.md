identity-saml-sinatra
=====================

An example service provider application for use with [Login.gov](https://login.gov/)'s identity provider.

## Running locally

These instructions assume [`identity-idp`](https://github.com/18F/identity-idp) is also running locally at http://localhost:3000 .

1. Set up the environment with:

  ```
  $ make setup
  ```

2. Run the application server:

  ```
  $ make run
  ```

3. To run specs:

  ```
  $ make test
  ```

This sample service provider is configured to run on http://localhost:4567 by default. Optionally, you can assign a custom hostname or port by passing `HOST=` or `PORT=` environment variables when starting the application server.

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md) for additional information.

## Public domain

This project is in the worldwide [public domain](LICENSE.md). As stated in [CONTRIBUTING](CONTRIBUTING.md):

> This project is in the public domain within the United States, and copyright and related rights in the work worldwide are waived through the [CC0 1.0 Universal public domain dedication](https://creativecommons.org/publicdomain/zero/1.0/).
>
> All contributions to this project will be released under the CC0 dedication. By submitting a pull request, you are agreeing to comply with this waiver of copyright interest.
