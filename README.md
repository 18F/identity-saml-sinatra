identity-saml-sinatra
=====================

An example **agency application** for use with [Login.gov](https://login.gov/)'s identity
provider, in two roles:

1. **Direct SAML sign-in.** The agency's own web app: users sign in to Login.gov and a
   SAML response is posted to `/consume`. This is the original sample and is unchanged.
2. **SAML resource server for delegated access** (reference implementation). An API,
   `GET`/`POST /api/benefits`, that accepts **delegated SAML 2.0 assertions** issued by
   Login.gov's token exchange (RFC 8693) on behalf of a user to a third-party *service
   provider*, validates them locally with `ruby-saml`, and enforces the capabilities the user
   approved. It also runs an Attempts API viewer in the **agency** role that joins Login.gov's
   fraud-signal events to the API's own decisions on `delegation_id`.

Everything here is a demo. Benefits data is fictional and generated from a hash of the
user's identifier; nothing is persisted beyond the process.

## Running locally

These instructions assume [`identity-idp`](https://github.com/18F/identity-idp) is running at
http://localhost:3000 with the delegated-access localdev fixtures.

1. Set up the environment (copies `.env.example` to `.env`, installs gems and assets):

   ```
   $ make setup
   ```

2. Run the application server (http://localhost:4567):

   ```
   $ make run
   ```

3. Run the specs and linters:

   ```
   $ make test
   $ make lint
   ```

Pass `HOST=` or `PORT=` to `make run` to change the bind address.

## Routes

| Route | Role | Purpose |
|---|---|---|
| `GET /`, `/login_get`, `/login_post`, `POST /consume`, `/logout`, `/slo_logout` | direct sign-in | The original SAML service-provider sample |
| `GET /api/benefits` | resource server | Requires `token_exchange:benefits_read` in the assertion's `delegation_scopes` |
| `POST /api/benefits` | resource server | Requires `token_exchange:benefits_write`; JSON body with `mailing_address` and/or `preferred_contact` |
| `GET /decisions`, `/decisions.json` | resource server | Every allow/deny decision the API made (in memory) |
| `GET /attempts-api` | agency | Attempts API events for this agency; `?tab=delegated` groups them by `delegation_id` with the matching API decisions |
| `POST /ack-events` | agency | Acknowledge (delete) events by JTI |

## Environment variables

Direct sign-in (unchanged from the original sample):

| Variable | Default | Purpose |
|---|---|---|
| `issuer` | `urn:gov:gsa:SAML:2.0.profiles:sp:sso:benefits_agency` | This agency's SAML issuer / entityID. Also the Attempts API issuer. |
| `assertion_consumer_service_url` | - | `http://localhost:4567/consume` locally |
| `idp_sso_target_url`, `idp_slo_target_url` | - | Login.gov's year-suffixed SSO/SLO endpoints |
| `idp_cert_fingerprint` | - | Fingerprint of the IdP signing certificate for the browser flow |
| `sp_cert`, `sp_private_key` | `config/demo_sp.crt`, `config/demo_sp.key` | Required explicitly when the IdP host is `login.gov` |

Resource server (new):

| Variable | Default | Purpose |
|---|---|---|
| `idp_url` | `http://localhost:3000` | Base URL of the IdP |
| `SAML_METADATA_YEAR` | `2026` | Year suffix of the metadata path; Login.gov rotates signing keys by publishing a new year |
| `IDP_METADATA_URL` | `{idp_url}/api/saml/metadata{SAML_METADATA_YEAR}` | Full override of the metadata URL |
| `IDP_METADATA_CACHE_SECONDS` | `3600` | How long fetched metadata is reused |
| `RESOURCE_IDENTIFIER` | `https://benefits-api.agency.localdev` | The identifier registered with Login.gov; `Audience` and `Recipient` must equal it |
| `RS_PRIVATE_KEY_PATH` | `./config/demo_sp.key` | Decrypts `EncryptedAssertion`s (assertions are encrypted to the registered certificate) |
| `ALLOWED_CLOCK_DRIFT` | `60` | Seconds of tolerance on every time comparison |
| `REPLAY_PROTECTION` | `true` | Refuse a second presentation of the same assertion ID (see below) |
| `DECISION_LOG_SIZE` | `200` | Entries kept for `/decisions` |

Attempts API viewer (agency role):

| Variable | Default | Purpose |
|---|---|---|
| `attempts_shared_secret` | `benefits-agency-attempts-secret` | Local-development placeholder matching the IdP's `allowed_attempts_providers` entry; replace for any real environment |
| `attempts_private_key_path` | `./config/demo_sp.key` | Decrypts event JWEs (the agency's registered public key locally is the SP certificate) |
| `signed_events` | `false` | Verify ES256-signed event payloads with the IdP's Attempts key |
| `allow_all_events_plaintext` | `false` | Show every field instead of redacting to the allow-list |

To run against the sandbox (`idp.int.identitysandbox.gov`) change `idp_url`, the
direct-sign-in URLs, and the identifiers to the values from onboarding; no code changes.

## Registering with Login.gov

The local IdP fixtures (`config/service_providers.localdev.yml` in `identity-idp`) register
this app as:

- **Agency service provider** — issuer `urn:gov:gsa:SAML:2.0.profiles:sp:sso:benefits_agency`,
  agency_id 2, IAL2, ACS `http://localhost:4567/consume`, certificate `sp_sinatra_demo`
  (this repo's `config/demo_sp.crt`), `block_encryption: aes256-cbc`, attribute bundle
  `email first_name last_name`, `token_exchange_target: true`, enrolled in the Attempts API
  with shared secret `benefits-agency-attempts-secret`.
- **Resource server** — `identifier: https://benefits-api.agency.localdev`,
  `token_format: saml2`, `certs: [sp_sinatra_demo]` (assertions are encrypted to it), with
  scopes `benefits_read` (read) and `benefits_write` (read_write).

An agency onboarding for real supplies the same things: its
SAML issuer, the resource server identifier, `token_format: saml2`, a certificate for
encryption, and one scope with plain-language content per capability.

## How a delegated call works

```
Service provider ── POST /api/openid_connect/token (token-exchange, requested_token_type=saml2) ──► Login.gov
                 ◄── { access_token: <base64url EncryptedAssertion>, token_type: N_A, ... } ──────
Service provider ── GET /api/benefits  Authorization: Bearer <access_token> ──────────────────────► this app
                 ◄── 200 { benefits, delegated_access: { actor, delegation_id, delegation_scopes }, _assertion }
```

`authorize!(required_scope)` in `app.rb` runs one function per protocol step so that the code can be copied step by step:

| Step | Function | Standard |
|---|---|---|
| Read the bearer token | `bearer_token` | RFC 6750 §2.1 |
| Base64url-decode it | `DelegatedAssertion.decode` | RFC 8693 §3, RFC 4648 §5 |
| Validate the assertion locally | `validate_assertion` → `DelegatedAssertion#validate!` | see below |
| Enforce the route's scope | `enforce_scope` | `delegation_scopes` attribute, compared as full strings |
| Record the decision | `log_decision` | shown at `/decisions` |

`DelegatedAssertion#validate!` (`delegated_assertion.rb`) runs, in order:

1. `decrypt_if_encrypted` — `<saml:EncryptedAssertion>` is decrypted with `RS_PRIVATE_KEY_PATH`
   using `OneLogin::RubySaml::Utils.decrypt_data` (AES-CBC/GCM data, RSA-OAEP key transport,
   the layout Login.gov's `saml_idp` gem emits).
2. `parse_assertion` — DTD-free parse; root must be a SAML 2.0 `<saml:Assertion>` with an ID.
3. `verify_signature` — **signature validation is real.** `XMLSecurity::SignedDocument` from
   `ruby-saml` is applied to the bare assertion: `validate_document_with_cert` canonicalizes the
   referenced element, checks the digest, and verifies `SignatureValue` over `SignedInfo` with
   each signing certificate from the IdP metadata until one succeeds. Around it: exactly one
   `ds:Signature`, a direct child of the Assertion, whose `Reference URI` is the assertion's own
   ID, which must be unique in the document; RSA-SHA256/384/512 and SHA-256/384/512 only. The
   assertion is used bare (not wrapped in a synthetic `<samlp:Response>` for
   `OneLogin::RubySaml::Response`) so that what is verified is exactly what Login.gov signed;
   the reasoning is in the method comment.
4. `check_issuer` — `<saml:Issuer>` equals the metadata entityID (SAML Core §2.2.5).
5. `check_subject` — `NameID` present; a bearer `SubjectConfirmation` whose
   `SubjectConfirmationData` has `Recipient == RESOURCE_IDENTIFIER`, `NotOnOrAfter` in the
   future (60 s drift; Login.gov sets it to issuance + 5 minutes), and **no `InResponseTo`**
   — an assertion answering a browser AuthnRequest is an ordinary sign-in, never delegation
   (SAML Core §2.4.1.2).
6. `check_conditions` — `NotBefore`/`NotOnOrAfter` with drift; every `AudienceRestriction`
   must contain `RESOURCE_IDENTIFIER` (SAML Core §2.5.1.4); no `AudienceRestriction` or any
   other Condition type makes the assertion invalid (SAML Core §2.5.1).
7. `read_attributes` — the `AttributeStatement`, keyed by `Name`. `delegation_scopes`
   (space-separated `token_exchange:*` values), `delegation_id` and `actor` are required;
   without them it is not a delegated assertion. `actor` is the service provider's issuer,
   the SAML counterpart of the OAuth `act` claim (RFC 8693 §4.1).
8. `check_replay` — optional, see below.

No step calls Login.gov. Metadata is fetched from `IDP_METADATA_URL` once and cached; a
signature failure triggers at most one early re-fetch per minute so a rotated key is picked up.

Error responses follow RFC 6750 §3: `401` with `WWW-Authenticate: Bearer realm="benefits-api"`
(no `error` when no credentials were sent; `error="invalid_token"` otherwise), `400
invalid_request` for a malformed header, `403 insufficient_scope` with the `scope` the route
needs, `503` if metadata cannot be fetched (fail closed).

### Delegation-aware policy

The API reads `actor` and treats every call carrying it as delegated access by that service
provider: the response's `delegated_access` block names the actor, the `delegation_id` and the
approved scopes, and a POST records who made the change. The policy itself is the scope check:
a delegation approved only for `benefits_read` gets `403 insufficient_scope` on POST. Which
service providers may act for this agency's users is agreed during onboarding, not enforced
by parsing the assertion.

### Revocation window (accepted)

Because validation is local, **a revoked delegation's assertion remains usable here until it
expires**. This app enforces `SubjectConfirmationData/@NotOnOrAfter`, so
the window is the five minutes after issuance plus 60 s drift; a validator that checked only
`Conditions` would accept it for up to an hour. Revocation takes effect at the service
provider's next refresh, which Login.gov refuses for a revoked grant. Introspection by
assertion ID is available from Login.gov for agencies that want a shorter window, but is not
required and this app does not use it.

### Replay protection (optional agency policy)

With `REPLAY_PROTECTION=true` (default) each assertion ID is accepted once and remembered
until its `NotOnOrAfter` + drift (`assertion_replay_cache.rb`, in memory, per process). This
is agency policy, not a Login.gov requirement: a service provider is expected to hold an
assertion for up to five minutes and may call the API more than once with it. Agencies that
expect repeat calls set `REPLAY_PROTECTION=false`; agencies that keep it on should tell
service providers to refresh before each call.

### The `_assertion` echo

API responses include `_assertion` (ID, issuer, NameID, windows, attributes) so the service
provider's demo page can show what the API saw. It is a demo affordance; a production API
would not return it.

## Attempts API viewer (agency role)

`/attempts-api` polls `POST {idp_url}/api/attempts/poll` with
`Authorization: Bearer <issuer> <attempts_shared_secret>`, decrypts each set (a JWE to the
agency's registered key) and, if `signed_events=true`, verifies the ES256 payload with the key
from `/.well-known/ssf-configuration`. Fields outside the allow-list in `app.rb`
(`ALLOWED_PLAINTEXT_KEYS`) are redacted; the allow-list includes the delegated-access fields
`actor_issuer`, `scopes`, `resources`, `remembered`, `ial`, `aal`, `delegation_id`, `reason`,
`token_format` and `resource`.

Delegated access adds four event types — `delegated-access-consented`,
`delegated-access-token-issued`, `delegated-access-token-refreshed`,
`delegated-access-revoked` — and tags the existing sign-in events with `delegation_id`. Any
event with `delegation_id` or `actor_issuer` is a delegated session; its `subject.session_id`
is the service provider's and will not match a session this agency started. The **Delegated
sessions** tab (`?tab=delegated`) groups events by `delegation_id` and lists beneath each
group the API decisions whose assertion carried the same `delegation_id`: the join agencies
implement.

## Layout

| File | Purpose |
|---|---|
| `app.rb` | Sinatra app: direct sign-in routes, `/api/benefits`, `authorize!` steps, decision log and Attempts routes |
| `delegated_assertion.rb` | Assertion validation, one method per step |
| `idp_metadata.rb` | Fetch/cache IdP metadata; signing certificates and entityID |
| `assertion_replay_cache.rb` | Optional replay protection |
| `decision_log.rb` | Ring buffer behind `/decisions` |
| `demo_benefits.rb` | Fictional records keyed by NameID |
| `resource_server_config.rb` | Environment variables and defaults |
| `attempts_client.rb`, `attempts_configuration.rb` | Attempts API polling, decryption, signature verification |
| `spec/support/delegated_assertion_factory.rb` | Builds signed and encrypted test assertions with a runtime-generated IdP key pair |

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md) for additional information.

## Public domain

This project is in the worldwide [public domain](LICENSE.md). As stated in [CONTRIBUTING](CONTRIBUTING.md):

> This project is in the public domain within the United States, and copyright and related rights in the work worldwide are waived through the [CC0 1.0 Universal public domain dedication](https://creativecommons.org/publicdomain/zero/1.0/).
>
> All contributions to this project will be released under the CC0 dedication. By submitting a pull request, you are agreeing to comply with this waiver of copyright interest.
