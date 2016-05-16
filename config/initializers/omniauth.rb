Rails.application.config.middleware.use OmniAuth::Builder do
  provider :saml,
           :assertion_consumer_service_url     => "http://localhost:3000/consume",
           :assertion_consumer_service_binding => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
           :issuer                             => "USA-RUBY-SP",
           :idp_sso_target_url                 => "https://upaya-idp-dev.18f.gov/api/saml/auth",
           :idp_cert                           => "-----BEGIN CERTIFICATE-----
MIIFcDCCA1gCCQCLxDQyL6Rq/jANBgkqhkiG9w0BAQsFADB6MQswCQYDVQQGEwJV
UzELMAkGA1UECBMCREMxEzARBgNVBAcTCldhc2hpbmd0b24xDDAKBgNVBAoTAzE4
RjE7MDkGA1UEAxMyZWMyLTU0LTE4My0yMTYtMTY5LnVzLXdlc3QtMS5jb21wdXRl
LmFtYXpvbmF3cy5jb20wHhcNMTQwOTE5MDcwNDE1WhcNMTYwOTE4MDcwNDE1WjB6
MQswCQYDVQQGEwJVUzELMAkGA1UECBMCREMxEzARBgNVBAcTCldhc2hpbmd0b24x
DDAKBgNVBAoTAzE4RjE7MDkGA1UEAxMyZWMyLTU0LTE4My0yMTYtMTY5LnVzLXdl
c3QtMS5jb21wdXRlLmFtYXpvbmF3cy5jb20wggIiMA0GCSqGSIb3DQEBAQUAA4IC
DwAwggIKAoICAQDMYOFxoaejHqunlhVCXIq4afydSLeraw7yZaWaDid1DyPAFh0B
D7fl7AyIDuYycTf2MeN9XtqnIOJvh5a/WI0hR4rnCCZoDsXRBACdrl+v7gMQbgfS
yU0nMGMzy9hgdjv1bKshy4HImPvkepbh+bfsQUcVey7d7fPofZbKFvglPuhl9m3R
TWPOttxs4KqU48jkVpo3xvrJtY1TpYdDti1DEGtXrIWiokqSeByeYjfWE0t8jucf
5kAjTqhCBwfelGkjiPogFRdNQyA14Yhp7Ri/EPHGWUZWuuuHdBiJXOvAM3fzafNF
PVpCdB91RmcRMzZp6NQxGt2BvOiq6pw1RSjDLvTJlsb6XH/fCnOqoLejwhTpM7nW
CW8tBuN1iU48TNNP1B12QNm35Uwx2TJc7y/NiPBukWVgn0JfeO6u567/WELxfUh3
0RmtTLwujEkpma8VEQre2c8b62mQV0sahcepY7kvRd18fWWozA2tUlxMO7k+54g+
pHxWc5eYG6B7KHbDytTakFcRSXJXB7MJHantSH0PH9XcKQdszjAjJRxOGzwe627i
AZrhA48tsT31qEH2J0jMGdQTurWsbAW37SBl/qqoki+v5Iq5QUvVAt9Dfhk63C2z
lcGmjRTEi+BPgTAdWPLfJt5JXzb7j6iTjWYGAqHs5nYzGXoKvrTia0gFlwIDAQAB
MA0GCSqGSIb3DQEBCwUAA4ICAQAucIhQLj2Rj5LTrfRkd4S8tcekaN6BYaNF49Eo
JofFfdKoe1bl+fhgnYXDXvJpqZZ/acChNT4uNNS0+OxWyyoYHAmBn8sDdJJI/5Hw
OpYyKSVcxGWq4EYijCyFxtYGbIUu7L79G1fIKeDG4Fd9jTyteHPkPzQZlxhT+hky
jVuXN3YVQRepJdwrZ2TgrCxpMsKtL2XyAK+TncWj08eWIL7eyDxAzlb3z4nwhFW4
SjhKXG9nLn/8VsZcCJ1VwxqRNj9wxuuN4uq/PgY7uDkxIKXL8LLvCILnvyWEn9sG
NLk3n3kb9XjVxteyb4+46OMUmlI9muQy9rA7uXhal/pDwF/E+OFBo+XNXZFOnQCy
8fRtVLfgPTl5vc87Rv3LMUAq6pTHceYQsWnqFsJW3nyBotGKA5dixOU8rvZ5UXGD
3yjK+BCWmNtDbMPyNNnbOTR8i1F3PPlNtKLhUlqWSfQnemTJgwrT++g8QhxqHi4d
OtcWfsX5H/JXBu4xf5MQcK0hUJc8lF+VDC8MiqKGeqpItDp/O0RkVLZyQ+h3Bj07
R7W2gxnLGVycYx+aiH3hH5PZxepVjLoczE05I5EHwoyF/q4izMgWAp4qUA7E8No1
GDgvklHR9Ej05xDscs3/RW5wfka+6fSFn1AEJUISzjK4pUt9hhsP8VfcI9nYl5bI
9QhHBA==
-----END CERTIFICATE-----",
           :idp_cert_fingerprint               => "95c879e4a3402be6e3497d3038cfe98336833565",
           :name_identifier_format             => "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
           :authn_context                      => "http://idmanagement.gov/ns/assurance/loa/1",
           :allowed_clock_drift                => 60,
           :security                           => {:authn_requests_signed => true,
                                                   :embed_sign            => true,
                                                   :digest_method         => "http://www.w3.org/2001/04/xmlenc#sha256",
                                                   :signature_method      => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"}
end
