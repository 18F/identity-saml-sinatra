Rails.application.config.middleware.use OmniAuth::Builder do
  provider :saml,
           :assertion_consumer_service_url     => "http://localhost:3003/consume",
           :assertion_consumer_service_binding => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
           :issuer                             => Rails.configuration.x.saml_issuer,
           :idp_sso_target_url                 => "https://upaya-idp-dev.18f.gov/api/saml/auth",
           :idp_cert                           => File.read('config/demo_sp.key'),
           :idp_cert_fingerprint               => "95c879e4a3402be6e3497d3038cfe98336833565",
           :name_identifier_format             => "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
           :authn_context                      => "http://idmanagement.gov/ns/assurance/loa/1",
           :allowed_clock_drift                => 60,
           :security                           => {:authn_requests_signed => true,
                                                   :embed_sign            => true,
                                                   :digest_method         => "http://www.w3.org/2001/04/xmlenc#sha256",
                                                   :signature_method      => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"}
end
