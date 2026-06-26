require 'dotenv/load'
require 'base64'
require 'erb'
require 'hashie/mash'
require 'json'
require 'onelogin/ruby-saml'
require 'openssl'
require 'saml_idp'
require 'sinatra/base'
require 'ostruct'
require 'uri'
require 'yaml'
require 'cgi'
require 'net/http'
require 'rexml/document'
require 'rexml/xpath'

class HeadlessBroker < Sinatra::Base
  use Rack::Session::Cookie, key: 'headless_broker', secret: SecureRandom.hex(32)

  helpers do
    def broker_secret
      ENV.fetch('BROKER_STATE_SECRET')
    end

    def encode_state(payload)
      body = Base64.urlsafe_encode64(payload.to_json)
      sig = OpenSSL::HMAC.hexdigest('SHA256', broker_secret, body)
      "#{body}.#{sig}"
    end

    def decode_state(token)
      body, sig = token.to_s.split('.', 2)
      return nil if body.nil? || sig.nil?

      expected_sig = OpenSSL::HMAC.hexdigest('SHA256', broker_secret, body)
      return nil unless Rack::Utils.secure_compare(sig, expected_sig)

      JSON.parse(Base64.urlsafe_decode64(body))
    rescue JSON::ParserError, ArgumentError
      nil
    end

    def incoming_relay_state
      params['RelayState'] || params['relay_state'] || params['TargetResource']
    end

    def default_relay_state
      ENV['BROKER_DEFAULT_RELAY_STATE']
    end

    def aws_signin_url
      ENV.fetch('AWS_SIGNIN_URL', 'https://signin.aws.amazon.com/saml')
    end

    def aws_saml_provider_arn
      ENV.fetch('BROKER_AWS_SAML_PROVIDER_ARN')
    end

    def aws_role_arn
      ENV.fetch('BROKER_AWS_ROLE_ARN')
    end

    def aws_role_arns_json
      ENV.fetch('BROKER_AWS_ROLE_ARNS_JSON', '')
    end

    def configured_role_arns
      return @configured_role_arns if defined?(@configured_role_arns)

      @configured_role_arns = {}
      return @configured_role_arns if aws_role_arns_json.empty?

      parsed = JSON.parse(aws_role_arns_json)
      parsed.each do |key, value|
        @configured_role_arns[key.to_s] = value
      end
      @configured_role_arns
    rescue JSON::ParserError
      {}
    end

    def role_arn_for(role_key)
      return aws_role_arn if role_key.nil? || role_key.empty?

      configured_role_arns[role_key.to_s]
    end

    def aws_idp_entity_id
      ENV.fetch('BROKER_AWS_IDP_ENTITY_ID', ENV.fetch('BROKER_ISSUER'))
    end

    def broker_public_url
      ENV.fetch('BROKER_PUBLIC_URL', request.base_url)
    end

    def broker_idp_metadata_url
      ENV.fetch('BROKER_IDP_METADATA_URL', '')
    end

    def broker_idp_metadata_cache_seconds
      Integer(ENV.fetch('BROKER_IDP_METADATA_CACHE_SECONDS', '300'))
    rescue ArgumentError
      300
    end

    def broker_idp_cert
      ENV.fetch('BROKER_IDP_CERT', '')
    end

    def metadata_xml(url)
      uri = URI.parse(url)
      raise 'BROKER_IDP_METADATA_URL must be https' unless uri.scheme == 'https'

      Net::HTTP.start(uri.host, uri.port, use_ssl: true, open_timeout: 5, read_timeout: 5) do |http|
        request = Net::HTTP::Get.new(uri)
        request['Accept'] = 'application/xml,text/xml'
        response = http.request(request)
        raise "metadata fetch failed: #{response.code}" unless response.is_a?(Net::HTTPSuccess)

        response.body
      end
    end

    def cert_from_metadata_xml(xml)
      doc = REXML::Document.new(xml)
      cert_node = REXML::XPath.first(doc, "//*[local-name()='X509Certificate']")
      cert_text = cert_node&.text&.gsub(/\s+/, '')
      return nil if cert_text.nil? || cert_text.empty?

      "-----BEGIN CERTIFICATE-----\n#{cert_text.scan(/.{1,64}/).join("\n")}\n-----END CERTIFICATE-----\n"
    end

    def broker_idp_cert_from_metadata
      return @broker_idp_cert_from_metadata if defined?(@broker_idp_cert_from_metadata) && @broker_idp_cert_from_metadata_expires_at && Time.now < @broker_idp_cert_from_metadata_expires_at

      return nil if broker_idp_metadata_url.empty?

      xml = metadata_xml(broker_idp_metadata_url)
      cert = cert_from_metadata_xml(xml)
      @broker_idp_cert_from_metadata = cert
      @broker_idp_cert_from_metadata_expires_at = Time.now + broker_idp_metadata_cache_seconds
      cert
    rescue StandardError
      nil
    end

    def metadata_sso_location
      "#{broker_public_url}/"
    end

    def metadata_slo_location
      "#{broker_public_url}/slo_logout"
    end

    def saml_sp_certificate_base64
      saml_sp_certificate
        .gsub('-----BEGIN CERTIFICATE-----', '')
        .gsub('-----END CERTIFICATE-----', '')
        .gsub(/\s+/, '')
    end

    def broker_metadata_xml
      entity_id = CGI.escapeHTML(aws_idp_entity_id)
      cert = CGI.escapeHTML(saml_sp_certificate_base64)
      sso_location = CGI.escapeHTML(metadata_sso_location)
      slo_location = CGI.escapeHTML(metadata_slo_location)

      <<~XML
        <?xml version="1.0" encoding="UTF-8"?>
        <EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="#{entity_id}">
          <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAuthnRequestsSigned="false">
            <KeyDescriptor use="signing">
              <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data>
                  <ds:X509Certificate>#{cert}</ds:X509Certificate>
                </ds:X509Data>
              </ds:KeyInfo>
            </KeyDescriptor>
            <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="#{sso_location}"/>
            <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="#{slo_location}"/>
          </IDPSSODescriptor>
        </EntityDescriptor>
      XML
    end

    def aws_audience_uri
      ENV.fetch('BROKER_AWS_AUDIENCE', 'urn:amazon:webservices')
    end

    def aws_role_pair_value
      "#{aws_role_arn},#{aws_saml_provider_arn}"
    end

    def broker_user_map_file
      ENV.fetch('BROKER_USER_MAP_FILE', '')
    end

    def broker_user_map
      return @broker_user_map if defined?(@broker_user_map)
      return @broker_user_map = {} if broker_user_map_file.empty?

      @broker_user_map = YAML.safe_load(File.read(broker_user_map_file), aliases: false) || {}
    end

    def user_map_enabled?
      !broker_user_map_file.empty?
    end

    def first_attr_value(login_gov_response, key)
      value = login_gov_response.attributes[key]
      return value.first if value.is_a?(Array)

      value
    end

    def normalized_identifiers(login_gov_response)
      email = first_attr_value(login_gov_response, 'email')
      uuid = first_attr_value(login_gov_response, 'uuid')
      name_id = login_gov_response.name_id

      {
        'email' => email&.downcase,
        'uuid' => uuid,
        'name_id' => name_id,
      }
    end

    def user_map_lookup_keys
      ENV.fetch('BROKER_USER_MAP_KEYS', 'email,uuid,name_id').split(',').map(&:strip).reject(&:empty?)
    end

    def mapped_user_entry(login_gov_response)
      users = broker_user_map.fetch('users', {})
      identifiers = normalized_identifiers(login_gov_response)

      user_map_lookup_keys.each do |lookup_key|
        identifier_value = identifiers[lookup_key]
        next if identifier_value.nil? || identifier_value.empty?

        entry = users[identifier_value]
        return [lookup_key, identifier_value, entry] unless entry.nil?
      end

      nil
    end

    def user_authorization_context(login_gov_response)
      default_entry = broker_user_map.fetch('default', {})
      mapped = mapped_user_entry(login_gov_response)

      if mapped.nil?
        if user_map_enabled? && default_entry.empty?
          return {
            authorized: false,
            reason: 'unmapped_user',
            identifiers: normalized_identifiers(login_gov_response),
          }
        end

        entry = {}
        matched_by = nil
        matched_value = nil
      else
        matched_by, matched_value, entry = mapped
      end

      role_key = entry.fetch('aws_role', default_entry['aws_role'])
      role_arn = role_arn_for(role_key)
      provider_arn = aws_saml_provider_arn
      role_session_name = entry.fetch('role_session_name', default_entry['role_session_name'])
      session_duration = entry.fetch('session_duration', default_entry['session_duration'])
      quicksight_groups = entry.fetch('quicksight_groups', default_entry['quicksight_groups'])

      if role_arn.nil? || provider_arn.nil?
        return {
          authorized: false,
          reason: 'missing_role_mapping',
          matched_by: matched_by,
          matched_value: matched_value,
        }
      end

      {
        authorized: true,
        matched_by: matched_by,
        matched_value: matched_value,
        aws_role: role_key,
        aws_role_arn: role_arn,
        aws_saml_provider_arn: provider_arn,
        role_session_name: role_session_name,
        session_duration: session_duration,
        quicksight_groups: quicksight_groups,
      }
    end

    def normalized_quicksight_groups(authz)
      Array(authz[:quicksight_groups]).map(&:to_s).map(&:strip).reject(&:empty?).uniq
    end

    def normalized_session_name(value)
      candidate = value.to_s.gsub(/[^A-Za-z0-9+=,.@-]/, '-')
      bounded = candidate[0, 64]
      bounded.empty? ? 'broker-session' : bounded
    end

    def role_session_name_for(login_gov_response, authz)
      mapped_name = authz[:role_session_name]
      return normalized_session_name(mapped_name) unless mapped_name.to_s.empty?

      static_name = ENV['BROKER_AWS_ROLE_SESSION_NAME_STATIC']
      return normalized_session_name(static_name) unless static_name.to_s.empty?

      source = ENV.fetch('BROKER_AWS_ROLE_SESSION_NAME_SOURCE', 'email')
      if source == 'name_id'
        return normalized_session_name(login_gov_response.name_id)
      end

      email = login_gov_response.attributes['email']
      normalized_session_name(email || login_gov_response.name_id)
    end

    def aws_session_duration
      value = ENV['BROKER_AWS_SESSION_DURATION']
      return nil if value.to_s.empty?

      Integer(value)
    rescue ArgumentError
      nil
    end

    def resolved_session_duration(authz)
      value = authz[:session_duration]
      return aws_session_duration if value.nil?

      Integer(value)
    rescue ArgumentError
      aws_session_duration
    end

    def build_aws_saml_response(login_gov_response, authz)
      role_session_name = role_session_name_for(login_gov_response, authz)
      session_duration = resolved_session_duration(authz)
      role_pair_value = "#{authz[:aws_role_arn]},#{authz[:aws_saml_provider_arn]}"
      quicksight_groups = normalized_quicksight_groups(authz)
      login_email = first_attr_value(login_gov_response, 'email')
      tag_keys = []

      principal = OpenStruct.new(
        name_id: role_session_name,
        role: role_pair_value,
        role_session_name: role_session_name,
        session_duration: session_duration,
        quicksight_groups_tag: quicksight_groups.join(','),
        email_tag: login_email,
        transitive_tag_keys: nil
      )

      asserted_attributes = {
        role: {
          name: 'https://aws.amazon.com/SAML/Attributes/Role',
          getter: :role,
        },
        role_session_name: {
          name: 'https://aws.amazon.com/SAML/Attributes/RoleSessionName',
          getter: :role_session_name,
        },
      }

      if session_duration
        asserted_attributes[:session_duration] = {
          name: 'https://aws.amazon.com/SAML/Attributes/SessionDuration',
          getter: :session_duration,
        }
      end

      unless login_email.to_s.empty?
        asserted_attributes[:principal_tag_email] = {
          name: 'https://aws.amazon.com/SAML/Attributes/PrincipalTag:Email',
          getter: :email_tag,
        }
        tag_keys << 'Email'
      end

      unless quicksight_groups.empty?
        asserted_attributes[:principal_tag_quicksight_groups] = {
          name: 'https://aws.amazon.com/SAML/Attributes/PrincipalTag:QuickSightGroups',
          getter: :quicksight_groups_tag,
        }
        tag_keys << 'QuickSightGroups'
      end

      unless tag_keys.empty?
        principal.transitive_tag_keys = tag_keys.join(',')
        asserted_attributes[:transitive_tag_keys] = {
          name: 'https://aws.amazon.com/SAML/Attributes/TransitiveTagKeys',
          getter: :transitive_tag_keys,
        }
      end

      SamlIdp.configure do |config|
        config.x509_certificate = -> { saml_sp_certificate }
        config.secret_key = -> { saml_sp_private_key }
        config.algorithm = :sha256
      end

      SamlIdp::SamlResponse.new(
        SecureRandom.uuid,
        SecureRandom.uuid,
        aws_idp_entity_id,
        principal,
        aws_audience_uri,
        nil,
        aws_signin_url,
        :sha256,
        'http://idmanagement.gov/ns/assurance/aal/1',
        60 * 60,
        nil,
        0,
        {
          persistent: ->(p) { p.name_id },
        },
        asserted_attributes,
        true,
        true,
        false
      ).build
    end

    def relay_state_allowed?(relay_state)
      allowlist = ENV.fetch('BROKER_RELAY_STATE_ALLOWLIST_PREFIXES', '').split(',').map(&:strip).reject(&:empty?)
      return true if allowlist.empty?

      allowlist.any? { |prefix| relay_state.start_with?(prefix) }
    end

    def resolved_relay_state(preferred_relay_state)
      candidate = preferred_relay_state || default_relay_state
      return nil if candidate.nil? || candidate.empty?
      return candidate if relay_state_allowed?(candidate)

      nil
    end

    def saml_settings
      template = File.read('config/broker_saml_settings.yml')
      base_config = Hashie::Mash.new(YAML.safe_load(ERB.new(template).result(binding)))

      base_config.certificate = saml_sp_certificate
      base_config.private_key = saml_sp_private_key

      dynamic_idp_cert = if !broker_idp_cert.empty?
        broker_idp_cert
      else
        broker_idp_cert_from_metadata
      end

      unless dynamic_idp_cert.nil? || dynamic_idp_cert.empty?
        base_config.idp_cert = dynamic_idp_cert
        base_config.delete('idp_cert_fingerprint')
        base_config.delete('idp_cert_fingerprint_algorithm')
      end

      OneLogin::RubySaml::Settings.new(base_config)
    end

    def saml_sp_certificate
      return @saml_sp_certificate if defined?(@saml_sp_certificate)

      @saml_sp_certificate = ENV.fetch('BROKER_SP_CERT') do
        File.read('config/demo_sp.crt')
      end
    end

    def saml_sp_private_key
      return @saml_sp_private_key if defined?(@saml_sp_private_key)

      @saml_sp_private_key = ENV.fetch('BROKER_SP_PRIVATE_KEY') do
        File.read('config/demo_sp.key')
      end
    end

    def add_relay_state(url, relay_state)
      uri = URI.parse(url)
      query = URI.decode_www_form(uri.query.to_s)
      query << ['RelayState', relay_state]
      uri.query = URI.encode_www_form(query)
      uri.to_s
    end

    def start_idp_login
      authn_request = OneLogin::RubySaml::Authrequest.new
      relay_state = incoming_relay_state
      signed_state = encode_state(
        {
          relay_state: relay_state,
          issued_at: Time.now.to_i,
        }
      )

      request_url = authn_request.create(saml_settings)
      redirect to(add_relay_state(request_url, signed_state))
    end

    def json(body, status_code: 200)
      content_type :json
      status status_code
      JSON.pretty_generate(body)
    end
  end

  get '/health' do
    json({ ok: true, service: 'headless-login-gov-broker' })
  end

  get '/metadata' do
    content_type 'application/samlmetadata+xml'
    broker_metadata_xml
  end

  get '/' do
    start_idp_login
  end

  get '/idp-init' do
    start_idp_login
  end

  post '/acs' do
    raw_login_gov_saml_response = params.fetch('SAMLResponse')
    response = OneLogin::RubySaml::Response.new(raw_login_gov_saml_response, settings: saml_settings)

    unless response.is_valid?
      return json(
        {
          ok: false,
          phase: 'acs',
          errors: response.errors,
        },
        status_code: 400
      )
    end

    broker_state = decode_state(params['RelayState'])
    requested_relay_state = broker_state && broker_state['relay_state']
    final_relay_state = resolved_relay_state(requested_relay_state)
    output_mode = ENV.fetch('BROKER_OUTPUT_MODE', 'aws_broker_assertion')

    if output_mode == 'aws_broker_assertion'
      authz = user_authorization_context(response)
      unless authz[:authorized]
        return json(
          {
            ok: false,
            phase: 'authorization',
            reason: authz[:reason],
            details: authz,
          },
          status_code: 403
        )
      end

      aws_response = build_aws_saml_response(response, authz)
      relay_html = final_relay_state ? "<input type=\"hidden\" name=\"RelayState\" value=\"#{Rack::Utils.escape_html(final_relay_state)}\">" : ''

      return <<~HTML
        <!doctype html>
        <html>
        <body onload="document.forms[0].submit()">
          <form action="#{Rack::Utils.escape_html(aws_signin_url)}" method="post">
            <input type="hidden" name="SAMLResponse" value="#{Rack::Utils.escape_html(aws_response)}">
            #{relay_html}
          </form>
        </body>
        </html>
      HTML
    end

    if output_mode == 'aws_post'
      relay_html = final_relay_state ? "<input type=\"hidden\" name=\"RelayState\" value=\"#{Rack::Utils.escape_html(final_relay_state)}\">" : ''

      return <<~HTML
        <!doctype html>
        <html>
        <body onload="document.forms[0].submit()">
          <form action="#{Rack::Utils.escape_html(aws_signin_url)}" method="post">
            <input type="hidden" name="SAMLResponse" value="#{Rack::Utils.escape_html(raw_login_gov_saml_response)}">
            #{relay_html}
          </form>
        </body>
        </html>
      HTML
    end

    json(
      {
        ok: true,
        phase: 'acs',
        name_id: response.name_id,
        requested_relay_state: requested_relay_state,
        resolved_relay_state: final_relay_state,
        output_mode: output_mode,
        user_map_enabled: user_map_enabled?,
        attributes: response.attributes.to_h,
        note: 'BROKER_OUTPUT_MODE=aws_broker_assertion mints a broker-signed AWS-compatible assertion. BROKER_OUTPUT_MODE=aws_post forwards Login.gov assertion as-is.',
      }
    )
  rescue OpenSSL::PKey::RSAError, OpenSSL::PKey::PKeyError => e
    json(
      {
        ok: false,
        phase: 'acs',
        error: 'saml_assertion_decryption_failed',
        message: 'Unable to decrypt Login.gov SAML assertion. Verify BROKER_SP_PRIVATE_KEY matches the certificate registered for this SP in the Login.gov partner portal.',
        details: e.message,
      },
      status_code: 400
    )
  rescue KeyError
    json({ ok: false, error: 'missing SAMLResponse' }, status_code: 400)
  end
end
