require 'dotenv/load'
require 'erb'
require 'hashie/mash'
require 'net/http'
require 'onelogin/ruby-saml'
require 'pp'
require 'sinatra/base'
require 'uri'
require 'yaml'
require 'active_support/core_ext/object/to_query'
require 'active_support/core_ext/object/blank'

class RelyingParty < Sinatra::Base
  use Rack::Session::Cookie, key: 'sinatra_sp', secret: SecureRandom.uuid

  def init(uri)
    @auth_server_uri = uri
  end

  def auth_server_uri
    @auth_server_uri ||= URI('https://localhost:1234')
  end

  def get_param(key, acceptable_values)
    value = params[key]
    value if acceptable_values.include?(value)
  end

  get '/' do
    agency = get_param(:agency, %w[uscis sba ed])

    logout_msg = session.delete(:logout)
    login_msg = session.delete(:login)
    if agency
      session[:agency] = agency
      erb :"agency/#{agency}/index", layout: false, locals: { logout_msg: logout_msg }
    else
      ial = get_param(:ial, %w[sp 1 2 2-strict 0 step-up]) || '1'
      aal = get_param(:aal, %w[sp 1 2 3 3-hspd12]) || '2'
      ial = prepare_step_up_flow(session: session, ial: ial, aal: aal)
      skip_encryption = get_param(:skip_encryption, %w[true false])

      login_path = '/login_get?' + {
        ial: ial,
        aal: aal,
      }.to_query

      session.delete(:agency)
      erb :index, locals: {
        ial: ial,
        aal: aal,
        skip_encryption: skip_encryption,
        logout_msg: logout_msg,
        login_msg: login_msg,
        login_path: login_path,
      }
    end
  end

  get '/login_get/?' do
    puts 'Logging in via GET'
    request = OneLogin::RubySaml::Authrequest.new
    puts "Request: #{request}"
    ial = get_param(:ial, %w[sp 1 2 2-strict 0 step-up]) || '1'
    aal = get_param(:aal, %w[sp 1 2 3 3-hspd12]) || '2'
    ial = prepare_step_up_flow(session: session, ial: ial, aal: aal)
    skip_encryption = get_param(:skip_encryption, %w[true false])
    request_url = request.create(saml_settings(ial: ial, aal: aal))
    request_url += "&#{ { skip_encryption: skip_encryption }.to_query }" if skip_encryption
    redirect to(request_url)
  end

  post '/login_post/?' do
    puts 'Logging in via POST'
    saml_request = OneLogin::RubySaml::Authrequest.new
    puts "Request: #{saml_request}"
    ial = get_param(:ial, %w[sp 1 2 2-strict 0 step-up]) || '1'
    aal = get_param(:aal, %w[sp 1 2 3 3-hspd12]) || '2'
    ial = prepare_step_up_flow(session: session, ial: ial, aal: aal)
    skip_encryption = get_param(:skip_encryption, %w[true false])
    settings = saml_settings(ial: ial, aal: aal)
    post_params = saml_request.create_params(settings, skip_encryption: skip_encryption, 'RelayState' => params[:id])
    login_url   = settings.idp_sso_target_url
    # erb :login_post, locals: { login_url: login_url, post_params: post_params }
    erb :login_post, locals: { login_url: login_url, post_params: { SAMLRequest: "PHNhbWxwOkF1dGhuUmVxdWVzdCB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94
      bWxkc2lnIyIgeG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlv
      biIgeG1sbnM6c2FtbHA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCIgRGVz
      dGluYXRpb249Imh0dHBzOi8vaWRwLmludC5pZGVudGl0eXNhbmRib3guZ292L2FwaS9zYW1sL2F1
      dGgyMDIyIiBGb3JjZUF1dGhuPSJ0cnVlIiBJRD0iRklNUkVRX2YzY2VlZTgwLTAxODQtMWJmZS1h
      ZWQ3LWY1YTQ1N2NmODI0ZiIgSXNQYXNzaXZlPSJmYWxzZSIgSXNzdWVJbnN0YW50PSIyMDIyLTEy
      LTA4VDIyOjE1OjM1WiIgVmVyc2lvbj0iMi4wIj48c2FtbDpJc3N1ZXIgRm9ybWF0PSJ1cm46b2Fz
      aXM6bmFtZXM6dGM6U0FNTDoyLjA6bmFtZWlkLWZvcm1hdDplbnRpdHkiPmh0dHBzOi8vc3FhLmVh
      dXRoLnZhLmdvdi9pc2FtL3Nwcy9zYW1sMjBzcC9zYW1sMjA8L3NhbWw6SXNzdWVyPjxkczpTaWdu
      YXR1cmUgSWQ9InV1aWRmM2NlZWU4Mi0wMTg0LTE5ZDgtYWFkOC1mNWE0NTdjZjgyNGYiPjxkczpT
      aWduZWRJbmZvPjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3
      dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIj48L2RzOkNhbm9uaWNhbGl6YXRpb25NZXRo
      b2Q+PGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEv
      MDQveG1sZHNpZy1tb3JlI3JzYS1zaGEyNTYiPjwvZHM6U2lnbmF0dXJlTWV0aG9kPjxkczpSZWZl
      cmVuY2UgVVJJPSIjRklNUkVRX2YzY2VlZTgwLTAxODQtMWJmZS1hZWQ3LWY1YTQ1N2NmODI0ZiI+
      PGRzOlRyYW5zZm9ybXM+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3Jn
      LzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIj48L2RzOlRyYW5zZm9ybT48ZHM6
      VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMx
      NG4jIj48ZWM6SW5jbHVzaXZlTmFtZXNwYWNlcyB4bWxuczplYz0iaHR0cDovL3d3dy53My5vcmcv
      MjAwMS8xMC94bWwtZXhjLWMxNG4jIiBQcmVmaXhMaXN0PSJkcyBzYW1sIHNhbWxwIj48L2VjOklu
      Y2x1c2l2ZU5hbWVzcGFjZXM+PC9kczpUcmFuc2Zvcm0+PC9kczpUcmFuc2Zvcm1zPjxkczpEaWdl
      c3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGEy
      NTYiPjwvZHM6RGlnZXN0TWV0aG9kPjxkczpEaWdlc3RWYWx1ZT5sY0ZOYi9IZlAzMGYzQ1JPUjNH
      UE4rMUYycmtzVXhEemNZaVNlSmE0Tk1rPTwvZHM6RGlnZXN0VmFsdWU+PC9kczpSZWZlcmVuY2U+
      PC9kczpTaWduZWRJbmZvPjxkczpTaWduYXR1cmVWYWx1ZT5HQlpqWEtqdFNyQkdNaFcraE1QNTdq
      L2dzNFJicG1FNFROdTdsb2RpVzQxUjJTMkFkTHU4T1FhcW9kYTJHQ1kydG9xYkhjWXpZbndtM2Yv
      WFNuanZvS3hSeG13YlhkSmFGOENnV0dXamt5UG9yUGtvRVJ5clUzdHVFU1NWRk1tU2hFQ0RqTTJX
      d3pRbEg5WVlBeEp2dFVKSzhlRWFsbHRJYUp5VnFZTjd2UUdJNlZwcjhFdWI3S2tzaFd0VVRabGxH
      Q1ZtM052VVRNZ3JjMVFpeEZxQkZoOTZwMERBc2g2bzZkbkYwcVVVdHdLOFE4OUdiR3htK1RtYVRF
      dXJjam16Y0FDZ1Q3OEprV3Vsa0daOWVuYWNxVi9zODRLYTVtUXQzV0d2SGlpTVh4aFl6UHpQaVZ5
      emkzcWwxWXZtdC94MUwzc0FZeHZXNUNlYTFoTVZZSEg1bGRvdW5tM2RES1JqeWZYdFh6eU1mRzFr
      akNEYU4xSEVTMnVZeHV2SjNNYklKNnd1TWtOZVpTNHZMVzlYSzJKL1BDUm5jZWMxQ0Q3RUtVdDN2
      Y3J1SEZyWm5JcFpsenNYMjJpUE4zdjBWR2w3aVI5YnlTMndNbFc5Y2dKZ0s0RlhwZlVyYUoycjEw
      S1ZiMHQySCsra2wxNmVnSXVSR2cyT2h4VFRrZWNPdGpIL0l0MzJNa0pmL3g4R1V3blBxR1JlR3cw
      dUMxdUV0TExiYjNRcUtOZC91bmVUdVhxWnJ4bmp1aUJJOEVudXVTQzdGZ3ZXeEQ4RkNJbUxQbXlU
      dGtxUnlqYTZCK0hxR3hZNXdZeEx0elplclo0VlhiV3NiWkxTVW5KbUlkR2twdGdRTmVCRmozcnFS
      d014VGI2ZGwxcWlyeXZpcHUxQkFSZDhqNnV0Qk0wTXI5az08L2RzOlNpZ25hdHVyZVZhbHVlPjxk
      czpLZXlJbmZvPjxkczpYNTA5RGF0YT48ZHM6WDUwOUNlcnRpZmljYXRlPk1JSUh4akNDQnE2Z0F3
      SUJBZ0lRRHFSWFN6TzBIby91ZmhIYTZuL1NDVEFOQmdrcWhraUc5dzBCQVFzRkFEQlBNUXN3Q1FZ
      RFZRUUdFd0pWVXpFVk1CTUdBMVVFQ2hNTVJHbG5hVU5sY25RZ1NXNWpNU2t3SndZRFZRUURFeUJF
      YVdkcFEyVnlkQ0JVVEZNZ1VsTkJJRk5JUVRJMU5pQXlNREl3SUVOQk1UQWVGdzB5TWpBNU1Ua3dN
      REF3TURCYUZ3MHlNekV3TVRBeU16VTVOVGxhTUhveEN6QUpCZ05WQkFZVEFsVlRNUTR3REFZRFZR
      UUlFd1ZVWlhoaGN6RVNNQkFHQTFVRUJ4TUpRWEpzYVc1bmRHOXVNU3d3S2dZRFZRUUtFeU5WTGxN
      dUlFUmxjR0Z5ZEcxbGJuUWdiMllnVm1WMFpYSmhibk1nUVdabVlXbHljekVaTUJjR0ExVUVBeE1R
      WkdWMkxtVmhkWFJvTG5aaExtZHZkakNDQWlJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dJUEFEQ0NB
      Z29DZ2dJQkFLMmFMSThiT3JFVGNZVlh2ZXoxVElnVFNkR2NxdDZUZkhIOUxPcDRJNVF2VUIrSjA5
      M0xPek83cEMyek5YL2hmZkxUaUEvRkVCWTZaSDltUUx1cHE5b015Q0tSVUpmczlZZ29rc01xcG9B
      QUcvazBHcHR4K3pGSXJ1VnFHVVdETlZDSjJ5ZjhxZFA1aThsUXkrdDZmNUlMb0JsYnVwZ3ZHb0hw
      cFlya1NNSkY0QjRMNWhCWVd5L2I0RWxvV1dwVG1DUks1MURxa1FacDk1ZWVUOHp2U2NFRWhYc0RY
      QlhIVUlvU0hka04rL25HU1lVdUY2SktLVnZGSTFXVFdJVDlONTZ4SWptMjA5QU12c1Y1ZG43VlhI
      QmxxUjVVRVcydHowVlFXQnk0dEIyL2VVQ1dJSjNRQURtVCtYekpjREZrOWZmR3BkYlNIRUNzVjZt
      Y3E5RFlaOU9jRTlZMllWU3o1V0N4dVp5OG5obkxmV2ljZWh6NjdsZ1kvYkpsQjBOeFlQaGpLaWY0
      V2g5YjhUOEI5Zlo3Mzh4UGNXOS81aGswRFJVM3U2MUJlTWF2dDIwRVVPZlJwOE96NUh2TUNHa3JU
      UjdlSTBnd2JsYjc0VmdYekVoRVkvNi90QkJNNEpWUFZvUFErcWhMUXFKMXl2YXlKZXNyME5PMDFr
      bkJPL2JSUWhYaU5pTWplb3VibGJISkNYMUlNZ3BjRlVXbUpzQnB6RncyTzFzWW8zcXZKclNpVGEv
      QnpkZDhxaDhhV0tpcE1rbFk3UmdDK04rWDNjM1BMVjVwSDJtT3V5MmlSN3FCaTQ1d3cyU2pCRlBv
      KzFpTkdlaFRaeDNmam1FSHlBK2tpVHZrZU93UGVYMkhSVkMyMndPQ1dBS1NrUnNvNFY1QVhKQ2Zs
      MmFic0xBRkFnTUJBQUdqZ2dOeE1JSURiVEFmQmdOVkhTTUVHREFXZ0JTM2E2THFxS3FFakhucXRO
      b1BtTExGbFhhNTlEQWRCZ05WSFE0RUZnUVVSZ1lrVlpPbG9TYWd2c3NxWndvbGdFMHp0eTR3R3dZ
      RFZSMFJCQlF3RW9JUVpHVjJMbVZoZFhSb0xuWmhMbWR2ZGpBT0JnTlZIUThCQWY4RUJBTUNCYUF3
      SFFZRFZSMGxCQll3RkFZSUt3WUJCUVVIQXdFR0NDc0dBUVVGQndNQ01JR1BCZ05WSFI4RWdZY3dn
      WVF3UUtBK29EeUdPbWgwZEhBNkx5OWpjbXd6TG1ScFoybGpaWEowTG1OdmJTOUVhV2RwUTJWeWRG
      Uk1VMUpUUVZOSVFUSTFOakl3TWpCRFFURXROQzVqY213d1FLQStvRHlHT21oMGRIQTZMeTlqY213
      MExtUnBaMmxqWlhKMExtTnZiUzlFYVdkcFEyVnlkRlJNVTFKVFFWTklRVEkxTmpJd01qQkRRVEV0
      TkM1amNtd3dQZ1lEVlIwZ0JEY3dOVEF6QmdabmdRd0JBZ0l3S1RBbkJnZ3JCZ0VGQlFjQ0FSWWJh
      SFIwY0RvdkwzZDNkeTVrYVdkcFkyVnlkQzVqYjIwdlExQlRNSDhHQ0NzR0FRVUZCd0VCQkhNd2NU
      QWtCZ2dyQmdFRkJRY3dBWVlZYUhSMGNEb3ZMMjlqYzNBdVpHbG5hV05sY25RdVkyOXRNRWtHQ0Nz
      R0FRVUZCekFDaGoxb2RIUndPaTh2WTJGalpYSjBjeTVrYVdkcFkyVnlkQzVqYjIwdlJHbG5hVU5s
      Y25SVVRGTlNVMEZUU0VFeU5UWXlNREl3UTBFeExURXVZM0owTUFrR0ExVWRFd1FDTUFBd2dnRi9C
      Z29yQmdFRUFkWjVBZ1FDQklJQmJ3U0NBV3NCYVFCMkFLMzN2dnA4L3hESWk1MDluQjQrR0dxMFp5
      bGR6N0VNSk1xRmhqVHIzSUtLQUFBQmcxYmJuSkFBQUFRREFFY3dSUUlnY0p6cEc5SXg3WGVpdHVS
      ekJkRTNubkZxOEZwZy94RVV0ZHd3RUZxQUNoc0NJUURMZGVEQVdwNWpwVzNBLzZSZGwzejhzZzJy
      Q0JtaDFYb0RCOGM5UFQ4NklBQjNBRFhQR1J1L3NXeFh2dyt0VEcxQ3k3dTJKeUFtVWVvLzRTcnZx
      QVBETzlaTUFBQUJnMWJibkhzQUFBUURBRWd3UmdJaEFQUXdGdm1WTEVlaVJwTmdsRmJYc2Y4SWpS
      TlJUNVhZSmhmNzZ5Y1ppSTZyQWlFQS9FaU1ObW9GRGkrSUd0N2NwMDRpRHZxNW05SU1CK3d5YTgw
      Smg2ZzM4ajhBZGdDemMzY0g0WVJRK0dPRzFnV3AzQkVKU25rdHNXY01DNGZjOEFNT2VUYWxtZ0FB
      QVlOVzI1eTVBQUFFQXdCSE1FVUNJUUM1Tk9WVXFXSzFFSFdEM3d4RUZCZmZtZDM1dXQ3bnFjQmRQ
      TTlZNEltazBRSWdWT1NTa2dCKzlMQUZ0cDJSblp4M1BiSC9rVjdXcTNkQ2J6ZTRvano0STRNd0RR
      WUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFCN0x0OWEzeDRaWDBBYXNKRzZDMXJiVm51Tmlra05CUjZS
      YkoxbGdzMzJKc1hMZFJGcG9xTWJNZCt6dzg5RFJmaTB6YTRNcGZUUUFVb3VvV284RHpweDQ5K0ha
      TXR2TzhhSUZ6dHA3UUR3VXYxdnVrdEtxWHhqUjlKNHEwQVZvS1lVbVFPV0ZNR0tMamI5UDZrVExL
      b0N6TDRieTNERTRpOUI1cFZzdkJkZzNhZVBtR1hGb3ZMMTVNRXRBN2h0QmlqdGROYWtwSktVd3hM
      T2RFdGNVQndCbWM3MnBpbk5ZNXphQURwbHZhemh1Q1grY2pBczh5OFhTczF1ZjNXUVB6TmZmcW00
      VTZXeS9sZEhBdUZZODBmTk13MEVLd0RXUkI2WVgxNEd1T2szTXQ0WW9hUkp5dHd6QUtOQVlpenh1
      SjNUclM4WWxhZEZ5U2N3b245NVhRYmM9PC9kczpYNTA5Q2VydGlmaWNhdGU+PC9kczpYNTA5RGF0
      YT48L2RzOktleUluZm8+PC9kczpTaWduYXR1cmU+PHNhbWxwOk5hbWVJRFBvbGljeSBBbGxvd0Ny
      ZWF0ZT0iZmFsc2UiIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6MS4xOm5hbWVpZC1m
      b3JtYXQ6ZW1haWxBZGRyZXNzIj48L3NhbWxwOk5hbWVJRFBvbGljeT48c2FtbHA6UmVxdWVzdGVk
      QXV0aG5Db250ZXh0IENvbXBhcmlzb249Im1pbmltdW0iPjxzYW1sOkF1dGhuQ29udGV4dENsYXNz
      UmVmPmh0dHA6Ly9pZG1hbmFnZW1lbnQuZ292L25zL2Fzc3VyYW5jZS9pYWwvMTwvc2FtbDpBdXRo
      bkNvbnRleHRDbGFzc1JlZj48c2FtbDpBdXRobkNvbnRleHRDbGFzc1JlZj5odHRwOi8vaWRtYW5h
      Z2VtZW50Lmdvdi9ucy9hc3N1cmFuY2UvYWFsLzI8L3NhbWw6QXV0aG5Db250ZXh0Q2xhc3NSZWY+
      PC9zYW1scDpSZXF1ZXN0ZWRBdXRobkNvbnRleHQ+PC9zYW1scDpBdXRoblJlcXVlc3Q+"} }
  end

  post '/logout/?' do
    puts 'Logout received'
    settings = saml_settings.dup
    settings.name_identifier_value = session[:userid]
    redirect to(OneLogin::RubySaml::Logoutrequest.new.create(settings))
  end

  post '/slo_logout/?' do
    if params[:SAMLRequest]
      puts 'SLO request came from IdP'
      idp_logout_request
    elsif params[:SAMLResponse]
      puts 'SLO response received'
      validate_slo_response
    else
      sp_logout_request
    end
  end

  get '/success/?' do
    agency = session[:agency]
    puts 'Success!'
    if !agency.nil?
      erb :"agency/#{agency}/success", layout: false
    else
      session[:login] = 'ok'
      redirect to('/')
    end
  end

  post '/consume/?' do
    response = OneLogin::RubySaml::Response.new(
      params.fetch('SAMLResponse'), settings: saml_settings
    )
    # require 'pry'
    # binding.pry

    user_uuid = response.name_id.gsub(/^_/, '')

    puts "Got SAMLResponse from NAMEID: #{user_uuid}"

    if response.is_valid?
      if session.delete(:step_up_enabled)
        aal = session.delete(:step_up_aal)

        redirect to("/login_get/?aal=#{aal}&ial=2")
      else
        session[:userid] = user_uuid
        session[:email] = response.attributes['email']
        session[:attributes] = response.attributes.to_h.to_json

        puts 'SAML Success!'
        redirect to('/success')
      end
    else
      puts 'SAML Fail :('
      @errors = response.errors
      erb :failure
    end
  end

  private

  def logout_session
    session.delete(:userid)
    session.delete(:email)
    session.delete(:attributes)
    session.delete(:step_up_enabled)
    session.delete(:step_up_aal)
  end

  def home_page
    if session[:agency]
      '/?' + { agency: session[:agency] }.to_query
    else
      '/'
    end
  end

  def saml_settings(ial: nil, aal: nil)
    template = File.read('config/saml_settings.yml')
    base_config = Hashie::Mash.new(YAML.safe_load(ERB.new(template).result(binding)))

    ial_context = case ial
    when '1'
      'http://idmanagement.gov/ns/assurance/ial/1'
    when '2'
      'http://idmanagement.gov/ns/assurance/ial/2'
    when '2-strict'
      'http://idmanagement.gov/ns/assurance/ial/2?strict=true'
    when '0'
      'http://idmanagement.gov/ns/assurance/ial/0'
    else
      nil
    end

    aal_context = case aal
    when '2'
      'http://idmanagement.gov/ns/assurance/aal/2'
    when '3'
      'http://idmanagement.gov/ns/assurance/aal/3'
    when '3-hspd12'
      'http://idmanagement.gov/ns/assurance/aal/3?hspd12=true'
    else
      nil
    end

    base_config.ial_context = ial_context if ial_context
    base_config.aal_context = aal_context if aal_context
    base_config.authn_context = [base_config.ial_context, base_config.aal_context].compact

    base_config.certificate = saml_sp_certificate
    base_config.private_key = saml_sp_private_key

    OneLogin::RubySaml::Settings.new(base_config)
  end

  def saml_sp_certificate
    return @saml_sp_certificate if defined?(@saml_sp_certificate)

    if running_in_prod_env? && !ENV['sp_cert']
      raise NotImplementedError, 'Refusing to use demo cert in production'
    end

    @saml_sp_certificate = ENV['sp_cert'] || File.read('config/demo_sp.crt')
  end

  def saml_sp_private_key
    return @saml_sp_private_key if defined?(@saml_sp_private_key)

    if running_in_prod_env? && !ENV['sp_private_key']
      raise NotImplementedError, 'Refusing to use demo private key in production'
    end

    @saml_sp_private_key = ENV['sp_private_key'] || File.read('config/demo_sp.key')
  end

  def running_in_prod_env?
    @running_in_prod_env ||= URI.parse(ENV['idp_sso_target_url']).hostname.match?(/login\.gov/)
  end

  def idp_logout_request
    logout_request = OneLogin::RubySaml::SloLogoutrequest.new(
      params[:SAMLRequest],
      settings: saml_settings
    )
    if logout_request.is_valid?
      redirect_to_logout(logout_request)
    else
      render_logout_error(logout_request)
    end
  end

  def redirect_to_logout(logout_request)
    puts "IdP initiated Logout for #{logout_request.nameid}"
    logout_session
    logout_response = OneLogin::RubySaml::SloLogoutresponse.new.create(
      saml_settings,
      logout_request.id,
      nil,
      RelayState: params[:RelayState]
    )
    redirect to(logout_response)
  end

  def render_logout_error(logout_request)
    error_msg = "IdP initiated LogoutRequest was not valid: #{logout_request.errors}"
    puts error_msg
    @errors = error_msg
    erb :failure
  end

  def validate_slo_response
    slo_response = idp_logout_response
    if slo_response.validate
      puts 'Logout OK'
      logout_session
      session[:logout] = 'ok'
      redirect to(home_page)
    else
      puts 'Logout failed'
      session[:logout] = 'fail'
      redirect to(home_page)
    end
  end

  def idp_logout_response
    OneLogin::RubySaml::Logoutresponse.new(params[:SAMLResponse], saml_settings)
  end

  def sp_logout_request
    settings = saml_settings.dup
    settings.name_identifier_value = session[:user_id]
    logout_request = OneLogin::RubySaml::Logoutrequest.new.create(settings)
    redirect to(logout_request)
  end

  def prepare_step_up_flow(session:, ial:, aal: nil)
    if ial == 'step-up'
      ial = '1'
      session[:step_up_enabled] = 'true'
      session[:step_up_aal] = aal if %r{^\d$}.match?(aal)
    else
      session.delete(:step_up_enabled)
      session.delete(:step_up_aal)
    end

    ial
  end

  def maybe_redact_ssn(ssn)
    ssn&.gsub(/\d/, '#')
  end

  run! if app_file == $0
end
