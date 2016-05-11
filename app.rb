require 'erb'
require 'net/http'
require 'sinatra/base'

class RelyingParty < Sinatra::Base
  def init(uri)
    @auth_server_uri = uri
  end

  def auth_server_uri
    @auth_server_uri ||= URI('https://localhost:1234')
  end

  get '/' do
    agency = params[:agency]
    whitelist = ['uscis']

    if whitelist.include?(agency)
      erb :"agency/#{agency}", :layout => false
    else
      erb :index
    end
  end

  post '/login/?' do
    begin
      Net::HTTP.post_form(auth_server_uri, params)
    rescue
      # Fake a success for now
      call env.merge("PATH_INFO" => '/success', "REQUEST_METHOD" => 'GET')
    end
  end

  get '/success/?' do
    erb :success
  end

  run! if app_file == $0
end
