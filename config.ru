app_mode = ENV.fetch('APP_MODE', 'rp')

if app_mode == 'broker'
	require './broker_app'
	run HeadlessBroker.new
else
	require './app'
	run RelyingParty.new
end
