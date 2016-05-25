Rails.application.routes.draw do
  get 'frontpage/index'

  get 'frontpage/login'

  get 'consume', to: 'frontpage/login_return'

  root 'frontpage#index'

  devise_for :users, :controllers => { :omniauth_callbacks => "users/omniauth_callbacks" }
end
