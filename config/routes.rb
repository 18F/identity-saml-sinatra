Rails.application.routes.draw do
  devise_for :users
  get 'frontpage/index'

  get 'frontpage/login'

  root 'frontpage#index'
end
