Rails.application.routes.draw do
  get 'frontpage/index'

  get 'frontpage/login'

  root 'frontpage#index'

  devise_for :users


end
