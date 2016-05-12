Rails.application.routes.draw do
  get 'frontpage/index'

  get 'frontpage/login'

  root 'frontpage#index'
end
