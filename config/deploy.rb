#################
# GLOBAL CONFIG
#################
set :application, 'sp-sinatra'
# set branch based on env var or ask with the default set to the current local branch
set :branch, ENV['branch'] || ENV['BRANCH'] || ask(:branch, `git branch`.match(/\* (\S+)\s/m)[1])
set :bundle_without, 'deploy'
set :deploy_to, ->{ "/srv/#{fetch(:application)}" }
set :deploy_via, :remote_cache
set :keep_releases, 5
set :linked_files, %w(.env
                      config/demo_sp.crt
                      config/demo_sp.key
                      config/saml_settings_demo.yml)
set :linked_dirs, %w(bin log tmp/pids tmp/cache tmp/sockets vendor/bundle public/system)
set :rack_env, :production
set :repo_url, ->{ "https://github.com/18F/identity-#{fetch(:application)}.git" }
set :ssh_options, forward_agent: false, user: 'ubuntu'
set :tmp_dir, ->{ "/srv/#{fetch(:application)}" }

#########
# TASKS
#########
namespace :deploy do
  desc 'Restart application'
  task :restart do
    on roles(:app), in: :sequence, wait: 5 do
      execute :touch, release_path.join('tmp/restart.txt')
    end
  end

  desc 'Write deploy information to deploy.json'
  task :deploy_json do
    on roles(:app, :web), in: :parallel do
      require 'stringio'

      within current_path do
        deploy = {
          env: fetch(:stage),
          branch: fetch(:branch),
          user: fetch(:local_user),
          sha: fetch(:current_revision),
          timestamp: fetch(:release_timestamp)
        }

        execute :mkdir, '-p', 'public/api'

        # the #upload! method does not honor the values of #within at the moment
        # https://github.com/capistrano/sshkit/blob/master/EXAMPLES.md#upload-a-file-from-a-stream
        upload! StringIO.new(deploy.to_json), "#{current_path}/public/api/deploy.json"
      end
    end
  end

  after 'deploy:log_revision', :deploy_json
end
