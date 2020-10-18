require_relative 'autoRequire'
require 'sinatra/base'
require 'rdiscount'
require 'digest'
require 'sass'
require 'mysql2'
require 'yaml'

$config = YAML.load(File.open('config.yml'))

$client = Mysql2::Client.new(
  host: $config['mysql']['host'], # 主机
  username: $config['mysql']['username'], # 用户名
  password: $config['mysql']['password'], # 密码
  database: $config['mysql']['database'] # 数据库
)

class App < Sinatra::Base
  use Rack::Session::Pool, expire_after: 600

  configure do
    enable :logging
    enable :sessions
    set :port, $config['sinatra']['port']
    set :adminPassSHA256, $config['sinatra']['adminPassSHA256']
  end

  not_found do
    'This is nowhere to be found.'
  end

  error do
    'Sorry there was a nasty error - ' + env['sinatra.error'].message
  end

  get '/' do
    "hello <a href='/admin'>admin</a>"
  end

  get '/login' do
    redirect to('admin') if session[:admin]
    erb :loginpage, locals: { loginstatus: nil }
  end

  post '/login' do
    results = $client.query("SELECT * FROM users WHERE username='#{params[:username]}';").to_a
    if results == []
      halt 401, erb(:loginpage, locals: { loginstatus: '登录失败，账号或密码错误' })
    else
      if Digest::SHA256.hexdigest(params[:password]) == results[0]['password']
        if results[0]['role'] == 1
          session[:admin] = true
          redirect to('admin')
        else
          halt 403, erb(:loginpage, locals: { loginstatus: '登录失败，权限组失效' })
        end
      else
        halt 400, erb(:loginpage, locals: { loginstatus: '登录失败，账号或密码错误' })
      end
    end
  end

  before '/admin' do
    halt(401, "Access denied, please <a href='/login'>login</a>.") unless session[:admin]
  end

  get '/admin' do
    erb :start
  end

  get '/logout' do
    session.clear
    redirect to('/login')
  end

  get '/changepass' do # /changepass?password=xxx&username=xxx&adminpass=xxx
    if request.ip == '127.0.0.1'
      if (request.forwarded? == false) && (Digest::SHA256.hexdigest(params[:adminpass]) == settings.adminPassSHA256)
        if params[:password]
          $client.query("UPDATE users SET password='#{Digest::SHA256.hexdigest(params[:password])}' WHERE username='#{params[:username]}';")
          results = $client.query("SELECT * FROM users WHERE username='#{params[:username]}';").to_a
          if results == []
            halt 400, 'wrong username'
          else
            if results[0]['password'] && (Digest::SHA256.hexdigest(params[:password]) == results[0]['password'])
              halt 200, 'success'
            else
              halt 400, 'wrong username or password'
            end
          end
        else
          halt 403, 'failed to update'
        end
      else
        halt 401, 'failed'
      end
    else
      redirect to('/login')
    end
  end
end

App.run!
