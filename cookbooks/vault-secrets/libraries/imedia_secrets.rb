require 'net/http'
require 'uri'
require 'json'
require 'openssl'

class VaultError < StandardError
end

class Chef
  # Class for get secrets via vault-auth
  class VaultSecrets
    def initialize
      chef_server_uri = URI.parse(Chef::Config[:chef_server_url])
      @vault_server = chef_server_uri.host
      @vault_port = 8200
      client_name = Chef::Config[:node_name]
      cert = ::File.read('/etc/chef/client.pem')
      auth = { 'key' => cert, 'client' => client_name }
      @client = Net::HTTP.new(@vault_server, @vault_port)
      @client.verify_mode = OpenSSL::SSL::VERIFY_NONE
      @client.use_ssl = true
      @token = get_token(auth)
    end

    # rubocop:disable Metrics/AbcSize
    def get_token(auth)
      req = Net::HTTP::Post.new('/v1/auth/chef/login/key')
      req.body = auth.to_json
      resp = @client.request(req)
      res = JSON.parse(resp.body)
      if res.key?('errors') && !res['errors'].empty?
        raise VaultError, "Error while auth [#{resp.code}]: #{res['errors'].join(', ')}"
      end
      res['auth']['client_token']
    end

    def get_secret(path, name)
      req = Net::HTTP::Get.new("/v1/#{path}/#{name}")
      req['X-Vault-Token'] = @token
      req.body = @auth.to_json
      resp = @client.request(req)
      r = JSON.parse(resp.body)
      resp.code == 404 && raise(VaultError, "Secrets weren't found: #{path}/#{name}")
      if r.key?('errors') && !r['errors'].empty?
        raise VaultError, "Error get secrets [#{resp.code}]: #{r['errors'].join(', ')}"
      end

      r['data']
    end
  end
end
