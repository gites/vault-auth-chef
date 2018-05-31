ssl_verify_mode                  :verify_none
verify_api_cert                  false
verify_api_cert                  false
log_level                :info
log_location             STDOUT

node_name                'admin'
client_key               "#{File.dirname(__FILE__)}/admin.pem"
chef_server_url          'https://chef-server/organizations/testorg'
