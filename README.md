# vault-auth-chef
Chef authorization plugin for Hashicorp Vault

If you have got any questions, please make issue in this project. If you want to help this project I will be happy:)

## Requirements

- golang >= 1.10

## Build

```
make build
```

Binary file of plugin is located at `build` directory

## Configuration

Plugin contains follow configuration options:
- `chef_server` - full url to your chef server e.g. https://chefserver/myorg
- `skip_tls` - Check certificate of chef server
- `anyone_policies` - policies for apply to any clients
- `ttl` - Duration after which authentication will expire
- `max_ttl` - Maximum duration after which authentication will expire 
- `run_list_src` - Describes where to look for information about client roles. For Chef node object use `node`, for data bags use `data`.
- `data_bags` - Comma-separated list of Chef Server data bags to look for the client data bag file


## Installation

```
$ export SHA256=$(shasum -a 256 /etc/vault/plugins/vault-auth-chef | cut -d' ' -f1)

$ vault write sys/plugins/catalog/vault-auth-chef sha_256=${SHA256} command="vault-auth-chef"

$ vault auth enable -path="chef" -plugin-name=vault-auth-chef plugin
```

## Configuration
Options in `[]` are optional.

# Use node object

```
$ vault write auth/chef/config chef_server='https://yourChefServer/organizations/yourOrg/' run_list_src=node [anyone_policies=anyone_policy1,anyone_policy2] [skip_tls=true]
$ vault write auth/chef/map/roles/role_name1 policy=policy_name1
$ vault write auth/chef/map/hosts/host_name2 policy=host_policy2
```

# Use data bags
```
$ vault write auth/chef/config chef_server='https://yourChefServer/organizations/yourOrg/' run_list_src=data data_bags=hosts,vms,something [anyone_policies=anyone_policy1,anyone_policy2] [skip_tls=true]
$ vault write auth/chef/map/roles/role_name1 policy=policy_name1
$ vault write auth/chef/map/hosts/host_name2 policy=host_policy2
```

If you decide to use data bags as a source for client data, the data bag needs to have at least the following fields:
```
{
  "id": "example-host-data-bag",
  "env": "dev",
  "run_list": [
    "role[role-1]",
    "role[role-2]",
    "role[role-n]"
  ]
}
```

## Dynamic role to policy mapping

Dynamic role to policy mapping is a feature that allows creating policy names dynamically based on metadata returned by the plugin.

Following variables can be used in policy names mappings:
- {{env}} - will be interpolated to a Chef Client Environment value
- {{name}} - will be interpolated to a Chef Client Node Name value

# Configuration
```
vault write auth/chef/map/roles/role_name1 policy=policy_name1_{{env}}
vault write auth/chef/map/hosts/host_name2 policy=policy2_{{env}}
```

As per the above configuration client with role `role_name1` and Chef Environment set to `dev` will have the following policies:
```
vault write auth/chef/login/key key=@/etc/chef/client.pem client=example-client
Key                                 Value
---                                 -----
token                               s.SWnIhr1dQNMErTlYhNYo0roC4
token_accessor                      qCTtTYJ0md9PVxQYpWZy38HMI
token_duration                      768h
token_renewable                     true
token_policies                      ["default" "policy_name1_dev"]
identity_policies                   []
policies                            ["default" "policy_name1_dev"]
token_meta_chef_node_environment    dev
token_meta_chef_node_name           example-client
```
