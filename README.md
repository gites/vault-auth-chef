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
