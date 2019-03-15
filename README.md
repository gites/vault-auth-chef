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


## Installation

```
$ export SHA256=$(shasum -a 256 /etc/vault/plugins/vault-auth-chef | cut -d' ' -f1)

$ vault write sys/plugins/catalog/vault-auth-chef sha_256=${SHA256} command="vault-auth-chef"

$ vault auth enable -path="chef" -plugin-name=vault-auth-chef plugin
```

## Configuration
Options in `[]` are optional.

```
$ vault write auth/chef/config chef_server='https://yourChefServer/organizations/yourOrg/' data_bags=host,vms,something [anyone_policies=anyone_policy1,anyone_policy2] [skip_tls=true]
$ vault write auth/chef/map/roles/role_name1 policy=policy_name1
$ vault write auth/chef/map/hosts/host_name2 policy=host_policy2
```
