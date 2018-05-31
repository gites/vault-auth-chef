package chefclient

import (
	log "github.com/mgutz/logxi/v1"

	"context"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/pkg/errors"
)

// Factory creates a new usable instance of this auth method.
func Factory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(c)
	if err := b.Setup(ctx, c); err != nil {
		return nil, errors.Wrapf(err, "failed to create factory")
	}
	return b, nil
}

// backend is the actual backend
type backend struct {
	*framework.Backend
	logger log.Logger

	RolesMap *framework.PolicyMap
	HostsMap *framework.PolicyMap
}

// Backend creates a new backend, mapping the proper paths, help information,
// and required callbacks.
func Backend(c *logical.BackendConfig) *backend {
	var b backend

	b.logger = c.Logger

	// RolesMap maps chef roles (run_list) to a series of policies.
	b.RolesMap = &framework.PolicyMap{
		PathMap: framework.PathMap{
			Name: "roles",
		},
		PolicyKey: "policy",
	}

	// HostsMap maps a chef client name to a series of policies.
	b.HostsMap = &framework.PolicyMap{
		PathMap: framework.PathMap{
			Name: "hosts",
		},
		PolicyKey: "policy",
	}

	b.Backend = &framework.Backend{
		BackendType: logical.TypeCredential,

		AuthRenew: b.pathAuthRenew,

		Help: backendHelp,

		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{"login/*"},
		},

		Paths: func() []*framework.Path {
			var paths []*framework.Path

			// auth/slack/info
			paths = append(paths, &framework.Path{
				Pattern:      "info",
				HelpSynopsis: "Display information about the plugin",
				HelpDescription: `

Displays information about the plugin, such as the plugin version and where to
get help.

`,
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.ReadOperation: b.pathInfoRead,
				},
			})

			// auth/chef/map/roles/*
			paths = append(paths, b.RolesMap.Paths()...)

			// auth/chef/map/hosts/*
			paths = append(paths, b.HostsMap.Paths()...)

			// auth/chef/config
			paths = append(paths, &framework.Path{
				Pattern:      "config",
				HelpSynopsis: "Configuration such the chef server and ttls",
				HelpDescription: `

Read or writer configuration to Vault's storage backend such as OAuth
information, team, behavior configuration tunables, and TTLs. For example:

    $ vault write auth/chef/config \
        chef_server="127.0.0.1" \
        check_tls=false

For more information and examples, please see the online documentation.

`,

				Fields: map[string]*framework.FieldSchema{
					"chef_server": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "Slack OAuth access token for your Slack application.",
					},

					"check_tls": &framework.FieldSchema{
						Type:        framework.TypeBool,
						Description: "Check certificate of chef server.",
					},

					"anyone_policies": &framework.FieldSchema{
						Type: framework.TypeCommaStringSlice,
						Description: "Comma-separated list of policies to apply to " +
							"everyone, even unmapped clients.",
					},

					"ttl": &framework.FieldSchema{
						Type:        framework.TypeDurationSecond,
						Description: "Duration after which authentication will expire.",
					},

					"max_ttl": &framework.FieldSchema{
						Type:        framework.TypeDurationSecond,
						Description: "Maximum duration after which authentication will expire.",
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathConfigWrite,
					logical.ReadOperation:   b.pathConfigRead,
				},
			})

			// auth/chef/login/key
			paths = append(paths, &framework.Path{
				Pattern:      "login/key",
				HelpSynopsis: "Authenticate using a chef client key",
				HelpDescription: `

Accepts a client's Chef private keys and performs a lookup on that client's
key to verify identity, run_list, etc. This identity information is
then used to map the client to policies in Vault.

`,
				Fields: map[string]*framework.FieldSchema{
					"key": &framework.FieldSchema{
						Type: framework.TypeString,
						Description: "Chef client private key to use for " +
							"authentication.",
					},
					"client": &framework.FieldSchema{
						Type: framework.TypeString,
						Description: "Chef client name to use for " +
							"authentication.",
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathAuthLogin,
				},
			})

			return paths
		}(),
	}

	return &b
}

const backendHelp = `
TODO
`
