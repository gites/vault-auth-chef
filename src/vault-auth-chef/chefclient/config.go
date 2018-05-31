package chefclient

import (
	"context"
	"time"

	"github.com/hashicorp/vault/logical"
	"github.com/pkg/errors"
)

// config represents the internally stored configuration information.
type config struct {
	ChefServer string `json:"chef_server" structs:"chef_server"`
	CheckTLS   bool   `json:"check_tls" structs:"check_tls"`
	// AnyonePolicies is the list of policies to apply to any valid Chef clients.
	AnyonePolicies []string `json:"anyone_policies" structs:"anyone_policies,omitempty"`

	// TTL and MaxTTL are the default TTLs.
	TTL    time.Duration `json:"ttl" structs:"ttl,omitempty"`
	MaxTTL time.Duration `json:"max_ttl" structs:"max_ttl,omitempty"`
}

// Config parses and returns the configuration data from the storage backend.
func (b *backend) Config(ctx context.Context, s logical.Storage) (*config, error) {
	entry, err := s.Get(ctx, "config")
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get config from storage")
	}
	if entry == nil || len(entry.Value) == 0 {
		return nil, errors.New("no configuration in storage")
	}

	var result config
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, errors.Wrapf(err, "failed to decode configuration")
	}

	return &result, nil
}
