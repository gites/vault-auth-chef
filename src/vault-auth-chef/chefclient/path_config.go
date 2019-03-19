package chefclient

import (
	"context"
	"time"

	"github.com/fatih/structs"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/pkg/errors"
)

// pathConfigRead corresponds to READ auth/slack/config.
func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.Config(ctx, req.Storage)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get configuration from storage")
	}

	// TTLs are stored as seconds
	config.TTL /= time.Second
	config.MaxTTL /= time.Second

	resp := &logical.Response{
		Data: structs.New(config).Map(),
	}
	return resp, nil
}

// pathConfigRead corresponds to POST auth/slack/config.
func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Validate we didn't get extraneous fields
	if err := validateFields(req, data); err != nil {
		return nil, logical.CodedError(422, err.Error())
	}

	// Get the access token
	chefServer := data.Get("chef_server").(string)
	if chefServer == "" {
		return errMissingField("chef_server"), nil
	}

	// Get the tunable options
	skipTLS := data.Get("skip_tls").(bool)
	anyonePolicies := data.Get("anyone_policies").([]string)

	// Calculate TTLs, if supplied
	ttl := time.Duration(data.Get("ttl").(int)) * time.Second
	maxTTL := time.Duration(data.Get("max_ttl").(int)) * time.Second

	// Built the entry
	entry, err := logical.StorageEntryJSON("config", &config{
		ChefServer:     chefServer,
		SkipTLS:        skipTLS,
		AnyonePolicies: anyonePolicies,
		TTL:            ttl,
		MaxTTL:         maxTTL,
	})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to generate storage entry")
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, errors.Wrapf(err, "failed to write configuration to storage")
	}
	return nil, nil
}

// pathRolesMapList corresponds to LIST auth/chef/map/roles.
func (b *backend) pathRolesMapList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	rolesMaps, err := req.Storage.List(ctx, "map/roles/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(rolesMaps), nil
}

// pathHostsMapList corresponds to LIST auth/chef/map/hosts.
func (b *backend) pathHostsMapList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	hostsMaps, err := req.Storage.List(ctx, "map/hosts/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(hostsMaps), nil
}
