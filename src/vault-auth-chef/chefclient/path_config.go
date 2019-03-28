package chefclient

import (
	"context"
	"fmt"
	"time"

	"github.com/fatih/structs"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/pkg/errors"
)

// pathConfigRead corresponds to READ auth/chef/config.
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

// pathConfigRead corresponds to POST auth/chef/config.
func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Validate we didn't get extraneous fields
	if err := validateFields(req, data); err != nil {
		return nil, logical.CodedError(422, err.Error())
	}

	// Get the Chef Server address
	chefServer := data.Get("chef_server").(string)
	if chefServer == "" {
		return errMissingField("chef_server"), nil
	}

	// Get the run list source configuration
	runListSrc := data.Get("run_list_src").(string)

	var dataBags []string

	switch runListSrc {
	case "":
		return errMissingField("run_list_src"), nil
	case "data":
		// Get the data bags
		dataBags = data.Get("data_bags").([]string)
		if len(dataBags) == 0 {
			return errMissingField("data_bags"), nil
		}
		b.logger.Info("Plugin configured to use run_list from data bags.")
	case "node":
		b.logger.Info("Plugin configured to use run_list from node object.")
	default:
		return logical.ErrorResponse(fmt.Sprintf("Bad value for required field 'run_list_src'. Only 'node' or 'data' are allowed.")), nil
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
		RunListSrc:     runListSrc,
		DataBags:       dataBags,
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
