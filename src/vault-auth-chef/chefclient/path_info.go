package chefclient

import (
	"context"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

var (
	// GitCommit hash
	GitCommit string
	// Version is a git tag
	Version string
	// BuildBranch describte on what branch the plugin was build
	BuildBranch string
	// BuildOrigin describe an origin rebo that was used for building plugin
	BuildOrigin string
)

// pathInfoRead corresponds to READ auth/chef/info.
func (b *backend) pathInfoRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return &logical.Response{
		Data: map[string]interface{}{
			"commit":       GitCommit,
			"version":      Version,
			"build_branch": BuildBranch,
			"build_origin": BuildOrigin,
		},
	}, nil
}
