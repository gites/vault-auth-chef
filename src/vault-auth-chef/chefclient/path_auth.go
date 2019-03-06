package chefclient

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/go-chef/chef"
	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/pkg/errors"
)

// verifyResp is a wrapper around fields returned from verifyCreds.
type verifyResp struct {
	policies []string
	node     *chef.Node

	ttl    time.Duration
	maxTTL time.Duration
}

// pathAuthLogin accepts a user's personal OAuth token and validates the user's
// identity to generate a Vault token.
func (b *backend) pathAuthLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Validate we didn't get extraneous fields
	if err := validateFields(req, d); err != nil {
		return nil, logical.CodedError(422, err.Error())
	}

	// Make sure we have a token
	key := d.Get("key").(string)
	if key == "" {
		return errMissingField("key"), nil
	}

	client := d.Get("client").(string)
	if client == "" {
		return errMissingField("client"), nil
	}

	// Verify the credentails
	creds, err := b.verifyCreds(ctx, req, client, key)
	if err != nil {
		if err, ok := err.(logical.HTTPCodedError); ok {
			return nil, err
		}
		return nil, logical.ErrPermissionDenied
	}

	// Compose the response
	return &logical.Response{
		Auth: &logical.Auth{
			InternalData: map[string]interface{}{
				"chef_key":    key,
				"chef_client": client,
			},
			Policies: creds.policies,
			Metadata: map[string]string{
				"chef_node_name":        creds.node.Name,
				"chef_node_environment": creds.node.Environment,
			},
			DisplayName: creds.node.Name,
			LeaseOptions: logical.LeaseOptions{
				TTL:       creds.ttl,
				Renewable: true,
			},
		},
	}, nil
}

// pathAuthRenew is used to renew authentication.
func (b *backend) pathAuthRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Verify we received auth
	if req.Auth == nil {
		return nil, errors.New("request auth was nil")
	}

	// Grab the chef key
	keyRaw, ok := req.Auth.InternalData["chef_key"]
	if !ok {
		return nil, errors.New("no internal token found in the store")
	}
	key, ok := keyRaw.(string)
	if !ok {
		return nil, errors.New("stored access token is not a string")
	}

	// Grab the chef client
	clientRaw, ok := req.Auth.InternalData["chef_client"]
	if !ok {
		return nil, errors.New("no internal token found in the store")
	}
	client, ok := clientRaw.(string)
	if !ok {
		return nil, errors.New("stored access token is not a string")
	}

	// Verify the credentails
	creds, err := b.verifyCreds(ctx, req, client, key)
	if err != nil {
		if err, ok := err.(logical.HTTPCodedError); ok {
			return nil, err
		}
		return nil, logical.ErrPermissionDenied
	}

	// Make sure the policies haven't changed. If they have, inform the user to
	// re-authenticate.
	if !policyutil.EquivalentPolicies(creds.policies, req.Auth.Policies) {
		return nil, errors.New("policies no longer match")
	}

	// Extend the lease
	return framework.LeaseExtend(creds.ttl, creds.maxTTL, b.System())(ctx, req, d)
}

// verifyCreds verifies the given credentials.
func (b *backend) verifyCreds(ctx context.Context, req *logical.Request, client, key string) (*verifyResp, error) {
	config, err := b.Config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	c, err := chef.NewClient(&chef.Config{
		Name:    client,
		Key:     key,
		BaseURL: config.ChefServer,
	})

	if err != nil {
		b.logger.Warn(fmt.Sprintf("Chef auth error while auth: %s", err.Error()))
		return nil, errors.Wrap(err, "auth.test")
	}

	// Get node
	node, err := c.Nodes.Get(client)
	if err != nil {
		b.logger.Warn(fmt.Sprintf("Chef auth error while get nodes: %s", err.Error()))
		return nil, errors.Wrap(err, "nodes.list")
	}
	nodeRoles := make([]string, 0)
	roleRe := regexp.MustCompile("^role\\[(.*)\\]$")
	for _, role := range node.RunList {
		b.logger.Debug(fmt.Sprintf("Client %s run_list: %s", client, role))
		res := roleRe.FindStringSubmatch(role)
		if len(res) == 2 {
			nodeRoles = append(nodeRoles, res[1])
		}
	}

	// Accumulate all policies
	hostsPolicies, err := b.HostsMap.Policies(ctx, req.Storage, client)
	if err != nil {
		b.logger.Warn(fmt.Sprintf("error while accumulate hosts policies: %s", err.Error()))
		return nil, errors.Wrap(err, "client policies")
	}
	rolesPolicies, err := b.RolesMap.Policies(ctx, req.Storage, nodeRoles...)
	if err != nil {
		b.logger.Warn(fmt.Sprintf("error while accumulate roles policies: %s", err.Error()))
		return nil, errors.Wrap(err, "run_list policies")
	}
	b.logger.Debug(fmt.Sprintf("Client %s role %s policy: %s", client, strings.Join(nodeRoles, ","), strings.Join(rolesPolicies, ",")))
	policies := make([]string, 0, len(hostsPolicies)+len(rolesPolicies))
	policies = append(policies, hostsPolicies...)
	policies = append(policies, rolesPolicies...)

	// Append the default policies
	policies = append(policies, config.AnyonePolicies...)

	// Unique, since we want to remove duplicates and that will cause errors when
	// we compare policies later.
	uniq := map[string]struct{}{}
	for _, v := range policies {
		if _, ok := uniq[v]; !ok {
			uniq[v] = struct{}{}
		}
	}
	newPolicies := make([]string, 0, len(uniq))
	for k := range uniq {
		newPolicies = append(newPolicies, k)
	}
	policies = newPolicies

	// If there are no policies attached, that means we should not issue a token
	if len(policies) == 0 {
		b.logger.Debug(fmt.Sprintf("Client %s no mapped policies", client))
		return nil, logical.CodedError(403, "client has no mapped policies")
	}

	// Parse TTLs
	ttl, maxTTL, err := b.SanitizeTTLStr(config.TTL.String(), config.MaxTTL.String())
	if err != nil {
		return nil, errors.Wrap(err, "failed to sanitize TTLs")
	}

	// Return the response
	return &verifyResp{
		policies: policies,
		node:     &node,
		ttl:      ttl,
		maxTTL:   maxTTL,
	}, nil
}
