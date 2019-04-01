package chefclient

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/go-chef/chef"
	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/pkg/errors"
	"github.com/tidwall/gjson"
)

// verifyResp is a wrapper around fields returned from verifyCreds.
type verifyResp struct {
	policies []string
	node     *chef.Node

	ttl    time.Duration
	maxTTL time.Duration
}

// roleMapTemplates defines fields that can be templated in a role to policy mapping
type roleMapTemplates struct {
	env  string
	name string
}

// pathAuthLogin accepts a user's personal OAuth token and validates the user's
// identity to generate a Vault token.
func (b *backend) pathAuthLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Validate we didn't get extraneous fields
	if err := validateFields(req, d); err != nil {
		return nil, logical.CodedError(422, err.Error())
	}

	// Make sure we have a Chef Client private key
	key := d.Get("key").(string)
	if key == "" {
		return errMissingField("key"), nil
	}

	// Make sure we have a Chef Client name
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
		SkipSSL: config.SkipTLS,
	})

	if err != nil {
		b.logger.Warn(fmt.Sprintf("Chef auth error while auth: %s", err.Error()))
		return nil, errors.Wrap(err, "auth.test")
	}

	nodeRoles := make([]string, 0)

	// Get node and validate client key
	node, err := c.Nodes.Get(client)
	if err != nil {
		b.logger.Warn(fmt.Sprintf("Chef auth error while get nodes: %s", err.Error()))
		return nil, errors.Wrap(err, "nodes.list")
	}

	switch config.RunListSrc {
	case "data":
		nodeData := make(map[string]string, 0)
		nodeRoles, nodeData = getRolesFromData(config.DataBags, client, c, b)
		if nodeData == nil {
			b.logger.Warn(fmt.Sprintf("Chef auth error while geting data bags: %s", err.Error()))
			return nil, errors.Wrap(err, "data_bags.list")
		}
		node.Name = nodeData["id"]
		node.Environment = nodeData["env"]
	case "node":
		nodeRoles = getRolesFromNode(node, client, c, b)
	}

	var templates roleMapTemplates
	templates.env = node.Environment
	templates.name = node.Name

	// Accumulate all policies
	hostsPolicies, err := b.HostsMap.Policies(ctx, req.Storage, client)
	if err != nil {
		b.logger.Warn(fmt.Sprintf("error while accumulate hosts policies: %s", err.Error()))
		return nil, errors.Wrap(err, "client policies")
	}
	hostsPolicies = dynamicRoleMap(b, templates, hostsPolicies)

	rolesPolicies, err := b.RolesMap.Policies(ctx, req.Storage, nodeRoles...)
	if err != nil {
		b.logger.Warn(fmt.Sprintf("error while accumulate roles policies: %s", err.Error()))
		return nil, errors.Wrap(err, "run_list policies")
	}
	rolesPolicies = dynamicRoleMap(b, templates, rolesPolicies)
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

func dynamicRoleMap(b *backend, templates roleMapTemplates, polices []string) []string {
	mappedPolices := make([]string, 0, len(polices))
	for _, p := range polices {
		b.logger.Debug(fmt.Sprintf("Dynamic policy mapping loop for: %s", p))
		p = strings.Replace(p, "{{env}}", templates.env, -1)
		p = strings.Replace(p, "{{name}}", templates.name, -1)
		b.logger.Debug(fmt.Sprintf("Policy mapped to: %s", p))
		mappedPolices = append(mappedPolices, p)
	}
	return mappedPolices
}

// getRolesFromData fetches client run_list from data bags
func getRolesFromData(dataBags []string, client string, c *chef.Client, b *backend) ([]string, map[string]string) {
	nodeRoles := make([]string, 0)
	nodeData := make(map[string]string, 2)
	//var node chef.Node
	var dataBag interface{}
	var err error

	// Get data bags
	// Iterate over configured data bags indexes and try to find the one for our client.

	for _, dataBagPath := range dataBags {
		dataBag, err = c.DataBags.GetItem(dataBagPath, client)
		if err != nil {
			b.logger.Debug(fmt.Sprintf("Looking for data bag in: %s", err.Error()))
		}
		if err == nil {
			break
		}
	}

	// Check if we realy got the data bag.
	jsonData, err := json.Marshal(dataBag)
	if err != nil {
		return nil, nil
	}
	dataBagMapRunList := gjson.GetBytes(jsonData, "run_list")

	roleRe := regexp.MustCompile("^role\\[(.*)\\]$")
	for _, role := range dataBagMapRunList.Array() {
		b.logger.Debug(fmt.Sprintf("Client %s run_list: %s", client, role))
		res := roleRe.FindStringSubmatch(role.String())
		if len(res) == 2 {
			nodeRoles = append(nodeRoles, res[1])
		}
	}
	nodeData["env"] = gjson.GetBytes(jsonData, "env").String()
	nodeData["id"] = gjson.GetBytes(jsonData, "id").String()
	return nodeRoles, nodeData
}

// getRolesFromNode fetches client run_list from node object
func getRolesFromNode(node chef.Node, client string, c *chef.Client, b *backend) []string {
	nodeRoles := make([]string, 0)
	roleRe := regexp.MustCompile("^role\\[(.*)\\]$")
	for _, role := range node.RunList {
		b.logger.Debug(fmt.Sprintf("Client %s run_list: %s", client, role))
		res := roleRe.FindStringSubmatch(role)
		if len(res) == 2 {
			nodeRoles = append(nodeRoles, res[1])
		}
	}
	return nodeRoles
}
