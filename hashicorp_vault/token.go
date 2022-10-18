package secretsengine

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// PluginToken defines a secret for the token
type PluginToken struct {
	// Set by the user when they sign in.
	Username string `json:"username"`
	//  JWT for the API.
	Token string `json:"token"`
}

// hashiCupsToken defines a secret to store for a given role and how it should be revoked or renewed.
func (b *pluginBackend) pluginToken() *framework.Secret {
	return &framework.Secret{
		Type: "JWT token",
		Fields: map[string]*framework.FieldSchema{
			"token": {
				Type:        framework.TypeString,
				Description: "Plugin Token",
			},
		},
		Revoke: b.tokenRevoke,
		Renew:  b.tokenRenew,
	}
}

// Signing out from the HashiCups API invalidates the JWT and prevents someone from using it.
// func deleteToken(
// 	ctx context.Context,
// 	c *PluginClient,
// 	token string) error {
// 
// 	c.Token = token
// 	err := c.SignOut()
// 
// 	if err != nil {
// 		return nil
// 	}
// 
// 	return nil
// }

// tokenRevoke removes the token from the Vault storage API and calls the client to revoke the token
func (b *pluginBackend) tokenRevoke(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData) (*logical.Response, error) {

	return nil, nil
	//client, err := b.getClient(ctx, req.Storage)
	//if err != nil {
	//	return nil, fmt.Errorf("error getting client: %w", err)
	//}
//
	//token := ""
	//tokenRaw, ok := req.Secret.InternalData["token"]
	//if ok {
	//	token, ok = tokenRaw.(string)
	//	if !ok {
	//		return nil, fmt.Errorf("invalid value for token in secret internal data")
	//	}
	//}
//
	//if err := deleteToken(ctx, client, token); err != nil {
	//	return nil, fmt.Errorf("error revoking user token: %w", err)
	//}
	//return nil, nil
}

// tokenRenew calls the client to create a new token and stores it in the Vault storage API
func createToken(
	c *PluginClient) (*PluginToken, error) {

	response, err := c.SignIn()
	if err != nil {
		return nil, fmt.Errorf("error creating HashiCups token: %w", err)
	}

	return &PluginToken{
		Username: c.Username,
		Token:    response.Token,
	}, nil
}

// Verify that a role exists in the secrets engine backend before HashiCups creates a token.
// You also pass the secrets object as a response and reset the time to live (TTL) and maximum TTL for the role.
func (b *pluginBackend) tokenRenew(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData) (*logical.Response, error) {
	resp := &logical.Response{Secret: req.Secret}
	return resp, nil
}
