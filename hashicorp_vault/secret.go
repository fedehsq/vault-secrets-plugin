package secretsengine

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathCredentials extends the Vault API with a `/creds`
// endpoint for a user. You can choose whether
// or not certain attributes should be displayed,
// required, and named.
func pathCredentials(b *pluginBackend) *framework.Path {
	return &framework.Path{
		Pattern: "creds",
		Fields: map[string]*framework.FieldSchema{
			"username": {
				Type:        framework.TypeLowerCaseString,
				Description: "username of the user to create a token for",
				Required:    true,
			},
			"password": {
				Type:        framework.TypeString,
				Description: "password of the user to create a token for",
				Required:    true,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathCredentialsRead,
			logical.UpdateOperation: b.pathCredentialsRead,
		},
		HelpSynopsis:    pathCredentialsHelpSyn,
		HelpDescription: pathCredentialsHelpDesc,
	}
}

// It creates the token based on the username passed to the creds endpoint
func (b *pluginBackend) createToken(
	username string,
	password string,
) (*PluginToken, error) {

	var token *PluginToken
	client, err := newClient(username, password)
	if err != nil {
		return nil, err
	}

	token, err = createToken(client)
	if err != nil {
		return nil, fmt.Errorf("error creating token: %w", err)
	}

	if token == nil {
		return nil, errors.New("error creating token")
	}

	return token, nil
}

// The method creates the token and maps it to a response for the secrets engine backend to return.
func (b *pluginBackend) createUserCreds(
	username string,
	password string,
) (*logical.Response, error) {

	token, err := b.createToken(username, password)
	if err != nil {
		return nil, err
	}

	resp := b.Secret("JWT token").Response(map[string]interface{}{
		"token":    token.Token,
		"username": token.Username,
	}, map[string]interface{}{
		"token": token.Token,
	})
	return resp, nil
}

// The method creates a new token based on the user.
func (b *pluginBackend) pathCredentialsRead(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData) (*logical.Response, error) {
	username := d.Get("username").(string)
	password := d.Get("password").(string)
	if username == "" {
		return logical.ErrorResponse("username is required"), nil
	}
	if password == "" {
		return logical.ErrorResponse("password is required"), nil
	}
	return b.createUserCreds(username, password)
}

const pathCredentialsHelpSyn = `
Generate a JWT token from a specific user.
`

const pathCredentialsHelpDesc = `
This path generates a JWT user tokens based on a particular user.
`
