package secretsengine

import (
	"context"
	"strings"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// ----
// Explore the secrets engine's backend:
// The contents create a backend in Vault for the secrets engine to store data.
// ----

// Factory returns a new backend as logical.Backend
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := createMyBackend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// myBacked defines an object that extends the Vault backend
// and stores the target API's client.
type pluginBackend struct {
	// implements logical.Backend
	*framework.Backend
	// locking mechanisms for writing or changing secrets engine data
	//lock sync.RWMutex
	//// stores the client for the target API, myApi
	//client *PluginClient
}

// createMyBackend defines the target API backend for Vault.
// It must include each path and the secrets it will store.
func createMyBackend() *pluginBackend {
	b := new(pluginBackend)
	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			LocalStorage: []string{},
			SealWrapStorage: []string{
				"config",
				"role/*",
			},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				pathCredentials(b),
			},
		),
		Secrets: []*framework.Secret{
			b.pluginToken(),
		},
		BackendType: logical.TypeLogical,
	}
	return b
}

// backendHelp should contain help information for the backend
const backendHelp = `
The myBackend secrets backend dynamically generates user tokens.
After mounting this backend, credentials to manage my user tokens
must be configured with the "config/" endpoints.
`
