package secretsengine

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ----- Client to access the demo application -----

// PluginClient -
type PluginClient struct {
	HTTPClient *http.Client
	HostURL    string
	Token      string
	Username   string
	Password   string
}

// AuthResponse -
type AuthResponse struct {
	UserID   int
	Username string
	Token    string
}

const (
	host = "http://localhost:19090"
)

// NewClient -
func NewClient(username string, password string) (*PluginClient, error) {
	c := PluginClient{
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
		// Default Hashicups URL
		HostURL:  host,
		Username: username,
		Password: password,
	}

	ar, err := c.SignIn()
	if err != nil {
		return nil, err
	}

	c.Token = ar.Token

	return &c, nil
}

// SignIn - Get a new token for user
func (c *PluginClient) SignIn() (*AuthResponse, error) {
	rb, err := json.Marshal(map[string]string{
		"username": c.Username,
		"password": c.Password,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/signin", c.HostURL), strings.NewReader(string(rb)))
	if err != nil {
		return nil, err
	}

	body, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}

	ar := AuthResponse{}
	err = json.Unmarshal(body, &ar)
	if err != nil {
		return nil, err
	}

	return &ar, nil
}

func (c *PluginClient) doRequest(req *http.Request) ([]byte, error) {
	req.Header.Set("Authorization", c.Token)

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status: %d, body: %s", res.StatusCode, body)
	}

	return body, err
}

// SignOut - Revoke the token for a user
func (c *PluginClient) SignOut() error {
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/signout", c.HostURL), strings.NewReader(string("")))
	if err != nil {
		return err
	}

	body, err := c.doRequest(req)
	if err != nil {
		return err
	}

	if string(body) != "Signed out user" {
		return errors.New(string(body))
	}

	return nil
}

// pluginClient creates an object storing the client.
// (to the client to interface with the my API.)

// newClient creates a new client to access my api
// and exposes it for any secrets or roles to use.
func newClient(username string, password string) (*PluginClient, error) {
	c, err := NewClient(username, password)
	if err != nil {
		return nil, err
	}
	return c, nil
}
