package client

import (
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/jaegdi/quay-client/pkg/auth"
)

type Client struct {
	auth    *auth.Auth
	client  *http.Client
	baseURL string
}

// NewClient creates a new Client instance
func NewClient(auth *auth.Auth, quayURL string) *Client {
	client := &Client{
		auth:    auth,
		client:  &http.Client{},
		baseURL: fmt.Sprintf("%s/api/v1", quayURL),
	}
	if err := client.validateBaseURL(); err != nil {
		panic(err)
	}
	return client
}

func (c *Client) Get(path string) (*http.Response, error) {
	req, err := http.NewRequest("GET", c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}

	c.setAuthHeader(req)
	return c.client.Do(req)
}

func (c *Client) Delete(path string) (*http.Response, error) {
	req, err := http.NewRequest("DELETE", c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}

	c.setAuthHeader(req)
	return c.client.Do(req)
}

func (c *Client) setAuthHeader(req *http.Request) {
	if c.auth.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.auth.Token)
	} else if c.auth.Username != "" && c.auth.Password != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", c.auth.Username, c.auth.Password)))
		req.Header.Set("Authorization", "Basic "+auth)
	}
}

func (c *Client) validateBaseURL() error {
	if c.baseURL == "" {
		return fmt.Errorf("base URL is empty")
	}
	if c.baseURL[len(c.baseURL)-1] == '/' {
		c.baseURL = c.baseURL[:len(c.baseURL)-1]
	}
	return nil
}
