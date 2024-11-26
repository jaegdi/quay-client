package client

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"qc/pkg/auth"
)

type Client struct {
    auth    *auth.Auth
    client  *http.Client
    baseURL string
}

// NewClient creates a new Client instance
func NewClient(auth *auth.Auth, quayURL string) *Client {
    return &Client{
        auth:    auth,
        client:  &http.Client{},
        baseURL: fmt.Sprintf("%s/api/v1", quayURL),
    }
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
