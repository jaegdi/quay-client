package client

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"

	"github.com/jaegdi/quay-client/pkg/auth"
	"github.com/jaegdi/quay-client/pkg/cli"
)

// Client represents a Quay client
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

// Get sends a GET request to the specified path
// and returns the response
// The function returns an error if the request fails
// or the response status code is not 200
// The function logs the request URL if the verify flag is set
// The function sets the Authorization header based on the client's authentication method
func (c *Client) Get(path string) (*http.Response, error) {
	flags := cli.GetFlags()
	if flags.Verify {
		log.Println("GET: ", c.baseURL+path)
	}
	req, err := http.NewRequest("GET", c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}

	c.setAuthHeader(req)
	return c.client.Do(req)
}

// Post sends a POST request to the specified path
// with the provided body and returns the response
// The function returns an error if the request fails
// or the response status code is not 200
// The function logs the request URL if the verify flag is set
// The function sets the Authorization header based on the client's authentication method
//
// Parameters:
// path: The path to send the POST request to
//
// Returns:
// *http.Response: The response from the POST request
// error: An error if the request fails or the response status code is not 200

func (c *Client) Delete(path string) (*http.Response, error) {
	req, err := http.NewRequest("DELETE", c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}

	c.setAuthHeader(req)
	return c.client.Do(req)
}

// setAuthHeader sets the Authorization header based on the client's authentication method
// The function sets the Bearer token if available
// Otherwise, it sets the Basic auth header with the username and password
//
// Parameters:
// req: The http.Request instance to set the Authorization header on
func (c *Client) setAuthHeader(req *http.Request) {
	if c.auth.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.auth.Token)
	} else if c.auth.Username != "" && c.auth.Password != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", c.auth.Username, c.auth.Password)))
		req.Header.Set("Authorization", "Basic "+auth)
	}
}

// validateBaseURL validates the base URL
// The function returns an error if the base URL is empty
// The function removes the trailing slash from the base URL
//
// Returns:
// error: An error if the base URL is empty
func (c *Client) validateBaseURL() error {
	if c.baseURL == "" {
		return fmt.Errorf("base URL is empty")
	}
	if c.baseURL[len(c.baseURL)-1] == '/' {
		c.baseURL = c.baseURL[:len(c.baseURL)-1]
	}
	return nil
}
