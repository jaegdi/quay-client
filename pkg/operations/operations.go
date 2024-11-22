package operations

import (
	"encoding/json"
	"fmt"
	"net/http"
	"qc/pkg/client"
	"regexp"
)

type Operations struct {
	client *client.Client
}

func NewOperations(client *client.Client) *Operations {
	return &Operations{client: client}
}

func (o *Operations) ListOrganizations() ([]string, error) {
	resp, err := o.client.Get("/organization/")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list organizations: %s", resp.Status)
	}

	var result struct {
		Organizations []struct {
			Name string `json:"name"`
		} `json:"organizations"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var orgs []string
	for _, org := range result.Organizations {
		orgs = append(orgs, org.Name)
	}

	return orgs, nil
}

func (o *Operations) ListOrganizationRepositories(org string) ([]string, error) {
	resp, err := o.client.Get(fmt.Sprintf("/repository/%s", org))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Repositories []struct {
			Name string `json:"name"`
		} `json:"repositories"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var repos []string
	for _, repo := range result.Repositories {
		repos = append(repos, repo.Name)
	}

	return repos, nil
}

func (o *Operations) ListRepositoriesByRegex(org, pattern string) ([]string, error) {
	repos, err := o.ListOrganizationRepositories(org)
	if err != nil {
		return nil, err
	}

	regex, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	var filtered []string
	for _, repo := range repos {
		if regex.MatchString(repo) {
			filtered = append(filtered, repo)
		}
	}

	return filtered, nil
}

func (o *Operations) DeleteTag(org, repo, tag string) error {
	path := fmt.Sprintf("/repository/%s/%s/tag/%s", org, repo, tag)
	resp, err := o.client.Delete(path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to delete tag: %s", resp.Status)
	}

	return nil
}
