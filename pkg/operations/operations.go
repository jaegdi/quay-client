package operations

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"qc/pkg/client"
	"regexp"
)

type Operations struct {
	client *client.Client
}

type VulnerabilityInfo struct {
	Name            string                   `json:"Name"`
	Version         string                   `json:"Version"`
	BaseScores      []float64                `json:"BaseScores"`
	CVEIds          []string                 `json:"CVEIds"`
	Vulnerabilities []featureVulnerabilities `json:"Vulnerabilities"`
}

type featureVulnerabilities struct {
	Name        string `json:"Name"`
	Link        string `json:"Link"`
	Description string `json:"Description"`
	FixVersion  string `json:"FixedBy"`
	Severity    string `json:"Severity"`
}

type Vulnerabilities struct {
	Status string `json:"status"`
	Data   struct {
		Layer struct {
			Features []VulnerabilityInfo `json:"Features"`
		} `json:"Layer"`
	} `json:"data"`
}

type TagDetails struct {
	Repo            string          `json:"repository"`
	Name            string          `json:"name"`
	Digest          string          `json:"manifest_digest"`
	LastModified    string          `json:"last_modified"`
	Size            int64           `json:"size"`
	Expired         bool            `json:"expired"`
	Manifest        string          `json:"manifest"`
	Vulnerabilities Vulnerabilities `json:"vulnerabilities"`
}

type TagResults struct {
	Tags []TagDetails `json:"tags"`
}

func NewOperations(client *client.Client) *Operations {
	return &Operations{client: client}
}

func (o *Operations) ListOrganizations() ([]string, error) {
	// resp, err := o.client.Get("/organization/")
	//  /api/v1/superuser/organizations/
	resp, err := o.client.Get("/superuser/organizations/")
	fmt.Printf("ListOrganizations resp.Body: %v\n", resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("failed to list organizations: endpoint not found (404)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list organizations: %s", resp.Status)
	}

	var result struct {
		Organizations []struct {
			Name string `json:"name"`
		} `json:"organizations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	var orgs []string
	for _, org := range result.Organizations {
		orgs = append(orgs, org.Name)
	}

	return orgs, nil
}

func (o *Operations) ListOrganizationRepositories(org string) ([]string, error) {
	// url := fmt.Sprintf("/repository?public=true&namespace=%s&starred=false", org)
	url := fmt.Sprintf("/repository?namespace=%s", org)
	fmt.Printf("ListOrganizationRepositories url: %v\n", url)
	resp, err := o.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}
	resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	var result struct {
		Repositories []struct {
			Name string `json:"name"`
		} `json:"repositories"`
	}

	if err := json.NewDecoder(bytes.NewBuffer(bodyBytes)).Decode(&result); err != nil {
		// fmt.Printf("Response body: %s\n", string(bodyBytes))
		return nil, fmt.Errorf("failed to decode response: %v", err)
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

func (o *Operations) ListRepositoryTags(org, repo string) (TagResults, error) {
	url := fmt.Sprintf("/repository/%s/%s/tag", org, repo)
	resp, err := o.client.Get(url)
	if err != nil {
		return TagResults{}, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return TagResults{}, fmt.Errorf("failed to read response body: %v", err)
	}
	resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	result := TagResults{}

	if err := json.NewDecoder(bytes.NewBuffer(bodyBytes)).Decode(&result); err != nil {
		// fmt.Printf("Response body: %s\n", string(bodyBytes))
		return TagResults{}, fmt.Errorf("failed to decode response: %v", err)
	}
	for i := range result.Tags {
		vul, status, err := o.getVulnerabilities(org, repo, result.Tags[i].Digest)
		if err == nil && status == "scanned" {
			// Erstelle eine neue Vulnerabilities-Struktur
			vulStruct := Vulnerabilities{
				Status: status,
				Data: struct {
					Layer struct {
						Features []VulnerabilityInfo `json:"Features"`
					} `json:"Layer"`
				}{
					Layer: struct {
						Features []VulnerabilityInfo `json:"Features"`
					}{
						Features: vul,
					},
				},
			}

			// Filtere nur Features mit Vulnerabilities
			var filteredFeatures []VulnerabilityInfo
			for _, feature := range vul {
				if len(feature.Vulnerabilities) > 0 || len(feature.BaseScores) > 0 || len(feature.CVEIds) > 0 {
					filteredFeatures = append(filteredFeatures, feature)
				}
			}

			vulStruct.Data.Layer.Features = filteredFeatures
			result.Tags[i].Vulnerabilities = vulStruct
		}
		result.Tags[i].Repo = repo
	}

	return result, nil
}

func CollectVulnerabilities(data Vulnerabilities) []VulnerabilityInfo {
	var vulns []VulnerabilityInfo

	for _, feature := range data.Data.Layer.Features {
		// Check if any of the vulnerability-related fields are non-empty
		if len(feature.BaseScores) > 0 || len(feature.CVEIds) > 0 || len(feature.Vulnerabilities) > 0 {
			vuln := VulnerabilityInfo{
				Name:            feature.Name,
				Version:         feature.Version,
				BaseScores:      feature.BaseScores,
				CVEIds:          feature.CVEIds,
				Vulnerabilities: feature.Vulnerabilities,
			}
			vulns = append(vulns, vuln)
		}
	}

	return vulns
}

// Usage example in the getVulnerabilities function:
func (o *Operations) getVulnerabilities(org, repo, digest string) ([]VulnerabilityInfo, string, error) {
	url := fmt.Sprintf("/repository/%s/%s/manifest/%s/security", org, repo, digest)
	resp, err := o.client.Get(url)
	if err != nil {
		return []VulnerabilityInfo{}, "", err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return []VulnerabilityInfo{}, "", fmt.Errorf("failed to read response body: %v", err)
	}
	resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	result := Vulnerabilities{}
	if err := json.NewDecoder(bytes.NewBuffer(bodyBytes)).Decode(&result); err != nil {
		// fmt.Printf("Response body: %s\n", string(bodyBytes))
		return []VulnerabilityInfo{}, "", fmt.Errorf("failed to decode response: %v", err)
	}

	// You can call CollectVulnerabilities here if needed
	vulnerabilities := CollectVulnerabilities(result)

	return vulnerabilities, result.Status, nil
}
