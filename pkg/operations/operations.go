package operations

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jaegdi/quay-client/pkg/client"
	"gopkg.in/yaml.v2"
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
	Data   *struct {
		Layer struct {
			Features []VulnerabilityInfo `json:"Features,omitempty"`
		} `json:"Layer,omitempty"`
	} `json:"data,omitempty"`
}

type TagDetails struct {
	Repo            string          `json:"repository"`
	Name            string          `json:"name"`
	Digest          string          `json:"manifest_digest"`
	LastModified    string          `json:"last_modified"`
	Size            float64         `json:"size"`
	Expired         bool            `json:"expired"`
	Manifest        string          `json:"manifest"`
	Vulnerabilities Vulnerabilities `json:"vulnerabilities"`
	HighestScore    float64         `json:"highest_score"`
	HighestSeverity string          `json:"highest_severity"`
}

var severityLevels = map[string]int{
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

type TagResults struct {
	Tags []TagDetails `json:"tags"`
}
type Prototypes struct {
	Prototypes []struct {
		ActivatingUser interface{} `json:"activating_user"`
		Delegate       struct {
			Name        string `json:"name"`
			Kind        string `json:"kind"`
			IsRobot     bool   `json:"is_robot,omitempty"`
			IsOrgMember bool   `json:"is_org_member,omitempty"`
			Avatar      struct {
				Name  string `json:"name"`
				Hash  string `json:"hash"`
				Color string `json:"color"`
				Kind  string `json:"kind"`
			} `json:"avatar"`
		} `json:"delegate"`
		Role string `json:"role"`
		ID   string `json:"id"`
	} `json:"prototypes"`
}

// NewOperations erstellt eine neue Instanz von Operations mit dem angegebenen Client.
func NewOperations(client *client.Client) *Operations {
	return &Operations{client: client}
}

// ListOrganizations returns a list of organizations that the user can see.
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

// ListOrganizationRepositories returns a list of repositories for the specified organization.
func (o *Operations) ListOrganizationRepositories(org string) ([]string, error) {
	// url := fmt.Sprintf("/repository?public=true&namespace=%s", org)
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

// ListRepositoriesByRegex returns a filtered list of repositories that match the specified regex pattern.
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

// DeleteTag deletes the specified tag from the organization's repository.
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

// GetUsers read the Prototypes Userinformation for specified organization.
func (o *Operations) GetUsers(org string) (Prototypes, error) {
	path := fmt.Sprintf("/organization/%s/prototypes", org)
	resp, err := o.client.Get(path)
	if err != nil {
		return Prototypes{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Prototypes{}, fmt.Errorf("failed to delete tag: %s", resp.Status)
	}
	var result Prototypes
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return Prototypes{}, fmt.Errorf("failed to decode response: %v", err)
	}
	return result, nil
}

// ListRepositoryTags retrieves the tags of a specified repository within an organization, optionally with details.
// ListRepositoryTags returns a list of tags for a specific repository.
// This function takes the name of the repository as an input parameter and returns a list of tags,
// associated with this repository. Tags are specific markings or labels that refer to certain
// Commits can be applied in the repository to mark important points in the project's history,
// such as versions or releases. This feature can be useful to get an overview of all available
// To obtain versions of a project or to obtain specific versions for download or further processing
// to identify.
//
// Parameters:
//   - org: The organization name.
//   - repo: The repository name.
//   - details: A boolean indicating whether to include detailed vulnerability information.
//   - severity: A string specifying the severity level to filter tags.
//   - baseScore: A float64 specifying the base score to filter tags.
//
// Returns:
//   - TagResults: A struct containing the filtered tags.
//   - error: An error if the operation fails at any point.
//
// The function performs the following steps:
//  1. Constructs the URL for the repository tags.
//  2. Sends a GET request to the URL.
//  3. Reads and decodes the response body into a TagResults struct.
//  4. Iterates over the tags and retrieves their vulnerabilities.
//  5. Filters the vulnerabilities based on the presence of features.
//  6. Calculates the highest score and severity for each tag.
//  7. Optionally includes detailed vulnerability information based on the 'details' parameter.
//  8. Filters the tags based on the specified severity and base score.
//  9. Returns the filtered tags and any error encountered.
func (o *Operations) ListRepositoryTags(org, repo, severity string, baseScore float64, details bool) (TagResults, error) {
	//  1. Constructs the URL for the repository tags.
	url := fmt.Sprintf("/repository/%s/%s/tag", org, repo)
	// 2. Sends a GET request to the URL.
	resp, err := o.client.Get(url)
	if err != nil {
		return TagResults{}, fmt.Errorf("failed to GET response: %v", err)
	}
	defer resp.Body.Close()
	// 3. Reads and decodes the response body into a TagResults struct.
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return TagResults{}, fmt.Errorf("failed to read response body: %v", err)
	}
	resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	result := TagResults{}
	filteredTags := TagResults{}

	if err := json.NewDecoder(bytes.NewBuffer(bodyBytes)).Decode(&result); err != nil {
		return TagResults{}, fmt.Errorf("failed to decode response: %v", err)
	}
	// 4. Iterates over the tags and retrieves their vulnerabilities.
	for i := range result.Tags {
		vul, status, err := o.getVulnerabilities(org, repo, result.Tags[i].Digest)
		// 5. Filters the vulnerabilities based on the presence of features.
		if err == nil && status == "scanned" {
			var filteredFeatures []VulnerabilityInfo
			vulStruct := Vulnerabilities{}
			for _, feature := range vul {
				if len(feature.Vulnerabilities) > 0 || len(feature.BaseScores) > 0 || len(feature.CVEIds) > 0 {
					filteredFeatures = append(filteredFeatures, feature)
				}
			}
			vulStruct.Data = &struct {
				Layer struct {
					Features []VulnerabilityInfo `json:"Features,omitempty"`
				} `json:"Layer,omitempty"`
			}{}
			vulStruct.Data.Layer.Features = filteredFeatures
			// 6. Calculates the highest score and severity for each tag.
			highestScore, highestSeverity := getHighestScoreAndSeverity(filteredFeatures)
			result.Tags[i].HighestScore = highestScore
			result.Tags[i].HighestSeverity = highestSeverity
			vulStruct.Status = status
			// 7. Optionally includes detailed vulnerability information based on the 'details' parameter.
			if details {
				result.Tags[i].Vulnerabilities = vulStruct
			} else {
				result.Tags[i].Vulnerabilities.Status = status
				result.Tags[i].Vulnerabilities.Data = nil
			}
			result.Tags[i].Repo = repo
			result.Tags[i].Size = float64(int(result.Tags[i].Size/(1024*1024)*100)) / 100
			// 8. Filters the tags based on the specified severity and base score.
			if severity != "" || baseScore > 0 {
				o.FilterTagsBySeverityAndBaseScore(result.Tags[i], vulStruct, severity, baseScore, &filteredTags)
			} else {
				filteredTags.Tags = append(filteredTags.Tags, result.Tags[i])
			}
		}
	}
	// 9. Returns the filtered tags and any error encountered.
	return filteredTags, nil
}

// getHighestScoreAndSeverity returns the highest base score and severity level from a list of VulnerabilityInfo.
// getHighestScoreAndSeverity takes a slice of VulnerabilityInfo and returns the highest base score and the
// highest severity level found.
//
// Parameters:
//
//	features []VulnerabilityInfo: A slice of VulnerabilityInfo structs containing vulnerability data.
//
// Returns:
//
//	float64: The highest base score among all vulnerabilities.
//	string: The highest severity level among all vulnerabilities.
func getHighestScoreAndSeverity(features []VulnerabilityInfo) (float64, string) {
	var highestScore float64
	var highestSeverity string

	for _, feature := range features {
		for _, score := range feature.BaseScores {
			if score > highestScore {
				highestScore = score
			}
		}
		for _, vuln := range feature.Vulnerabilities {
			severity := strings.ToLower(vuln.Severity)
			if severityLevels[severity] > severityLevels[strings.ToLower(highestSeverity)] {
				highestSeverity = vuln.Severity
			}
		}
	}
	return highestScore, highestSeverity
}

// PrintRepositoriyTags prints the tags of a repository to the console.
func (o *Operations) PrintRepositoriyTags(tags TagResults) {
	for _, tag := range tags.Tags {
		expired := "No"
		if tag.Expired {
			expired = "Yes"
		}
		size := float64(tag.Size) / (1024 * 1024)
		size = tag.Size
		lastModified, err := time.Parse(time.RFC1123, tag.LastModified)
		if err != nil {
			fmt.Printf("Failed to parse LastModified: %v\n", err)
		} else {
			lastModified = lastModified.Local()
		}
		fmt.Printf("Repo: %-30.30s  Tag: %-20.20s  Digest: %s  LastModified: %s Size: %10.2fMb  Expired: %s  Status: %-9.9s  Score: %5.2f  Severity: %-10.10s\n",
			tag.Repo, tag.Name, tag.Digest, lastModified.Format("02.01.2006-15:04:05"), size,
			expired, tag.Vulnerabilities.Status, tag.HighestScore, tag.HighestSeverity)
		if tag.Vulnerabilities.Data != nil {
			for _, feature := range tag.Vulnerabilities.Data.Layer.Features {
				fmt.Printf("        Feature: %s Version: %s  BaseScore: %3.1f\n", string(feature.Name), feature.Version, feature.BaseScores)
				for _, vuln := range feature.Vulnerabilities {
					v, err := yaml.Marshal(vuln)
					if err == nil {
						lines := strings.Split(string(v), "\n")
						for _, line := range lines {
							fmt.Printf("            %s\n", line)
						}
					}
				}
			}
		}
	}
}

func (o *Operations) PrintUsers(users Prototypes) {
	line := "-----------------------------"
	format := "%-15.15s  %-25.25s %-10.10s %-15.15s %-25.25s\n"
	fmt.Printf(format, "Kind", "Name", "Role", "AvatarKind", "AvatarName")
	fmt.Printf(format, line, line, line, line, line)
	for _, user := range users.Prototypes {
		fmt.Printf(format, user.Delegate.Kind, user.Delegate.Name, user.Role, user.Delegate.Avatar.Kind, user.Delegate.Avatar.Name)
	}
}

// CollectVulnerabilities collects and returns a list of VulnerabilityInfo from the given vulnerabilities.
func CollectVulnerabilities(data Vulnerabilities) []VulnerabilityInfo {
	var vulns []VulnerabilityInfo

	if data.Data != nil {
		for _, feature := range data.Data.Layer.Features {
			// Check if any of the vulnerability-related fields are non-empty
			if len(feature.BaseScores) > 0 || len(feature.CVEIds) > 0 || len(feature.Vulnerabilities) > 0 {
				vuln := VulnerabilityInfo{
					Name:       feature.Name,
					Version:    feature.Version,
					BaseScores: feature.BaseScores,
					CVEIds:     feature.CVEIds,
				}
				vuln.Vulnerabilities = feature.Vulnerabilities
				vulns = append(vulns, vuln)
			}
		}
	}
	return vulns
}

// getVulnerabilities returns a list of VulnerabilityInfo, status and an error for the specified digest.
func (o *Operations) getVulnerabilities(org string, repo string, digest string) ([]VulnerabilityInfo, string, error) {
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
		return []VulnerabilityInfo{}, "", fmt.Errorf("failed to decode response: %v", err)
	}

	// You can call CollectVulnerabilities here if needed
	vulnerabilities := CollectVulnerabilities(result)
	return vulnerabilities, result.Status, nil
}

// FilterTagsBySeverityAndBaseScore filters the tags according to the specified severity and base score.
func (o *Operations) FilterTagsBySeverityAndBaseScore(tag TagDetails, vulnerabilities Vulnerabilities, severity string, baseScore float64, filteredTags *TagResults) {
	filteredFeatures := []VulnerabilityInfo{}
	if vulnerabilities.Data != nil {
		for _, feature := range vulnerabilities.Data.Layer.Features {
			filteredVulns := []featureVulnerabilities{}
			for _, vuln := range feature.Vulnerabilities {
				if (severity == "" || severityLevels[strings.ToLower(vuln.Severity)] >= severityLevels[strings.ToLower(severity)]) &&
					(baseScore == 0 || anyBaseScoreAbove(feature.BaseScores, baseScore)) {
					filteredVulns = append(filteredVulns, vuln)
				}
			}
			if len(filteredVulns) > 0 {
				feature.Vulnerabilities = filteredVulns
				filteredFeatures = append(filteredFeatures, feature)
			}
		}
	}
	if len(filteredFeatures) > 0 {
		filteredTags.Tags = append(filteredTags.Tags, tag)
	}
	// return filteredTags
}

// anyBaseScoreAbove checks whether any of the base scores are above the specified threshold.
func anyBaseScoreAbove(baseScores []float64, threshold float64) bool {
	for _, score := range baseScores {
		if score > threshold {
			return true
		}
	}
	return false
}
