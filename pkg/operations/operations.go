package operations

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jaegdi/quay-client/pkg/cli"
	"github.com/jaegdi/quay-client/pkg/client"
	"github.com/jaegdi/quay-client/pkg/config"
	"github.com/jaegdi/quay-client/pkg/helper"
	"github.com/jaegdi/quay-client/pkg/imagetool"
)

// Operations represents the operations that can be performed on the Quay API.
type Operations struct {
	client *client.Client
}

// Repository represents a repository in the Quay registry.
type Repository struct {
	Name string       `json:"name"`
	Tags []TagDetails `json:"tags,omitempty"`
}

// Organization represents an organization in the Quay registry.
type Organization struct {
	Name         string       `json:"name"`
	Repositories []Repository `json:"repositories,omitempty"`
}

// OrgSet represents a set of organizations in the Quay registry.
type OrgSet struct {
	Organizations []Organization `json:"organizations"`
}

// VulnerabilityInfo represents the information about a vulnerability.
type VulnerabilityInfo struct {
	Name            string                   `json:"Name"`
	Version         string                   `json:"Version"`
	BaseScores      []float64                `json:"BaseScores"`
	CVEIds          []string                 `json:"CVEIds"`
	Vulnerabilities []FeatureVulnerabilities `json:"Vulnerabilities"`
}

// FeatureVulnerabilities represents the vulnerabilities of a feature.
type FeatureVulnerabilities struct {
	Name        string `json:"Name"`
	Link        string `json:"Link"`
	Description string `json:"Description"`
	FixVersion  string `json:"FixedBy"`
	Severity    string `json:"Severity"`
}

// Vulnerabilities represents the vulnerabilities of a repository.
type Vulnerabilities struct {
	Status string `json:"status"`
	Data   *struct {
		Layer struct {
			Features []VulnerabilityInfo `json:"Features,omitempty"`
		} `json:"Layer,omitempty"`
	} `json:"data,omitempty"`
}

// TagDetails represents the details of a tag in the Quay registry.
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
	Age             int             `json:"age"`
}

// severityLevels maps severity levels to their corresponding integer values.
var severityLevels = map[string]int{
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

// TagResults represents the results of a tag operation.
type TagResults struct {
	Tags []TagDetails `json:"tags"`
}

// Prototypes represents the user information for an organization.
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

// Notification represents a notification in the Quay registry.
type Notification struct {
	ID          int    `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	CreatedAt   string `json:"created_at"`
}

// NewOperations erstellt eine neue Instanz von Operations mit dem angegebenen Client.
// NewOperations creates a new instance of Operations with the specified client.
//
// Parameters:
//
//	client: The client to use for the operations.
//
// Returns:
//
//	A new instance of Operations.
func NewOperations(client *client.Client) *Operations {
	return &Operations{client: client}
}

// ListOrganizations returns a list of organizations that the user can see.
// ListOrganizations retrieves the list of organizations that the user has access to.
// This function sends a GET request to the /organization endpoint and decodes the response
// into a list of Organization structs. The function returns the list of organizations and
// an error if the request fails or the response cannot be processed.
//
// Returns:
//   - OrgSet: A struct containing the list of organizations.
//   - error:  An error if the operation fails at any point.
//
// The function performs the following steps:
//  1. Send a GET request to the /organization endpoint.
//  2. Read and decode the response body into a list of Organization structs.
//  3. Return the list of organizations and any error encountered.
func (ops *Operations) ListOrganizations() (OrgSet, error) {
	// resp, err := o.client.Get("/organization/")
	//  /api/v1/superuser/organizations/
	resp, err := ops.client.Get("/superuser/organizations/")
	// log.Printf("ListOrganizations resp.Body: %v\n", resp.Body)
	if err != nil {
		return OrgSet{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return OrgSet{}, fmt.Errorf("failed to list organizations: endpoint not found (404)")
	}
	if resp.StatusCode != http.StatusOK {
		return OrgSet{}, fmt.Errorf("failed to list organizations: %s", resp.Status)
	}

	var result struct {
		Organizations []Organization `json:"organizations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return OrgSet{}, fmt.Errorf("failed to decode response: %v", err)
	}

	var orgs OrgSet
	for _, org := range result.Organizations {
		orgs.Organizations = append(orgs.Organizations, org)
	}

	return orgs, nil
}

// ListOrganizationRepositories returns a list of repositories for the specified organization.
// ListOrganizationRepositories retrieves the list of repositories for the specified organization.
// This function takes the name of the organization as an input parameter and returns a list of
// repositories associated with this organization. Repositories are collections of container images
// that are stored in the Quay registry. This feature can be useful to get an overview of all
// repositories in an organization or to obtain specific repositories for further processing.
//
// Parameters:
//   - org: The organization name.
//
// Returns:
//   - OrgSet: A struct containing the list of repositories.
//   - error:  An error if the operation fails at any point.
func (ops *Operations) ListOrganizationRepositories(org string, details bool) (OrgSet, error) {
	flags := cli.GetFlags()
	onlyYoungest := details && flags.Tag == ""
	url := fmt.Sprintf("/repository?namespace=%s", org)
	helper.Verifyf("ListOrganizationRepositories url: %v   organisation: %s\n", url, org)
	// query the repositories of org
	resp, err := ops.client.Get(url)
	if err != nil {
		helper.Verify("ListOrganizationRepositories failed to GET response: ", err)
		return OrgSet{}, err
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		helper.Verify("ListOrganizationRepositories failed to read response body: ", err)
		return OrgSet{}, fmt.Errorf("failed to read response body: %v", err)
	}
	resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	var result struct {
		Repositories []Repository
	}
	if err := json.NewDecoder(bytes.NewBuffer(bodyBytes)).Decode(&result); err != nil {
		// fmt.Printf("Response body: %s\n", string(bodyBytes))
		helper.Verifyf("Response body: %s\n", string(bodyBytes))
		if strings.Contains(string(bodyBytes), "<html>") {
			return OrgSet{}, fmt.Errorf("received HTML response, likely an error page")
		}
		return OrgSet{}, fmt.Errorf("failed to decode response: %v", err)
	}

	var orgs OrgSet
	orgs.Organizations = append(orgs.Organizations, Organization{Name: org})

	for oi := range orgs.Organizations {
		for _, repo := range result.Repositories {
			orgs.Organizations[oi].Repositories = append(orgs.Organizations[oi].Repositories, repo)
		}
		if details {
			var wg sync.WaitGroup
			repoChan := make(chan Repository, len(orgs.Organizations[oi].Repositories))

			for ri := range orgs.Organizations[oi].Repositories {
				wg.Add(1)
				time.Sleep(1 * time.Millisecond)

				// repo := orgs.Organizations[oi].Repositories[i]
				go func(repo Repository) {
					defer wg.Done()
					helper.Verify("ListOrganizationRepositories with org: ", org, " repo: ", orgs.Organizations[oi].Repositories[ri].Name)
					tags, err := ops.ListRepositoryTags(org, repo.Name, flags.Tag, "", 0, false, onlyYoungest)
					if err != nil {
						log.Printf("Failed to list tags for repository %s: %v", repo.Name, err)
						return
					}
					repo.Tags = tags.Tags
					if len(repo.Tags) == 0 {
						return
					}

					repoChan <- repo
				}(orgs.Organizations[oi].Repositories[ri])
			}

			wg.Wait()
			close(repoChan)

			var updatedRepos []Repository
			for repo := range repoChan {
				updatedRepos = append(updatedRepos, repo)
			}

			orgs.Organizations[oi].Repositories = updatedRepos
		}
	}
	return orgs, nil
}

// ListRepositoriesByRegex returns a filtered list of repositories that match the specified regex pattern.
// ListRepositoriesByRegex retrieves a filtered list of repositories that match the specified regex pattern.
// This function takes the name of the organization and a regex pattern as input parameters and returns
// a list of repositories that match the specified pattern. The regex pattern is used to filter the list
// of repositories based on their names. This feature can be useful to get an overview of repositories
// that match a specific naming convention or to obtain repositories that contain certain keywords.
//
// Parameters:
//   - org: The organization name.
//   - pattern: The regex pattern to filter repositories.
//
// Returns:
//   - OrgSet: A struct containing the filtered list of repositories.
//   - error:  An error if the operation fails at any point.
func (ops *Operations) ListRepositoriesByRegex(org, pattern string, details bool) (OrgSet, error) {
	orgs, err := ops.ListOrganizationRepositories(org, details)
	if err != nil {
		return OrgSet{}, err
	}
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return OrgSet{}, err
	}
	filtered := OrgSet{}

	for i, org := range orgs.Organizations {
		filtered.Organizations = append(filtered.Organizations, org)
		filtered.Organizations[i].Repositories = []Repository{}
		// helper.Verifyf("\nStart filtered.Organizations with \n    org: %v\n", filtered.Organizations[i])
		for j, repo := range org.Repositories {
			if regex.MatchString(org.Repositories[j].Name) {
				// r, _ := json.MarshalIndent(repo, "", "  ")
				// helper.Verifyf("\n  before append ListRepositoriesByRegex with \n    org: %v, \n    repo: %v\n", filtered, string(r))
				filtered.Organizations[i].Repositories = append(filtered.Organizations[i].Repositories, repo)
				// f, _ := json.MarshalIndent(filtered, "", "  ")
				// helper.Verifyf("\n  after append filtered ListRepositoriesByRegex with \n    org: %v, \n    repo: %v\n", org.Name, string(f))
			}
		}
	}
	// f, _ := json.MarshalIndent(filtered, "", "  ")
	// helper.Verifyf("\nfound repos: \n  %v\n", filtered)
	return filtered, nil
}

// DeleteTag deletes the specified tag from the organization's repository.
// This function takes the name of the organization, the repository, and the tag as input parameters
// and deletes the specified tag from the repository. Tags are specific markings or labels that refer
// to certain commits in the repository and can be used to mark important points in the project's history,
// such as versions or releases. This feature can be useful to remove outdated or unused tags from a repository.
//
// Parameters:
//   - org:   The organization name.
//   - repo:  The repository name.
//   - tag:   The tag name to delete.
//
// Returns:
//   - error: An error if the operation fails at any point.
func (ops *Operations) DeleteTag(org, repo, tag string) (string, error) {
	path := fmt.Sprintf("/repository/%s/%s/tag/%s", org, repo, tag)
	resp, err := ops.client.Delete(path)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to delete tag: %s", resp.Status)
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}
	return string(bodyBytes), nil
}

// GenShellCmdsToDeleteTags filters tags based on repository name, tag name, severity, or age criteria and prints a command for each found tag.
// This function takes the organization name, repository name pattern, tag name pattern, severity level, and age as input parameters.
// It filters the tags based on the provided criteria and prints a command for each found tag in the format:
// "qc -o org -r repo -t tag -d     # Age: x, Severity ....".
//
// Parameters:
//   - org:         The organization name.
//   - repoPattern: The regex pattern to filter repository names.
//   - tagPattern:  The regex pattern to filter tag names.
//   - severity:    The minimum severity level to filter tags.
//   - minage: 	    The maximum age of the tags in days.
//
// Returns:
//   - error: An error if the operation fails at any point.
func (ops *Operations) GenShellCmdsToDeleteTags(org string, cfg *config.Config, repoPattern, tagPattern, severity string, minage int) error {
	orgs, err := ops.ListOrganizationRepositories(org, true)
	if err != nil {
		return err
	}
	repoRegex, err := regexp.Compile(repoPattern)
	if err != nil {
		return err
	}
	tagRegex, err := regexp.Compile(tagPattern)
	if err != nil {
		return err
	}

	for _, org := range orgs.Organizations {
		// read all used image tags of this org
		usedTags, err := imagetool.LoadImageToolData(org.Name)
		if err != nil {
			return err
		}
		for _, repo := range org.Repositories {
			if !repoRegex.MatchString(repo.Name) {
				continue
			}
			for _, tag := range repo.Tags {
				// check, if tag is used somewhere in the clusters
				ClusterRegistryUrl := fmt.Sprintf("%s-images/%s:%s", org.Name, repo.Name, tag.Name)
				QuayRegistryUrl := fmt.Sprintf("%s/%s/%s:%s", cfg.QuayURL, org.Name, repo.Name, tag.Name)
				if cluster, namespace, regurl, found := imagetool.IsRegistryUrlFound(usedTags, ClusterRegistryUrl); found {
					fmt.Printf("# %s/%s:%s is used in cluster %s in namespace %s - Url: %s\n", org.Name, repo.Name, tag.Name, cluster, namespace, regurl)
					continue
				}
				if cluster, namespace, regurl, found := imagetool.IsRegistryUrlFound(usedTags, QuayRegistryUrl); found {
					fmt.Printf("# %s/%s:%s is used in cluster %s in namespace %s - Url: %s\n", org.Name, repo.Name, tag.Name, cluster, namespace, regurl)
					continue
				}
				if !tagRegex.MatchString(tag.Name) {
					continue
				}
				if severity != "" && severityLevels[strings.ToLower(tag.HighestSeverity)] < severityLevels[strings.ToLower(severity)] {
					continue
				}
				if minage > 0 && tag.Age < minage {
					continue
				}
				s := fmt.Sprintf("qc -o %-5s -r %-36s -t %-25s -d", org.Name, tag.Repo, tag.Name)
				fmt.Printf("%-80s   # Age: %4d, Severity %-10s\n", s, tag.Age, tag.HighestSeverity)
			}
		}
	}
	return nil
}

// GetUsers retrieves the user information for the specified organization.
// GetUsers retrieves the user information for the specified organization.
// This function takes the name of the organization as an input parameter and returns a list of
// user information associated with this organization. User information includes details such as
// the user's role, ID, and avatar. This feature can be useful to get an overview of all users
// in an organization or to obtain specific user information for further processing.
//
// Parameters:
//   - org: The organization name.
//
// Returns:
//   - Prototypes: A struct containing the user information.
//   - error:      An error if the operation fails at any point.
func (ops *Operations) GetUsers(org string) (Prototypes, error) {
	path := fmt.Sprintf("/organization/%s/prototypes", org)
	resp, err := ops.client.Get(path)
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
// This function takes the name of the repository as an input parameter and returns a list of tags,
// associated with this repository. Tags are specific markings or labels that refer to certain
// Commits can be applied in the repository to mark important points in the project's history,
// such as versions or releases. This feature can be useful to get an overview of all available
// To obtain versions of a project or to obtain specific versions for download or further processing
// to identify.
//
// Parameters:
//   - org:       The organization name.
//   - repo:      The repository name.
//   - details:   A boolean indicating whether to include detailed vulnerability information.
//   - severity:  A string specifying the severity level to filter tags.
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
func (ops *Operations) ListRepositoryTags(org, repo, tag, severity string, baseScore float64, details bool, onlyYoungest bool) (TagResults, error) {
	//  1. Constructs the URL for the repository tags.
	helper.Verify("ListRepositoryTags with org: ", org, " repo: ", repo, " tag: ", tag, " severity: ", severity, " baseScore: ", baseScore, " details: ", details)
	url := fmt.Sprintf("/repository/%s/%s/tag", org, repo)
	// 2. Sends a GET request to the URL.
	resp, err := ops.client.Get(url)
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

	var result, filteredTags TagResults
	if err := json.NewDecoder(bytes.NewBuffer(bodyBytes)).Decode(&result); err != nil {
		if strings.Contains(string(bodyBytes), "<html>") {
			return TagResults{}, fmt.Errorf("received HTML response, likely an error page")
		}
		return TagResults{}, fmt.Errorf("failed to decode response: %v", err)
	}

	if onlyYoungest && len(result.Tags) > 0 {
		// Find the youngest tag
		if len(result.Tags) == 0 {
			return TagResults{}, nil
		}
		youngestTag := result.Tags[0]
		for _, tag := range result.Tags {
			if tag.Age < youngestTag.Age {
				youngestTag = tag
			}
		}
		result.Tags = []TagDetails{youngestTag}
	}
	var wg sync.WaitGroup
	tagChan := make(chan TagDetails, len(result.Tags))

	// 4. Iterates over the tags and retrieves their vulnerabilities in parallel.
	for i := range result.Tags {
		if !tagMatches(tag, result.Tags[i].Name) {
			continue
		}
		wg.Add(1)
		go func(tag TagDetails) {
			defer wg.Done()
			// Retrieve vulnerabilities for the given tag
			vul, status, err := ops.getVulnerabilities(org, repo, tag.Digest)
			if err != nil || status != "scanned" {
				// If there's an error or the status is not "scanned", skip this tag
				return
			}

			// Filter out features that do not have any vulnerabilities, base scores, or CVE IDs
			filteredFeatures := filterVulnerabilities(vul)
			// Create a Vulnerabilities struct from the filtered features and status
			vulStruct := createVulnerabilityStruct(filteredFeatures, status)

			// Calculate the highest base score and severity level from the filtered features
			tag.HighestScore, tag.HighestSeverity = getHighestScoreAndSeverity(&filteredFeatures)
			// Calculate the age of the tag in days based on its last modified timestamp
			tag.Age = calculateTagAge(tag.LastModified)
			// Set the vulnerability details based on the 'details' flag
			tag.Vulnerabilities = setVulnerabilityDetails(details, vulStruct)
			// Set the repository name for the tag
			tag.Repo = repo
			// Format the size of the tag in megabytes with two decimal places
			tag.Size = formatTagSize(tag.Size)

			// If severity or baseScore filtering is required, filter the tags accordingly
			if severity != "" || baseScore > 0 {
				ops.FilterTagsBySeverityAndBaseScore(tag, vulStruct, severity, baseScore, &filteredTags)
			} else {
				// Otherwise, send the tag to the tagChan channel
				tagChan <- tag
			}
		}(result.Tags[i])
		time.Sleep(1 * time.Millisecond)
	}

	wg.Wait()
	close(tagChan)

	for tag := range tagChan {
		filteredTags.Tags = append(filteredTags.Tags, tag)
	}

	return filteredTags, nil
}

// tagMatches checks if a tag string matches a given regex pattern.
// This function takes a regex pattern and a tag string as input parameters and returns a boolean
// indicating whether the tag string matches the pattern. If the pattern is empty, the function
// returns true, indicating that all tags match. If the pattern is not empty, the function uses
// the regexp.MatchString function to check for a match and returns the result.
//
// Parameters:
//   - tagPattern: The regex pattern to match against the tag string.
//   - tagString:  The tag string to be matched.
//
// Returns:
//   - bool: true if the tag string matches the pattern, false otherwise.
func tagMatches(tagPattern, tagString string) bool {
	if tagPattern != "" {
		if matched, err := regexp.MatchString(tagPattern, tagString); err != nil {
			return false
		} else {
			return matched
		}
	}
	return true
}

// filterVulnerabilities filters out features that do not have any vulnerabilities, base scores, or CVE IDs.
// This function takes a slice of VulnerabilityInfo and returns a new slice containing only the features
// that have at least one vulnerability, base score, or CVE ID. This feature can be useful to remove
// features that do not contain any relevant vulnerability information.
//
// Parameters:
//   - vul: A slice of VulnerabilityInfo containing the features to be filtered.
//
// Returns:
//   - []VulnerabilityInfo: A new slice containing only the features with vulnerabilities, base scores, or CVE IDs.
func filterVulnerabilities(vul []VulnerabilityInfo) []VulnerabilityInfo {
	var filteredFeatures []VulnerabilityInfo
	for _, feature := range vul {
		if len(feature.Vulnerabilities) > 0 || len(feature.BaseScores) > 0 || len(feature.CVEIds) > 0 {
			filteredFeatures = append(filteredFeatures, feature)
		}
	}
	return filteredFeatures
}

// createVulnerabilityStruct creates a Vulnerabilities struct from the given filtered features and status.
// This function takes a slice of filtered VulnerabilityInfo and a status string as input parameters and
// returns a Vulnerabilities struct containing the filtered features and the status. This feature can be
// useful to encapsulate the vulnerability information in a structured format for further processing or
// display.
//
// Parameters:
//   - filteredFeatures: A slice of VulnerabilityInfo containing the filtered features.
//   - status:           A string representing the status of the vulnerability scan.
//
// Returns:
//   - Vulnerabilities: A struct containing the filtered features and the status.
func createVulnerabilityStruct(filteredFeatures []VulnerabilityInfo, status string) Vulnerabilities {
	return Vulnerabilities{
		Status: status,
		Data: &struct {
			Layer struct {
				Features []VulnerabilityInfo `json:"Features,omitempty"`
			} `json:"Layer,omitempty"`
		}{
			Layer: struct {
				Features []VulnerabilityInfo `json:"Features,omitempty"`
			}{
				Features: filteredFeatures,
			},
		},
	}
}

// calculateTagAge calculates the age of a tag in days based on its last modified timestamp.
// This function takes the last modified timestamp of a tag as a string in RFC1123 format and
// returns the age of the tag in days. If the timestamp cannot be parsed, the function logs
// an error and returns 0.
//
// Parameters:
//   - lastModified: The last modified timestamp of the tag in RFC1123 format.
//
// Returns:
//   - int: The age of the tag in days.
func calculateTagAge(lastModified string) int {
	lastModifiedTime, err := time.Parse(time.RFC1123, lastModified)
	if err != nil {
		log.Printf("Failed to parse LastModified: %v", err)
		return 0
	}
	return int(time.Since(lastModifiedTime).Hours() / 24)
}

// setVulnerabilityDetails returns the vulnerability details based on the 'details' flag.
// If 'details' is true, it returns the full vulnerability structure. Otherwise, it returns
// only the status of the vulnerabilities.
//
// Parameters:
//   - details:   A boolean indicating whether to include detailed vulnerability information.
//   - vulStruct: The full vulnerability structure.
//
// Returns:
//   - Vulnerabilities: The vulnerability structure with or without details based on the 'details' flag.
func setVulnerabilityDetails(details bool, vulStruct Vulnerabilities) Vulnerabilities {
	if details {
		return vulStruct
	}
	return Vulnerabilities{Status: vulStruct.Status}
}

// formatTagSize formats the size of a tag in megabytes with two decimal places.
// This function takes the size of a tag in bytes as a float64 and returns the size
// in megabytes, rounded to two decimal places. This feature can be useful to display
// the size of a tag in a more human-readable format.
//
// Parameters:
//   - size: The size of the tag in bytes.
//
// Returns:
//   - float64: The size of the tag in megabytes, rounded to two decimal places.
func formatTagSize(size float64) float64 {
	return float64(int(size/(1024*1024)*100)) / 100
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
//	string:  The highest severity level among all vulnerabilities.
func getHighestScoreAndSeverity(features *[]VulnerabilityInfo) (float64, string) {
	var highestScore float64
	var highestSeverity string
	longlines := regexp.MustCompile(`\. `)
	blanklines := regexp.MustCompile(`\n\s*\n`)
	linebreaks := regexp.MustCompile(`\\n`)

	for i := range *features {
		for _, score := range (*features)[i].BaseScores {
			if score > highestScore {
				highestScore = score
			}
		}
		for j := range (*features)[i].Vulnerabilities {
			// Format the vulnerability description by replacing certain patterns with newlines and spaces
			(*features)[i].Vulnerabilities[j].Description = longlines.ReplaceAllString((*features)[i].Vulnerabilities[j].Description, ".\n")
			(*features)[i].Vulnerabilities[j].Description = blanklines.ReplaceAllString((*features)[i].Vulnerabilities[j].Description, "\n")
			(*features)[i].Vulnerabilities[j].Description = linebreaks.ReplaceAllString((*features)[i].Vulnerabilities[j].Description, "\n")
			(*features)[i].Vulnerabilities[j].Description = strings.ReplaceAll((*features)[i].Vulnerabilities[j].Description, "*", "  *")

			// Determine the highest severity level among the vulnerabilities
			severity := strings.ToLower((*features)[i].Vulnerabilities[j].Severity)
			if severityLevels[severity] > severityLevels[strings.ToLower(highestSeverity)] {
				highestSeverity = (*features)[i].Vulnerabilities[j].Severity
			}
		}
	}
	return highestScore, highestSeverity
}

// collectVulnerabilities collects and returns a list of VulnerabilityInfo from the given vulnerabilities.
// collectVulnerabilities collects and returns a list of VulnerabilityInfo from the given vulnerabilities.
// This function takes a Vulnerabilities struct as input and returns a list of VulnerabilityInfo structs
// containing the vulnerabilities found in the data. The function iterates over the features of the data
// and checks if any of the vulnerability-related fields are non-empty. If any fields are non-empty, the
// feature is added to the list of vulnerabilities. This feature can be useful to collect and display
// vulnerability information for a given repository digest.
//
// Parameters:
//   - data: The vulnerabilities data to collect from.
//
// Returns:
//   - []VulnerabilityInfo: A list of VulnerabilityInfo containing the vulnerabilities found.
func collectVulnerabilities(data Vulnerabilities) []VulnerabilityInfo {
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

// getVulnerabilities retrieves the list of vulnerabilities for a given repository digest.
//
// Parameters:
//
//   - org:    The organization name.
//   - repo:   The repository name.
//   - digest: The digest of the repository manifest.
//
// Returns:
//
//	A slice of VulnerabilityInfo containing the vulnerabilities found.
//	A string representing the status of the vulnerability scan.
//	An error if the request fails or the response cannot be processed.
func (ops *Operations) getVulnerabilities(org string, repo string, digest string) ([]VulnerabilityInfo, string, error) {
	url := fmt.Sprintf("/repository/%s/%s/manifest/%s/security", org, repo, digest)
	resp, err := ops.client.Get(url)
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
		if strings.Contains(string(bodyBytes), "<html>") {
			return []VulnerabilityInfo{}, "", fmt.Errorf("received HTML response, likely an error page")
		}
		return []VulnerabilityInfo{}, "", fmt.Errorf("failed to decode response: %v", err)
	}

	// You can call CollectVulnerabilities here if needed
	vulnerabilities := collectVulnerabilities(result)
	return vulnerabilities, result.Status, nil
}

// FilterTagsBySeverityAndBaseScore filters the vulnerabilities of a given tag based on severity and base score criteria.
// It updates the filteredTags with tags that meet the criteria.
//
// Parameters:
//   - tag:             The tag details to be filtered.
//   - vulnerabilities: The vulnerabilities associated with the tag.
//   - severity:        The minimum severity level to filter vulnerabilities. If empty, all severities are considered.
//   - baseScore:       The minimum base score to filter vulnerabilities. If zero, all base scores are considered.
//   - filteredTags:    The result set where tags that meet the criteria are appended.
//
// The function iterates through the features of the vulnerabilities and filters out those that do not meet the severity
// and base score criteria. If any features remain after filtering, the tag is added to the filteredTags result set.
func (ops *Operations) FilterTagsBySeverityAndBaseScore(tag TagDetails, vulnerabilities Vulnerabilities, severity string, baseScore float64, filteredTags *TagResults) {
	filteredFeatures := []VulnerabilityInfo{}
	if vulnerabilities.Data != nil {
		for _, feature := range vulnerabilities.Data.Layer.Features {
			filteredVulns := []FeatureVulnerabilities{}
			for _, vuln := range feature.Vulnerabilities {
				// Check if the vulnerability meets the severity and base score criteria
				if (severity == "" || severityLevels[strings.ToLower(vuln.Severity)] >= severityLevels[strings.ToLower(severity)]) &&
					(baseScore == 0 || anyBaseScoreAbove(feature.BaseScores, baseScore)) {
					filteredVulns = append(filteredVulns, vuln)
				}
			}
			// If there are any vulnerabilities that meet the criteria, add the feature to the filtered features
			if len(filteredVulns) > 0 {
				feature.Vulnerabilities = filteredVulns
				filteredFeatures = append(filteredFeatures, feature)
			}
		}
	}
	if len(filteredFeatures) > 0 {
		filteredTags.Tags = append(filteredTags.Tags, tag)
	}
}

// anyBaseScoreAbove checks if any score in the baseScores slice is above the given threshold.
// It returns true if at least one score is greater than the threshold, otherwise it returns false.
//
// Parameters:
// - baseScores: A slice of float64 values representing the base scores to be checked.
// - threshold:  A float64 value representing the threshold to compare against.
//
// Returns:
// - bool: true if any score in baseScores is greater than the threshold, false otherwise.
func anyBaseScoreAbove(baseScores []float64, threshold float64) bool {
	for _, score := range baseScores {
		if score > threshold {
			return true
		}
	}
	return false
}

// ListNotifications retrieves the list of notifications from all repositories of an organization in the Quay registry.
// This function takes the name of the organization as an input parameter and returns a list of notifications
// associated with all repositories within this organization. Notifications provide information about various
// events and activities related to the repositories, such as build statuses, security alerts, and other updates.
//
// Parameters:
//   - org: The organization name.
//
// Returns:
//   - []Notification: A slice containing the notifications from all repositories.
//   - error:          An error if the operation fails at any point.
func (ops *Operations) ListNotifications(org string) ([]Notification, error) {
	orgSet, err := ops.ListOrganizationRepositories(org, false)
	if err != nil {
		return nil, fmt.Errorf("failed to list repositories: %v", err)
	}

	var allNotifications []Notification
	for _, repository := range orgSet.Organizations[0].Repositories {
		url := fmt.Sprintf("/repository/%s/%s/notification/", org, repository.Name)
		resp, err := ops.client.Get(url)
		if err != nil {
			return nil, fmt.Errorf("failed to get notifications for repository %s: %v", repository.Name, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("failed to list notifications: endpoint not found (404)")
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("failed to list notifications: %s", resp.Status)
		}

		var result struct {
			Notifications []Notification `json:"notifications"`
		}
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %v", err)
		}
		resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			if strings.Contains(string(bodyBytes), "<html>") {
				return nil, fmt.Errorf("received HTML response, likely an error page")
			}
			return nil, fmt.Errorf("failed to decode response: %v", err)
		}

		allNotifications = append(allNotifications, result.Notifications...)
	}

	return allNotifications, nil
}
