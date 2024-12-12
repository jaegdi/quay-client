package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/ghodss/yaml"
	"github.com/hokaccha/go-prettyjson"
	"github.com/jaegdi/quay-client/pkg/auth"
	"github.com/jaegdi/quay-client/pkg/operations"
)

func OutputCurlCommand(auth *auth.Auth, quayURL string) {
	if auth.Token != "" {
		fmt.Printf("curl -H \"Authorization: Bearer %s\" %s\n", auth.Token, quayURL)
	} else {
		fmt.Printf("No Bearer token found in the provided secret.\n")
	}
}

func DeleteTag(ops *operations.Operations, org, repo, tag string) {
	err := ops.DeleteTag(org, repo, tag)
	if err != nil {
		fmt.Printf("Failed to delete tag: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Successfully deleted tag %s from %s/%s\n", tag, org, repo)
}

func GetUserInformation(ops *operations.Operations, org, outputFormat string, prettyprint bool) {
	if org == "" {
		fmt.Printf("Organisation name is required to get users\n")
		os.Exit(1)
	}
	users, err := ops.GetUsers(org)
	if err != nil {
		fmt.Printf("Failed to get users: %v\n", err)
		os.Exit(1)
	}
	OutputData(users, outputFormat, prettyprint, PrintUsers)
}

func ListRepositoryTags(ops *operations.Operations, org, repo, severity string, baseScore float64, details bool, outputFormat string, prettyprint bool) {
	tags, err := ops.ListRepositoryTags(org, repo, severity, baseScore, details)
	if err != nil {
		fmt.Printf("Failed to list tags: %v\n", err)
		os.Exit(1)
	}
	if len(tags.Tags) == 0 {
		fmt.Printf("No tags found for %s/%s\n", org, repo)
		return
	}
	OutputData(tags, outputFormat, prettyprint, PrintRepositoriyTags)
}

func ListRepositoriesByRegex(ops *operations.Operations, org, pattern string) {
	repos, err := ops.ListRepositoriesByRegex(org, pattern)
	if err != nil {
		fmt.Printf("Failed to list repositories: %v\n", err)
		os.Exit(1)
	}
	for _, repo := range repos {
		fmt.Println(repo)
	}
}

func ListOrganizationRepositories(ops *operations.Operations, org string) {
	repos, err := ops.ListOrganizationRepositories(org)
	if err != nil {
		fmt.Printf("Failed to list repositories: %v\n", err)
		os.Exit(1)
	}
	for _, repo := range repos {
		fmt.Println(repo)
	}
}

func ListOrganizations(ops *operations.Operations) {
	orgs, err := ops.ListOrganizations()
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			fmt.Printf("Failed to list organizations: endpoint not found (404)\n")
		} else {
			fmt.Printf("Failed to list organizations: %v\n", err)
		}
		os.Exit(1)
	}
	for _, org := range orgs {
		fmt.Println(org)
	}
}

func OutputData(data interface{}, format string, prettyprint bool, printFunc func(interface{})) {
	switch format {
	case "json":
		OutputJSON(data, prettyprint)
	case "text":
		printFunc(data)
	default:
		OutputYAML(data, prettyprint)
	}
}

func OutputJSON(data interface{}, prettyprint bool) {
	var output []byte
	var err error
	if prettyprint {
		formatter := prettyjson.NewFormatter()
		output, err = formatter.Marshal(data)
	} else {
		output, err = json.Marshal(data)
	}
	if err != nil {
		fmt.Printf("Failed to marshal JSON: %v\n", err)
		fmt.Println(data)
	} else {
		PrintWithJQ(output)
	}
}

func OutputYAML(data interface{}, prettyprint bool) {
	output, err := yaml.Marshal(data)
	if err != nil {
		fmt.Printf("Failed to marshal YAML: %v\n", err)
		fmt.Println(data)
	} else {
		if prettyprint {
			PrintWithYQ(output)
		} else {
			fmt.Println(string(output))
		}
	}
}

func PrintWithJQ(data []byte) {
	cmd := exec.Command("jq", ".")
	cmd.Stdin = bytes.NewReader(data)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Failed to run jq: %v\n", err)
		fmt.Println(string(data))
	}
}

func PrintWithYQ(data []byte) {
	cmd := exec.Command("yq", "eval", "-P", "-")
	cmd.Stdin = bytes.NewReader(data)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Failed to run yq: %v\n", err)
		fmt.Println(string(data))
	}
}

func PrintRepositoriyTags(data interface{}) {
	tags := data.(operations.TagResults)
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

func PrintUsers(data interface{}) {
	users := data.(operations.Prototypes)
	line := "-----------------------------"
	format := "%-15.15s  %-25.25s %-10.10s %-15.15s %-25.25s\n"
	fmt.Printf(format, "Kind", "Name", "Role", "AvatarKind", "AvatarName")
	fmt.Printf(format, line, line, line, line, line)
	for _, user := range users.Prototypes {
		fmt.Printf(format, user.Delegate.Kind, user.Delegate.Name, user.Role, user.Delegate.Avatar.Kind, user.Delegate.Avatar.Name)
	}
}
