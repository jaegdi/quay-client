package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/ghodss/yaml"
	"github.com/jaegdi/quay-client/pkg/auth"
	"github.com/jaegdi/quay-client/pkg/cli"
	"github.com/jaegdi/quay-client/pkg/operations"
)

// OutputCurlCommand prints a curl command that can be used to query the Quay registry.
// The command includes the Bearer token from the provided auth object.
// If no Bearer token is found in the auth object, a message will be printed.
//
// Parameters:
// auth: The auth object containing the Bearer token.
// quayURL: The URL of the Quay registry.
func OutputCurlCommand(auth *auth.Auth, quayURL string) {
	if auth.Token != "" {
		fmt.Printf("curl -H \"Authorization: Bearer %s\" %s\n", auth.Token, quayURL)
	} else {
		fmt.Printf("No Bearer token found in the provided secret.\n")
	}
}

// DeleteTag deletes the specified tag from the given organization and repository.
// If an error occurs, the error message will be printed and the program will exit with status code 1.
// If the tag was successfully deleted, a success message will be printed.
//
// Parameters:
// ops: The operations object used to delete the tag.
// org: The organization name.
// repo: The repository name.
// tag: The tag name to be deleted.
func DeleteTag(ops *operations.Operations, org, repo, tag string) {
	err := ops.DeleteTag(org, repo, tag)
	if err != nil {
		fmt.Printf("Failed to delete tag: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Successfully deleted tag %s from %s/%s\n", tag, org, repo)
}

// GetUserInformation gets user information for the given organization.
// If an error occurs, the error message will be printed and the program will exit with status code 1.
// The output will be printed in the specified format.
// If prettyprint is true, the output will be formatted with indentation.
// Otherwise, the output will be compact.
//
// Parameters:
// ops: The operations object used to get the user information.
// org: The organization name.
// outputFormat: The output format: text, json, or yaml.
// prettyprint: A boolean flag indicating whether to pretty-print the output.
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
	OutputData(users, outputFormat, prettyprint, PrintUsers, "Users")
}

// ListRepositoryTags lists all tags of the given repository.
// If an error occurs, the error message will be printed and the program will exit with status code 1.
// The output will be printed in the specified format.
// If prettyprint is true, the output will be formatted with indentation.
// Otherwise, the output will be compact.
//
// Parameters:
// ops: The operations object used to list the tags.
// org: The organization name.
// repo: The repository name.
// tag: The tag name or regex pattern to filter the tags.
// severity: The severity to filter the vulnerabilities (low, medium, high, critical).
// baseScore: The base score to filter the vulnerabilities.
// details: A boolean flag indicating whether to show detailed information.
// outputFormat: The output format: text, json, or yaml.
// prettyprint: A boolean flag indicating whether to pretty-print the output.
func ListRepositoryTags(ops *operations.Operations, org, repo, tag, severity string, baseScore float64, details bool, outputFormat string, prettyprint bool) {
	tags, err := ops.ListRepositoryTags(org, repo, tag, severity, baseScore, details, false)
	if err != nil {
		fmt.Printf("Failed to list tags: %v\n", err)
		os.Exit(1)
	}
	if len(tags.Tags) == 0 {
		fmt.Printf("No tags found for %s/%s\n", org, repo)
		return
	}
	OutputData(tags, outputFormat, prettyprint, PrintRepositoriyTags, "RepositoryTags")
}

// ListRepositoriesByRegex lists all repositories of the given organization that match the given regex pattern.
// If an error occurs, the error message will be printed and the program will exit with status code 1.
// The output will be printed in the specified format.
// If prettyprint is true, the output will be formatted with indentation.
// Otherwise, the output will be compact.
//
// Parameters:
// ops: The operations object used to list the repositories.
// org: The organization name.
// pattern: The regex pattern to filter the repositories.
// outputFormat: The output format: text, json, or yaml.
// prettyprint: A boolean flag indicating whether to pretty-print the output.
func ListRepositoriesByRegex(ops *operations.Operations, org, pattern, outputFormat string, prettyprint, details bool) {
	repos, err := ops.ListRepositoriesByRegex(org, pattern, details)
	if err != nil {
		fmt.Printf("Failed to list repositories filtered by regex: %v\n", err)
		os.Exit(1)
	}
	OutputData(repos, outputFormat, prettyprint, PrintList, "Repositories")
}

// ListOrganizationRepositories lists all repositories of the given organization.
// If an error occurs, the error message will be printed and the program will exit with status code 1.
// The output will be printed in the specified format.
// If prettyprint is true, the output will be formatted with indentation.
// Otherwise, the output will be compact.
//
// Parameters:
// ops: The operations object used to list the repositories.
// org: The organization name.
// outputFormat: The output format: text, json, or yaml.
// prettyprint: A boolean flag indicating whether to pretty-print the output.
func ListOrganizationRepositories(ops *operations.Operations, org string, outputFormat string, prettyprint bool, details bool) {
	repos, err := ops.ListOrganizationRepositories(org, details)
	if err != nil {
		fmt.Printf("Failed to list repositories: %v\n", err)
		os.Exit(1)
	}
	if details {
		for _, org := range repos.Organizations {
			tags := []operations.TagDetails{}
			for _, repo := range org.Repositories {
				tags = append(tags, repo.Tags...)
			}
			taglist := operations.TagResults{Tags: tags}
			OutputData(taglist, outputFormat, prettyprint, PrintRepositoriyTags, "Overview - From every repo of org: "+org.Name+", the youngest tag of each repo.")
		}
	} else {
		OutputData(repos, outputFormat, prettyprint, PrintList, "Repositories")
	}
}

// ListOrganizations lists all organizations.
// If an error occurs, the error message will be printed and the program will exit with status code 1.
// The output will be printed in the specified format.
// If prettyprint is true, the output will be formatted with indentation.
// Otherwise, the output will be compact.
//
// Parameters:
// ops: The operations object used to list the organizations.
// outputFormat: The output format: text, json, or yaml.
// prettyprint: A boolean flag indicating whether to pretty-print the output.
func ListOrganizations(ops *operations.Operations, outputFormat string, prettyprint bool) {
	orgs, err := ops.ListOrganizations()
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			fmt.Printf("Failed to list organizations: endpoint not found (404)\n")
		} else {
			fmt.Printf("Failed to list organizations: %v\n", err)
		}
		os.Exit(1)
	}
	OutputData(orgs, outputFormat, prettyprint, PrintList, "Organizations")
}

// ListNotifications lists all notifications.
// If an error occurs, the error message will be printed and the program will exit with status code 1.
// The output will be printed in the specified format.
// If prettyprint is true, the output will be formatted with indentation.
// Otherwise, the output will be compact.
//
// Parameters:
// ops: The operations object used to list the notifications.
// outputFormat: The output format: text, json, or yaml.
// prettyprint: A boolean flag indicating whether to pretty-print the output.
func ListNotifications(ops *operations.Operations, org, outputFormat string, prettyprint bool) {
	notifications, err := ops.ListNotifications(org)
	if err != nil {
		fmt.Printf("Failed to list notifications: %v\n", err)
		os.Exit(1)
	}
	OutputData(notifications, outputFormat, prettyprint, PrintNotifications, "Notifications")
}

// OutputData prints the given data in the specified format.
// If prettyprint is true, the output will be formatted with indentation.
// Otherwise, the output will be compact.
// The printFunc parameter is a function that prints the data in the desired format.
// The headline parameter is a string that will be printed before the data.
//
// Parameters:
//
//	data: The data to be printed.
//	format: The output format: text, json, or yaml.
//	prettyprint: A boolean flag indicating whether to pretty-print the output.
//	printFunc: A function that prints the data in the desired format.
//	headline: A string that will be printed before the data.
//
// WriteToFileOrStdout writes the given content either to a file if outputFile is specified,
// or to stdout if outputFile is empty
func WriteToFileOrStdout(content []byte, outputFile string) error {
	if outputFile != "" {
		return os.WriteFile(outputFile, content, 0644)
	}
	fmt.Print(string(content))
	return nil
}
func OutputData(data interface{}, format string, prettyprint bool, printFunc func(interface{}, string), headline string) {
	switch format {
	case "json":
		OutputJSON(data, prettyprint)
	case "text":
		printFunc(data, headline)
		fmt.Println()
	default:
		OutputYAML(data, prettyprint)
	}
}

// OutputJSON marshals the given data into JSON format and prints it.
// If prettyprint is true, the JSON output will be formatted with indentation.
// Otherwise, the JSON output will be compact.
// In case of an error during marshaling, the error and the original data will be printed.
//
// Parameters:
//
//	data: The data to be marshaled into JSON.
//	prettyprint: A boolean flag indicating whether to pretty-print the JSON output.
func OutputJSON(data interface{}, prettyprint bool) error {
	var output []byte
	var err error
	// if prettyprint {
	// 	formatter := prettyjson.NewFormatter()
	// 	output, err = formatter.Marshal(data)
	// } else {
	output, err = json.Marshal(data)
	// }
	if err != nil {
		fmt.Printf("Failed to marshal JSON: %v\n", err)
		fmt.Println(data)
		return err
	}

	if prettyprint {
		return PrintWithJQ(output)
	}
	flags := cli.GetFlags()
	return WriteToFileOrStdout(output, flags.OutputFile)
}

// OutputYAML marshals the given data into YAML format and prints it.
// If prettyprint is true, the YAML output will be formatted with indentation.
// Otherwise, the YAML output will be compact.
// In case of an error during marshaling, the error and the original data will be printed.
//
// Parameters:
// data: The data to be marshaled into YAML.
// prettyprint: A boolean flag indicating whether to pretty-print the YAML output.
func OutputYAML(data interface{}, prettyprint bool) {
	output, err := yaml.Marshal(data)
	if err != nil {
		fmt.Printf("Failed to marshal YAML: %v\n", err)
		fmt.Println(data)
	} else {
		o := []byte(strings.ReplaceAll(string(output), "\n\n", "\n"))
		if prettyprint {
			PrintWithYQ(o)
		} else {
			fmt.Println(string(o))
		}
	}
}

// PrintWithJQ prints the given data using the jq command-line tool.
// The data is passed to jq via stdin, and the output is printed to stdout.
// In case of an error running jq, the original data will be printed.
//
// Parameters:
// data: The data to be printed with jq.
func PrintWithJQ(data []byte) error {
	cmd := exec.Command("jq", ".")
	cmd.Stdin = bytes.NewReader(data)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Failed to run jq: %v\n", err)
		flags := cli.GetFlags()
		return WriteToFileOrStdout(data, flags.OutputFile)
	}
	return nil
}

// PrintWithYQ prints the given data using the yq command-line tool.
// The data is passed to yq via stdin, and the output is printed to stdout.
// In case of an error running yq, the original data will be printed.
//
// Parameters:
// data: The data to be printed with yq.
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

// PrintRepositoriyTags prints the tags of a repository in a table format.
// The tags are sorted by age, and the vulnerabilities are printed in a nested format.
// The output includes the repository name, tag name, expiration status, vulnerability status, highest score, highest severity,
// age in days, last modified date, size in MB, and digest.
//
// Parameters:
// data: The tag results to be printed.
// headline: A string that will be printed before the data.
func PrintRepositoriyTags(data interface{}, headline string) {
	tags, ok := data.(operations.TagResults)
	if !ok {
		fmt.Printf("Unsupported data type for PrintRepositoriyTags: %T\n", data)
		return
	}

	// define formating strings
	line := "-----------------------------"
	fmt.Println(headline)
	fmt.Printf("%206.206s\n", strings.Repeat(line, 8))
	f := "%-30.30s  %-20.20s  %-7.7s  %-9.9s  %5.2f  %-10.10s  %7d  %-19.19s  %10.2f  %s\n"
	fh := "%-30.30s  %-20.20s  %-7.7s  %-9.9s  %-5.5s  %-10.10s  %7.7s  %-19.19s  %10.10s  %-71.71s\n"

	// print header
	fmt.Printf(fh, "Repo", "Tag", "Expired", "Status", "Score", "Severity", "Age [D]", "LastModified", "Size [Mb]", "Digest")
	fmt.Printf(fh, line, line, line, line, line, line, line, line, line, strings.Repeat(line, 5))

	if strings.Contains(headline, "Overview") {
		sort.Slice(tags.Tags, func(i, j int) bool {
			return tags.Tags[i].Repo < tags.Tags[j].Repo
		})
	} else {
		// sort tags by age
		sort.Slice(tags.Tags, func(i, j int) bool {
			return tags.Tags[i].Age < tags.Tags[j].Age
		})
	}

	// print data
	for _, tag := range tags.Tags {
		// convert tag data
		expired := "No"
		if tag.Expired {
			expired = "Yes"
		}
		size := float64(tag.Size) / (1024 * 1024)
		size = tag.Size
		// convert last modified date
		lastModified, err := time.Parse(time.RFC1123, tag.LastModified)
		if err != nil {
			fmt.Printf("Failed to parse LastModified: %v\n", err)
		} else {
			lastModified = lastModified.Local()
		}

		// print tag data
		fmt.Printf(f, tag.Repo, tag.Name, expired, tag.Vulnerabilities.Status, tag.HighestScore, tag.HighestSeverity,
			tag.Age, lastModified.Format("02.01.2006-15:04:05"), size, tag.Digest)

		// print vulnerabilities
		if !strings.Contains(headline, "Overview") && tag.Vulnerabilities.Data != nil {
			for _, feature := range tag.Vulnerabilities.Data.Layer.Features {
				fmt.Printf("        Feature: %s Version: %s  BaseScore: %3.1f\n", string(feature.Name), feature.Version, feature.BaseScores)
				for _, vuln := range feature.Vulnerabilities {
					v, err := yaml.Marshal(vuln)
					// print vulnerability
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

// PrintUsers prints the user information in a table format.
// The output includes the kind, name, role, avatar kind, and avatar name of each user.
//
// Parameters:
// data: The user information to be printed.
// headline: A string that will be printed before the data.
func PrintUsers(data interface{}, headline string) {
	users := data.(operations.Prototypes)

	// define formating strings
	line := "-----------------------------"
	fmt.Println(headline)
	fmt.Println(strings.Repeat(line, 3))
	format := "%-15.15s  %-25.25s %-10.10s %-15.15s %-25.25s\n"

	// print header
	fmt.Printf(format, "Kind", "Name", "Role", "AvatarKind", "AvatarName")
	fmt.Printf(format, line, line, line, line, line)

	// print data
	for _, user := range users.Prototypes {
		fmt.Printf(format, user.Delegate.Kind, user.Delegate.Name, user.Role, user.Delegate.Avatar.Kind, user.Delegate.Avatar.Name)
	}
}

// PrintList prints a list of strings or repositories in a table format.
// The output includes the organization name and repository name.
//
// Parameters:
// data: The list of strings or repositories to be printed.
// headline: A string that will be printed before the data.
func PrintList(data interface{}, headline string) {
	line := "-----------------------------"

	switch v := data.(type) {
	// print a list of strings
	case []string:
		fmt.Println(headline)
		fmt.Println(line)
		for _, e := range v {
			fmt.Printf(e)
		}
	// print a list of Repositories
	case operations.OrgSet:
		//  define the format string to the maxlen of Organization Names
		maxlen := 0
		for _, org := range v.Organizations {
			if len(org.Name) > maxlen {
				maxlen = len(org.Name)
			}
		}
		f := fmt.Sprintf("%%-%d.%ds  %%s\n", maxlen, maxlen)

		//  print Header
		fmt.Printf(f, "Organisation", "Repository")
		fmt.Printf(f, line, strings.Repeat(line, 4))

		//  print Data
		for _, org := range v.Organizations {
			if len(org.Repositories) > 0 {
				sort.Slice(org.Repositories, func(i, j int) bool {
					return org.Repositories[i].Name < org.Repositories[j].Name
				})
				for _, repo := range org.Repositories {
					fmt.Printf(f, org.Name, repo.Name)
				}
			} else {
				fmt.Println(org.Name)
			}
		}
	// Error handling
	default:
		fmt.Printf("Unsupported data type: %T\n", v)
	}
}

// PrintNotifications prints the notifications in a table format.
// The output includes the ID, title, description, and creation date of each notification.
//
// Parameters:
// data: The notifications to be printed.
// headline: A string that will be printed before the data.
func PrintNotifications(data interface{}, headline string) {
	notifications, ok := data.([]operations.Notification)
	if !ok {
		fmt.Printf("Unsupported data type for PrintNotifications: %T\n", data)
		return
	}

	// define formatting strings
	line := "-----------------------------"
	fmt.Println(headline)
	fmt.Printf("%-5s  %-30s  %-50s  %-20s\n", "ID", "Title", "Description", "Created At")
	fmt.Printf("%-5s  %-30s  %-50s  %-20s\n", line, line, line, line)

	// print data
	for _, notification := range notifications {
		fmt.Printf("%-5d  %-30s  %-50s  %-20s\n", notification.ID, notification.Title, notification.Description, notification.CreatedAt)
	}
}

func DisplayNotifications(ops *operations.Operations, org string) error {
	notifications, err := ops.ListNotifications(org)
	if err != nil {
		return fmt.Errorf("failed to list notifications: %v", err)
	}

	for _, notification := range notifications {
		fmt.Printf("ID: %d, Title: %s, Description: %s, CreatedAt: %s\n",
			notification.ID, notification.Title, notification.Description, notification.CreatedAt)
	}

	return nil
}
