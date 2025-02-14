package main

import (
	"fmt"
	"os"

	"github.com/jaegdi/quay-client/pkg/auth"
	"github.com/jaegdi/quay-client/pkg/cli"
	"github.com/jaegdi/quay-client/pkg/client"
	"github.com/jaegdi/quay-client/pkg/config"
	"github.com/jaegdi/quay-client/pkg/docs"
	"github.com/jaegdi/quay-client/pkg/helper"
	"github.com/jaegdi/quay-client/pkg/operations"
	"github.com/jaegdi/quay-client/pkg/output"
)

// main is the entry point of the quay-client command line tool. It parses the command line flags,
// initializes the configuration and authentication, and performs various operations based on the flags provided.
//
// The function performs the following steps:
// 1. Parse command line flags using cli.ParseFlags().
// 2. If the ShowMan flag is set, display the manual page and exit.
// 3. Retrieve the kubeconfig path and initialize the configuration using config.NewConfig().
// 4. Initialize authentication using auth.NewAuth().
// 5. If the CurlReq flag is set, output the curl command and exit.
// 6. Create a new client and operations instance.
// 7. Perform operations based on the flags provided:
//   - If the Delete flag is set along with Organisation, Repo, and Tag, delete the specified tag.
//   - If the GetUsers flag is set, get user information.
//   - If the GetNotifications flag is set, list notifications.
//   - If Organisation is specified:
//   - If Repo is specified, list repository tags.
//   - If Regex is specified, list repositories by regex.
//   - Otherwise, list organization repositories.
//   - If no Organisation is specified, list organizations.
func main() {
	flags := cli.ParseFlags()

	if flags.ShowMan {
		docs.ShowManPage()
		return
	}
	// Get kubeconfig path and initialize config
	kubeconfig := config.GetKubeconfigPath(flags.KubeconfigPath)
	cfg, err := config.NewConfig(kubeconfig, flags.SecretName, flags.SecretNamespace, flags.QuayURL, flags.Org)
	if err != nil && !flags.CreateConfig {
		fmt.Printf("Failed to initialize config: %v\n", err)
		os.Exit(1)
	}

	if flags.CreateConfig {
		if err := config.SaveConfigToFile(cfg); err != nil {
			fmt.Printf("Failed to save config: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Config file created successfully\n")
		return
	}

	// Initialize authentication
	auth, err := auth.NewAuth(cfg)
	if err != nil {
		fmt.Printf("Authentication failed: %v\n", err)
		os.Exit(1)
	}
	// Output curl command if CurlReq flag is set
	if flags.CurlReq {
		output.OutputCurlCommand(auth, cfg.QuayURL)
		return
	}
	// Create client and operations
	client := client.NewClient(auth, cfg.QuayURL)
	// Create operations
	ops := operations.NewOperations(client)
	// Perform operations based on flags
	if flags.Delete {
		//
		if cfg.Organisation != "" && flags.Repo != "" && flags.Tag != "" {
			output.DeleteTag(ops, cfg.Organisation, flags.Repo, flags.Tag)
			return
		} else {
			fmt.Printf("Organisation, repository, and tag name are required to delete a tag\n")
			os.Exit(1)
		}
	}
	// Get user information
	if flags.GetUsers {
		if cfg.Organisation != "" {
			output.GetUserInformation(ops, cfg.Organisation, flags.OutputFormat, flags.Prettyprint)
			return
		} else {
			fmt.Printf("Organisation name is required to get users\n")
			os.Exit(1)
		}
	}

	// List notifications
	if flags.GetNotifications {
		output.ListNotifications(ops, cfg.Organisation, flags.OutputFormat, flags.Prettyprint)
		return
	}

	// List repositories
	if cfg.Organisation != "" {
		// Filter tags to delete
		if flags.FilterTags {
			output.GenShellCmdsToDeleteTagsWrapper(ops, cfg)
			return
		}
		if flags.Repo != "" {
			// List repository tags
			output.ListRepositoryTags(ops, cfg.Organisation, flags.Repo, flags.Tag, flags.Severity, flags.BaseScore, flags.Details, flags.OutputFormat, flags.Prettyprint)
			return
		}
		if flags.RepoRegex != "" {
			helper.Verify("List repositories by regex")
			output.ListRepositoriesByRegex(ops, cfg.Organisation, flags.RepoRegex, flags.OutputFormat, flags.Prettyprint, flags.Details)
			return
		}
		// List organization repositories
		output.ListOrganizationRepositories(ops, cfg.Organisation, flags.OutputFormat, flags.Prettyprint, flags.Details)
		return
	}

	// Without organisation, list all organizations
	output.ListOrganizations(ops, flags.OutputFormat, flags.Prettyprint)
}
