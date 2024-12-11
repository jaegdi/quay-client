package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"qc/docs"
	"qc/pkg/auth"
	"qc/pkg/client"
	"qc/pkg/config"
	"qc/pkg/operations"

	"gopkg.in/yaml.v2"
)

func main() {
	// CLI flags
	showMan := flag.Bool("man", false, "Show manual page")
	secretName := flag.String("secret", "", "Secret name containing Quay credentials")
	namespace := flag.String("namespace", "", "Namespace containing the secret")
	org := flag.String("organisation", "", "Organisation name")
	repo := flag.String("repository", "", "Repository name")
	tag := flag.String("tag", "", "Tag name")
	delete := flag.Bool("delete", false, "Delete specified tag")
	regex := flag.String("regex", "", "Regex pattern to filter repositories")
	quayURL := flag.String("registry", "", "Quay registry URL (default: $QUAYREGISTRY or https://quay.io)")
	outputFormat := flag.String("output", "yaml", "Output format: text, json, or yaml, default is yaml")
	details := flag.Bool("details", false, "Show detailed information")
	curlReq := flag.Bool("curlreq", false, "Output a curl commandline with the Bearer token to query the Quay registry")
	severity := flag.String("severity", "", "Filter vulnerabilities by severity")
	baseScore := flag.Float64("basescore", 0, "Filter vulnerabilities by base score")

	// Short flags
	flag.BoolVar(showMan, "m", false, "Show manual page")
	flag.StringVar(secretName, "s", "", "Secret name containing Quay credentials")
	flag.StringVar(namespace, "n", "", "Namespace containing the secret")
	flag.StringVar(org, "o", "", "Organisation name")
	flag.StringVar(repo, "r", "", "Repository name")
	flag.StringVar(tag, "t", "", "Tag name")
	flag.BoolVar(delete, "d", false, "Delete specified tag")
	flag.StringVar(regex, "x", "", "Regex pattern to filter repositories")
	flag.StringVar(quayURL, "u", "", "Quay registry URL (default: $QUAYREGISTRY or https://quay.io)")
	flag.StringVar(outputFormat, "f", "yaml", "Output format: text, json, or yaml, default is yaml")
	flag.BoolVar(details, "i", false, "Show detailed information")
	flag.BoolVar(curlReq, "c", false, "Output a curl commandline with the Bearer token to query the Quay registry")
	flag.StringVar(severity, "sev", "", "Filter vulnerabilities by severity")
	flag.Float64Var(baseScore, "b", 0, "Filter vulnerabilities by base score")

	flag.Usage = docs.ShowHelpPage
	flag.Parse()

	if *showMan {
		docs.ShowManPage()
		return
	}

	// Get KUBECONFIG path
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		kubeconfig = filepath.Join(os.Getenv("HOME"), ".kube", "config")
	}

	// Initialize configuration
	cfg, err := config.NewConfig(kubeconfig, *secretName, *namespace, *quayURL, *org)
	if err != nil {
		fmt.Printf("Failed to initialize config: %v\n", err)
		os.Exit(1)
	}

	// Initialize authentication
	auth, err := auth.NewAuth(cfg)
	if err != nil {
		fmt.Printf("Authentication failed: %v\n", err)
		os.Exit(1)
	}

	// Output curl commandline if -curlreq flag is set
	if *curlReq {
		if auth.Token != "" {
			fmt.Printf("curl -H \"Authorization: Bearer %s\" %s\n", auth.Token, cfg.QuayURL)
		} else {
			fmt.Printf("No Bearer token found in the provided secret.\n")
		}
		return
	}

	// Initialize client
	client := client.NewClient(auth, cfg.QuayURL)

	// Perform operations based on flags
	ops := operations.NewOperations(client)

	if *delete && cfg.Organisation != "" && *repo != "" && *tag != "" {
		err = ops.DeleteTag(cfg.Organisation, *repo, *tag)
		if err != nil {
			fmt.Printf("Failed to delete tag: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Successfully deleted tag %s from %s/%s\n", *tag, cfg.Organisation, *repo)
		return
	}

	if cfg.Organisation != "" {
		if *repo != "" {
			tags, err := ops.ListRepositoryTags(cfg.Organisation, *repo, *details)
			if err != nil {
				fmt.Printf("Failed to list tags: %v\n", err)
				os.Exit(1)
			}
			if len(tags.Tags) == 0 {
				fmt.Printf("No tags found for %s/%s\n", cfg.Organisation, *repo)
				return
			}
			if *severity != "" || *baseScore > 0 {
				tags = ops.FilterTagsBySeverityAndBaseScore(tags, *severity, *baseScore)
			}
			switch *outputFormat {
			case "json":
				data, err := json.MarshalIndent(tags, "", "  ")
				if err != nil {
					fmt.Printf("Failed to marshal JSON: %v\n", err)
				} else {
					fmt.Println(string(data))
				}
			case "text":
				ops.PrintRepositoriyTags(tags)

			default:
				data, err := yaml.Marshal(tags)
				if err != nil {
					fmt.Printf("Failed to marshal YAML: %v\n", err)
				} else {
					fmt.Println(string(data))
				}
			}
			return
		}
		if *regex != "" {
			repos, err := ops.ListRepositoriesByRegex(cfg.Organisation, *regex)
			if err != nil {
				fmt.Printf("Failed to list repositories: %v\n", err)
				os.Exit(1)
			}
			for _, repo := range repos {
				fmt.Println(repo)
			}
			return
		}

		repos, err := ops.ListOrganizationRepositories(cfg.Organisation)
		if err != nil {
			fmt.Printf("Failed to list repositories: %v\n", err)
			os.Exit(1)
		}
		for _, repo := range repos {
			fmt.Println(repo)
		}
		return
	}

	// Default: list all organizations
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
