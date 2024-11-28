package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"qc/docs"
	"qc/pkg/auth"
	"qc/pkg/client"
	"qc/pkg/config"
	"qc/pkg/operations"
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
			tags, err := ops.ListRepositoryTags(cfg.Organisation, *repo)
			if err != nil {
				fmt.Printf("Failed to list tags: %v\n", err)
				os.Exit(1)
			}

			for _, tag := range tags.Tags {
				expired := "No"
				if tag.Expired {
					expired = "Yes"
				}
				size := float64(tag.Size) / (1024 * 1024)
				lastModified, err := time.Parse(time.RFC1123, tag.LastModified)
				if err != nil {
					fmt.Printf("Failed to parse LastModified: %v\n", err)
					os.Exit(1)
				}
				fmt.Printf("Repo: %s  Tag: %s  Digest: %s  LastModified: %s Size: %10.3fMb  Expired: %s  ", tag.Repo, tag.Name, tag.Digest, lastModified.Format("02.01.2006-15:04:05"), size, expired)
				fmt.Printf("VulnerabilityStatus: %v\n", tag.Vulnerabilities)

				for featureName, feature := range tag.Vulnerabilities.Data.Layer.Features {
					fmt.Printf("Feature: %s Version: %s\n", featureName, feature.Version)
					for _, vuln := range feature.Vulnerabilities {
						fmt.Printf("  - %s (%s): %s\n", vuln.Name, vuln.Severity, vuln.Description)
						if vuln.FixVersion != "" {
							fmt.Printf("    Fixed in version: %s\n", vuln.FixVersion)
						}
					}
				}
				// fmt.Println()
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
