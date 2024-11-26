package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"qc/docs"
	"qc/pkg/auth"
	"qc/pkg/client"
	"qc/pkg/config"
	"qc/pkg/operations"
)

func main() {
    // CLI flags
    showMan := flag.Bool("man", false, "Show manual page")
    secretName := flag.String("secret", "quay-admin", "Secret name containing Quay credentials")
    namespace := flag.String("namespace", "scp-build", "Namespace containing the secret")
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
    cfg, err := config.NewConfig(kubeconfig, *secretName, *namespace, *quayURL)  // Added quayURL parameter
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

    if *delete && *org != "" && *repo != "" && *tag != "" {
        err = ops.DeleteTag(*org, *repo, *tag)
        if err != nil {
            fmt.Printf("Failed to delete tag: %v\n", err)
            os.Exit(1)
        }
        fmt.Printf("Successfully deleted tag %s from %s/%s\n", *tag, *org, *repo)
        return
    }

    if *org != "" {
        if *regex != "" {
            repos, err := ops.ListRepositoriesByRegex(*org, *regex)
            if err != nil {
                fmt.Printf("Failed to list repositories: %v\n", err)
                os.Exit(1)
            }
            for _, repo := range repos {
                fmt.Println(repo)
            }
            return
        }

        repos, err := ops.ListOrganizationRepositories(*org)
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
        fmt.Printf("Failed to list organizations: %v\n", err)
        os.Exit(1)
    }
    for _, org := range orgs {
        fmt.Println(org)
    }
}
