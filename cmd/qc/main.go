package main

import (
	"fmt"
	"os"

	"github.com/jaegdi/quay-client/pkg/auth"
	"github.com/jaegdi/quay-client/pkg/cli"
	"github.com/jaegdi/quay-client/pkg/client"
	"github.com/jaegdi/quay-client/pkg/config"
	"github.com/jaegdi/quay-client/pkg/docs"
	"github.com/jaegdi/quay-client/pkg/operations"
	"github.com/jaegdi/quay-client/pkg/output"
)

func main() {
	flags := cli.ParseFlags()

	if flags.ShowMan {
		docs.ShowManPage()
		return
	}

	kubeconfig := config.GetKubeconfigPath(flags.KubeconfigPath)
	cfg, err := config.NewConfig(kubeconfig, flags.SecretName, flags.Namespace, flags.QuayURL, flags.Org)
	if err != nil {
		fmt.Printf("Failed to initialize config: %v\n", err)
		os.Exit(1)
	}

	auth, err := auth.NewAuth(cfg)
	if err != nil {
		fmt.Printf("Authentication failed: %v\n", err)
		os.Exit(1)
	}

	if flags.CurlReq {
		output.OutputCurlCommand(auth, cfg.QuayURL)
		return
	}

	client := client.NewClient(auth, cfg.QuayURL)
	ops := operations.NewOperations(client)

	if flags.Delete && cfg.Organisation != "" && flags.Repo != "" && flags.Tag != "" {
		output.DeleteTag(ops, cfg.Organisation, flags.Repo, flags.Tag)
		return
	}

	if flags.GetUsers {
		output.GetUserInformation(ops, cfg.Organisation, flags.OutputFormat, flags.Prettyprint)
		return
	}

	if cfg.Organisation != "" {
		if flags.Repo != "" {
			output.ListRepositoryTags(ops, cfg.Organisation, flags.Repo, flags.Severity, flags.BaseScore, flags.Details, flags.OutputFormat, flags.Prettyprint)
			return
		}
		if flags.Regex != "" {
			output.ListRepositoriesByRegex(ops, cfg.Organisation, flags.Regex)
			return
		}
		output.ListOrganizationRepositories(ops, cfg.Organisation)
		return
	}

	output.ListOrganizations(ops)
}
