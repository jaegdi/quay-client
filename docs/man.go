package docs

import "fmt"

func ShowManPage() {
	fmt.Println(`
NAME
    qc - Quay Container Registry Client

SYNOPSIS
    qc [OPTIONS]

DESCRIPTION
    A command-line tool for managing Quay container registry repositories and tags.
    Uses Kubernetes configuration and secrets for authentication.

CONFIGURATION
    The tool looks for configuration in the following locations (in order):
    1. Command line arguments
    2. Environment variables
    3. Configuration file (yaml):
       - ./config.yaml
       - $HOME/.config/qc/config.yaml
       - /etc/qc/config.yaml

    Example config.yaml:
        registry:
          url: https://quay.io
          secret_name: quay-admin
          namespace: scp-build

ENVIRONMENT
    KUBECONFIG
        Path to the Kubernetes configuration file (default: ~/.kube/config)

    QUAYREGISTRY
        URL of the Quay registry (used if -registry parameter is not provided)

OPTIONS
    -man
        Show this manual page

    -registry string
        Quay registry URL (default: from config or https://quay.io)

    -secret string
        Secret name containing Quay credentials (default: from config or "quay-admin")

    -namespace string
        Namespace containing the secret (default: from config or "scp-build")

    ... [rest of the manual remains the same] ...
`)
}
