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
          organisation: myorg

ENVIRONMENT
    KUBECONFIG
        Path to the Kubernetes configuration file (default: ~/.kube/config)

    QUAYREGISTRY
        URL of the Quay registry (used if -registry parameter is not provided)

    QUAYORG
        Default organization to use (used if -organisation parameter is not provided)

OPTIONS
    -man, -m
        Show this manual page

    -registry, -u string
        Quay registry URL (default: from $QUAYREGISTRY or config)

    -secret, -s string
        Secret name containing Quay credentials (default: from config)

    -namespace, -n string
        Namespace containing the secret (default: from config)

    -organisation, -o string
        Organisation name (default: from $QUAYORG or config)
        List all repositories, if no -repository flag is provided

    -repository, -r string
        Repository name for tag operations

    -tag, -t string
        Tag name for delete operations

    -delete, -d
        Delete specified tag when used with -organisation, -repository, and -tag

    -regex, -x string
        Regex pattern to filter repositories

    -output, -f string
        Output format: text, json, or yaml (default: yaml)

    -details, -i
        Show detailed information

    -curlreq, -c
        Output a curl commandline with the Bearer token to query the Quay registry

EXAMPLES
    List all organizations:
        qc

    List repositories in an organization:
        qc -organisation myorg

    List filtered repositories:
        qc -organisation myorg -regex "^app-.*"

    Delete a tag:
        qc -delete -organisation myorg -repository myrepo -tag v1.0.0

    Output a curl commandline:
        qc -curlreq

AUTHENTICATION
    The tool supports authentication using either:
    1. Docker config secrets (type: kubernetes.io/dockerconfigjson)
    2. Opaque secrets containing either:
       - token
       - username and password`)
	fmt.Println()
}
