package docs

import "fmt"

func ShowManPage() {
	manpage := `
NAME
    qc - Quay Container Registry Client

SYNOPSIS
    qc [OPTIONS]

DESCRIPTION
    A command-line tool for managing Quay container registry repositories and tags.
    Uses Kubernetes configuration and secrets for authentication.

ENVIRONMENT
    KUBECONFIG
        Path to the Kubernetes configuration file (default: ~/.kube/config)

OPTIONS
    -man
        Show this manual page

    -secret string
        Secret name containing Quay credentials (default "quay-admin")

    -namespace string
        Namespace containing the secret (default "scp-build")

    -organisation string
        Organisation name to list repositories from

    -repository string
        Repository name for tag operations

    -tag string
        Tag name for delete operations

    -delete
        Delete specified tag when used with -organisation, -repository, and -tag

    -regex string
        Regex pattern to filter repositories

EXAMPLES
    List all organizations:
        qc

    List repositories in an organization:
        qc -organisation myorg

    List filtered repositories:
        qc -organisation myorg -regex "^app-.*"

    Delete a tag:
        qc -delete -organisation myorg -repository myrepo -tag v1.0.0

AUTHENTICATION
    The tool supports authentication using either:
    1. Docker config secrets (type: kubernetes.io/dockerconfigjson)
    2. Opaque secrets containing either:
       - token
       - username and password
`
	fmt.Println(manpage)
}
