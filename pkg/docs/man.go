package docs

import (
	"fmt"
	"os"
)

// ShowManPage displays the manual page for the quay-client command line tool.
// The manual page provides detailed information about the available flags and their usage.
func ShowManPage() {
	fmt.Print(`NAME
    qc - Quay Client Command Line Tool

SYNOPSIS
    qc [OPTIONS]

DESCRIPTION
    The Quay Client Command Line Tool (qc) allows you to interact with the Quay registry.
    You can perform various operations such as listing organizations, repositories, and tags,
    deleting tags, and retrieving user information.

OPTIONS
    -m, --man
        Show manual page

    -s, --secret
        Secret name containing Quay credentials

    -sn, --secret-namespace
        Namespace containing the secret

    -o, --organisation
        Organisation name

    -r, --repository
        Repository name

    -t, --tag
        Tag name or regexp for tagname

    -d, --delete
        Delete specified tag

    -x, --regex
        Regex pattern to filter repositories

    -u, --registry
        Quay registry URL (default: $QUAYREGISTRY or https://quay.io)

    -f, --format
        Output format: text, json, or yaml (default: yaml)
        -of, --output-file
            Write output to file instead of stdout

    --ft
        Set Output format to text

    --fj
        Set Output format to json

    -i, --details
        Show detailed information

    -c, --curlreq
        Output a curl commandline with the Bearer token to query the Quay registry

    --sev
        Filter vulnerabilities by severity [low, medium, high, critical]

    -b, --basescore
        Filter vulnerabilities by base score

    -kc, --kubeconfig
        Path to the kubeconfig file

    -pp, --prettyprint
        Enable prettyprint

    -gu, --getusers
        Get user information

    -gn, --getnotifications
        Get notifications

    -v, --verify
        Enable print verify infos

    --create-config, -cc
        Create a example config in $HOME/.config/qc/config.yaml

EXAMPLES
    qc -o my-org -r my-repo -t my-tag -d
    qc -o my-org -r my-repo -x ".*test.*"
    qc -o my-org -gu
    qc -gn
    qc -c
    qc -m
`)
	os.Exit(0)
}
