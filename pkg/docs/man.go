package docs

import (
	"fmt"
	"os"
)

// ShowManPage displays the manual page for the quay-client command line tool.
// The manual page provides detailed information about the available flags and their usage.
func ShowManPage() {
	fmt.Print(`
NAME
    qc - Quay Client Command Line Tool

SYNOPSIS
    qc [OPTIONS]

DESCRIPTION
    The Quay Client Command Line Tool (qc) allows you to interact with the Quay registry.
    You can perform various operations such as listing organizations, repositories, tags and
    their vulnerabilities, deleting tags, and retrieving user information.

    Special function is to generate a schell script of istags to delete based on criterias.

OPTIONS
    -m, --man                               Show manual page
    -h, --help                              Show help

    -s, --secret                            Secret name containing Quay credentials
    -sn, --secret-namespace                 Namespace containing the secret
    -o, --organisation                      Organisation name
    -r, --repository                        Repository name
    -t, --tag                               Tag name or regexp for tagname
    -rx, --reporegex                        Regex pattern to filter repositories
    -url, --registryurl                     Quay registry URL (default: $QUAYREGISTRY or https://quay.io)
    -f, --format                            Output format: text, json, or yaml (default: yaml)
    -of, --output-file                      Write output to file instead of stdout
    --ft                                    Set Output format to text
    --fj                                    Set Output format to json
    -i, --details                           Show detailed information
    -c, --curlreq                           Output a curl commandline with the Bearer token to query the Quay registry
    --sev                                   Filter vulnerabilities by severity [low, medium, high, critical]
    -b, --basescore                         Filter vulnerabilities by base score
    -kc, --kubeconfig                       Path to the kubeconfig file
    -pp, --prettyprint                      Enable prettyprint
    -gu, --getusers                         Get user information
    -gn, --getnotifications                 Get notifications
    -v, --verify                            Enable print verify infos
    -cc, --create-config                    Create a example config in $HOME/.config/qc/config.yaml
    -u, --username                          Quay username
    -p, --password                          Quay password

    -d, --delete                            Delete specified tag
    -fd, --filter-delete-tags               Generate shell script to delete tags based on criterias org name, repo name, minage
    -a, --minage                            Minimum age of tags to delete

EXAMPLES

  List repos of an organization                    qc -o my-org
  List repos by regex:                             qc -o my-org -r my-repo -rx ".*test.*"
  List repo overview of org inkl vulnerabilities:  qc -o pkp -i -ft
  List vulnerabilities of a repo:                  qc -o my-org -r my-repo -i [ft]
  List users:                                      qc -o my-org -gu [ft]
  List Notifications:                              qc -gn

  Generate shellscript to delete tags:             qc -o my-org -rx 'repo-pattern' -t 'tag-pattern' -a 'minage' --fd
  eg.                                              qc -o pkp    -rx '.*'           -t 'SNAPSHOT'    -a 100      --fd

  Delete a tag:                                    qc -o my-org -r my-repo -t my-tag -d
  eg.                                              qc -o pkp  -r vertragsverwaltung-service  -t 4.23.0-SNAPSHOT-0  -d

  Print curl cmd:                                  qc -c
  Print man page:                                  qc -m

  `)
	os.Exit(0)
}
