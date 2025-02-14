package docs

import (
	"fmt"
	"os"
)

// ShowHelpPage displays the help page for the quay-client command line tool.
// The help page provides information about the available flags and their usage.
func ShowHelpPage() {
	fmt.Print(`Usage: qc [OPTIONS]

Options:
  -m, --man                    Show manual page
  -s, --secret                 Secret name containing Quay credentials
  -sn, --secret-namespace      Namespace containing the secret
  -o, --organisation           Organisation name
  -r, --repository             Repository name
  -t, --tag                    Tag name or regexp for tagname
  -rx, --reporegex             Regex pattern to filter repositories
  -url, --registryurl          Quay registry URL (default: $QUAYREGISTRY or https://quay.io)
  -f, --format                 Output format: text, json, or yaml (default: yaml)
  -of, --output-file           Write output to file instead of stdout
  -ft                          Set Output format to text
  -fj                          Set Output format to json
  -i, --details                Show detailed information
  -c, --curlreq                Output a curl commandline with the Bearer token to query the Quay registry
  --sev                        Filter vulnerabilities by severity [low, medium, high, critical]
  -b, --basescore              Filter vulnerabilities by base score
  -kc, --kubeconfig            Path to the kubeconfig file
  -pp, --prettyprint           Enable prettyprint
  -gu, --getusers              Get user information
  -gn, --getnotifications      Get notifications
  -v, --verify                 Enable print verify infos
  -cc, --create-config         Create a example config in $HOME/.config/qc/config.yaml
  -u, --username               Quay username
  -p, --password               Quay password

  -fd --filter-delete-tags     Generate shell script for tags to delete
  -a, --minage                 Minimum age of tags to delete
  -d, --delete                 Execute delete of a specified tag


Examples:
  List repos by regex:                             qc -o my-org -r my-repo -rx ".*test.*"
  List repo overview of org inkl vulnerabilities:  qc -o pkp -i -ft
  List vulnerabilities of a repo:                  qc -o my-org -r my-repo -i [ft]
  List users:                                      qc -o my-org -gu [ft]
  List Notifications:                              qc -gn
  Print curl cmd:                                  qc -c
  Print man page:                                  qc -m

  Generate shellscript to delete tags:             qc -o my-org -fd tag-pattern -a
  Delete a tag:                                    qc -o my-org -r my-repo -t my-tag -d
`)
	os.Exit(0)
}
