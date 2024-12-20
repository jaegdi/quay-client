Usage: qc [OPTIONS]

Options:
  -m, --man                Show manual page
  -s, --secret             Secret name containing Quay credentials
  -n, --secret_namespace   Namespace containing the secret
  -o, --organisation       Organisation name
  -r, --repository         Repository name
  -t, --tag                Tag name or regexp for tagname
  -d, --delete             Delete specified tag
  -x, --regex              Regex pattern to filter repositories
  -u, --registry           Quay registry URL (default: $QUAYREGISTRY or https://quay.io)
  -f, --output             Output format: text, json, or yaml (default: yaml)
  --ft                     Set Output format to text
  --fj                     Set Output format to json
  -i, --details            Show detailed information
  -c, --curlreq            Output a curl commandline with the Bearer token to query the Quay registry
  --sev                    Filter vulnerabilities by severity [low, medium, high, critical]
  -b, --basescore          Filter vulnerabilities by base score
  -kc, --kubeconfig        Path to the kubeconfig file
  -pp, --prettyprint       Enable prettyprint
  -gu, --getusers          Get user information
  -v, --verify             Enable print verify infos
  --create-config, -cc     Create a example config in $HOME/.config/qc/config.yaml

Examples:
  qc -o my-org -r my-repo -t my-tag -d
  qc -o my-org -r my-repo -x ".*test.*"
  qc -o my-org -gu
  qc -c
  qc -m

