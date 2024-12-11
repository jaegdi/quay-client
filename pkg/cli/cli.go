package cli

import (
	"flag"

	"github.com/jaegdi/quay-client/docs"
)

type Flags struct {
	ShowMan        bool
	SecretName     string
	Namespace      string
	Org            string
	Repo           string
	Tag            string
	Delete         bool
	Regex          string
	QuayURL        string
	OutputFormat   string
	Details        bool
	CurlReq        bool
	Severity       string
	BaseScore      float64
	KubeconfigPath string
	Prettyprint    bool
	GetUsers       bool
}

func ParseFlags() *Flags {
	flags := &Flags{}

	flag.BoolVar(&flags.ShowMan, "man", false, "Show manual page")
	flag.StringVar(&flags.SecretName, "secret", "", "Secret name containing Quay credentials")
	flag.StringVar(&flags.Namespace, "namespace", "", "Namespace containing the secret")
	flag.StringVar(&flags.Org, "organisation", "", "Organisation name")
	flag.StringVar(&flags.Repo, "repository", "", "Repository name")
	flag.StringVar(&flags.Tag, "tag", "", "Tag name")
	flag.BoolVar(&flags.Delete, "delete", false, "Delete specified tag")
	flag.StringVar(&flags.Regex, "regex", "", "Regex pattern to filter repositories")
	flag.StringVar(&flags.QuayURL, "registry", "", "Quay registry URL (default: $QUAYREGISTRY or https://quay.io)")
	flag.StringVar(&flags.OutputFormat, "output", "yaml", "Output format: text, json, or yaml, default is yaml")
	flag.BoolVar(&flags.Details, "details", false, "Show detailed information")
	flag.BoolVar(&flags.CurlReq, "curlreq", false, "Output a curl commandline with the Bearer token to query the Quay registry")
	flag.StringVar(&flags.Severity, "severity", "", "Filter vulnerabilities by severity[low,medium,high,critical]")
	flag.Float64Var(&flags.BaseScore, "basescore", 0, "Filter vulnerabilities by base score")
	flag.StringVar(&flags.KubeconfigPath, "kubeconfig", "", "Path to the kubeconfig file")
	flag.BoolVar(&flags.Prettyprint, "prettyprint", false, "Enable prettyprint")
	flag.BoolVar(&flags.GetUsers, "getusers", false, "Get user information")

	// Short flags
	flag.BoolVar(&flags.ShowMan, "m", false, "Show manual page")
	flag.StringVar(&flags.SecretName, "s", "", "Secret name containing Quay credentials")
	flag.StringVar(&flags.Namespace, "n", "", "Namespace containing the secret")
	flag.StringVar(&flags.Org, "o", "", "Organisation name")
	flag.StringVar(&flags.Repo, "r", "", "Repository name")
	flag.StringVar(&flags.Tag, "t", "", "Tag name")
	flag.BoolVar(&flags.Delete, "d", false, "Delete specified tag")
	flag.StringVar(&flags.Regex, "x", "", "Regex pattern to filter repositories")
	flag.StringVar(&flags.QuayURL, "u", "", "Quay registry URL (default: $QUAYREGISTRY or https://quay.io)")
	flag.StringVar(&flags.OutputFormat, "f", "yaml", "Output format: text, json, or yaml, default is yaml")
	flag.BoolVar(&flags.Details, "i", false, "Show detailed information")
	flag.BoolVar(&flags.CurlReq, "c", false, "Output a curl commandline with the Bearer token to query the Quay registry")
	flag.StringVar(&flags.Severity, "sev", "", "Filter vulnerabilities by severity")
	flag.Float64Var(&flags.BaseScore, "b", 0, "Filter vulnerabilities by base score")
	flag.StringVar(&flags.KubeconfigPath, "kc", "", "Path to the kubeconfig file")
	flag.BoolVar(&flags.Prettyprint, "pp", false, "Enable prettyprint")
	flag.BoolVar(&flags.GetUsers, "gu", false, "Get user information")

	flag.Usage = docs.ShowHelpPage
	flag.Parse()

	return flags
}
