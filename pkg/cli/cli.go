package cli

import (
	"flag"

	"github.com/jaegdi/quay-client/pkg/docs"
)

// Flags represents the command line flags
type Flags struct {
	OutputFile       string
	ShowMan          bool
	SecretName       string
	SecretNamespace  string
	Org              string
	Repo             string
	Tag              string
	Delete           bool
	RepoRegex        string
	QuayURL          string
	OutputFormat     string
	OutputFormatText bool
	OutputFormatJson bool
	Details          bool
	CurlReq          bool
	Severity         string
	BaseScore        float64
	KubeconfigPath   string
	Prettyprint      bool
	GetUsers         bool
	Verify           bool
	CreateConfig     bool
	GetNotifications bool
	Username         string
	Password         string
	FilterTags       bool
	MinAge           int
}

var flags Flags

// ParseFlags parses the command line flags, long and short flags are defined for each option.
func ParseFlags() *Flags {
	flag.StringVar(&flags.OutputFile, "output-file", "", "Write output to file instead of stdout")
	flag.StringVar(&flags.OutputFile, "of", "", "Write output to file instead of stdout")

	flag.BoolVar(&flags.ShowMan, "man", false, "Show manual page")
	flag.BoolVar(&flags.ShowMan, "m", false, "Show manual page")

	flag.StringVar(&flags.SecretName, "secret", "", "Secret name containing Quay credentials")
	flag.StringVar(&flags.SecretName, "s", "", "Secret name containing Quay credentials")

	flag.StringVar(&flags.SecretNamespace, "secret-namespace", "", "Namespace containing the secret")
	flag.StringVar(&flags.SecretNamespace, "sn", "", "Namespace containing the secret")

	flag.StringVar(&flags.Org, "organisation", "", "Organisation name")
	flag.StringVar(&flags.Org, "o", "", "Organisation name")

	flag.StringVar(&flags.Repo, "repository", "", "Repository name")
	flag.StringVar(&flags.Repo, "r", "", "Repository name")

	flag.StringVar(&flags.Tag, "tag", "", "Tag name or regexp for tagname")
	flag.StringVar(&flags.Tag, "t", "", "Tag name")

	flag.BoolVar(&flags.Delete, "delete", false, "Delete specified tag")
	flag.BoolVar(&flags.Delete, "d", false, "Delete specified tag")

	flag.StringVar(&flags.RepoRegex, "reporegex", "", "Regex pattern to filter repositories")
	flag.StringVar(&flags.RepoRegex, "rx", "", "Regex pattern to filter repositories")

	flag.StringVar(&flags.QuayURL, "registryurl", "", "Quay registry URL (default: $QUAYREGISTRY or https://quay.io)")
	flag.StringVar(&flags.QuayURL, "url", "", "Quay registry URL (default: $QUAYREGISTRY or https://quay.io)")

	flag.StringVar(&flags.OutputFormat, "format", "yaml", "Output format: text, json, or yaml, default is yaml")
	flag.StringVar(&flags.OutputFormat, "f", "yaml", "Output format: text, json, or yaml, default is yaml")

	flag.BoolVar(&flags.OutputFormatText, "ft", false, "Set Output format to text")
	flag.BoolVar(&flags.OutputFormatJson, "fj", false, "Set Output format to json")

	flag.BoolVar(&flags.Details, "details", false, "Show detailed information")
	flag.BoolVar(&flags.Details, "i", false, "Show detailed information")

	flag.BoolVar(&flags.CurlReq, "curlreq", false, "Output a curl commandline with the Bearer token to query the Quay registry")
	flag.BoolVar(&flags.CurlReq, "c", false, "Output a curl commandline with the Bearer token to query the Quay registry")

	flag.StringVar(&flags.Severity, "severity", "", "Filter vulnerabilities by severity[low,medium,high,critical]")
	flag.StringVar(&flags.Severity, "sev", "", "Filter vulnerabilities by severity")

	flag.Float64Var(&flags.BaseScore, "basescore", 0, "Filter vulnerabilities by base score")
	flag.Float64Var(&flags.BaseScore, "b", 0, "Filter vulnerabilities by base score")

	flag.StringVar(&flags.KubeconfigPath, "kubeconfig", "", "Path to the kubeconfig file")
	flag.StringVar(&flags.KubeconfigPath, "kc", "", "Path to the kubeconfig file")

	flag.BoolVar(&flags.Prettyprint, "prettyprint", false, "Enable prettyprint")
	flag.BoolVar(&flags.Prettyprint, "pp", false, "Enable prettyprint")

	flag.BoolVar(&flags.GetUsers, "getusers", false, "Get user information")
	flag.BoolVar(&flags.GetUsers, "gu", false, "Get user information")

	flag.BoolVar(&flags.CreateConfig, "create-config", false, "Create a example config in $HOME/.config/qc/config.yaml")
	flag.BoolVar(&flags.CreateConfig, "cc", false, "Create a example config in $HOME/.config/qc/config.yaml")

	flag.BoolVar(&flags.GetNotifications, "getnotifications", false, "Get notifications")
	flag.BoolVar(&flags.GetNotifications, "gn", false, "Get notifications")

	flag.StringVar(&flags.Username, "username", "", "Quay username")
	flag.StringVar(&flags.Username, "u", "", "Quay username")

	flag.StringVar(&flags.Password, "password", "", "Quay password")
	flag.StringVar(&flags.Password, "p", "", "Quay password")

	flag.BoolVar(&flags.FilterTags, "filter-delete-tags", false, "Create script to delete tags based on criteria")
	flag.BoolVar(&flags.FilterTags, "fd", false, "Create script to delete tags based on criteria")

	flag.IntVar(&flags.MinAge, "minage", 100, "Minimum age of tags in days")
	flag.IntVar(&flags.MinAge, "a", 100, "Minimum age of tags in days")

	flag.BoolVar(&flags.Verify, "verify", false, "Enable print verify infos")
	flag.BoolVar(&flags.Verify, "v", false, "Enable verify")

	flag.Usage = docs.ShowHelpPage
	flag.Parse()

	if flags.OutputFormatText {
		flags.OutputFormat = "text"
	}
	if flags.OutputFormatJson {
		flags.OutputFormat = "json"
	}

	return &flags
}

// GetFlags returns the command line flags
func GetFlags() *Flags {
	return &flags
}
