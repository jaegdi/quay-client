package config

import (
	"os"
	"path/filepath"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Config represents the configuration of the Quay client
type Config struct {
	KubeConfig   string
	SecretName   string
	Namespace    string
	K8sConfig    *rest.Config
	QuayURL      string
	Organisation string
}

// GetKubeconfigPath returns the path to the kubeconfig file
// The function checks the following locations (in order):
// 1. Command line argument
// 2. Environment variable KUBECONFIG
// 3. Default location: $HOME/.kube/config
// The function returns the first valid path found.
// If no path is found, the function returns an empty string.
func GetKubeconfigPath(kubeconfigPath string) string {
	if kubeconfigPath != "" {
		return kubeconfigPath
	}
	if kubeconfig := os.Getenv("KUBECONFIG"); kubeconfig != "" {
		return kubeconfig
	}
	return filepath.Join(os.Getenv("HOME"), ".kube", "config")
}

// NewConfig creates a new Config instance
// The function initializes the configuration using the following priority order:
// 1. Command line arguments
// 2. Environment variables
// 3. Configuration file (yaml)
// 4. Hardcoded defaults
// The function returns a Config instance and an error if the configuration fails.
func NewConfig(kubeconfig, secretName, namespace, quayURL, organisation string) (*Config, error) {
	// Load YAML config first
	yamlConfig, err := LoadYamlConfig()
	if err != nil {
		return nil, err
	}

	// Priority order: CLI args > Environment vars > YAML config > hardcoded defaults

	// Handle QuayURL
	if quayURL == "" {
		quayURL = os.Getenv("QUAYREGISTRY")
		if quayURL == "" {
			quayURL = yamlConfig.Registry.URL
		}
	}

	// Handle SecretName
	if secretName == "" {
		secretName = yamlConfig.Registry.SecretName
	}

	// Handle Namespace
	if namespace == "" {
		namespace = yamlConfig.Registry.Namespace
	}

	// Handle Organisation
	if organisation == "" {
		organisation = os.Getenv("QUAYORG")
		if organisation == "" {
			organisation = yamlConfig.Registry.Organisation
		}
	}
	if organisation == "-" {
		organisation = ""
	}

	// Load kubernetes configuration
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, err
	}

	// Ensure URL doesn't end with a slash
	if len(quayURL) > 0 && quayURL[len(quayURL)-1] == '/' {
		quayURL = quayURL[:len(quayURL)-1]
	}

	return &Config{
		KubeConfig:   kubeconfig,
		SecretName:   secretName,
		Namespace:    namespace,
		K8sConfig:    config,
		QuayURL:      quayURL,
		Organisation: organisation,
	}, nil
}
