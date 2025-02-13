package config

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v2"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Config represents the configuration of the Quay client
type Config struct {
	KubeConfig      string
	SecretName      string
	SecretNamespace string
	K8sConfig       *rest.Config
	QuayURL         string
	Organisation    string
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

// SaveConfigToFile saves the given Config instance to a YAML file
// The function creates a configuration directory in the user's home directory
// and writes the configuration to a file named config.yaml.
// If the provided Config instance is nil, the function writes default values to the file.
// The function returns an error if the directory or file creation fails,
// or if the encoding of the configuration to YAML fails.
func SaveConfigToFile(config *Config) error {
	configDir := filepath.Join(os.Getenv("HOME"), ".config", "qc")
	if err := os.MkdirAll(configDir, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	configFilePath := filepath.Join(configDir, "config.yaml")
	file, err := os.Create(configFilePath)
	if err != nil {
		return fmt.Errorf("failed to create config file: %v", err)
	}
	defer file.Close()

	encoder := yaml.NewEncoder(file)
	defer encoder.Close()
	yamlConfig := &YamlConfig{}
	if config != nil {
		yamlConfig = &YamlConfig{
			Registry: Registry{
				URL:             config.QuayURL,
				KubeconfigPath:  config.KubeConfig,
				SecretName:      config.SecretName,
				SecretNamespace: config.SecretNamespace,
			},
			Organisation: config.Organisation,
		}
	} else {
		yamlConfig = &YamlConfig{
			Registry: Registry{
				URL:             "https://quay.io",
				KubeconfigPath:  "$KUBECONFIG",
				SecretName:      "Name of secret for quay admin user",
				SecretNamespace: "Namespace of secret for quay admin user",
			},
			Organisation: "optional set here the default organisation",
		}
	}

	if err := encoder.Encode(yamlConfig); err != nil {
		return fmt.Errorf("failed to encode config to file: %v", err)
	}
	log.Println("Config file created successfully in path:", configFilePath)
	return nil
}

// NewConfig creates a new Config instance
// The function initializes the configuration using the following priority order:
// 1. Command line arguments
// 2. Environment variables
// 3. Configuration file (yaml)
// 4. Hardcoded defaults
// The function returns a Config instance and an error if the configuration fails.
func NewConfig(kubeconfig, secretName, secretNamespace, quayURL, organisation string) (*Config, error) {
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
		secretName = os.Getenv("QUAYREGISTRYADMINSECRET")
		if secretName == "" {
			secretName = yamlConfig.Registry.SecretName
		}
	}

	// Handle secretNamespace
	if secretNamespace == "" {
		secretNamespace = os.Getenv("QUAYREGISTRYSECRETNAMESPACE")
		if secretNamespace == "" {
			secretNamespace = yamlConfig.Registry.SecretNamespace
		}
	}

	// Handle Organisation
	if organisation == "" {
		organisation = os.Getenv("QUAYDEFAULTORG")
		if organisation == "" {
			organisation = yamlConfig.Organisation
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
		KubeConfig:      kubeconfig,
		SecretName:      secretName,
		SecretNamespace: secretNamespace,
		K8sConfig:       config,
		QuayURL:         quayURL,
		Organisation:    organisation,
	}, nil
}
