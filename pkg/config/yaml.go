package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v2"
)

// YamlConfig represents the structure of the YAML configuration file
type Registry struct {
	URL             string `yaml:"url"`
	KubeconfigPath  string `yaml:"kubeconfig_path"`
	SecretName      string `yaml:"secret_name"`
	SecretNamespace string `yaml:"secret_namespace"`
}

type YamlConfig struct {
	Registry     Registry `yaml:"registry"`
	Organisation string   `yaml:"organisation"`
}

// LoadYamlConfig loads configuration from config.yaml file
//
// The function searches for the config file in the following locations:
// 1. ./config.yaml
// 2. $HOME/.config/qc/config.yaml
// 3. /etc/qc/config.yaml
//
// If no config file is found, the function returns default values.
func LoadYamlConfig() (*YamlConfig, error) {
	// Define possible config file locations
	configLocations := []string{
		"config.yaml",
		filepath.Join(os.Getenv("HOME"), ".config", "qc", "config.yaml"),
		"/etc/qc/config.yaml",
	}

	configFile := ""
	for _, loc := range configLocations {
		if _, err := os.Stat(loc); err == nil {
			configFile = loc
			break
		}
	}

	yamlConfig := YamlConfig{
		Registry: Registry{
			URL:             "",
			KubeconfigPath:  "",
			SecretName:      "",
			SecretNamespace: "",
		},
		Organisation: "",
	}

	// If no config file found, return default values
	if configFile == "" {
		return &yamlConfig, nil
	}

	file, err := os.Open(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %v", err)
	}
	defer file.Close()
	// Read and parse config file
	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&yamlConfig); err != nil {
		return nil, fmt.Errorf("failed to decode config file: %v", err)
	}

	return &yamlConfig, nil
}
