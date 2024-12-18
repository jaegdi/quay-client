package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v2"
)

// YamlConfig represents the structure of the YAML configuration file
type YamlConfig struct {
	Registry struct {
		URL          string `yaml:"url"`
		SecretName   string `yaml:"secret_name"`
		Namespace    string `yaml:"namespace"`
		Organisation string `yaml:"organisation"`
	} `yaml:"registry"`
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

	var configFile string
	for _, loc := range configLocations {
		if _, err := os.Stat(loc); err == nil {
			configFile = loc
			break
		}
	}

	// If no config file found, return default values
	if configFile == "" {
		return &YamlConfig{
			Registry: struct {
				URL          string `yaml:"url"`
				SecretName   string `yaml:"secret_name"`
				Namespace    string `yaml:"namespace"`
				Organisation string `yaml:"organisation"`
			}{
				URL:          "https://quay.io",
				SecretName:   "quay-admin",
				Namespace:    "scp-build",
				Organisation: "",
			},
		}, nil
	}

	// Read and parse config file
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, err
	}

	config := &YamlConfig{}
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, err
	}

	return config, nil
}
