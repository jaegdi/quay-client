package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v2"
)

type YamlConfig struct {
	Registry struct {
		URL          string `yaml:"url"`
		SecretName   string `yaml:"secret_name"`
		Namespace    string `yaml:"namespace"`
		Organisation string `yaml:"organisation"`
	} `yaml:"registry"`
}

// LoadYamlConfig loads configuration from config.yaml file
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
