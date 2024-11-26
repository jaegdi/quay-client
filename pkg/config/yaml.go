package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v2"
)

type YamlConfig struct {
    Registry struct {
        URL        string `yaml:"url"`
        SecretName string `yaml:"secret_name"`
        Namespace  string `yaml:"namespace"`
    } `yaml:"registry"`
}

// LoadYamlConfig loads configuration from config.yaml file
func LoadYamlConfig() (*YamlConfig, error) {
    // Define possible config file locations
    configLocations := []string{
        "config.yaml",                                              // Current directory
        filepath.Join(os.Getenv("HOME"), ".config", "qc", "config.yaml"), // User's config directory
        "/etc/qc/config.yaml",                                      // System-wide config
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
                URL        string `yaml:"url"`
                SecretName string `yaml:"secret_name"`
                Namespace  string `yaml:"namespace"`
            }{
                URL:        "https://quay.io",
                SecretName: "quay-admin",
                Namespace:  "scp-build",
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
