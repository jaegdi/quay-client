package config

import (
	"os"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type Config struct {
    KubeConfig   string
    SecretName   string
    Namespace    string
    K8sConfig    *rest.Config
    QuayURL      string
    Organisation string
}

// NewConfig creates a new Config instance
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
