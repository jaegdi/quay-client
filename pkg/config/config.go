package config

import (
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type Config struct {
    KubeConfig  string
    SecretName  string
    Namespace   string
    K8sConfig   *rest.Config
}

// NewConfig creates a new Config instance
func NewConfig(kubeconfig, secretName, namespace string) (*Config, error) {
    // Load kubernetes configuration
    config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
    if err != nil {
        return nil, err
    }

    return &Config{
        KubeConfig: kubeconfig,
        SecretName: secretName,
        Namespace:  namespace,
        K8sConfig:  config,
    }, nil
}
