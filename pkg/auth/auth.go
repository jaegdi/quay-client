package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"qc/pkg/config"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Auth holds authentication information for Quay
type Auth struct {
    Username string
    Password string
    Token    string
}

type dockerConfigJSON struct {
    Auths map[string]struct {
        Auth string `json:"auth"`
    } `json:"auths"`
}

// NewAuth creates a new Auth instance using OpenShift secret
func NewAuth(cfg *config.Config) (*Auth, error) {
    clientset, err := kubernetes.NewForConfig(cfg.K8sConfig)
    if err != nil {
        return nil, fmt.Errorf("failed to create kubernetes client: %v", err)
    }

    secret, err := clientset.CoreV1().Secrets(cfg.Namespace).Get(
        context.Background(),
        cfg.SecretName,
        metav1.GetOptions{},
    )
    if err != nil {
        return nil, fmt.Errorf("failed to get secret: %v", err)
    }

    switch secret.Type {
    case corev1.SecretTypeDockerConfigJson:
        return parseDockerConfig(secret)
    case corev1.SecretTypeOpaque:
        return parseOpaqueSecret(secret)
    default:
        return nil, fmt.Errorf("unsupported secret type: %v", secret.Type)
    }
}

func parseDockerConfig(secret *corev1.Secret) (*Auth, error) {
    configJSON := secret.Data[".dockerconfigjson"]
    var config dockerConfigJSON
    if err := json.Unmarshal(configJSON, &config); err != nil {
        return nil, err
    }

    // Look for Quay.io auth
    for _, auth := range config.Auths {
        if decoded, err := base64.StdEncoding.DecodeString(auth.Auth); err == nil {
            parts := strings.SplitN(string(decoded), ":", 2)
            if len(parts) == 2 {
                return &Auth{
                    Username: parts[0],
                    Password: parts[1],
                }, nil
            }
        }
    }
    return nil, fmt.Errorf("no valid Quay.io credentials found in docker config")
}

func parseOpaqueSecret(secret *corev1.Secret) (*Auth, error) {
    if token, exists := secret.Data["token"]; exists {
        return &Auth{Token: string(token)}, nil
    }
    if username, exists := secret.Data["username"]; exists {
        if password, exists := secret.Data["password"]; exists {
            return &Auth{
                Username: string(username),
                Password: string(password),
            }, nil
        }
    }
    return nil, fmt.Errorf("no valid credentials found in opaque secret")
}
