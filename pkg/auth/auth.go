package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jaegdi/quay-client/pkg/config"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	// "k8s.io/client-go/kubernetes"
)

// Auth holds authentication information for Quay
type Auth struct {
	Username string
	Password string
	Token    string
}

// dockerConfigJSON represents the structure of a Docker config JSON
type dockerConfigJSON struct {
	Auths map[string]struct {
		Auth string `json:"auth"`
	} `json:"auths"`
}

// NewAuth creates a new Auth instance using OpenShift secret
// The function returns an Auth instance and an error if the authentication fails
// The function retrieves the secret from the specified namespace and extracts the credentials
// The function returns an error if the secret type is not supported
// The function returns an error if the secret does not contain valid credentials
//
// Parameters:
//
//	cfg: a pointer to the Config instance
//
// Returns:
//
//	a pointer to the Auth instance
//	an error if the authentication fails
func NewAuth(cfg *config.Config) (*Auth, error) {
	clientset, err := kubernetes.NewForConfig(cfg.K8sConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %v", err)
	}

	secret, err := clientset.CoreV1().Secrets(cfg.SecretNamespace).Get(
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

// setAuthHeader sets the Authorization header based on the client's authentication method
// The function sets the Authorization header based on the client's authentication method
// The function sets the Authorization header to the token if the token is provided
// The function sets the Authorization header to the base64 encoded username and password if both are provided
//
// Parameters:
//
//	req: The http.Request instance to set the Authorization header on
//
// Returns:
// a pointer to the Auth instance
// An error if the authentication fails
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

// parseOpaqueSecret extracts the credentials from an opaque secret
// The function returns an Auth instance and an error if the secret does not contain valid credentials
// The function returns an error if the secret does not contain valid credentials
//
// Parameters:
//
//	secret: a pointer to the Secret instance
//
// Returns:
//
//	a pointer to the Auth instance
//	an error if the secret does not contain valid credentials
func parseOpaqueSecret(secret *corev1.Secret) (*Auth, error) {
	if token, exists := secret.Data["token"]; exists {
		return &Auth{Token: string(token)}, nil
	}
	if auth, exists := secret.Data["auth"]; exists {
		return &Auth{Token: string(auth)}, nil
		// if decoded, err := base64.StdEncoding.DecodeString(string(auth)); err == nil {
		//     return &Auth{
		//         Username: "",
		//         Password: string(decoded),
		//     }, nil
		// }
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
