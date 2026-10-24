package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// OIDCClient is an OpenID Connect client that can sign in with Tinyauth. It is
// an alternative to environment variable or config-based OIDC clients.
type OIDCClient struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec OIDCClientSpec `json:"spec,omitempty"`
}

// +k8s:deepcopy-gen=true

// OIDCClientSpec describes the OIDC client
type OIDCClientSpec struct {
	// +required
	ClientID string `json:"clientId,omitempty"`
	// +required
	ClientSecretRef *corev1.SecretKeySelector `json:"clientSecretRef,omitempty"`
	// +required
	TrustedRedirectURIs []string `json:"trustedRedirectUris,omitempty"`
	Name                string   `json:"name,omitempty"`
}
