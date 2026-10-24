package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/pkg/apis/tinyauth/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientfake "k8s.io/client-go/kubernetes/fake"
)

func TestKubernetesOIDCClientExtractorExtract(t *testing.T) {
	meta := &ResourceMeta{Typ: ResourceTypeOIDCClient, Name: "grafana", Namespace: "default"}
	base := &v1alpha1.OIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "grafana", Namespace: "default"},
		Spec: v1alpha1.OIDCClientSpec{
			ClientID:            "grafana-client",
			ClientSecretRef:     &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "grafana-oidc"}, Key: "secret"},
			TrustedRedirectURIs: []string{"https://grafana.example.com/callback"},
			Name:                "Grafana",
		},
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "grafana-oidc", Namespace: "default"}, Data: map[string][]byte{"secret": []byte("s3cret")}}
	missingKey := secret.DeepCopy()
	missingKey.Data = map[string][]byte{"other": []byte("s3cret")}
	client := model.OIDCClientConfig{
		ClientID:            "grafana-client",
		ClientSecret:        "s3cret",
		TrustedRedirectURIs: []string{"https://grafana.example.com/callback"},
		Name:                "Grafana",
	}
	tests := []struct {
		name       string
		resource   *corev1.Secret
		oidcClient func() *v1alpha1.OIDCClient
		want       ExtractionResult
		reads      int
	}{
		{"valid client", secret, func() *v1alpha1.OIDCClient { return base.DeepCopy() }, ExtractionResult{Meta: meta, OIDCClients: map[string]model.OIDCClientConfig{"grafana": client}}, 1},
		{"secret not found", nil, func() *v1alpha1.OIDCClient { return base.DeepCopy() }, ExtractionResult{Meta: meta}, 1},
		{"secret key not found", missingKey, func() *v1alpha1.OIDCClient { return base.DeepCopy() }, ExtractionResult{Meta: meta}, 1},
		{"missing client ID", secret, func() *v1alpha1.OIDCClient { c := base.DeepCopy(); c.Spec.ClientID = ""; return c }, ExtractionResult{Meta: meta}, 0},
		{"missing secret ref", secret, func() *v1alpha1.OIDCClient { c := base.DeepCopy(); c.Spec.ClientSecretRef = nil; return c }, ExtractionResult{Meta: meta}, 0},
		{"missing namespace", secret, func() *v1alpha1.OIDCClient { c := base.DeepCopy(); c.Namespace = ""; return c }, ExtractionResult{}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := clientfake.NewClientset()
			if tt.resource != nil {
				client = clientfake.NewClientset(tt.resource)
			}
			extractor := NewKubernetesOIDCClientExtractor(KubernetesOIDCClientInput{Log: kubernetesTestLogger(), Client: client, Ctx: context.Background()})
			assert.Equal(t, tt.want, extractor.Extract(tt.oidcClient()))
			assert.Len(t, client.Actions(), tt.reads)
		})
	}
}
