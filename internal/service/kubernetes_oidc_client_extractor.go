package service

import (
	"context"
	"fmt"
	"time"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	"github.com/tinyauthapp/tinyauth/pkg/apis/tinyauth/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type KubernetesOIDCClientInput struct {
	Log    *logger.Logger
	Ctx    context.Context
	Client kubernetes.Interface
}

type KubernetesOIDCClientExtractor struct {
	log    *logger.Logger
	ctx    context.Context
	client kubernetes.Interface
}

func NewKubernetesOIDCClientExtractor(i KubernetesOIDCClientInput) *KubernetesOIDCClientExtractor {
	return &KubernetesOIDCClientExtractor{
		log:    i.Log,
		ctx:    i.Ctx,
		client: i.Client,
	}
}

func (k *KubernetesOIDCClientExtractor) Extract(oidcClient *v1alpha1.OIDCClient) ExtractionResult {
	meta := &ResourceMeta{
		Typ:       ResourceTypeOIDCClient,
		Name:      oidcClient.GetName(),
		Namespace: oidcClient.GetNamespace(),
	}

	if !ensureResourceMeta(meta) {
		k.log.App.Warn().Str("namespace", meta.Namespace).Str("name", meta.Name).Msg("Resource has no namespace or name, skipping")
		return ExtractionResult{}
	}

	ref := oidcClient.Spec.ClientSecretRef

	if oidcClient.Spec.ClientID == "" || ref == nil {
		k.log.App.Warn().Str("namespace", meta.Namespace).Str("name", meta.Name).Msg("OIDC client has no client ID or client secret, skipping")
		return ExtractionResult{Meta: meta}
	}

	ctx, cancel := context.WithTimeout(k.ctx, 10*time.Second)
	secret, err := k.client.CoreV1().Secrets(meta.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
	cancel()

	clientSecret := ""
	if err == nil {
		if value, ok := secret.Data[ref.Key]; ok {
			clientSecret = string(value)
		} else {
			err = fmt.Errorf("key %q not found in Secret %q", ref.Key, ref.Name)
		}
	}

	if err != nil || clientSecret == "" {
		k.log.App.Warn().Err(err).
			Str("namespace", meta.Namespace).
			Str("name", meta.Name).
			Str("secret", ref.Name).
			Str("key", ref.Key).
			Msg("Failed to resolve OIDC client secret, skipping")

		return ExtractionResult{Meta: meta}
	}

	client := oidcClient.Spec.ToInternalOIDCClient()
	client.ClientSecret = clientSecret

	return ExtractionResult{
		Meta: meta,
		OIDCClients: map[string]model.OIDCClientConfig{
			meta.Name: client,
		},
	}
}
