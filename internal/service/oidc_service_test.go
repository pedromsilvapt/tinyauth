package service

import (
	"context"
	"testing"

	"github.com/steveiliop56/ding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository/memory"
	"github.com/tinyauthapp/tinyauth/internal/utils/decoders"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
)

func newTestUser() UserinfoResponse {
	return UserinfoResponse{
		Sub:               "test-sub",
		Name:              "Test User",
		PreferredUsername: "testuser",
		Email:             "test@example.com",
		Groups:            []string{"admins", "users"},
		UpdatedAt:         1234567890,
		GivenName:         "Test",
		FamilyName:        "User",
		MiddleName:        "M",
		Nickname:          "testy",
		Profile:           "https://example.com/testuser",
		Picture:           "https://example.com/testuser.jpg",
		Website:           "https://testuser.example.com",
		Gender:            "male",
		Birthdate:         "1990-01-01",
		Zoneinfo:          "America/Chicago",
		Locale:            "en-US",
		PhoneNumber:       "+15555550100",
		Address: &model.AddressClaim{
			Formatted:     "123 Main St",
			StreetAddress: "123 Main St",
			Locality:      "Springfield",
			Region:        "IL",
			PostalCode:    "62701",
			Country:       "US",
		},
	}
}

func TestCompileUserinfo(t *testing.T) {
	dir := t.TempDir()

	cfg := model.Config{
		OIDC: model.OIDCConfig{
			PrivateKeyPath: dir + "/key.pem",
			PublicKeyPath:  dir + "/key.pub",
		},
		Auth: model.AuthConfig{
			SessionExpiry: 3600,
		},
	}

	runtime := model.RuntimeConfig{
		AppURL: "https://tinyauth.example.com",
	}

	log := logger.NewLogger().WithTestConfig()
	log.Init()

	ctx := context.TODO()
	dg := ding.New(ctx)

	store := memory.New()

	svc, err := NewOIDCService(OIDCServiceInput{
		Log:     log,
		Config:  &cfg,
		Runtime: &runtime,
		Queries: store,
		Ding:    dg,
	})
	require.NoError(t, err)

	type testCase struct {
		description string
		mutate      func(u *UserinfoResponse)
		scope       string
		run         func(t *testing.T, info UserinfoResponse)
	}

	tests := []testCase{
		{
			description: "openid scope only returns sub and updated_at",
			scope:       "openid",
			run: func(t *testing.T, info UserinfoResponse) {
				assert.Equal(t, "test-sub", info.Sub)
				assert.Equal(t, int64(1234567890), info.UpdatedAt)
				assert.Empty(t, info.Name)
				assert.Empty(t, info.Email)
				assert.Nil(t, info.Groups)
				assert.Nil(t, info.PhoneNumberVerified)
				assert.Nil(t, info.Address)
			},
		},
		{
			description: "profile scope returns all profile fields",
			scope:       "openid profile",
			run: func(t *testing.T, info UserinfoResponse) {
				assert.Equal(t, "Test User", info.Name)
				assert.Equal(t, "testuser", info.PreferredUsername)
				assert.Equal(t, "Test", info.GivenName)
				assert.Equal(t, "User", info.FamilyName)
				assert.Equal(t, "M", info.MiddleName)
				assert.Equal(t, "testy", info.Nickname)
				assert.Equal(t, "https://example.com/testuser", info.Profile)
				assert.Equal(t, "https://example.com/testuser.jpg", info.Picture)
				assert.Equal(t, "https://testuser.example.com", info.Website)
				assert.Equal(t, "male", info.Gender)
				assert.Equal(t, "1990-01-01", info.Birthdate)
				assert.Equal(t, "America/Chicago", info.Zoneinfo)
				assert.Equal(t, "en-US", info.Locale)
				assert.Empty(t, info.Email)
			},
		},
		{
			description: "email scope sets email and email_verified true when email present",
			scope:       "openid email",
			run: func(t *testing.T, info UserinfoResponse) {
				assert.Equal(t, "test@example.com", info.Email)
				assert.True(t, info.EmailVerified)
				assert.Empty(t, info.Name)
			},
		},
		{
			description: "email scope sets email_verified false when email absent",
			scope:       "openid email",
			mutate:      func(u *UserinfoResponse) { u.Email = "" },
			run: func(t *testing.T, info UserinfoResponse) {
				assert.Empty(t, info.Email)
				assert.False(t, info.EmailVerified)
			},
		},
		{
			description: "phone scope sets phone_number_verified true when phone present",
			scope:       "openid phone",
			run: func(t *testing.T, info UserinfoResponse) {
				assert.Equal(t, "+15555550100", info.PhoneNumber)
				require.NotNil(t, info.PhoneNumberVerified)
				assert.True(t, *info.PhoneNumberVerified)
			},
		},
		{
			description: "phone scope sets phone_number_verified false when phone absent",
			scope:       "openid phone",
			mutate:      func(u *UserinfoResponse) { u.PhoneNumber = "" },
			run: func(t *testing.T, info UserinfoResponse) {
				require.NotNil(t, info.PhoneNumberVerified)
				assert.False(t, *info.PhoneNumberVerified)
			},
		},
		{
			description: "address scope returns parsed address",
			scope:       "openid address",
			run: func(t *testing.T, info UserinfoResponse) {
				require.NotNil(t, info.Address)
				assert.Equal(t, "123 Main St", info.Address.Formatted)
				assert.Equal(t, "123 Main St", info.Address.StreetAddress)
				assert.Equal(t, "Springfield", info.Address.Locality)
				assert.Equal(t, "IL", info.Address.Region)
				assert.Equal(t, "62701", info.Address.PostalCode)
				assert.Equal(t, "US", info.Address.Country)
			},
		},
		{
			description: "groups scope returns split groups",
			scope:       "openid groups",
			run: func(t *testing.T, info UserinfoResponse) {
				assert.Equal(t, []string{"admins", "users"}, info.Groups)
			},
		},
		{
			description: "all scopes return all fields",
			scope:       "openid profile email phone address groups",
			run: func(t *testing.T, info UserinfoResponse) {
				assert.Equal(t, "Test User", info.Name)
				assert.Equal(t, "test@example.com", info.Email)
				assert.Equal(t, "+15555550100", info.PhoneNumber)
				require.NotNil(t, info.PhoneNumberVerified)
				assert.True(t, *info.PhoneNumberVerified)
				require.NotNil(t, info.Address)
				assert.Equal(t, "Springfield", info.Address.Locality)
				assert.Equal(t, []string{"admins", "users"}, info.Groups)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			user := newTestUser()
			if test.mutate != nil {
				test.mutate(&user)
			}
			info := svc.CompileUserinfo(user, test.scope)
			test.run(t, info)
		})
	}
}

type fakeOIDCLabelProvider struct {
	clients map[string]model.OIDCClientConfig
}

func (f *fakeOIDCLabelProvider) Lookup(locator func(name string, app *model.App)) error {
	return nil
}

func (f *fakeOIDCLabelProvider) GetOIDCClients() map[string]model.OIDCClientConfig {
	return f.clients
}

func TestOIDCLabelClients(t *testing.T) {
	dir := t.TempDir()

	labels, err := decoders.DecodeLabels[model.OIDCClients](map[string]string{
		"tinyauth.oidc.clients.myapp.clientId":            "label-client",
		"tinyauth.oidc.clients.myapp.clientSecret":        "label-secret",
		"tinyauth.oidc.clients.myapp.trustedRedirectUris": "https://myapp.example.com/callback",
		"tinyauth.oidc.clients.other.clientId":            "static-client",
		"tinyauth.oidc.clients.other.name":                "Label Name",
	}, "oidc")
	require.NoError(t, err)

	cfg := model.Config{
		OIDC: model.OIDCConfig{
			PrivateKeyPath: dir + "/key.pem",
			PublicKeyPath:  dir + "/key.pub",
			Labels:         true,
		},
	}

	log := logger.NewLogger().WithTestConfig()
	log.Init()

	newService := func(t *testing.T) *OIDCService {
		svc, err := NewOIDCService(OIDCServiceInput{
			Log:           log,
			Config:        &cfg,
			Runtime:       &model.RuntimeConfig{AppURL: "https://tinyauth.example.com"},
			Queries:       memory.New(),
			Ding:          ding.New(context.TODO()),
			LabelProvider: &fakeOIDCLabelProvider{clients: labels.OIDC.Clients},
		})
		require.NoError(t, err)
		require.NotNil(t, svc)
		return svc
	}

	t.Run("starts without static clients and finds label clients", func(t *testing.T) {
		client, ok := newService(t).GetClient("label-client")
		require.True(t, ok)
		assert.Equal(t, "myapp", client.ID)
		assert.Equal(t, "Myapp", client.Name)
		assert.Equal(t, "label-secret", client.ClientSecret)
		assert.Equal(t, []string{"https://myapp.example.com/callback"}, client.TrustedRedirectURIs)

		_, ok = newService(t).GetClient("unknown")
		assert.False(t, ok)
	})

	t.Run("static clients take precedence over label clients", func(t *testing.T) {
		cfg.OIDC.Clients = map[string]model.OIDCClientConfig{
			"other": {ClientID: "static-client", Name: "Static Name"},
		}
		defer func() { cfg.OIDC.Clients = nil }()

		client, ok := newService(t).GetClient("static-client")
		require.True(t, ok)
		assert.Equal(t, "Static Name", client.Name)
	})
}
