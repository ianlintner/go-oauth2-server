package authcode_test

import (
	"context"
	"testing"

	"github.com/ianlintner/go-oauth2-server/internal/authcode"
	"github.com/ianlintner/go-oauth2-server/internal/oauth"
)

var allowedScopes = []string{"openid", "read"}

func TestRegisterCreatesConfidentialClient(t *testing.T) {
	e := newEnv(t)
	resp, err := e.svc.Register(context.Background(), authcode.RegistrationRequest{
		RedirectURIs:            []string{"https://client.example/dyn"},
		ClientName:              "conformance-dyn",
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		Scope:                   "read",
	}, allowedScopes)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if resp.ClientID == "" || resp.ClientSecret == "" || resp.ClientSecretExpiresAt != 0 {
		t.Fatalf("response = %+v", resp)
	}
	if resp.ClientName != "conformance-dyn" || resp.TokenEndpointAuthMethod != "client_secret_basic" {
		t.Fatalf("metadata = %+v", resp)
	}
	if len(resp.RedirectURIs) != 1 || resp.RedirectURIs[0] != "https://client.example/dyn" {
		t.Fatalf("redirect_uris = %+v", resp.RedirectURIs)
	}

	// The client is real and authenticated by its issued secret.
	c, err := e.store.Clients().Get(context.Background(), resp.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	if c.Public || c.SecretHash == "" || c.AuthMethod != "client_secret_basic" {
		t.Fatalf("stored client = %+v", c)
	}
	if got := c.GrantTypes; len(got) != 1 || got[0] != "authorization_code" {
		t.Fatalf("grant types = %+v", got)
	}
}

func TestRegisterPublicClient(t *testing.T) {
	e := newEnv(t)
	resp, err := e.svc.Register(context.Background(), authcode.RegistrationRequest{
		RedirectURIs:            []string{"https://client.example/cb"},
		TokenEndpointAuthMethod: "none",
		GrantTypes:              []string{"authorization_code"},
	}, allowedScopes)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if resp.ClientSecret != "" {
		t.Fatalf("public client got a secret: %+v", resp)
	}
	c, err := e.store.Clients().Get(context.Background(), resp.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Public || c.SecretHash != "" {
		t.Fatalf("stored client = %+v", c)
	}
}

func TestRegisterDefaults(t *testing.T) {
	e := newEnv(t)
	resp, err := e.svc.Register(context.Background(), authcode.RegistrationRequest{
		RedirectURIs: []string{"https://client.example/cb"},
	}, allowedScopes)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if resp.TokenEndpointAuthMethod != "client_secret_basic" {
		t.Fatalf("default auth method = %q", resp.TokenEndpointAuthMethod)
	}
	if len(resp.GrantTypes) != 1 || resp.GrantTypes[0] != "authorization_code" {
		t.Fatalf("default grants = %+v", resp.GrantTypes)
	}
}

func TestRegisterRejects(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	cases := []struct {
		name string
		req  authcode.RegistrationRequest
		want oauth.Code
	}{
		{"no redirect_uris", authcode.RegistrationRequest{ClientName: "x"}, oauth.CodeInvalidRedirectURI},
		{"bad redirect uri", authcode.RegistrationRequest{RedirectURIs: []string{"not a uri"}}, oauth.CodeInvalidRedirectURI},
		{"http non-loopback", authcode.RegistrationRequest{RedirectURIs: []string{"http://example.com/cb"}}, oauth.CodeInvalidRedirectURI},
		{"fragment", authcode.RegistrationRequest{RedirectURIs: []string{"https://e.com/cb#frag"}}, oauth.CodeInvalidRedirectURI},
		{"javascript scheme", authcode.RegistrationRequest{RedirectURIs: []string{"javascript:alert(1)"}}, oauth.CodeInvalidRedirectURI},
		{"unsupported auth method", authcode.RegistrationRequest{RedirectURIs: []string{"https://e.com/cb"}, TokenEndpointAuthMethod: "private_key_jwt"}, oauth.CodeInvalidClientMetadata},
		{"client_credentials grant", authcode.RegistrationRequest{RedirectURIs: []string{"https://e.com/cb"}, GrantTypes: []string{"client_credentials"}}, oauth.CodeInvalidClientMetadata},
		{"implicit response type", authcode.RegistrationRequest{RedirectURIs: []string{"https://e.com/cb"}, ResponseTypes: []string{"token"}}, oauth.CodeInvalidClientMetadata},
		{"scope outside ceiling", authcode.RegistrationRequest{RedirectURIs: []string{"https://e.com/cb"}, Scope: "admin"}, oauth.CodeInvalidClientMetadata},
		{"refresh without a grant", authcode.RegistrationRequest{RedirectURIs: []string{"https://e.com/cb"}, GrantTypes: []string{"refresh_token"}}, oauth.CodeInvalidClientMetadata},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := e.svc.Register(ctx, c.req, allowedScopes)
			wantCode(t, err, c.want)
		})
	}
}

func TestRegisterCannotGrantClientCredentials(t *testing.T) {
	e := newEnv(t)
	// A registered client must never gain the client_credentials grant.
	_, err := e.svc.Register(context.Background(), authcode.RegistrationRequest{
		RedirectURIs: []string{"https://e.com/cb"},
		GrantTypes:   []string{"client_credentials"},
	}, allowedScopes)
	wantCode(t, err, oauth.CodeInvalidClientMetadata)
}
