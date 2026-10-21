package authcode_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ianlintner/go-oauth2-server/internal/authcode"
	"github.com/ianlintner/go-oauth2-server/internal/oauth"
	"github.com/ianlintner/go-oauth2-server/internal/secret"
)

func pushRequest(t *testing.T, e *env, auth string, kv ...string) (authcode.PushedResponse, error) {
	t.Helper()
	ensureParClient(t, e)
	return e.svc.PushAuthorizationRequest(context.Background(), auth, params(t, kv...))
}

// ensureParClient registers a scoped confidential client (the shared fixture
// clients carry no scopes). It is idempotent per env.
func ensureParClient(t *testing.T, e *env) {
	t.Helper()
	h, err := secret.Hash(oauth.CryptoRandom{}, "par-secret")
	if err != nil {
		t.Fatal(err)
	}
	err = e.store.Clients().Create(context.Background(), oauth.Client{
		ID: "client-par", SecretHash: h, AuthMethod: "client_secret_basic", RedirectURIs: []string{callback},
		Scopes: []string{"read"}, GrantTypes: []string{"authorization_code"},
	})
	if err != nil && !errors.Is(err, oauth.ErrConflict) {
		t.Fatal(err)
	}
}

func TestPushAuthorizationRequestCreatesUnguessableURI(t *testing.T) {
	e := newEnv(t)
	basicAuth := basic("client-par", "par-secret")
	base := []string{"client_id", "client-par", "response_type", "code", "redirect_uri", callback,
		"scope", "read", "state", "s-par", "code_challenge", challenge, "code_challenge_method", "S256"}

	r1, err := pushRequest(t, e, basicAuth, base...)
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if !strings.HasPrefix(r1.RequestURI, authcode.RequestURIPrefix) {
		t.Fatalf("request_uri = %q, want %s prefix", r1.RequestURI, authcode.RequestURIPrefix)
	}
	if len(r1.RequestURI) < len(authcode.RequestURIPrefix)+32 {
		t.Fatalf("request_uri too short: %q", r1.RequestURI)
	}
	if r1.ExpiresIn <= 0 {
		t.Fatalf("expires_in = %d", r1.ExpiresIn)
	}
	// Distinct pushes produce distinct URIs.
	r2, err := pushRequest(t, e, basicAuth, base...)
	if err != nil {
		t.Fatal(err)
	}
	if r1.RequestURI == r2.RequestURI {
		t.Fatalf("two pushes produced the same request_uri %q", r1.RequestURI)
	}
}

func TestPushAuthorizationRequestRejects(t *testing.T) {
	e := newEnv(t)
	ensureParClient(t, e)
	ctx := context.Background()
	good := func(kv ...string) authcode.PushedResponse {
		t.Helper()
		r, err := e.svc.PushAuthorizationRequest(ctx, basic("client-par", "par-secret"), params(t, kv...))
		if err != nil {
			t.Fatalf("push: %v", err)
		}
		return r
	}

	cases := []struct {
		name string
		auth string
		kv   []string
		want oauth.Code
	}{
		{"no client auth", "", []string{"client_id", "client-par", "response_type", "code", "redirect_uri", callback}, oauth.CodeInvalidClient},
		{"missing response_type", basic("client-par", "par-secret"), []string{"client_id", "client-par", "redirect_uri", callback}, oauth.CodeInvalidRequest},
		{"missing redirect_uri", basic("client-par", "par-secret"), []string{"client_id", "client-par", "response_type", "code"}, oauth.CodeInvalidRequest},
		{"wrong redirect_uri", basic("client-par", "par-secret"), []string{"client_id", "client-par", "response_type", "code", "redirect_uri", "https://evil.example/cb"}, oauth.CodeInvalidRequest},
		{"request_uri forbidden", basic("client-par", "par-secret"), []string{"client_id", "client-par", "response_type", "code", "redirect_uri", callback, "request_uri", "urn:ietf:params:oauth:request_uri:x"}, oauth.CodeInvalidRequest},
		{"request object forbidden", basic("client-par", "par-secret"), []string{"client_id", "client-par", "response_type", "code", "redirect_uri", callback, "request", "x"}, oauth.CodeInvalidRequest},
		{"missing PKCE", basic("client-par", "par-secret"), []string{"client_id", "client-par", "response_type", "code", "redirect_uri", callback}, oauth.CodeInvalidRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := e.svc.PushAuthorizationRequest(ctx, c.auth, params(t, c.kv...))
			wantCode(t, err, c.want)
		})
	}
	_ = good
}

func TestPushedRequestRedeemLifecycle(t *testing.T) {
	e := newEnv(t)
	r, err := pushRequest(t, e, basic("client-par", "par-secret"),
		"client_id", "client-par", "response_type", "code", "redirect_uri", callback,
		"scope", "read", "state", "s-par", "code_challenge", challenge, "code_challenge_method", "S256")
	if err != nil {
		t.Fatal(err)
	}

	// Redeem yields a validated AuthRequest.
	req, err := e.svc.RedeemPushed(context.Background(), "client-par", r.RequestURI)
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if req.Client.ID != "client-par" || req.RedirectURI != callback || req.Scope != "read" ||
		req.State != "s-par" || req.CodeChallenge != challenge {
		t.Fatalf("redeemed request = %+v", req)
	}

	// Second redeem (single use) and wrong-client use both fail.
	_, err = e.svc.RedeemPushed(context.Background(), "client-par", r.RequestURI)
	wantCode(t, err, oauth.CodeInvalidRequestURI)
	err = e.svc.CheckPushed(context.Background(), "client-enc", r.RequestURI)
	wantCode(t, err, oauth.CodeInvalidRequestURI)
}

func TestPushedRequestClientBoundOnUse(t *testing.T) {
	e := newEnv(t)
	r, err := pushRequest(t, e, basic("client-par", "par-secret"),
		"client_id", "client-par", "response_type", "code", "redirect_uri", callback,
		"scope", "read", "code_challenge", challenge, "code_challenge_method", "S256")
	if err != nil {
		t.Fatal(err)
	}
	// Another client cannot even validate the request_uri.
	err = e.svc.CheckPushed(context.Background(), "client-enc", r.RequestURI)
	wantCode(t, err, oauth.CodeInvalidRequestURI)
	// The rightful client still can.
	if err := e.svc.CheckPushed(context.Background(), "client-par", r.RequestURI); err != nil {
		t.Fatalf("check by rightful client: %v", err)
	}
}

func TestPushedRequestExpires(t *testing.T) {
	e := newEnv(t)
	r, err := pushRequest(t, e, basic("client-par", "par-secret"),
		"client_id", "client-par", "response_type", "code", "redirect_uri", callback,
		"scope", "read", "code_challenge", challenge, "code_challenge_method", "S256")
	if err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(authcode.DefaultPushedRequestTTL + time.Second)
	err = e.svc.CheckPushed(context.Background(), "client-par", r.RequestURI)
	wantCode(t, err, oauth.CodeInvalidRequestURI)
	_, err = e.svc.RedeemPushed(context.Background(), "client-par", r.RequestURI)
	wantCode(t, err, oauth.CodeInvalidRequestURI)
}

func TestPushedRequestMalformedURI(t *testing.T) {
	e := newEnv(t)
	err := e.svc.CheckPushed(context.Background(), "client-par", "urn:not-a-pushed-uri")
	wantCode(t, err, oauth.CodeInvalidRequestURI)
	err = e.svc.CheckPushed(context.Background(), "", authcode.RequestURIPrefix+"deadbeefdeadbeefdeadbeefdeadbeef")
	wantCode(t, err, oauth.CodeInvalidRequest)
}
