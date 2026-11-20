package server_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
	"github.com/ianlintner/go-oauth2-server/internal/secret"
)

// RFC 9700 §2.1.1: when an authorization code is replayed the server must
// revoke every token previously issued from it.

func (e *tokenEnv) authorizeCode(t *testing.T, clientID string) string {
	t.Helper()
	h, err := secret.Hash(oauth.CryptoRandom{}, "test-only-password")
	if err != nil {
		t.Fatal(err)
	}
	err = e.store.Users().Create(context.Background(), oauth.User{ID: "user-1", Username: "alice", PasswordHash: h})
	if err != nil && !errors.Is(err, oauth.ErrConflict) {
		t.Fatal(err)
	}
	rec := e.get("/oauth/authorize?"+authQuery(clientID, callback, nil), cookie(e.login(t)))
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize = %d %q", rec.Code, rec.Body.String())
	}
	c := location(t, rec).Query().Get("code")
	if c == "" {
		t.Fatalf("no code in %q", rec.Header().Get("Location"))
	}
	return c
}

func (e *tokenEnv) introspectActive(t *testing.T, accessToken string) bool {
	t.Helper()
	rec := e.postForm("/oauth/introspect", "token="+accessToken, basic("client-rt", "rt-test-secret"))
	if rec.Code != http.StatusOK {
		t.Fatalf("introspect = %d %q", rec.Code, rec.Body.String())
	}
	active, _ := jsonBody(t, rec)["active"].(bool)
	return active
}

func TestCodeReplayRevokesAccessAndRefreshTokensIssuedFromTheCode(t *testing.T) {
	e := newTokenEnv(t)
	auth := basic("client-rt", "rt-test-secret")
	c := e.authorizeCode(t, "client-rt")

	first := e.postForm("/oauth/token", codeForm(c), auth)
	if first.Code != http.StatusOK {
		t.Fatalf("first redemption = %d %q", first.Code, first.Body.String())
	}
	body := jsonBody(t, first)
	at, _ := body["access_token"].(string)
	rt, _ := body["refresh_token"].(string)
	if at == "" || rt == "" {
		t.Fatalf("token body = %v", body)
	}
	if !e.introspectActive(t, at) {
		t.Fatal("access token should be active before the replay")
	}

	replay := e.postForm("/oauth/token", codeForm(c), auth)
	if replay.Code != http.StatusBadRequest || jsonBody(t, replay)["error"] != "invalid_grant" {
		t.Fatalf("replay = %d %q, want 400 invalid_grant", replay.Code, replay.Body.String())
	}

	if e.introspectActive(t, at) {
		t.Fatal("access token issued from the replayed code must be inactive")
	}
	ref := e.postForm("/oauth/token", "grant_type=refresh_token&refresh_token="+rt, auth)
	if ref.Code != http.StatusBadRequest || jsonBody(t, ref)["error"] != "invalid_grant" {
		t.Fatalf("refresh after replay = %d %q, want 400 invalid_grant", ref.Code, ref.Body.String())
	}
}

func TestCodeReplayRevokesRotatedRefreshDescendants(t *testing.T) {
	e := newTokenEnv(t)
	auth := basic("client-rt", "rt-test-secret")
	c := e.authorizeCode(t, "client-rt")
	first := jsonBody(t, e.postForm("/oauth/token", codeForm(c), auth))
	rt1, _ := first["refresh_token"].(string)
	second := e.postForm("/oauth/token", "grant_type=refresh_token&refresh_token="+rt1, auth)
	if second.Code != http.StatusOK {
		t.Fatalf("rotation = %d %q", second.Code, second.Body.String())
	}
	rt2, _ := jsonBody(t, second)["refresh_token"].(string)

	if r := e.postForm("/oauth/token", codeForm(c), auth); r.Code != http.StatusBadRequest {
		t.Fatalf("replay = %d", r.Code)
	}
	ref := e.postForm("/oauth/token", "grant_type=refresh_token&refresh_token="+rt2, auth)
	if ref.Code != http.StatusBadRequest {
		t.Fatalf("rotated descendant still live after code replay: %d %q", ref.Code, ref.Body.String())
	}
}

func TestFabricatedCodeDoesNotRevokeAnotherGrantsTokens(t *testing.T) {
	e := newTokenEnv(t)
	auth := basic("client-rt", "rt-test-secret")
	c := e.authorizeCode(t, "client-rt")
	body := jsonBody(t, e.postForm("/oauth/token", codeForm(c), auth))
	at, _ := body["access_token"].(string)
	rt, _ := body["refresh_token"].(string)

	if r := e.postForm("/oauth/token", codeForm("not-a-real-code"), auth); r.Code != http.StatusBadRequest {
		t.Fatalf("fabricated code = %d", r.Code)
	}
	if !e.introspectActive(t, at) {
		t.Fatal("unrelated invalid code revoked a live access token")
	}
	if r := e.postForm("/oauth/token", "grant_type=refresh_token&refresh_token="+rt, auth); r.Code != http.StatusOK {
		t.Fatalf("unrelated invalid code revoked a live refresh token: %d", r.Code)
	}
}
