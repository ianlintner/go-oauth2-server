package server_test

import (
	"net/http"
	"strings"
	"testing"
)

// The /oauth/userinfo endpoint is the profile's protected resource (RFC 6750).
// These tests pin the exact wire contract asserted by the shared token-lifecycle
// scenarios bearer/{missing-token,invalid-token,header-accepted}.yaml and
// revocation/access-token.yaml at the pinned contract commit.

func bearerAuth(token string) reqOpt {
	return header("Authorization", "Bearer "+token)
}

func TestUserInfoMissingTokenGetsBareBearerChallenge(t *testing.T) {
	e := newTokenEnv(t)
	rec := e.get("/oauth/userinfo")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d %q, want 401", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != "Bearer" {
		t.Fatalf("WWW-Authenticate = %q, want bare %q", got, "Bearer")
	}
}

func TestUserInfoInvalidTokenGetsErrorChallenge(t *testing.T) {
	e := newTokenEnv(t)
	rec := e.get("/oauth/userinfo", bearerAuth("not-a-valid-token"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d %q, want 401", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != `Bearer error="invalid_token"` {
		t.Fatalf("WWW-Authenticate = %q, want %q", got, `Bearer error="invalid_token"`)
	}
	if got := jsonBody(t, rec)["error"]; got != "invalid_token" {
		t.Fatalf("error body = %v, want invalid_token", got)
	}
}

func TestUserInfoAcceptsValidBearerToken(t *testing.T) {
	e := newTokenEnv(t)
	at := e.issueAccessToken(t, "client-a", "user-1")
	rec := e.get("/oauth/userinfo", bearerAuth(at.Value))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d %q, want 200", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type = %q", ct)
	}
	if got := jsonBody(t, rec)["sub"]; got != "user-1" {
		t.Fatalf("sub = %v, want user-1", got)
	}
}

func TestUserInfoRejectsRevokedAccessToken(t *testing.T) {
	e := newTokenEnv(t)
	at := e.issueAccessToken(t, "client-a", "user-1")

	rev := e.postForm("/oauth/revoke", "token="+at.Value, basic("client-a", "test-only-secret"))
	if rev.Code != http.StatusOK {
		t.Fatalf("revoke = %d %q", rev.Code, rev.Body.String())
	}

	rec := e.get("/oauth/userinfo", bearerAuth(at.Value))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d %q, want 401", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != `Bearer error="invalid_token"` {
		t.Fatalf("WWW-Authenticate = %q", got)
	}
}

func TestMetadataAdvertisesUserInfoEndpoint(t *testing.T) {
	e := newTokenEnv(t)
	rec := e.get("/.well-known/oauth-authorization-server")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := jsonBody(t, rec)["userinfo_endpoint"]; got != issuer+"/oauth/userinfo" {
		t.Fatalf("userinfo_endpoint = %v, want %q", got, issuer+"/oauth/userinfo")
	}
}
