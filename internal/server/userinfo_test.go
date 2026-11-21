package server_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/ianlintner/go-oauth2-server/internal/token"
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
	at := e.issueAccessTokenScope(t, "client-a", "user-1", "openid")
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
	at := e.issueAccessTokenScope(t, "client-a", "user-1", "openid")

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

func TestUserInfoRefusesClientCredentialsSubject(t *testing.T) {
	e := newTokenEnv(t)
	rec := e.postForm("/oauth/token", "grant_type=client_credentials", basic("client-cc", "test-only-secret"))
	if rec.Code != http.StatusOK {
		t.Fatalf("token status = %d %q", rec.Code, rec.Body.String())
	}
	at := jsonBody(t, rec)["access_token"].(string)
	rec = e.get("/oauth/userinfo", bearerAuth(at))
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Header().Get("WWW-Authenticate"), `error="insufficient_scope"`) {
		t.Fatalf("status = %d %q %q, want 403 insufficient_scope", rec.Code, rec.Header().Get("WWW-Authenticate"), rec.Body.String())
	}
}

// A machine token that already carries openid (issued before the grant refused
// it) must still not yield a client id as the subject.
func TestUserInfoRefusesMachineTokenCarryingOpenid(t *testing.T) {
	e := newTokenEnv(t)
	at := e.issueAccessTokenScope(t, "client-cc", "client-cc", "openid")
	rec := e.get("/oauth/userinfo", bearerAuth(at.Value))
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Header().Get("WWW-Authenticate"), `error="insufficient_scope"`) {
		t.Fatalf("status = %d %q %q, want 403 insufficient_scope", rec.Code, rec.Header().Get("WWW-Authenticate"), rec.Body.String())
	}
}

func TestUserInfoRequiresOpenidScope(t *testing.T) {
	e := newTokenEnv(t)
	at := e.issueAccessToken(t, "client-a", "user-1")
	rec := e.get("/oauth/userinfo", bearerAuth(at.Value))
	if rec.Code != http.StatusForbidden || rec.Header().Get("WWW-Authenticate") != `Bearer error="insufficient_scope", scope="openid"` {
		t.Fatalf("status = %d %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
	ok := e.issueAccessTokenScope(t, "client-a", "user-1", "openid")
	rec = e.get("/oauth/userinfo", bearerAuth(ok.Value))
	if rec.Code != http.StatusOK || jsonBody(t, rec)["sub"] != "user-1" {
		t.Fatalf("status = %d %q", rec.Code, rec.Body.String())
	}
}

// A token issued for a user whose id equals the client id is still a user
// token when issuance recorded the delegation.
func TestUserInfoAcceptsDelegatedTokenWithMatchingIDs(t *testing.T) {
	e := newTokenEnv(t)
	at, err := e.tokens.Issue(context.Background(), token.IssueParams{ClientID: "client-a", Subject: "client-a", Scope: "openid", Audience: []string{issuer}, UserDelegated: true})
	if err != nil {
		t.Fatal(err)
	}
	rec := e.get("/oauth/userinfo", bearerAuth(at.Value))
	if rec.Code != http.StatusOK || jsonBody(t, rec)["sub"] != "client-a" {
		t.Fatalf("status = %d %q, want 200 sub=client-a", rec.Code, rec.Body.String())
	}
	// The same shape without the delegation record stays refused.
	legacy := e.issueAccessTokenScope(t, "client-a", "client-a", "openid")
	rec = e.get("/oauth/userinfo", bearerAuth(legacy.Value))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("legacy status = %d, want 403", rec.Code)
	}
}
