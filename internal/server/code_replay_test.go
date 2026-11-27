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
	// Main's consent gate issues a code only for an explicitly approved
	// client; seed an approval so this helper models a consented resource
	// owner and the authorize response carries the code directly.
	approveClient(t, e.store, "user-1", clientID)
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
	if rt2 == "" || rt2 == rt1 {
		t.Fatalf("rotation returned no distinct replacement refresh token: %q", second.Body.String())
	}

	if r := e.postForm("/oauth/token", codeForm(c), auth); r.Code != http.StatusBadRequest || jsonBody(t, r)["error"] != "invalid_grant" {
		t.Fatalf("replay = %d %q, want 400 invalid_grant", r.Code, r.Body.String())
	}
	ref := e.postForm("/oauth/token", "grant_type=refresh_token&refresh_token="+rt2, auth)
	if ref.Code != http.StatusBadRequest || jsonBody(t, ref)["error"] != "invalid_grant" {
		t.Fatalf("rotated descendant after code replay = %d %q, want 400 invalid_grant", ref.Code, ref.Body.String())
	}
}

// hookedStore runs onAccessTokenCreate immediately before the access token row
// is inserted, so a test can interleave a replay at exactly that point.
type hookedStore struct {
	oauth.Store
	onAccessTokenCreate func()
}

func (h *hookedStore) AccessTokens() oauth.AccessTokenRepository {
	return &hookedAccessTokens{AccessTokenRepository: h.Store.AccessTokens(), hook: h.onAccessTokenCreate}
}

type hookedAccessTokens struct {
	oauth.AccessTokenRepository
	hook func()
}

func (h *hookedAccessTokens) Create(ctx context.Context, t oauth.AccessToken) error {
	if h.hook != nil {
		h.hook()
	}
	return h.AccessTokenRepository.Create(ctx, t)
}

// A replay that lands after the code was consumed but before the access token
// row is persisted must still leave no active access token.
func TestCodeReplayDuringIssuanceLeavesNoActiveAccessToken(t *testing.T) {
	var hs *hookedStore
	e := newTokenEnvWrapped(t, func(s oauth.Store) oauth.Store {
		hs = &hookedStore{Store: s}
		return hs
	})
	auth := basic("client-rt", "rt-test-secret")
	c := e.authorizeCode(t, "client-rt")

	replays := 0
	hs.onAccessTokenCreate = func() {
		replays++
		hs.onAccessTokenCreate = nil // only the first (redeeming) issuance is interleaved
		r := e.postForm("/oauth/token", codeForm(c), auth)
		if r.Code != http.StatusBadRequest || jsonBody(t, r)["error"] != "invalid_grant" {
			t.Errorf("interleaved replay = %d %q, want 400 invalid_grant", r.Code, r.Body.String())
		}
	}
	first := e.postForm("/oauth/token", codeForm(c), auth)
	if replays != 1 {
		t.Fatalf("replay hook ran %d times, want 1", replays)
	}
	if first.Code != http.StatusOK {
		t.Fatalf("redemption = %d %q", first.Code, first.Body.String())
	}
	body := jsonBody(t, first)
	at, _ := body["access_token"].(string)
	rt, _ := body["refresh_token"].(string)
	if at == "" || rt == "" {
		t.Fatalf("token body = %v", body)
	}
	if e.introspectActive(t, at) {
		t.Fatal("access token issued concurrently with a code replay is still active")
	}
	if r := e.postForm("/oauth/token", "grant_type=refresh_token&refresh_token="+rt, auth); r.Code != http.StatusBadRequest {
		t.Fatalf("refresh token issued concurrently with a code replay is still live: %d", r.Code)
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
