package server_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ianlintner/go-oauth2-server/internal/authcode"
	"github.com/ianlintner/go-oauth2-server/internal/jwt"
	"github.com/ianlintner/go-oauth2-server/internal/oauth"
	"github.com/ianlintner/go-oauth2-server/internal/secret"
	"github.com/ianlintner/go-oauth2-server/internal/server"
	"github.com/ianlintner/go-oauth2-server/internal/session"
	"github.com/ianlintner/go-oauth2-server/internal/storage/sqlite"
	"github.com/ianlintner/go-oauth2-server/internal/token"
)

// tokenEnv is a handlerEnv with the token-lifecycle service wired, so the
// introspection, revocation and JWKS endpoints actually serve.
type tokenEnv struct {
	*handlerEnv
	tokens *token.Service
}

func newTokenEnv(t *testing.T) *tokenEnv {
	t.Helper()
	st, err := sqlite.Open(sqlite.MemoryDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	rnd := oauth.CryptoRandom{}
	ctx := context.Background()
	hash := func(s string) string {
		h, e := secret.Hash(rnd, s)
		if e != nil {
			t.Fatal(e)
		}
		return h
	}
	clients := []oauth.Client{
		{ID: "client-a", SecretHash: hash("test-only-secret"), AuthMethod: "client_secret_basic", RedirectURIs: []string{callback}, GrantTypes: []string{"authorization_code"}},
		{ID: "client-b", SecretHash: hash("other-test-secret"), AuthMethod: "client_secret_basic", RedirectURIs: []string{callback}, GrantTypes: []string{"authorization_code"}},
		{ID: "client-public", Public: true, AuthMethod: "none", RedirectURIs: []string{callback}, GrantTypes: []string{"authorization_code"}},
	}
	for _, c := range clients {
		if err := st.Clients().Create(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	clk := &hClock{t: time.Unix(1_700_000_000, 0).UTC()}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ks := jwt.NewKeySet(key)
	signer := jwt.NewSigner(ks, jwt.WithType(token.AccessTokenType))
	verifier := jwt.NewVerifier(ks, jwt.WithRequiredType(token.AccessTokenType))
	tokens, err := token.New(token.Config{
		Issuer:   issuer,
		Signer:   signer,
		Verifier: verifier,
		Keys:     ks,
		Store:    st,
		Clock:    clk,
		Random:   rnd,
	})
	if err != nil {
		t.Fatal(err)
	}

	svc, err := authcode.New(authcode.Config{Store: st, Clock: clk, Random: rnd, Tokens: tokens})
	if err != nil {
		t.Fatal(err)
	}
	sess, err := session.New([]byte("0123456789abcdef0123456789abcdef"), clk, true)
	if err != nil {
		t.Fatal(err)
	}
	h := server.New(server.Deps{Service: svc, Sessions: sess, Issuer: issuer, Conformance: true, Tokens: tokens})
	env := &handlerEnv{h: h, store: st, clock: clk}
	return &tokenEnv{handlerEnv: env, tokens: tokens}
}

// issueAccessToken mints a real access token for the given client, so tests
// can exercise introspection and revocation against a persisted JWT.
func (e *tokenEnv) issueAccessToken(t *testing.T, clientID, subject string) token.AccessToken {
	t.Helper()
	at, err := e.tokens.Issue(context.Background(), token.IssueParams{ClientID: clientID, Subject: subject, Scope: "read write"})
	if err != nil {
		t.Fatal(err)
	}
	return at
}

func introspectBodyVal(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	return jsonBody(t, rec)
}

// ---- GET /.well-known/jwks.json ----

func TestJWKSPublishesTheSigningKey(t *testing.T) {
	e := newTokenEnv(t)
	rec := e.get("/.well-known/jwks.json")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d %q", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type = %q", ct)
	}
	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Alg string `json:"alg"`
			Use string `json:"use"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("JWKS is not valid JSON: %v", err)
	}
	if len(doc.Keys) != 1 {
		t.Fatalf("keys = %d, want 1", len(doc.Keys))
	}
	k := doc.Keys[0]
	if k.Kty != "RSA" || k.Kid == "" || k.Alg != "RS256" || k.Use != "sig" {
		t.Fatalf("key = %+v", k)
	}
}

// ---- POST /oauth/introspect ----

func TestIntrospectReportsAnActiveTokenForItsOwner(t *testing.T) {
	e := newTokenEnv(t)
	at := e.issueAccessToken(t, "client-a", "user-1")

	rec := e.postForm("/oauth/introspect", "token="+at.Value, basic("client-a", "test-only-secret"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d %q", rec.Code, rec.Body.String())
	}
	body := introspectBodyVal(t, rec)
	if body["active"] != true {
		t.Fatalf("active = %v, want true (%v)", body["active"], body)
	}
	if body["client_id"] != "client-a" || body["sub"] != "user-1" || body["token_type"] != "Bearer" {
		t.Fatalf("body = %v", body)
	}
	if body["scope"] != "read write" || body["exp"] == nil || body["iat"] == nil || body["jti"] == "" {
		t.Fatalf("body is missing fields: %v", body)
	}
}

func TestIntrospectHidesAnotherClientsToken(t *testing.T) {
	e := newTokenEnv(t)
	at := e.issueAccessToken(t, "client-a", "user-1")

	// client-b authenticates and introspects client-a's token: the server must
	// not reveal anything, even though the token is active.
	rec := e.postForm("/oauth/introspect", "token="+at.Value, basic("client-b", "other-test-secret"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d %q", rec.Code, rec.Body.String())
	}
	body := introspectBodyVal(t, rec)
	if body["active"] != false {
		t.Fatalf("active = %v, want false (client binding leak)", body["active"])
	}
	// A bound response leaks nothing beyond active:false.
	if len(body) != 1 {
		t.Fatalf("cross-client introspection leaked fields: %v", body)
	}
}

func TestIntrospectReportsInactiveForUnknownToken(t *testing.T) {
	e := newTokenEnv(t)
	rec := e.postForm("/oauth/introspect", "token=not-a-real-token", basic("client-a", "test-only-secret"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d %q", rec.Code, rec.Body.String())
	}
	if body := introspectBodyVal(t, rec); body["active"] != false {
		t.Fatalf("active = %v, want false", body["active"])
	}
}

func TestIntrospectRejectsMissingToken(t *testing.T) {
	e := newTokenEnv(t)
	rec := e.postForm("/oauth/introspect", "", basic("client-a", "test-only-secret"))
	if rec.Code != http.StatusBadRequest || jsonBody(t, rec)["error"] != "invalid_request" {
		t.Fatalf("%d %q", rec.Code, rec.Body.String())
	}
}

func TestIntrospectRequiresClientAuthentication(t *testing.T) {
	e := newTokenEnv(t)
	at := e.issueAccessToken(t, "client-a", "user-1")

	// Bad secret must answer 401 invalid_client with a challenge.
	rec := e.postForm("/oauth/introspect", "token="+at.Value, basic("client-a", "wrong"))
	if rec.Code != http.StatusUnauthorized || jsonBody(t, rec)["error"] != "invalid_client" {
		t.Fatalf("%d %q", rec.Code, rec.Body.String())
	}
	// Missing credentials altogether: a public client still needs client_id.
	rec = e.postForm("/oauth/introspect", "token="+at.Value)
	if rec.Code != http.StatusBadRequest && rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d %q", rec.Code, rec.Body.String())
	}
}

func TestIntrospectRejectsNonPOST(t *testing.T) {
	e := newTokenEnv(t)
	rec := e.get("/oauth/introspect")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

// ---- POST /oauth/revoke ----

func TestRevokeReleasesTheTokenThenItIsInactive(t *testing.T) {
	e := newTokenEnv(t)
	at := e.issueAccessToken(t, "client-a", "user-1")

	rev := e.postForm("/oauth/revoke", "token="+at.Value, basic("client-a", "test-only-secret"))
	if rev.Code != http.StatusOK {
		t.Fatalf("revoke = %d %q", rev.Code, rev.Body.String())
	}

	rec := e.postForm("/oauth/introspect", "token="+at.Value, basic("client-a", "test-only-secret"))
	if body := introspectBodyVal(t, rec); body["active"] != false {
		t.Fatalf("revoked token still active: %v", body)
	}
}

func TestRevokeAnswers200ForAnotherClientsToken(t *testing.T) {
	e := newTokenEnv(t)
	at := e.issueAccessToken(t, "client-a", "user-1")

	// client-b tries to revoke client-a's token: 200, and the token is NOT
	// revoked (owner binding), so client-a still sees it active.
	rev := e.postForm("/oauth/revoke", "token="+at.Value, basic("client-b", "other-test-secret"))
	if rev.Code != http.StatusOK {
		t.Fatalf("revoke = %d %q", rev.Code, rev.Body.String())
	}
	rec := e.postForm("/oauth/introspect", "token="+at.Value, basic("client-a", "test-only-secret"))
	if body := introspectBodyVal(t, rec); body["active"] != true {
		t.Fatalf("token incorrectly revoked by another client: %v", body)
	}
}

func TestRevokeAnswers200ForUnknownToken(t *testing.T) {
	e := newTokenEnv(t)
	rev := e.postForm("/oauth/revoke", "token=not-a-real-token", basic("client-a", "test-only-secret"))
	if rev.Code != http.StatusOK {
		t.Fatalf("revoke = %d %q", rev.Code, rev.Body.String())
	}
}

func TestRevokeRejectsMissingToken(t *testing.T) {
	e := newTokenEnv(t)
	rec := e.postForm("/oauth/revoke", "", basic("client-a", "test-only-secret"))
	if rec.Code != http.StatusBadRequest || jsonBody(t, rec)["error"] != "invalid_request" {
		t.Fatalf("%d %q", rec.Code, rec.Body.String())
	}
}

func TestRevokeRejectsNonPOST(t *testing.T) {
	e := newTokenEnv(t)
	rec := e.get("/oauth/revoke")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

// ---- discovery metadata ---- //

func TestMetadataAdvertisesTokenLifecycleEndpoints(t *testing.T) {
	e := newTokenEnv(t)
	rec := e.get("/.well-known/oauth-authorization-server")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	m := jsonBody(t, rec)
	want := map[string]string{
		"introspection_endpoint": issuer + "/oauth/introspect",
		"revocation_endpoint":    issuer + "/oauth/revoke",
		"jwks_uri":               issuer + "/.well-known/jwks.json",
	}
	for k, v := range want {
		if m[k] != v {
			t.Fatalf("%s = %v, want %v", k, m[k], v)
		}
	}
}

// ---- end to end: token endpoint now issues a signed JWT ---- //

func TestTokenEndpointIssuesSignedAccessToken(t *testing.T) {
	e := newTokenEnv(t)
	// Wire a login-capable user so the authorization-code flow can complete.
	if err := e.store.Users().Create(context.Background(), oauth.User{ID: "user-1", Username: "alice", PasswordHash: func() string {
		h, err := secret.Hash(oauth.CryptoRandom{}, "test-only-password")
		if err != nil {
			t.Fatal(err)
		}
		return h
	}()}); err != nil {
		t.Fatal(err)
	}
	c := e.login(t)
	rec := e.get("/oauth/authorize?"+authQuery("client-a", callback, nil), cookie(c))
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize = %d %q", rec.Code, rec.Body.String())
	}
	code := location(t, rec).Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %q", rec.Header().Get("Location"))
	}

	tok := e.postForm("/oauth/token", codeForm(code), basic("client-a", "test-only-secret"))
	if tok.Code != http.StatusOK {
		t.Fatalf("token = %d %q", tok.Code, tok.Body.String())
	}
	body := jsonBody(t, tok)
	at, _ := body["access_token"].(string)
	if at == "" || body["token_type"] != "Bearer" {
		t.Fatalf("token body = %v", body)
	}
	// The access token is a three-part JWT with the RFC 9068 at+jwt typ.
	parts := strings.Split(at, ".")
	if len(parts) != 3 {
		t.Fatalf("access token is not a JWS: %q", at)
	}
}
