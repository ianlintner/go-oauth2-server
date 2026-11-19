package authcode_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ianlintner/go-oauth2-server/internal/authcode"
	"github.com/ianlintner/go-oauth2-server/internal/jwt"
	"github.com/ianlintner/go-oauth2-server/internal/oauth"
	"github.com/ianlintner/go-oauth2-server/internal/token"
)

// newTokenEnv is newEnv with a token service wired in, so issued access tokens
// are signed JWTs with persisted records.
func newTokenEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := jwt.NewKeySet(key)
	if err != nil {
		t.Fatal(err)
	}
	const issuer = "https://issuer.example"
	tokens, err := token.New(token.Config{
		Issuer:   issuer,
		Signer:   jwt.NewSigner(ks, jwt.WithType(token.AccessTokenType)),
		Verifier: jwt.NewVerifier(ks, jwt.WithRequiredType(token.AccessTokenType)),
		Keys:     ks,
		Store:    e.store,
		Clock:    e.clock,
		Random:   oauth.CryptoRandom{},
	})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := authcode.New(authcode.Config{Store: e.store, Clock: e.clock, Random: oauth.CryptoRandom{}, Tokens: tokens})
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	return e
}

func jtiOf(t *testing.T, accessToken string) string {
	t.Helper()
	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %q", accessToken)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	jti, _ := m["jti"].(string)
	if jti == "" {
		t.Fatal("access token has no jti")
	}
	return jti
}

func revokedAt(t *testing.T, e *env, jti string) bool {
	t.Helper()
	rec, err := e.store.AccessTokens().GetByJTI(context.Background(), jti)
	if err != nil {
		t.Fatalf("get access token: %v", err)
	}
	return !rec.RevokedAt.IsZero()
}

func TestReplayedCodeRevokesIssuedAccessTokens(t *testing.T) {
	e := newTokenEnv(t)
	auth := basic("client-a", "test-only-secret")

	c := e.issue(t, "client-a", callback)
	first, err := e.token(auth, codeParams(t, c))
	if err != nil {
		t.Fatalf("first redemption: %v", err)
	}
	jti := jtiOf(t, first.AccessToken)

	// An unrelated grant of the same client and user must be unaffected.
	c2 := e.issue(t, "client-a", callback)
	second, err := e.token(auth, codeParams(t, c2))
	if err != nil {
		t.Fatalf("second grant redemption: %v", err)
	}
	otherJTI := jtiOf(t, second.AccessToken)

	if revokedAt(t, e, jti) {
		t.Fatal("access token revoked before any replay")
	}
	_, err = e.token(auth, codeParams(t, c))
	if got := code(t, err); got != oauth.CodeInvalidGrant {
		t.Fatalf("replay code = %q, want invalid_grant", got)
	}
	if !revokedAt(t, e, jti) {
		t.Fatal("access token from the replayed code is still active")
	}
	if revokedAt(t, e, otherJTI) {
		t.Fatal("replay revoked a token of an unrelated grant")
	}

	// The refresh token of the grant died with it.
	_, err = e.token(auth, params(t, "grant_type", "refresh_token", "refresh_token", first.RefreshToken))
	if got := code(t, err); got != oauth.CodeInvalidGrant {
		t.Fatalf("refresh after replay = %q, want invalid_grant", got)
	}
	// A second replay is still just invalid_grant.
	_, err = e.token(auth, codeParams(t, c))
	if got := code(t, err); got != oauth.CodeInvalidGrant {
		t.Fatalf("second replay code = %q, want invalid_grant", got)
	}
}

func TestRefreshedTokensStayInTheGrant(t *testing.T) {
	e := newTokenEnv(t)
	auth := basic("client-a", "test-only-secret")

	c := e.issue(t, "client-a", callback)
	first, err := e.token(auth, codeParams(t, c))
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	rotated, err := e.token(auth, params(t, "grant_type", "refresh_token", "refresh_token", first.RefreshToken))
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	refreshedJTI := jtiOf(t, rotated.AccessToken)

	// Replaying the original refresh token ends the whole grant, including the
	// access token minted by the legitimate rotation.
	_, err = e.token(auth, params(t, "grant_type", "refresh_token", "refresh_token", first.RefreshToken))
	if got := code(t, err); got != oauth.CodeInvalidGrant {
		t.Fatalf("refresh replay = %q, want invalid_grant", got)
	}
	if !revokedAt(t, e, jtiOf(t, first.AccessToken)) || !revokedAt(t, e, refreshedJTI) {
		t.Fatal("access tokens of the grant survived a refresh replay")
	}
	_, err = e.token(auth, params(t, "grant_type", "refresh_token", "refresh_token", rotated.RefreshToken))
	if got := code(t, err); got != oauth.CodeInvalidGrant {
		t.Fatalf("rotated refresh token after replay = %q, want invalid_grant", got)
	}
}

// failingGrantStore fails the transaction that revokes a grant.
type failingGrantStore struct{ oauth.Store }

func (failingGrantStore) WithTx(context.Context, func(context.Context, oauth.Repositories) error) error {
	return errors.New("revocation unavailable")
}

func TestReplayedCodeWithFailingRevocationFailsClosed(t *testing.T) {
	e := newTokenEnv(t)
	auth := basic("client-a", "test-only-secret")
	c := e.issue(t, "client-a", callback)
	if _, err := e.token(auth, codeParams(t, c)); err != nil {
		t.Fatalf("redeem: %v", err)
	}

	svc, err := authcode.New(authcode.Config{Store: failingGrantStore{e.store}, Clock: e.clock, Random: oauth.CryptoRandom{}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.Token(context.Background(), auth, codeParams(t, c))
	if got := code(t, err); got != oauth.CodeServerError {
		t.Fatalf("replay with failing revocation = %q, want server_error", got)
	}
}
