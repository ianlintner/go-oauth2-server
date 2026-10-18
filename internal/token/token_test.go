package token_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ianlintner/go-oauth2-server/internal/jwt"
	"github.com/ianlintner/go-oauth2-server/internal/oauth"
	"github.com/ianlintner/go-oauth2-server/internal/storage/sqlite"
	"github.com/ianlintner/go-oauth2-server/internal/token"
)

// fixedClock lets each test move time explicitly.
type fixedClock struct{ t time.Time }

func (c *fixedClock) Now() time.Time { return c.t }

// seqRandom returns deterministic bytes so jti values are predictable-but-unique.
type seqRandom struct{ n byte }

func (r *seqRandom) Bytes(n int) ([]byte, error) {
	b := make([]byte, n)
	for i := range b {
		b[i] = r.n + byte(i)
	}
	r.n++
	return b, nil
}

const testIssuer = "https://issuer.example"

func newKeySet(t *testing.T) *jwt.KeySet {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return jwt.NewKeySet(key)
}

func newStore(t *testing.T) oauth.Store {
	t.Helper()
	st, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func newService(t *testing.T, ks *jwt.KeySet, st oauth.Store) (*token.Service, *fixedClock) {
	t.Helper()
	clk := &fixedClock{t: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}
	svc, err := token.New(token.Config{
		Issuer:   testIssuer,
		Signer:   jwt.NewSigner(ks, jwt.WithType("at+jwt")),
		Verifier: jwt.NewVerifier(ks, jwt.WithRequiredType("at+jwt")),
		Keys:     ks,
		Store:    st,
		Clock:    clk,
		Random:   &seqRandom{},
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return svc, clk
}

func issue(t *testing.T, svc *token.Service, clientID, subject, scope string) token.AccessToken {
	t.Helper()
	res, err := svc.Issue(context.Background(), token.IssueParams{
		ClientID: clientID,
		Subject:  subject,
		Scope:    scope,
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return res
}

// rawClaims decodes the JWT payload without verifying, for claim-shape checks.
func rawClaims(t *testing.T, value string) map[string]any {
	t.Helper()
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %q", value)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	return m
}

func TestIssueSignsAtJWTAndPersists(t *testing.T) {
	ks := newKeySet(t)
	st := newStore(t)
	svc, _ := newService(t, ks, st)

	res := issue(t, svc, "client-1", "user-1", "read write")

	if parts := strings.Split(res.Value, "."); len(parts) != 3 {
		t.Fatalf("token is not a compact JWS: %q", res.Value)
	}

	// The persisted record is reachable and matches the issue parameters.
	info, err := svc.Introspect(context.Background(), res.Value)
	if err != nil {
		t.Fatalf("introspect issued token: %v", err)
	}
	if !info.Active {
		t.Fatalf("freshly issued token should be active: %+v", info)
	}
	if info.ClientID != "client-1" || info.Sub != "user-1" || info.Scope != "read write" {
		t.Fatalf("unexpected introspection identity: %+v", info)
	}
	if info.Issuer != testIssuer {
		t.Fatalf("unexpected issuer: %q", info.Issuer)
	}

	claims := rawClaims(t, res.Value)
	for k, want := range map[string]any{
		"iss":       testIssuer,
		"sub":       "user-1",
		"client_id": "client-1",
		"scope":     "read write",
		"kid":       ks.KeyID(),
	} {
		if got := claims[k]; got != want {
			t.Fatalf("claim %q = %v, want %v", k, got, want)
		}
	}
	if s, ok := claims["jti"].(string); !ok || s == "" {
		t.Fatalf("jti missing or not a string: %v", claims["jti"])
	}
	if _, ok := claims["iat"].(float64); !ok {
		t.Fatalf("iat missing or not numeric: %v", claims["iat"])
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		t.Fatalf("exp missing or not numeric: %v", claims["exp"])
	}
	if res.ExpiresAt.Unix() != int64(exp) {
		t.Fatalf("exp claim %v != result expires %v", exp, res.ExpiresAt.Unix())
	}
	// The verify path also accepts the token (signature + typ + iss + exp).
	if _, err := svc.VerifyAccessToken(context.Background(), res.Value); err != nil {
		t.Fatalf("verify issued token: %v", err)
	}
}

func TestIssueJTIUnique(t *testing.T) {
	ks := newKeySet(t)
	svc, _ := newService(t, ks, newStore(t))
	a := issue(t, svc, "c", "u", "read")
	b := issue(t, svc, "c", "u", "read")
	if a.JTI == b.JTI {
		t.Fatalf("two issues produced the same jti %q", a.JTI)
	}
}

func TestVerifyAccessTokenRejectsWrongKey(t *testing.T) {
	ks := newKeySet(t)
	st := newStore(t)
	svc, _ := newService(t, ks, st)
	res := issue(t, svc, "c", "u", "read")

	otherKS := newKeySet(t)
	otherSvc, err := token.New(token.Config{
		Issuer:   testIssuer,
		Signer:   jwt.NewSigner(otherKS, jwt.WithType("at+jwt")),
		Verifier: jwt.NewVerifier(otherKS, jwt.WithRequiredType("at+jwt")),
		Keys:     otherKS,
		Store:    newStore(t),
		Clock:    &fixedClock{t: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)},
		Random:   &seqRandom{n: 100},
	})
	if err != nil {
		t.Fatalf("new other service: %v", err)
	}

	if _, err := otherSvc.VerifyAccessToken(context.Background(), res.Value); err == nil {
		t.Fatalf("token signed by a different key verified")
	}
}

func TestVerifyAccessTokenRejectsExpired(t *testing.T) {
	ks := newKeySet(t)
	svc, clk := newService(t, ks, newStore(t))
	res := issue(t, svc, "c", "u", "read")

	clk.t = clk.t.Add(2 * time.Hour)
	if _, err := svc.VerifyAccessToken(context.Background(), res.Value); err == nil {
		t.Fatalf("expired token verified")
	}
}

func TestVerifyAccessTokenRejectsWrongIssuer(t *testing.T) {
	ks := newKeySet(t)
	st := newStore(t)
	svc, clk := newService(t, ks, st)

	// Issue a token signed with the same key but a different issuer, then ask
	// the real service to verify it: signature and typ pass, iss must not.
	forger, err := token.New(token.Config{
		Issuer:   "https://evil.example",
		Signer:   jwt.NewSigner(ks, jwt.WithType("at+jwt")),
		Verifier: jwt.NewVerifier(ks, jwt.WithRequiredType("at+jwt")),
		Keys:     ks,
		Store:    st,
		Clock:    clk,
		Random:   &seqRandom{n: 50},
	})
	if err != nil {
		t.Fatalf("new forger: %v", err)
	}
	forged := issue(t, forger, "c", "u", "read")

	if _, err := svc.VerifyAccessToken(context.Background(), forged.Value); err == nil {
		t.Fatalf("token with wrong iss verified")
	}
}

func TestVerifyAccessTokenRejectsRevoked(t *testing.T) {
	ks := newKeySet(t)
	svc, _ := newService(t, ks, newStore(t))
	res := issue(t, svc, "c", "u", "read")

	if err := svc.Revoke(context.Background(), res.Value, "c"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := svc.VerifyAccessToken(context.Background(), res.Value); err == nil {
		t.Fatalf("revoked token verified")
	}
}

func TestVerifyAccessTokenRejectsGarbage(t *testing.T) {
	ks := newKeySet(t)
	svc, _ := newService(t, ks, newStore(t))
	if _, err := svc.VerifyAccessToken(context.Background(), "not-a-jwt"); err == nil {
		t.Fatalf("garbage token verified")
	}
}

func TestIntrospectReturnsInactiveExpired(t *testing.T) {
	ks := newKeySet(t)
	svc, clk := newService(t, ks, newStore(t))
	res := issue(t, svc, "c", "u", "read")
	clk.t = clk.t.Add(2 * time.Hour)

	info, err := svc.Introspect(context.Background(), res.Value)
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	if info.Active {
		t.Fatalf("expired token reported active")
	}
}

func TestIntrospectReturnsInactiveRevoked(t *testing.T) {
	ks := newKeySet(t)
	svc, _ := newService(t, ks, newStore(t))
	res := issue(t, svc, "c", "u", "read")
	if err := svc.Revoke(context.Background(), res.Value, "c"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	info, err := svc.Introspect(context.Background(), res.Value)
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	if info.Active {
		t.Fatalf("revoked token reported active")
	}
}

func TestIntrospectReturnsInactiveUnknown(t *testing.T) {
	ks := newKeySet(t)
	svc, _ := newService(t, ks, newStore(t))
	info, err := svc.Introspect(context.Background(), "garbage")
	if err != nil {
		t.Fatalf("introspect unknown: %v", err)
	}
	if info.Active {
		t.Fatalf("unknown token reported active")
	}
}

func TestRevokeOwnerBinding(t *testing.T) {
	ks := newKeySet(t)
	svc, _ := newService(t, ks, newStore(t))
	res := issue(t, svc, "client-a", "u", "read")

	// A different client must not revoke it.
	if err := svc.Revoke(context.Background(), res.Value, "client-b"); err != nil {
		t.Fatalf("revoke by wrong client errored: %v", err)
	}
	if info, _ := svc.Introspect(context.Background(), res.Value); !info.Active {
		t.Fatalf("token was revoked by a client that does not own it")
	}

	// The owning client revokes it.
	if err := svc.Revoke(context.Background(), res.Value, "client-a"); err != nil {
		t.Fatalf("revoke by owner errored: %v", err)
	}
	if info, _ := svc.Introspect(context.Background(), res.Value); info.Active {
		t.Fatalf("token still active after owner revoke")
	}
}

func TestRevokeUnknownTokenIsNotAnError(t *testing.T) {
	ks := newKeySet(t)
	svc, _ := newService(t, ks, newStore(t))
	if err := svc.Revoke(context.Background(), "garbage", "c"); err != nil {
		t.Fatalf("revoking an unknown token errored: %v", err)
	}
}

func TestRotateRefreshReplayRevokesFamily(t *testing.T) {
	ks := newKeySet(t)
	st := newStore(t)
	svc, clk := newService(t, ks, st)

	family := "family-1"
	ref1 := oauth.RefreshToken{
		TokenHash: "h1",
		FamilyID:  family,
		ClientID:  "c",
		UserID:    "u",
		Scope:     "read",
		ExpiresAt: clk.t.Add(time.Hour),
	}
	if err := st.RefreshTokens().Create(context.Background(), ref1); err != nil {
		t.Fatalf("create refresh token: %v", err)
	}

	if _, err := svc.RotateRefresh(context.Background(), "h1", family); err != nil {
		t.Fatalf("first rotate: %v", err)
	}

	// Replay triggers family revocation and returns ErrAlreadyConsumed.
	_, err := svc.RotateRefresh(context.Background(), "h1", family)
	if !errors.Is(err, oauth.ErrAlreadyConsumed) {
		t.Fatalf("replay rotate error = %v, want ErrAlreadyConsumed", err)
	}

	// The family is revoked: rotating a *different* token in the family fails.
	ref2 := oauth.RefreshToken{
		TokenHash: "h2",
		FamilyID:  family,
		ClientID:  "c",
		UserID:    "u",
		Scope:     "read",
		ExpiresAt: clk.t.Add(time.Hour),
	}
	if err := st.RefreshTokens().Create(context.Background(), ref2); err != nil {
		t.Fatalf("create sibling refresh token: %v", err)
	}
	if _, err := svc.RotateRefresh(context.Background(), "h2", family); !errors.Is(err, oauth.ErrAlreadyConsumed) {
		t.Fatalf("sibling rotate error = %v, want ErrAlreadyConsumed (family revoked)", err)
	}
}

func TestJWKSExposesPublicKeys(t *testing.T) {
	ks := newKeySet(t)
	svc, _ := newService(t, ks, newStore(t))
	raw, err := svc.JWKS()
	if err != nil {
		t.Fatalf("jwks: %v", err)
	}
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Use string `json:"use"`
			Alg string `json:"alg"`
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatalf("unmarshal jwks: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("jwks has %d keys, want 1", len(set.Keys))
	}
	if set.Keys[0].Use != "sig" || set.Keys[0].Alg != "RS256" || set.Keys[0].Kty != "RSA" {
		t.Fatalf("unexpected jwk: %+v", set.Keys[0])
	}
}
