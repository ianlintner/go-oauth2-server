package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ks := mustKeySet(t, key)
	s := NewSigner(ks, WithType("at+jwt"))
	v := NewVerifier(ks)

	token, err := s.Sign(context.Background(), map[string]any{"iss": "http://a", "exp": 1234})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token, "eyJ") || strings.Count(token, ".") != 2 {
		t.Fatalf("not a compact JWT: %q", token)
	}

	claims, err := v.Verify(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if claims["iss"] != "http://a" {
		t.Fatalf("iss = %v", claims["iss"])
	}
	// exp is decoded as a float64 by encoding/json.
	if claims["exp"] != float64(1234) {
		t.Fatalf("exp = %v (%T)", claims["exp"], claims["exp"])
	}
}

func TestVerifyWrongKeyFails(t *testing.T) {
	keyA, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyB, _ := rsa.GenerateKey(rand.Reader, 2048)
	s := NewSigner(mustKeySet(t, keyA))
	v := NewVerifier(mustKeySet(t, keyB))

	token, err := s.Sign(context.Background(), map[string]any{"iss": "http://a"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), token); err == nil {
		t.Fatal("expected verification to fail against a different key")
	}
}

func TestKeySetJWKS(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	ks := mustKeySet(t, key)
	jwks := ks.JWKS()
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(jwks.Keys))
	}
	if jwks.Keys[0].KeyID != ks.Kid() {
		t.Fatalf("kid mismatch: %q vs %q", jwks.Keys[0].KeyID, ks.Kid())
	}
	b, err := json.Marshal(jwks)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"kty":"RSA"`) {
		t.Fatalf("JWKS missing RSA kty: %s", b)
	}
}

func TestPrepareKeySetPlaceholderGeneratesEphemeral(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signing.key")
	if err := os.WriteFile(path, []byte("placeholder-key-material"), 0o600); err != nil {
		t.Fatal(err)
	}
	ks, err := PrepareKeySet(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if ks.Kid() == "" {
		t.Fatal("empty kid")
	}
	_, err = NewSigner(ks).Sign(context.Background(), map[string]any{"iss": "http://a"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPrepareKeySetProductionRefusesPlaceholder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signing.key")
	if err := os.WriteFile(path, []byte("placeholder-key-material"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareKeySet(path, true); err == nil {
		t.Fatal("expected production to refuse placeholder key material")
	}
}

func TestPrepareKeySetRejectsMangledKeyEvenInNonProduction(t *testing.T) {
	// A file that is neither a parseable RSA key nor the literal placeholder
	// sentinel must fail loudly even in development/test, so a mangled or
	// mistyped real key is never silently swapped for an ephemeral one.
	dir := t.TempDir()
	path := filepath.Join(dir, "signing.key")
	if err := os.WriteFile(path, []byte("truncated real key material"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareKeySet(path, false); err == nil {
		t.Fatal("expected a mangled non-placeholder key to be rejected, not silently regenerated")
	}
}

func mustKeySet(t *testing.T, key *rsa.PrivateKey) *KeySet {
	t.Helper()
	ks, err := NewKeySet(key)
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

func TestPrepareKeySetRejectsWeakRSAKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Skipf("crypto/rsa refuses to generate a 1024-bit key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "signing.key")
	if err := os.WriteFile(path, marshalRSAPrivateKeyPEM(t, key), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, production := range []bool{true, false} {
		_, err = PrepareKeySet(path, production)
		if err == nil || !strings.Contains(err.Error(), "1024 bits") {
			t.Fatalf("PrepareKeySet(production=%v) error = %v, want one naming the 1024-bit modulus", production, err)
		}
	}
}

func TestNewKeySetRejectsWeakKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Skipf("crypto/rsa refuses to generate a 1024-bit key: %v", err)
	}
	if _, err := NewKeySet(key); err == nil || !strings.Contains(err.Error(), "1024 bits") {
		t.Fatalf("NewKeySet error = %v, want one naming the 1024-bit modulus", err)
	}
	if _, err := NewKeySet(nil); err == nil {
		t.Fatal("NewKeySet(nil) succeeded")
	}
}

func TestPrepareKeySetParsesPEM(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pem := marshalRSAPrivateKeyPEM(t, key)
	dir := t.TempDir()
	path := filepath.Join(dir, "signing.key")
	if err := os.WriteFile(path, pem, 0o600); err != nil {
		t.Fatal(err)
	}
	ks, err := PrepareKeySet(path, true)
	if err != nil {
		t.Fatalf("production should accept a real PEM key: %v", err)
	}
	if ks.Kid() != keyID(&key.PublicKey) {
		t.Fatalf("kid mismatch: %q vs %q", ks.Kid(), keyID(&key.PublicKey))
	}
}
