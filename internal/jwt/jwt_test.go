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
	ks := NewKeySet(key)
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
	s := NewSigner(NewKeySet(keyA))
	v := NewVerifier(NewKeySet(keyB))

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
	ks := NewKeySet(key)
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
