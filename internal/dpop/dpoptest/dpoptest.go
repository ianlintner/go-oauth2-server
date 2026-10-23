// Package dpoptest builds DPoP proofs for tests of code that consumes them.
// It is a test helper: nothing in the server binary imports it.
package dpoptest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Key is a throwaway ES256 proof key.
type Key struct{ priv *ecdsa.PrivateKey }

// NewKey generates a key.
func NewKey(t testing.TB) Key {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return Key{priv: k}
}

// JKT is the RFC 7638 thumbprint of the public key, base64url encoded.
func (k Key) JKT(t testing.TB) string {
	t.Helper()
	tp, err := (&jose.JSONWebKey{Key: &k.priv.PublicKey}).Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(tp)
}

// Spec describes a proof. Zero values produce a valid proof for HTM and HTU,
// issued at Now, with a random jti and the dpop+jwt type.
type Spec struct {
	HTM, HTU    string
	Now         time.Time
	IATOffset   time.Duration
	JTI         string
	Typ         string
	AccessToken string // when set, ath is its base64url SHA-256
	Omit        []string
}

// Proof signs a proof with k.
func (k Key) Proof(t testing.TB, s Spec) string {
	t.Helper()
	typ := s.Typ
	if typ == "" {
		typ = "dpop+jwt"
	}
	jti := s.JTI
	if jti == "" {
		var b [12]byte
		_, _ = rand.Read(b[:])
		jti = base64.RawURLEncoding.EncodeToString(b[:])
	}
	claims := map[string]any{"jti": jti, "htm": s.HTM, "htu": s.HTU, "iat": s.Now.Add(s.IATOffset).Unix()}
	if s.AccessToken != "" {
		sum := sha256.Sum256([]byte(s.AccessToken))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	for _, name := range s.Omit {
		delete(claims, name)
	}
	opts := (&jose.SignerOptions{}).WithType(jose.ContentType(typ)).WithHeader("jwk", jose.JSONWebKey{Key: &k.priv.PublicKey})
	sg, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: k.priv}, opts)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	obj, err := sg.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	out, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}
