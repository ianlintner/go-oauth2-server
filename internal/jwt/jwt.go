// Package jwt implements JWT signing, verification and JWKS publication for
// the token-lifecycle stage: an RS256 signer/verifier (oauth.Signer/Verifier)
// backed by go-jose, with persisted keys and a stable key id (kid).
//
// Key provision rule (see docs/architecture-proposal.md): signing keys are
// persisted and rotated deliberately, never regenerated per restart. In
// production the key file must contain a real RSA key. In development/test the
// file may contain placeholder material, in which case an ephemeral RSA key is
// generated for the process lifetime so the contract runner (which writes
// "placeholder-key-material") still gets a working JWKS. Production refuses to
// invent a key.
package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/go-jose/go-jose/v4"
)

const (
	// rsaBits is the RSA modulus size for generated/ephemeral keys.
	rsaBits = 2048
)

// KeySet holds the active RSA signing key and the public keys it publishes.
type KeySet struct {
	key  *rsa.PrivateKey
	kid  string
	jwk  jose.JSONWebKey
	jwks jose.JSONWebKeySet
}

// PrepareKeySet loads a signing key from path, applying the provision rule
// described above. production must be true for the production environment.
func PrepareKeySet(path string, production bool) (*KeySet, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("jwt: read signing key: %w", err)
	}

	if key, loadErr := parseRSAPrivateKey(raw); loadErr == nil {
		return NewKeySet(key), nil
	}

	// Not a parseable RSA key. Only non-production may fall back to an
	// ephemeral generated key; the contract smoke/conformance scripts write
	// literal "placeholder-key-material" here precisely because it is not a
	// key, and the runner still needs a working JWKS.
	if production {
		return nil, errors.New("jwt: signing key file does not contain a valid RSA private key; refusing to generate one in production")
	}
	key, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return nil, fmt.Errorf("jwt: generate ephemeral signing key: %w", err)
	}
	return NewKeySet(key), nil
}

// NewKeySet builds a KeySet from an existing RSA private key.
func NewKeySet(key *rsa.PrivateKey) *KeySet {
	kid := keyID(&key.PublicKey)
	jwk := jose.JSONWebKey{
		Key:       &key.PublicKey,
		KeyID:     kid,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}
	return &KeySet{
		key:  key,
		kid:  kid,
		jwk:  jwk,
		jwks: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}},
	}
}

// parseRSAPrivateKey parses a PEM PKCS#1 or PKCS#8 RSA private key.
func parseRSAPrivateKey(raw []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return parsePKCS1(block.Bytes)
	case "PRIVATE KEY":
		k, err := parsePKCS8(block.Bytes)
		if err != nil {
			return nil, err
		}
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an RSA key")
		}
		return rk, nil
	default:
		return nil, fmt.Errorf("unsupported PEM type %q", block.Type)
	}
}

// keyID is the stable kid: base64(rawurl) of the SHA-256 of the DER public key.
func keyID(pub *rsa.PublicKey) string {
	sum := sha256.Sum256(x509PublicKeyDER(pub))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func x509PublicKeyDER(pub *rsa.PublicKey) []byte {
	// PKCS#1 DER: SEQUENCE { INTEGER n, INTEGER e }. Reconstruct the minimal
	// DER without pulling in the full x509 marshal path (which varies by Go
	// version). RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
	return marshalRSAPublicKeyDER(pub)
}

// Signer signs claim sets into RS256 JWTs with the active key.
type Signer struct {
	ks  *KeySet
	typ string
	iss string
}

// SignerOption customizes a Signer.
type SignerOption func(*Signer)

// WithType sets the JWT typ header (RFC 9068 uses "at+jwt").
func WithType(typ string) SignerOption { return func(s *Signer) { s.typ = typ } }

// NewSigner returns an oauth.Signer for ks.
func NewSigner(ks *KeySet, opts ...SignerOption) *Signer {
	s := &Signer{ks: ks, typ: "JWT"}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Kid returns the active key id of the signer's key set.
func (s *Signer) Kid() string { return s.ks.kid }

// Sign implements oauth.Signer.
func (s *Signer) Sign(_ context.Context, claims map[string]any) (string, error) {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: s.ks.key},
		(&jose.SignerOptions{}).WithType(jose.ContentType(s.typ)).WithHeader("kid", s.ks.kid),
	)
	if err != nil {
		return "", fmt.Errorf("jwt: new signer: %w", err)
	}
	raw, err := signer.Sign([]byte(mustJSON(claims)))
	if err != nil {
		return "", fmt.Errorf("jwt: sign: %w", err)
	}
	return raw.CompactSerialize()
}

// Verifier validates RS256 JWTs against the key set and returns their claims.
type Verifier struct {
	ks  *KeySet
	typ string // required JOSE typ header when non-empty
}

// VerifierOption customizes a Verifier.
type VerifierOption func(*Verifier)

// WithRequiredType requires the JOSE typ header to equal typ (RFC 9068 uses
// "at+jwt"). A token with a different or missing typ fails verification.
func WithRequiredType(typ string) VerifierOption {
	return func(v *Verifier) { v.typ = typ }
}

// NewVerifier returns an oauth.Verifier for ks.
func NewVerifier(ks *KeySet, opts ...VerifierOption) *Verifier {
	v := &Verifier{ks: ks}
	for _, o := range opts {
		o(v)
	}
	return v
}

// Verify implements oauth.Verifier.
func (v *Verifier) Verify(_ context.Context, token string) (map[string]any, error) {
	obj, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, fmt.Errorf("jwt: parse: %w", err)
	}
	// Select the key by kid header when present; otherwise try every key.
	hdr := obj.Signatures[0].Header
	if v.typ != "" {
		var typ string
		switch t := hdr.ExtraHeaders[jose.HeaderType].(type) {
		case jose.ContentType:
			typ = string(t)
		case string:
			typ = t
		}
		if typ != v.typ {
			return nil, fmt.Errorf("jwt: unexpected typ %q, want %q", typ, v.typ)
		}
	}
	var key any
	if hdr.KeyID != "" && hdr.KeyID != v.ks.kid {
		return nil, errors.New("jwt: unknown kid")
	}
	key = &v.ks.key.PublicKey
	payload, err := obj.Verify(key)
	if err != nil {
		return nil, fmt.Errorf("jwt: verify: %w", err)
	}
	claims, err := parseJSON(payload)
	if err != nil {
		return nil, fmt.Errorf("jwt: claims: %w", err)
	}
	return claims, nil
}

// JWKS returns the published JSON Web Key Set (RFC 7517).
func (ks *KeySet) JWKS() jose.JSONWebKeySet { return ks.jwks }

// Kid returns the active key id.
func (ks *KeySet) Kid() string { return ks.kid }

// KeyID returns the active key id. It exists alongside Kid so a KeySet can
// satisfy interfaces that name the accessor KeyID.
func (ks *KeySet) KeyID() string { return ks.kid }

// PublicJWKS returns the published JSON Web Key Set as raw JSON, for the
// discovery endpoint (RFC 8414) via the token-lifecycle service.
func (ks *KeySet) PublicJWKS() (json.RawMessage, error) {
	return json.Marshal(ks.jwks)
}
