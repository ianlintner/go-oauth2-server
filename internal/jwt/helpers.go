package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"math/big"
)

func parsePKCS1(b []byte) (*rsa.PrivateKey, error) {
	return x509.ParsePKCS1PrivateKey(b)
}

func parsePKCS8(b []byte) (any, error) {
	return x509.ParsePKCS8PrivateKey(b)
}

// marshalRSAPublicKeyDER returns the PKCS#1 RSAPublicKey DER encoding.
// RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
func marshalRSAPublicKeyDER(pub *rsa.PublicKey) []byte {
	// Use x509.MarshalPKIXPublicKey then extract? Simpler: build PKCS#1 by
	// hand with asn1.
	der, err := asn1.Marshal(rsaPublicKey{N: pub.N, E: pub.E})
	if err != nil {
		// Unreachable for a well-formed *rsa.PublicKey.
		panic(err)
	}
	return der
}

type rsaPublicKey struct {
	N *big.Int
	E int
}

func mustJSON(v map[string]any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func parseJSON(b []byte) (map[string]any, error) {
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// marshalRSAPrivateKeyPEM returns a PKCS#8 PEM encoding of key, for tests.
func marshalRSAPrivateKeyPEM(t requireTB, key *rsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

type requireTB interface {
	Helper()
	Fatalf(string, ...any)
}
