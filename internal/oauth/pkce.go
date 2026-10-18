package oauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// MethodS256 is the only PKCE code_challenge_method this server accepts. The
// "plain" transformation is deliberately unsupported (RFC 9700 §2.1.1).
const MethodS256 = "S256"

// Length bounds from RFC 7636 §4.1 (verifier) and the fixed size of an
// unpadded base64url SHA-256 digest (challenge, §4.2).
const (
	minVerifierLen = 43
	maxVerifierLen = 128
	challengeLen   = 43
)

// ChallengeS256 returns BASE64URL-ENCODE(SHA256(ASCII(verifier))) without
// padding (RFC 7636 §4.2).
func ChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// VerifyS256 reports whether verifier hashes to challenge, in constant time.
// An empty challenge never verifies.
func VerifyS256(challenge, verifier string) bool {
	if challenge == "" {
		return false
	}
	want := []byte(challenge)
	got := []byte(ChallengeS256(verifier))
	return subtle.ConstantTimeCompare(want, got) == 1
}

// ValidCodeVerifier reports whether s is a syntactically valid code_verifier:
// 43 to 128 characters from the unreserved set [A-Za-z0-9-._~] (RFC 7636 §4.1).
func ValidCodeVerifier(s string) bool {
	if len(s) < minVerifierLen || len(s) > maxVerifierLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '.', c == '_', c == '~':
		default:
			return false
		}
	}
	return true
}

// ValidCodeChallenge reports whether s has the shape of an S256 challenge:
// exactly 43 base64url characters with no padding.
func ValidCodeChallenge(s string) bool {
	if len(s) != challengeLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}
