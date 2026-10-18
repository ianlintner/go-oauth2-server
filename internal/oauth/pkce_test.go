package oauth_test

import (
	"strings"
	"testing"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
)

// RFC 7636 Appendix B.
const (
	rfcVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	rfcChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

func TestChallengeS256MatchesRFC7636AppendixB(t *testing.T) {
	if got := oauth.ChallengeS256(rfcVerifier); got != rfcChallenge {
		t.Fatalf("ChallengeS256 = %q, want %q", got, rfcChallenge)
	}
}

func TestVerifyS256(t *testing.T) {
	if !oauth.VerifyS256(rfcChallenge, rfcVerifier) {
		t.Fatal("matching verifier must verify")
	}
	// The challenge string itself is not a valid verifier (comparison is
	// against S256(verifier)).
	if oauth.VerifyS256(rfcChallenge, rfcChallenge) {
		t.Fatal("challenge presented as verifier must not verify")
	}
	wrong := rfcVerifier[:len(rfcVerifier)-1] + "A"
	if oauth.VerifyS256(rfcChallenge, wrong) {
		t.Fatal("verifier differing in one character must not verify")
	}
	if oauth.VerifyS256("", "") {
		t.Fatal("empty challenge must never verify")
	}
}

func TestValidCodeVerifier(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"rfc example", rfcVerifier, true},
		{"minimum length 43", strings.Repeat("a", 43), true},
		{"maximum length 128", strings.Repeat("a", 128), true},
		{"42 is too short", strings.Repeat("a", 42), false},
		{"129 is too long", strings.Repeat("a", 129), false},
		{"empty", "", false},
		{"unreserved punctuation", strings.Repeat("a", 40) + "-._~", true},
		{"space rejected", strings.Repeat("a", 42) + " ", false},
		{"plus rejected", strings.Repeat("a", 42) + "+", false},
		{"slash rejected", strings.Repeat("a", 42) + "/", false},
		{"non-ascii rejected", strings.Repeat("a", 42) + "é", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := oauth.ValidCodeVerifier(tc.in); got != tc.want {
				t.Fatalf("ValidCodeVerifier(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestValidCodeChallenge(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"rfc example", rfcChallenge, true},
		{"42 chars", strings.Repeat("a", 42), false},
		{"44 chars", strings.Repeat("a", 44), false},
		{"padding rejected", strings.Repeat("a", 42) + "=", false},
		{"standard base64 plus rejected", strings.Repeat("a", 42) + "+", false},
		{"empty", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := oauth.ValidCodeChallenge(tc.in); got != tc.want {
				t.Fatalf("ValidCodeChallenge(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
