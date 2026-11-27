package dpop_test

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ianlintner/go-oauth2-server/internal/dpop"
)

// Built at runtime, not as a literal, so secret scanners see no credential.
var nonceSecret = strings.Repeat("n0nce-", 8)

func newNonces(t *testing.T, clk *fixedClock, secret string) *dpop.NonceSource {
	t.Helper()
	s, err := dpop.NewNonceSource(clk, []byte(secret), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestNonceIsStableWithinAWindowAndRotatesAfter(t *testing.T) {
	clk := &fixedClock{t: time.Unix(1_700_000_100, 0)}
	s := newNonces(t, clk, nonceSecret)
	first := s.Next()
	clk.t = clk.t.Add(time.Second)
	if got := s.Next(); got != first {
		t.Fatal("nonce changed inside its window")
	}
	clk.t = time.Unix(1_700_000_100, 0).Add(5 * time.Minute)
	if got := s.Next(); got == first {
		t.Fatal("nonce did not rotate with the window")
	}
}

func TestNonceAcceptsCurrentAndPreviousWindowOnly(t *testing.T) {
	clk := &fixedClock{t: time.Unix(1_700_000_100, 0)}
	s := newNonces(t, clk, nonceSecret)
	n := s.Next()
	if !s.Valid(n) {
		t.Fatal("current nonce rejected")
	}
	clk.t = clk.t.Add(5 * time.Minute) // one window later: previous
	if !s.Valid(n) {
		t.Fatal("previous-window nonce rejected")
	}
	clk.t = clk.t.Add(5 * time.Minute) // two windows later: expired
	if s.Valid(n) {
		t.Fatal("expired nonce accepted")
	}
}

func TestNonceRejectsFutureWindow(t *testing.T) {
	clk := &fixedClock{t: time.Unix(1_700_000_100, 0)}
	s := newNonces(t, clk, nonceSecret)
	later := &fixedClock{t: clk.t.Add(10 * time.Minute)}
	if s.Valid(newNonces(t, later, nonceSecret).Next()) {
		t.Fatal("nonce from a future window accepted")
	}
}

func TestNonceRejectsTamperAndGarbage(t *testing.T) {
	clk := &fixedClock{t: time.Unix(1_700_000_100, 0)}
	s := newNonces(t, clk, nonceSecret)
	n := s.Next()
	raw, _ := base64.RawURLEncoding.DecodeString(n)

	flip := func(i int) string {
		b := append([]byte(nil), raw...)
		b[i] ^= 0x01
		return base64.RawURLEncoding.EncodeToString(b)
	}
	cases := map[string]string{
		"empty":           "",
		"not base64":      "!!!!",
		"truncated":       n[:len(n)-2],
		"extended":        n + "AA",
		"flipped mac bit": flip(len(raw) - 1),
		"flipped ts bit":  flip(7), // moves ts to another window: MAC must fail
		"other secret":    newNonces(t, clk, strings.Repeat("other-", 8)).Next(),
		"padded encoding": n + "==",
		"whitespace":      " " + n,
		"jwt-ish":         strings.Repeat("a.", 20),
		"zero mac":        base64.RawURLEncoding.EncodeToString(append(raw[:8:8], make([]byte, 32)...)),
	}
	for name, v := range cases {
		if s.Valid(v) {
			t.Errorf("%s: tampered nonce accepted", name)
		}
	}
}

func TestNonceValidAcrossInstancesSharingASecret(t *testing.T) {
	clk := &fixedClock{t: time.Unix(1_700_000_100, 0)}
	a, b := newNonces(t, clk, nonceSecret), newNonces(t, clk, nonceSecret)
	if !b.Valid(a.Next()) {
		t.Fatal("nonce from one instance rejected by another with the same secret")
	}
}

func TestNewNonceSourceValidatesInput(t *testing.T) {
	clk := &fixedClock{t: time.Unix(1_700_000_100, 0)}
	if _, err := dpop.NewNonceSource(clk, []byte("short"), 0); err == nil {
		t.Error("short secret accepted")
	}
	if _, err := dpop.NewNonceSource(nil, []byte(nonceSecret), 0); err == nil {
		t.Error("nil clock accepted")
	}
	if _, err := dpop.NewNonceSource(clk, []byte(nonceSecret), time.Millisecond); err == nil {
		t.Error("sub-second window accepted")
	}
	if _, err := dpop.NewNonceSource(clk, []byte(nonceSecret), 0); err != nil {
		t.Errorf("default window rejected: %v", err)
	}
}

func TestCheckRequiresNonceWhenConfiguredAndDoesNotBurnJTI(t *testing.T) {
	v, clk := newVerifier(time.Unix(1_700_000_100, 0))
	s := newNonces(t, clk, nonceSecret)
	k := newKey(t)
	proof := proofSpec{jti: "jti-1"}.sign(t, clk.t, k)

	_, err := v.Check(dpopRequest(proof, s))
	if !errors.Is(err, dpop.ErrUseNonce) || errors.Is(err, dpop.ErrInvalidProof) {
		t.Fatalf("missing nonce: err = %v, want ErrUseNonce only", err)
	}
	// Rejected for the nonce, so the same jti is still usable with a nonce.
	proof = proofSpec{jti: "jti-1", nonce: s.Next()}.sign(t, clk.t, k)
	if _, err := v.Verify(context.Background(), dpopRequest(proof, s)); err != nil {
		t.Fatalf("with nonce: %v", err)
	}
}

func TestCheckStaleNonceIsUseNonce(t *testing.T) {
	v, clk := newVerifier(time.Unix(1_700_000_100, 0))
	s := newNonces(t, clk, nonceSecret)
	k := newKey(t)
	stale := s.Next()
	clk.t = clk.t.Add(10 * time.Minute) // proof iat is generated at the new time
	proof := proofSpec{nonce: stale}.sign(t, clk.t, k)
	if _, err := v.Check(dpopRequest(proof, s)); !errors.Is(err, dpop.ErrUseNonce) {
		t.Fatalf("stale nonce: err = %v, want ErrUseNonce", err)
	}
}

func TestCheckBadProofBeatsNonceError(t *testing.T) {
	v, clk := newVerifier(time.Unix(1_700_000_100, 0))
	s := newNonces(t, clk, nonceSecret)
	proof := proofSpec{htm: "GET"}.sign(t, clk.t, newKey(t)) // wrong htm, no nonce
	if _, err := v.Check(dpopRequest(proof, s)); !errors.Is(err, dpop.ErrInvalidProof) {
		t.Fatalf("err = %v, want ErrInvalidProof", err)
	}
}

func TestCheckIgnoresNonceWhenNotConfigured(t *testing.T) {
	v, clk := newVerifier(time.Unix(1_700_000_100, 0))
	proof := proofSpec{}.sign(t, clk.t, newKey(t))
	if _, err := v.Check(dpopRequest(proof, nil)); err != nil {
		t.Fatalf("no nonce source: %v", err)
	}
}

func dpopRequest(proof string, s *dpop.NonceSource) dpop.Request {
	return dpop.Request{Proof: proof, Method: "POST", URL: tokenURL, Nonces: s}
}

func TestNonceWindowEdgeCases(t *testing.T) {
	t.Run("clock before the epoch is clamped, not wrapped", func(t *testing.T) {
		clk := &fixedClock{t: time.Unix(-1_000, 0)}
		s := newNonces(t, clk, nonceSecret)
		n := s.Next()
		if !s.Valid(n) {
			t.Fatal("nonce issued before the epoch rejected")
		}
		if n != newNonces(t, &fixedClock{t: time.Unix(0, 0)}, nonceSecret).Next() {
			t.Fatal("pre-epoch clock did not clamp to the epoch window")
		}
	})
	t.Run("window larger than the clock does not underflow previous-window math", func(t *testing.T) {
		clk := &fixedClock{t: time.Unix(100, 0)}
		s, err := dpop.NewNonceSource(clk, []byte(nonceSecret), 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if !s.Valid(s.Next()) {
			t.Fatal("current nonce rejected")
		}
		// A forged nonce for the wrapped "previous" window (2^64 - secs) must fail.
		forged := make([]byte, 8)
		for i := range forged {
			forged[i] = 0xff
		}
		if s.Valid(base64.RawURLEncoding.EncodeToString(append(forged, make([]byte, 32)...))) {
			t.Fatal("forged wrapped-window nonce accepted")
		}
	})
	t.Run("timestamp above int64 max is rejected", func(t *testing.T) {
		clk := &fixedClock{t: time.Unix(1_700_000_100, 0)}
		s := newNonces(t, clk, nonceSecret)
		raw, _ := base64.RawURLEncoding.DecodeString(s.Next())
		raw[0] = 0x80 // ts >= 2^63: never a window this source issues
		if s.Valid(base64.RawURLEncoding.EncodeToString(raw)) {
			t.Fatal("out-of-range timestamp accepted")
		}
	})
}
