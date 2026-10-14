package secret_test

import (
	"strings"
	"testing"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
	"github.com/ianlintner/go-oauth2-server/internal/secret"
)

// fixedRandom makes salts deterministic.
type fixedRandom byte

func (f fixedRandom) Bytes(n int) ([]byte, error) {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(f)
	}
	return b, nil
}

var _ oauth.Random = fixedRandom(0)

func TestHashVerifyRoundTrip(t *testing.T) {
	h, err := secret.Hash(oauth.CryptoRandom{}, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$") {
		t.Fatalf("hash = %q, want PHC argon2id", h)
	}
	if strings.Contains(h, "correct horse") {
		t.Fatal("hash contains the secret")
	}
	ok, err := secret.Verify(h, "correct horse")
	if err != nil || !ok {
		t.Fatalf("Verify = %v, %v; want true", ok, err)
	}
	ok, err = secret.Verify(h, "wrong")
	if err != nil || ok {
		t.Fatalf("Verify(wrong) = %v, %v; want false, nil", ok, err)
	}
}

func TestHashIsSaltedPerCall(t *testing.T) {
	a, _ := secret.Hash(fixedRandom(1), "same")
	b, _ := secret.Hash(fixedRandom(2), "same")
	if a == b {
		t.Fatal("different salts produced the same hash")
	}
}

func TestHashRejectsEmptySecret(t *testing.T) {
	if _, err := secret.Hash(oauth.CryptoRandom{}, ""); err == nil {
		t.Fatal("empty secret accepted")
	}
}

func TestVerifyRejectsMalformedHashes(t *testing.T) {
	for _, bad := range []string{
		"", "plaintext", "$argon2id$", "$argon2i$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=0,t=2,p=1$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=19456,t=0,p=1$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=999999999,t=2,p=1$c2FsdA$aGFzaA", // DoS-sized memory
		"$argon2id$v=19$m=19456,t=2,p=1$!!!$aGFzaA",
	} {
		ok, err := secret.Verify(bad, "x")
		if ok || err == nil {
			t.Errorf("Verify(%q) = %v, %v; want false with error", bad, ok, err)
		}
	}
}

func TestHashFailsClosedOnRandomFailure(t *testing.T) {
	if _, err := secret.Hash(failingRandom{}, "x"); err == nil {
		t.Fatal("Hash succeeded without entropy")
	}
}

type failingRandom struct{}

func (failingRandom) Bytes(int) ([]byte, error) { return nil, errNoEntropy }

var errNoEntropy = &entropyErr{}

type entropyErr struct{}

func (*entropyErr) Error() string { return "no entropy" }
