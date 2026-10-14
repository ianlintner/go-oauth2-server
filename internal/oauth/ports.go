package oauth

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"time"
)

// Clock supplies the current time so expiry logic is deterministic in tests.
type Clock interface {
	Now() time.Time
}

// SystemClock is the production Clock.
type SystemClock struct{}

// Now returns the current UTC time.
func (SystemClock) Now() time.Time { return time.Now().UTC() }

// Random supplies unpredictable bytes for codes, tokens and identifiers.
type Random interface {
	// Bytes returns n cryptographically secure random bytes.
	Bytes(n int) ([]byte, error)
}

// CryptoRandom is the production Random, backed by crypto/rand.
type CryptoRandom struct {
	// Reader overrides the entropy source; nil means crypto/rand.Reader.
	Reader io.Reader
}

// Bytes returns n random bytes and fails closed on a short or failed read.
func (r CryptoRandom) Bytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, fmt.Errorf("random: invalid length %d", n)
	}
	src := r.Reader
	if src == nil {
		src = rand.Reader
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(src, buf); err != nil {
		return nil, fmt.Errorf("random: read entropy: %w", err)
	}
	return buf, nil
}

// Signer produces signed JWTs from a claim set. Implementations (a later card,
// backed by go-jose) own key selection and the `kid`/`alg` headers; callers
// never touch key material.
type Signer interface {
	Sign(ctx context.Context, claims map[string]any) (string, error)
}

// Verifier validates a compact JWS and returns its claims.
type Verifier interface {
	Verify(ctx context.Context, token string) (map[string]any, error)
}
