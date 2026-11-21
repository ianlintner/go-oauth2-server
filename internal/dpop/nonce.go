package dpop

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"time"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
)

const (
	// DefaultNonceWindow is how long one nonce value is the current one. A
	// nonce stays acceptable for the window after it too, so a client holds a
	// given nonce for between one and two windows.
	DefaultNonceWindow = 5 * time.Minute

	// MinNonceSecretLen is the shortest HMAC secret NewNonceSource accepts.
	MinNonceSecretLen = 32

	nonceTSLen = 8
	nonceLen   = nonceTSLen + sha256.Size
)

// nonceEncLen is the unpadded base64url length of a nonce.
var nonceEncLen = base64.RawURLEncoding.EncodedLen(nonceLen)

// ErrUseNonce is returned by Check when a proof must carry a server-provided
// nonce (RFC 9449 §8, §9) and its nonce claim is missing, malformed, forged or
// out of date. It is deliberately not an ErrInvalidProof: the HTTP layer
// answers it with use_dpop_nonce and a fresh DPoP-Nonce header so the client
// can retry, rather than with invalid_dpop_proof.
var ErrUseNonce = errors.New("dpop: a current server nonce is required")

// NonceSource issues and validates stateless DPoP server nonces.
//
// A nonce is base64url(ts || HMAC-SHA256(secret, ts)) where ts is the 8-byte
// big-endian Unix start (seconds) of a fixed window. It holds no state, so any
// instance sharing the secret accepts nonces issued by any other. The current
// and the immediately previous window are accepted; anything older is stale.
type NonceSource struct {
	clock  oauth.Clock
	secret []byte
	window time.Duration
}

// NewNonceSource returns a NonceSource. The secret must be at least
// MinNonceSecretLen bytes and is copied. A non-positive window selects
// DefaultNonceWindow; windows are rounded down to whole seconds and must be at
// least one second.
func NewNonceSource(clock oauth.Clock, secret []byte, window time.Duration) (*NonceSource, error) {
	if clock == nil {
		return nil, errors.New("dpop: nonce source requires a clock")
	}
	if len(secret) < MinNonceSecretLen {
		return nil, errors.New("dpop: nonce secret is too short")
	}
	if window <= 0 {
		window = DefaultNonceWindow
	}
	window = window.Truncate(time.Second)
	if window < time.Second {
		return nil, errors.New("dpop: nonce window must be at least one second")
	}
	return &NonceSource{clock: clock, secret: append([]byte(nil), secret...), window: window}, nil
}

func (s *NonceSource) windowStart() int64 {
	w := int64(s.window / time.Second)
	now := s.clock.Now().Unix()
	return now - ((now%w)+w)%w
}

func (s *NonceSource) mac(ts []byte) []byte {
	m := hmac.New(sha256.New, s.secret)
	m.Write(ts)
	return m.Sum(nil)
}

func (s *NonceSource) encode(start int64) string {
	buf := make([]byte, nonceTSLen, nonceLen)
	binary.BigEndian.PutUint64(buf, uint64(start))
	buf = append(buf, s.mac(buf)...)
	return base64.RawURLEncoding.EncodeToString(buf)
}

// Next returns the nonce for the current window.
func (s *NonceSource) Next() string { return s.encode(s.windowStart()) }

// Valid reports whether nonce was issued by a source sharing this secret for
// the current or the previous window. The MAC is compared in constant time.
func (s *NonceSource) Valid(nonce string) bool {
	if len(nonce) != nonceEncLen {
		return false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(nonce)
	if err != nil || len(raw) != nonceLen {
		return false
	}
	ts := raw[:nonceTSLen]
	if !hmac.Equal(raw[nonceTSLen:], s.mac(ts)) {
		return false
	}
	start := int64(binary.BigEndian.Uint64(ts))
	cur := s.windowStart()
	return start == cur || start == cur-int64(s.window/time.Second)
}
