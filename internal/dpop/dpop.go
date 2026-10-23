// Package dpop validates RFC 9449 DPoP proofs (Demonstrating Proof of
// Possession) and tracks proof replay.
//
// It is independent of HTTP: callers hand it the proof, the request method,
// the request URL as the client saw it and, at a resource, the presented access
// token. It returns the RFC 7638 JWK thumbprint (the value for cnf.jkt) of the
// proof key. Every rejection wraps ErrInvalidProof so the HTTP layer can map it
// to one error without leaking which check failed.
//
// Scope of this slice: proof syntax, signature, header/claim checks, ath
// binding and single-process jti replay detection. Server-provided nonces
// (RFC 9449 §8, §9) and a replay store shared across instances or restarts are
// NOT implemented; see docs/sender-constrained.md.
package dpop

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
)

// ProofType is the required JOSE typ header of a DPoP proof (RFC 9449 §4.1).
const ProofType = "dpop+jwt"

// SigningAlgs are the proof signature algorithms this server accepts and
// advertises as dpop_signing_alg_values_supported (RFC 9449 §5.1). Asymmetric
// only: "none" and MAC algorithms are never acceptable (RFC 9449 §4.2).
var SigningAlgs = []jose.SignatureAlgorithm{jose.ES256, jose.ES384, jose.EdDSA}

const (
	// DefaultMaxAge is how old a proof's iat may be, and DefaultFutureSkew how
	// far ahead of the server clock it may be (RFC 9449 §11.1).
	DefaultMaxAge     = 60 * time.Second
	DefaultFutureSkew = 30 * time.Second

	// maxProofBytes bounds the header value parsed; real proofs are < 1 KiB.
	maxProofBytes = 4096
)

// ErrInvalidProof is wrapped by every proof rejection.
var ErrInvalidProof = errors.New("dpop: invalid proof")

// ErrReplayStoreFull is returned (not wrapped in ErrInvalidProof) when the
// replay store cannot record a proof. Verification then fails closed: a proof
// that cannot be recorded cannot be accepted.
var ErrReplayStoreFull = errors.New("dpop: replay store is full")

func invalid(reason string) error { return fmt.Errorf("%w: %s", ErrInvalidProof, reason) }

// ReplayStore records proof identifiers until they can no longer be fresh.
type ReplayStore interface {
	// Add records key until expires and reports whether it was new. A false
	// result with a nil error means key was already present (a replay).
	Add(key string, expires time.Time) (bool, error)
}

// Config configures a Verifier.
type Config struct {
	Clock  oauth.Clock
	Replay ReplayStore
	// MaxAge and FutureSkew default to DefaultMaxAge and DefaultFutureSkew.
	MaxAge     time.Duration
	FutureSkew time.Duration
}

// Verifier validates DPoP proofs.
type Verifier struct {
	clock  oauth.Clock
	replay ReplayStore
	maxAge time.Duration
	skew   time.Duration
}

// NewVerifier returns a Verifier. Clock and Replay are required; a Verifier
// without a replay store would silently accept replays, so it panics instead of
// defaulting.
func NewVerifier(cfg Config) *Verifier {
	if cfg.Clock == nil || cfg.Replay == nil {
		panic("dpop: Clock and Replay are required")
	}
	v := &Verifier{clock: cfg.Clock, replay: cfg.Replay, maxAge: cfg.MaxAge, skew: cfg.FutureSkew}
	if v.maxAge <= 0 {
		v.maxAge = DefaultMaxAge
	}
	if v.skew <= 0 {
		v.skew = DefaultFutureSkew
	}
	return v
}

// Request is what a proof is checked against.
type Request struct {
	Proof  string // the DPoP header value
	Method string // HTTP method of the request
	// URL is the request target as the client addressed it (scheme, host and
	// path from the configured public origin). Its query and fragment are
	// ignored (RFC 9449 §4.2).
	URL string
	// AccessToken is set at a protected resource: the proof must then carry
	// ath = base64url(SHA-256(AccessToken)) (RFC 9449 §4.2, §7.1). Empty at the
	// token endpoint, where a proof carrying ath is refused.
	AccessToken string
}

type proofClaims struct {
	JTI string   `json:"jti"`
	HTM string   `json:"htm"`
	HTU string   `json:"htu"`
	IAT *float64 `json:"iat"`
	ATH string   `json:"ath"`
}

// Verify validates req.Proof and returns the JWK thumbprint of its key.
func (v *Verifier) Verify(_ context.Context, req Request) (string, error) {
	if req.Proof == "" || len(req.Proof) > maxProofBytes {
		return "", invalid("missing or oversized proof")
	}
	jws, err := jose.ParseSigned(req.Proof, SigningAlgs)
	if err != nil || len(jws.Signatures) != 1 {
		return "", invalid("not a compact JWS with an allowed algorithm")
	}
	hdr := jws.Signatures[0].Header
	if typ, _ := hdr.ExtraHeaders[jose.HeaderType].(string); typ != ProofType {
		return "", invalid("typ must be " + ProofType)
	}
	jwk := hdr.JSONWebKey
	if jwk == nil || !jwk.Valid() || !jwk.IsPublic() {
		return "", invalid("jwk header must be a valid public key")
	}
	payload, err := jws.Verify(jwk)
	if err != nil {
		return "", invalid("signature does not verify against the jwk header")
	}
	var c proofClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return "", invalid("claims are not a JSON object")
	}
	if c.JTI == "" {
		return "", invalid("jti is required")
	}
	if c.HTM == "" || c.HTM != req.Method {
		return "", invalid("htm does not match the request method")
	}
	if !sameTarget(c.HTU, req.URL) {
		return "", invalid("htu does not match the request URI")
	}
	if c.IAT == nil {
		return "", invalid("iat is required")
	}
	now := v.clock.Now()
	iat := time.Unix(0, int64(*c.IAT*float64(time.Second)))
	if now.Sub(iat) > v.maxAge || iat.Sub(now) > v.skew {
		return "", invalid("iat is outside the acceptance window")
	}
	if req.AccessToken == "" {
		if c.ATH != "" {
			return "", invalid("ath is not allowed at the token endpoint")
		}
	} else {
		sum := sha256.Sum256([]byte(req.AccessToken))
		want := base64.RawURLEncoding.EncodeToString(sum[:])
		if c.ATH == "" || subtle.ConstantTimeCompare([]byte(c.ATH), []byte(want)) != 1 {
			return "", invalid("ath does not match the access token")
		}
	}

	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", invalid("jwk has no thumbprint")
	}
	jkt := base64.RawURLEncoding.EncodeToString(tp)

	// Replay detection runs last so a proof rejected above never burns its
	// jti. Uniqueness is per key (RFC 9449 §11.1): the key is bound to jkt.
	// The entry lives until the proof could no longer pass the iat window.
	sum := sha256.Sum256([]byte(jkt + "\x00" + c.JTI))
	fresh, err := v.replay.Add(base64.RawURLEncoding.EncodeToString(sum[:]), iat.Add(v.maxAge+v.skew))
	if err != nil {
		return "", err
	}
	if !fresh {
		return "", invalid("proof was already used")
	}
	return jkt, nil
}

// sameTarget compares the proof htu to the request URL. The request side has
// its query and fragment removed; the proof side must already be bare (htu is
// defined without them, RFC 9449 §4.2). Scheme and host compare
// case-insensitively, the path exactly.
func sameTarget(htu, requestURL string) bool {
	p, err := url.Parse(htu)
	if err != nil || p.RawQuery != "" || p.ForceQuery || p.Fragment != "" || p.Opaque != "" || p.User != nil {
		return false
	}
	r, err := url.Parse(requestURL)
	if err != nil {
		return false
	}
	norm := func(u *url.URL) string {
		path := u.EscapedPath()
		if path == "" {
			path = "/"
		}
		return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + path
	}
	return p.Scheme != "" && p.Host != "" && norm(p) == norm(r)
}

// MemoryReplayStore is a bounded in-process ReplayStore. It does not survive a
// restart and is not shared between instances: a proof replayed after a restart
// or against another instance is accepted. It is the floor RFC 9449 §11.1
// allows for a single-process deployment, not a distributed replay defence.
type MemoryReplayStore struct {
	clock oauth.Clock
	max   int

	mu      sync.Mutex
	entries map[string]time.Time
}

// NewMemoryReplayStore returns a store holding at most max live entries.
func NewMemoryReplayStore(clock oauth.Clock, max int) *MemoryReplayStore {
	return &MemoryReplayStore{clock: clock, max: max, entries: make(map[string]time.Time)}
}

// Add implements ReplayStore. When the store is full of unexpired entries it
// returns ErrReplayStoreFull instead of evicting a live one: evicting would let
// an attacker flush the store and replay a captured proof.
func (s *MemoryReplayStore) Add(key string, expires time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock.Now()
	if exp, ok := s.entries[key]; ok && now.Before(exp) {
		return false, nil
	}
	if len(s.entries) >= s.max {
		for k, exp := range s.entries {
			if !now.Before(exp) {
				delete(s.entries, k)
			}
		}
		if len(s.entries) >= s.max {
			return false, ErrReplayStoreFull
		}
	}
	s.entries[key] = expires
	return true, nil
}
