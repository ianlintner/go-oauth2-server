package authcode

import (
	"crypto/sha256"
	"errors"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
	"github.com/ianlintner/go-oauth2-server/internal/secret"
)

// Throttling policy. Everything in this file is in-process: a deployment that
// runs several replicas multiplies the effective budgets by the replica
// count, mirroring the device user-code limiter (docs/extended-grants.md).
const (
	// DefaultAuthFailureLimit is how many failed authentication attempts a
	// single presented client id or username may accumulate per window.
	DefaultAuthFailureLimit = 10
	// authFailureWindow is the sliding window the failure budgets use.
	authFailureWindow = time.Minute
	// sourceLimitFactor scales the per-username budget up to the per-source
	// budget used for resource-owner login (several users may share a source).
	sourceLimitFactor = 5
	// maxLimiterKeys bounds limiter memory. Keys are attacker-chosen, so past
	// this many live keys new keys share one overflow bucket instead of
	// growing the map.
	maxLimiterKeys = 8192
	overflowKey    = "\x00overflow"
)

// DefaultMaxConcurrentHashes is the default bound on concurrent argon2id
// computations: one per CPU.
func DefaultMaxConcurrentHashes() int { return runtime.GOMAXPROCS(0) }

// errThrottled marks a request refused by a limiter before any hash was
// computed. It is the same error whichever limiter refused.
var errThrottled = oauth.TemporarilyUnavailable("too many requests; retry later").WithStatus(http.StatusTooManyRequests)

// hashGate bounds concurrent password-hash computations. It never queues: a
// caller that cannot take a slot immediately is refused.
type hashGate struct {
	slots chan struct{} // nil means unbounded
}

func newHashGate(n int) hashGate {
	if n <= 0 {
		return hashGate{}
	}
	return hashGate{slots: make(chan struct{}, n)}
}

func (g hashGate) acquire() bool {
	if g.slots == nil {
		return true
	}
	select {
	case g.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (g hashGate) release() {
	if g.slots != nil {
		<-g.slots
	}
}

// attemptLimiter counts recent failed attempts per opaque key in a sliding
// window. allow is checked before any work is done for a key; fail records an
// attempt that did not authenticate. Only failures count, so legitimate
// traffic never consumes budget. Requests already past allow when the budget
// is reached may still record failures, so the overshoot is bounded by the
// number of in-flight hash computations (see hashGate). Keys are hashed so
// memory per key is constant regardless of the presented value.
type attemptLimiter struct {
	limit  int // <= 0 disables the limiter
	window time.Duration

	mu sync.Mutex
	m  map[[sha256.Size]byte][]time.Time
}

func newAttemptLimiter(limit int, window time.Duration) *attemptLimiter {
	return &attemptLimiter{limit: limit, window: window}
}

// slot returns the live failure times for k, pruned to the window. The caller
// holds l.mu. Past maxLimiterKeys, unseen keys share one overflow bucket so
// attacker-chosen keys cannot grow the map without bound.
func (l *attemptLimiter) slot(k string, now time.Time) ([sha256.Size]byte, []time.Time) {
	if l.m == nil {
		l.m = map[[sha256.Size]byte][]time.Time{}
	}
	cutoff := now.Add(-l.window)
	prune := func(key [sha256.Size]byte) []time.Time {
		kept := l.m[key][:0]
		for _, t := range l.m[key] {
			if t.After(cutoff) {
				kept = append(kept, t)
			}
		}
		return kept
	}
	key := sha256.Sum256([]byte(k))
	if _, exists := l.m[key]; !exists && len(l.m) >= maxLimiterKeys {
		for kk := range l.m {
			if kept := prune(kk); len(kept) == 0 {
				delete(l.m, kk)
			} else {
				l.m[kk] = kept
			}
		}
		if len(l.m) >= maxLimiterKeys {
			key = sha256.Sum256([]byte(overflowKey))
		}
	}
	kept := prune(key)
	l.m[key] = kept
	return key, kept
}

// allow reports whether k is still within its failure budget.
func (l *attemptLimiter) allow(k string, now time.Time) bool {
	if l == nil || l.limit <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, kept := l.slot(k, now)
	return len(kept) < l.limit
}

// fail records one failed attempt for k.
func (l *attemptLimiter) fail(k string, now time.Time) {
	if l == nil || l.limit <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	key, kept := l.slot(k, now)
	l.m[key] = append(kept, now)
}

// isInvalidClient reports whether err is a failed client authentication, as
// opposed to a throttle, a malformed request or a storage error.
func isInvalidClient(err error) bool {
	var oe *oauth.Error
	return errors.As(err, &oe) && oe.Code == oauth.CodeInvalidClient
}

// verifyBounded is the only place the service runs a password hash. A request
// that cannot take a hash slot immediately is refused with errThrottled.
func (s *Service) verifyBounded(encoded, presented string) (bool, error) {
	if !s.gate.acquire() {
		return false, errThrottled
	}
	defer s.gate.release()
	if s.hashHook != nil {
		s.hashHook()
	}
	return secret.Verify(encoded, presented)
}

// dummyVerify spends the time a real check would, for identities that do not
// exist. Hash-slot exhaustion is reported like any other throttle.
func (s *Service) dummyVerify() error {
	_, err := s.verifyBounded(s.dummyHash, "x")
	return err
}
