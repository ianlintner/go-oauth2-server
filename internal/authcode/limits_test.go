package authcode_test

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ianlintner/go-oauth2-server/internal/authcode"
	"github.com/ianlintner/go-oauth2-server/internal/oauth"
)

func TestConcurrentHashComputationIsBounded(t *testing.T) {
	var inFlight, peak atomic.Int64
	e := newEnvWith(t, func(c *authcode.Config) {
		c.MaxConcurrentHashes = 2
		c.AuthFailureLimit = -1
		c.HashObserver = func() {
			n := inFlight.Add(1)
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			time.Sleep(50 * time.Millisecond) // widen the overlap window
			inFlight.Add(-1)
		}
	})
	const n = 16
	var wg sync.WaitGroup
	var refused atomic.Int64
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			p := params(t, "grant_type", "client_credentials", "client_id", "ghost-"+string(rune('a'+i)), "client_secret", "x")
			_, err := e.token("", p)
			if oe := wantCode(t, err, codeFor(err)); oe.Code == oauth.CodeTemporarilyUnavailable {
				if oe.HTTPStatus() != 429 {
					t.Errorf("status = %d, want 429", oe.HTTPStatus())
				}
				refused.Add(1)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if got := peak.Load(); got > 2 {
		t.Fatalf("peak concurrent hashes = %d, want <= 2", got)
	}
	if got := refused.Load(); got < 8 {
		t.Fatalf("refused = %d of %d, want at least 8", got, n)
	}
}

func codeFor(err error) oauth.Code {
	if oe, ok := err.(*oauth.Error); ok {
		return oe.Code
	}
	return ""
}

func TestClientSecretGuessingIsRefusedAfterBudget(t *testing.T) {
	var hashes atomic.Int64
	e := newEnvWith(t, func(c *authcode.Config) {
		c.MaxConcurrentHashes = -1
		c.AuthFailureLimit = 10
		c.HashObserver = func() { hashes.Add(1) }
	})
	cc := func(sec string) (authcode.TokenResponse, error) {
		return e.token(basic("client-cc", sec), params(t, "grant_type", "client_credentials"))
	}
	for i := 0; i < 10; i++ {
		_, err := cc("wrong")
		wantCode(t, err, oauth.CodeInvalidClient)
	}
	before := hashes.Load()
	_, err := cc("wrong")
	oe := wantCode(t, err, oauth.CodeTemporarilyUnavailable)
	if oe.HTTPStatus() != 429 {
		t.Fatalf("status = %d, want 429", oe.HTTPStatus())
	}
	// Even the right secret is refused inside the window, without hashing.
	_, err = cc("test-only-cc-secret")
	wantCode(t, err, oauth.CodeTemporarilyUnavailable)
	if hashes.Load() != before {
		t.Fatal("a throttled request must not compute a hash")
	}
	e.clock.Advance(61 * time.Second)
	if _, err := cc("test-only-cc-secret"); err != nil {
		t.Fatalf("after the window: %v", err)
	}
}

func TestUnknownClientIDIsThrottledLikeAKnownOne(t *testing.T) {
	e := newEnvWith(t, func(c *authcode.Config) { c.MaxConcurrentHashes = -1; c.AuthFailureLimit = 3 })
	for i := 0; i < 3; i++ {
		_, err := e.token(basic("ghost", "x"), params(t, "grant_type", "client_credentials"))
		wantCode(t, err, oauth.CodeInvalidClient)
	}
	_, err := e.token(basic("ghost", "x"), params(t, "grant_type", "client_credentials"))
	wantCode(t, err, oauth.CodeTemporarilyUnavailable)
}

func TestSuccessfulAuthenticationDoesNotConsumeBudget(t *testing.T) {
	e := newEnvWith(t, func(c *authcode.Config) { c.MaxConcurrentHashes = -1; c.AuthFailureLimit = 2 })
	for i := 0; i < 6; i++ {
		if _, err := e.token(basic("client-cc", "test-only-cc-secret"), params(t, "grant_type", "client_credentials")); err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
}

func TestUserLoginFailuresAreThrottled(t *testing.T) {
	e := newEnvWith(t, func(c *authcode.Config) { c.MaxConcurrentHashes = -1; c.AuthFailureLimit = 3 })
	ctx := t.Context()
	for i := 0; i < 3; i++ {
		if _, err := e.svc.AuthenticateUserFrom(ctx, "192.0.2.1", "alice", "wrong"); err != authcode.ErrInvalidCredentials {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	_, err := e.svc.AuthenticateUserFrom(ctx, "192.0.2.1", "alice", "test-only-password")
	wantCode(t, err, oauth.CodeTemporarilyUnavailable)
	// Unknown usernames are counted the same way.
	for i := 0; i < 3; i++ {
		_, _ = e.svc.AuthenticateUserFrom(ctx, "", "nobody", "x")
	}
	_, err = e.svc.AuthenticateUserFrom(ctx, "", "nobody", "x")
	wantCode(t, err, oauth.CodeTemporarilyUnavailable)
}
