package storagetest

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
)

// fakeRefreshRepo overrides only the methods rotationRacingInFlightRevoke
// uses. RevokeFamily sleeps so the caller can race it against a short
// startDeadline.
type fakeRefreshRepo struct {
	oauth.RefreshTokenRepository
	sleep time.Duration
}

func (f *fakeRefreshRepo) Create(ctx context.Context, t oauth.RefreshToken) error {
	return nil
}

func (f *fakeRefreshRepo) RevokeFamily(ctx context.Context, familyID string, now time.Time) (int, error) {
	time.Sleep(f.sleep)
	return 1, nil
}

func (f *fakeRefreshRepo) Rotate(ctx context.Context, tokenHash string, now time.Time) (oauth.RefreshToken, error) {
	return oauth.RefreshToken{}, oauth.ErrAlreadyConsumed
}

// fakeRepositories overrides only RefreshTokens.
type fakeRepositories struct {
	oauth.Repositories
	refresh oauth.RefreshTokenRepository
}

func (f *fakeRepositories) RefreshTokens() oauth.RefreshTokenRepository {
	return f.refresh
}

// fakeStore overrides only RefreshTokens (delegated to the same repos used
// inside WithTx) and WithTx, which runs fn synchronously and closes
// txReturned when it returns, letting the test detect a leaked transaction.
type fakeStore struct {
	oauth.Store
	repos      oauth.Repositories
	txReturned chan struct{}
}

func (f *fakeStore) RefreshTokens() oauth.RefreshTokenRepository {
	return f.repos.RefreshTokens()
}

func (f *fakeStore) WithTx(ctx context.Context, fn func(ctx context.Context, tx oauth.Repositories) error) error {
	defer close(f.txReturned)
	return fn(ctx, f.repos)
}

// TestRotationRacingInFlightRevoke_ReleasesOnStartDeadlineFailure proves that
// when the "revoke transaction did not start" deadline fires before the
// revoke's RevokeFamily call has finished, the in-flight transaction is still
// released (and its goroutine returns) rather than being leaked forever. It
// is RED before the storagetest.go fix (the goroutine never returns, the
// t.Cleanup below times out and reports an error) and GREEN after.
func TestRotationRacingInFlightRevoke_ReleasesOnStartDeadlineFailure(t *testing.T) {
	refreshRepo := &fakeRefreshRepo{sleep: 100 * time.Millisecond}
	repos := &fakeRepositories{refresh: refreshRepo}
	txReturned := make(chan struct{})
	store := &fakeStore{repos: repos, txReturned: txReturned}

	// Registered before calling the helper so it runs after the helper's own
	// t.Cleanup (t.Cleanup is LIFO), i.e. after closeRelease has already run.
	t.Cleanup(func() {
		select {
		case <-txReturned:
		case <-time.After(5 * time.Second):
			t.Error("WithTx goroutine never returned; the in-flight revoke transaction was leaked")
		}
	})

	var mu sync.Mutex
	var failures []string
	failf := func(format string, args ...any) {
		mu.Lock()
		failures = append(failures, fmt.Sprintf(format, args...))
		mu.Unlock()
	}

	// The sleep (100ms) comfortably outlasts this deadline, so the helper's
	// startDeadline branch fires while the fake RevokeFamily call (and the
	// transaction holding it) is still in flight.
	rotationRacingInFlightRevoke(t, store, 20*time.Millisecond, failf)

	mu.Lock()
	defer mu.Unlock()
	if len(failures) == 0 {
		t.Fatal("expected rotationRacingInFlightRevoke to report a failure via failf")
	}
}
