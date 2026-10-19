// Package storagetest is the reusable storage contract suite. Every
// oauth.Store adapter (SQLite now, PostgreSQL later) runs the same suite so
// the security-relevant guarantees — single-use codes, refresh rotation,
// family revocation, transaction atomicity and persistence — are verified
// once, adapter-independently.
package storagetest

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
)

// Factory describes how to build the adapter under test.
type Factory struct {
	// New returns a fresh, empty store. Cleanup is registered on t.
	New func(t *testing.T) oauth.Store
	// NewPersistent returns an opener over durable storage: every call to
	// open returns a new Store over the same underlying data, and the caller
	// closes each one. Nil skips the persistence tests (for an adapter with
	// no durable mode); durable adapters must provide it.
	NewPersistent func(t *testing.T) (open func(t *testing.T) oauth.Store)
}

var ref = time.Date(2026, time.October, 13, 12, 0, 0, 0, time.UTC)

// Run executes the whole contract against f.
func Run(t *testing.T, f Factory) {
	t.Helper()
	groups := []struct {
		name string
		fn   func(*testing.T, Factory)
	}{
		{"Clients", testClients},
		{"Users", testUsers},
		{"AuthCodes", testAuthCodes},
		{"RefreshTokens", testRefreshTokens},
		{"AccessTokens", testAccessTokens},
		{"Transactions", testTransactions},
		{"Persistence", testPersistence},
		{"Lifecycle", testLifecycle},
	}
	for _, g := range groups {
		t.Run(g.name, func(t *testing.T) { g.fn(t, f) })
	}
}

func newStore(t *testing.T, f Factory) oauth.Store {
	t.Helper()
	s := f.New(t)
	if s == nil {
		t.Fatal("Factory.New returned nil")
	}
	return s
}

func sampleClient(id string) oauth.Client {
	return oauth.Client{
		ID:           id,
		Name:         "Client " + id,
		SecretHash:   "hash-" + id,
		AuthMethod:   "client_secret_basic",
		RedirectURIs: []string{"https://client.example/callback", "https://client.example/other"},
		Scopes:       []string{"openid", "profile"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
	}
}

func sampleUser(id, username string) oauth.User {
	return oauth.User{ID: id, Username: username, PasswordHash: "pw-" + id, Email: username + "@example.com", Scopes: []string{"openid"}}
}

func sampleCode(hash string) oauth.AuthorizationCode {
	return oauth.AuthorizationCode{
		CodeHash:            hash,
		ClientID:            "client-a",
		UserID:              "user-1",
		RedirectURI:         "https://client.example/callback",
		Scope:               "openid profile",
		CodeChallenge:       "challenge-" + hash,
		CodeChallengeMethod: "S256",
		ExpiresAt:           ref.Add(time.Minute),
	}
}

func sampleRefresh(hash, family string) oauth.RefreshToken {
	return oauth.RefreshToken{TokenHash: hash, FamilyID: family, ClientID: "client-a", UserID: "user-1", Scope: "openid", ExpiresAt: ref.Add(24 * time.Hour)}
}

func sampleAccessToken(jti string) oauth.AccessToken {
	return oauth.AccessToken{
		JTI:       jti,
		ClientID:  "client-a",
		UserID:    "user-1",
		Scope:     "openid profile",
		IssuedAt:  ref,
		ExpiresAt: ref.Add(time.Hour),
	}
}

func mustNoErr(t *testing.T, err error, what string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

func wantErr(t *testing.T, err, target error, what string) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("%s: err = %v, want %v", what, err, target)
	}
}

func testClients(t *testing.T, f Factory) {
	ctx := context.Background()

	t.Run("round trip preserves every field", func(t *testing.T) {
		s := newStore(t, f)
		want := sampleClient("client-a")
		mustNoErr(t, s.Clients().Create(ctx, want), "create")
		got, err := s.Clients().Get(ctx, "client-a")
		mustNoErr(t, err, "get")
		assertClient(t, got, want)
	})

	t.Run("redirect URIs keep order and are stored verbatim", func(t *testing.T) {
		s := newStore(t, f)
		c := sampleClient("client-a")
		c.RedirectURIs = []string{"https://c.example/b", "https://c.example/a/", "HTTPS://C.example/A", "http://127.0.0.1/cb"}
		mustNoErr(t, s.Clients().Create(ctx, c), "create")
		got, err := s.Clients().Get(ctx, "client-a")
		mustNoErr(t, err, "get")
		assertClient(t, got, c)
	})

	t.Run("public client has no secret", func(t *testing.T) {
		s := newStore(t, f)
		c := oauth.Client{ID: "pub", Public: true, AuthMethod: "none", RedirectURIs: []string{"https://p.example/cb"}}
		mustNoErr(t, s.Clients().Create(ctx, c), "create")
		got, err := s.Clients().Get(ctx, "pub")
		mustNoErr(t, err, "get")
		if !got.Public || got.SecretHash != "" {
			t.Fatalf("public client = %+v", got)
		}
		assertClient(t, got, c)
	})

	t.Run("duplicate id conflicts and keeps the original", func(t *testing.T) {
		s := newStore(t, f)
		mustNoErr(t, s.Clients().Create(ctx, sampleClient("client-a")), "create")
		dup := sampleClient("client-a")
		dup.Name = "impostor"
		wantErr(t, s.Clients().Create(ctx, dup), oauth.ErrConflict, "duplicate create")
		got, err := s.Clients().Get(ctx, "client-a")
		mustNoErr(t, err, "get")
		if got.Name == "impostor" {
			t.Fatal("duplicate create overwrote the original client")
		}
	})

	t.Run("unknown client is not found", func(t *testing.T) {
		s := newStore(t, f)
		_, err := s.Clients().Get(ctx, "missing")
		wantErr(t, err, oauth.ErrNotFound, "get missing")
	})

	t.Run("lookup is exact, not case-folded or prefix", func(t *testing.T) {
		s := newStore(t, f)
		mustNoErr(t, s.Clients().Create(ctx, sampleClient("Client-A")), "create")
		for _, id := range []string{"client-a", "Client-", "Client-A "} {
			_, err := s.Clients().Get(ctx, id)
			wantErr(t, err, oauth.ErrNotFound, "get "+id)
		}
	})
}

func assertClient(t *testing.T, got, want oauth.Client) {
	t.Helper()
	if got.ID != want.ID || got.Name != want.Name || got.SecretHash != want.SecretHash ||
		got.AuthMethod != want.AuthMethod || got.Public != want.Public ||
		!equalStrings(got.RedirectURIs, want.RedirectURIs) ||
		!equalStrings(got.Scopes, want.Scopes) ||
		!equalStrings(got.GrantTypes, want.GrantTypes) {
		t.Fatalf("client mismatch\n got: %+v\nwant: %+v", got, want)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func testUsers(t *testing.T, f Factory) {
	ctx := context.Background()

	t.Run("round trip", func(t *testing.T) {
		s := newStore(t, f)
		want := sampleUser("user-1", "alice")
		mustNoErr(t, s.Users().Create(ctx, want), "create")
		got, err := s.Users().GetByUsername(ctx, "alice")
		mustNoErr(t, err, "get")
		if got.ID != want.ID || got.Username != want.Username || got.PasswordHash != want.PasswordHash ||
			got.Email != want.Email || !equalStrings(got.Scopes, want.Scopes) {
			t.Fatalf("user mismatch\n got: %+v\nwant: %+v", got, want)
		}
	})

	t.Run("duplicate username conflicts", func(t *testing.T) {
		s := newStore(t, f)
		mustNoErr(t, s.Users().Create(ctx, sampleUser("user-1", "alice")), "create")
		wantErr(t, s.Users().Create(ctx, sampleUser("user-2", "alice")), oauth.ErrConflict, "duplicate username")
	})

	t.Run("duplicate id conflicts", func(t *testing.T) {
		s := newStore(t, f)
		mustNoErr(t, s.Users().Create(ctx, sampleUser("user-1", "alice")), "create")
		wantErr(t, s.Users().Create(ctx, sampleUser("user-1", "bob")), oauth.ErrConflict, "duplicate id")
	})

	t.Run("unknown username is not found", func(t *testing.T) {
		s := newStore(t, f)
		_, err := s.Users().GetByUsername(ctx, "nobody")
		wantErr(t, err, oauth.ErrNotFound, "get missing")
	})

	t.Run("username lookup is exact", func(t *testing.T) {
		s := newStore(t, f)
		mustNoErr(t, s.Users().Create(ctx, sampleUser("user-1", "alice")), "create")
		_, err := s.Users().GetByUsername(ctx, "ALICE")
		wantErr(t, err, oauth.ErrNotFound, "case-folded lookup")
	})
}

func testAuthCodes(t *testing.T, f Factory) {
	ctx := context.Background()

	t.Run("consume returns the stored code", func(t *testing.T) {
		s := newStore(t, f)
		want := sampleCode("h1")
		mustNoErr(t, s.AuthCodes().Create(ctx, want), "create")
		got, err := s.AuthCodes().Consume(ctx, "h1", ref)
		mustNoErr(t, err, "consume")
		if got != (oauth.AuthorizationCode{
			CodeHash: want.CodeHash, ClientID: want.ClientID, UserID: want.UserID, RedirectURI: want.RedirectURI,
			Scope: want.Scope, CodeChallenge: want.CodeChallenge, CodeChallengeMethod: want.CodeChallengeMethod, Nonce: want.Nonce,
			ExpiresAt: got.ExpiresAt,
		}) || !got.ExpiresAt.Equal(want.ExpiresAt) {
			t.Fatalf("code mismatch\n got: %+v\nwant: %+v", got, want)
		}
	})

	t.Run("second consume is replay", func(t *testing.T) {
		s := newStore(t, f)
		mustNoErr(t, s.AuthCodes().Create(ctx, sampleCode("h1")), "create")
		_, err := s.AuthCodes().Consume(ctx, "h1", ref)
		mustNoErr(t, err, "first consume")
		_, err = s.AuthCodes().Consume(ctx, "h1", ref.Add(time.Second))
		wantErr(t, err, oauth.ErrAlreadyConsumed, "second consume")
		_, err = s.AuthCodes().Consume(ctx, "h1", ref.Add(time.Hour))
		wantErr(t, err, oauth.ErrAlreadyConsumed, "third consume")
	})

	t.Run("unknown code is not found", func(t *testing.T) {
		s := newStore(t, f)
		_, err := s.AuthCodes().Consume(ctx, "nope", ref)
		wantErr(t, err, oauth.ErrNotFound, "consume unknown")
	})

	t.Run("duplicate hash conflicts", func(t *testing.T) {
		s := newStore(t, f)
		mustNoErr(t, s.AuthCodes().Create(ctx, sampleCode("h1")), "create")
		wantErr(t, s.AuthCodes().Create(ctx, sampleCode("h1")), oauth.ErrConflict, "duplicate")
	})

	t.Run("expired code is still burned and returned", func(t *testing.T) {
		// Expiry is the caller's decision; storage must still consume so an
		// expired code cannot be probed repeatedly.
		s := newStore(t, f)
		c := sampleCode("h1")
		c.ExpiresAt = ref.Add(-time.Minute)
		mustNoErr(t, s.AuthCodes().Create(ctx, c), "create")
		got, err := s.AuthCodes().Consume(ctx, "h1", ref)
		mustNoErr(t, err, "consume expired")
		if !got.ExpiresAt.Equal(c.ExpiresAt) {
			t.Fatalf("ExpiresAt = %v, want %v", got.ExpiresAt, c.ExpiresAt)
		}
		_, err = s.AuthCodes().Consume(ctx, "h1", ref)
		wantErr(t, err, oauth.ErrAlreadyConsumed, "consume expired again")
	})

	t.Run("exactly one of many concurrent consumers wins", func(t *testing.T) {
		s := newStore(t, f)
		mustNoErr(t, s.AuthCodes().Create(ctx, sampleCode("race")), "create")

		const workers = 16
		var wins, replays, other atomic.Int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, err := s.AuthCodes().Consume(ctx, "race", ref)
				switch {
				case err == nil:
					wins.Add(1)
				case errors.Is(err, oauth.ErrAlreadyConsumed):
					replays.Add(1)
				default:
					other.Add(1)
					t.Errorf("unexpected error: %v", err)
				}
			}()
		}
		close(start)
		wg.Wait()
		if wins.Load() != 1 || replays.Load() != workers-1 || other.Load() != 0 {
			t.Fatalf("wins=%d replays=%d other=%d, want 1/%d/0", wins.Load(), replays.Load(), other.Load(), workers-1)
		}
	})
}

func testRefreshTokens(t *testing.T, f Factory) {
	ctx := context.Background()

	t.Run("rotate returns the stored token once", func(t *testing.T) {
		s := newStore(t, f)
		want := sampleRefresh("r1", "fam-1")
		mustNoErr(t, s.RefreshTokens().Create(ctx, want), "create")
		got, err := s.RefreshTokens().Rotate(ctx, "r1", ref)
		mustNoErr(t, err, "rotate")
		if got.TokenHash != want.TokenHash || got.FamilyID != want.FamilyID || got.ClientID != want.ClientID ||
			got.UserID != want.UserID || got.Scope != want.Scope || !got.ExpiresAt.Equal(want.ExpiresAt) {
			t.Fatalf("token mismatch\n got: %+v\nwant: %+v", got, want)
		}
		_, err = s.RefreshTokens().Rotate(ctx, "r1", ref)
		wantErr(t, err, oauth.ErrAlreadyConsumed, "rotate replay")
	})

	t.Run("unknown token is not found", func(t *testing.T) {
		s := newStore(t, f)
		_, err := s.RefreshTokens().Rotate(ctx, "nope", ref)
		wantErr(t, err, oauth.ErrNotFound, "rotate unknown")
	})

	t.Run("duplicate hash conflicts", func(t *testing.T) {
		s := newStore(t, f)
		mustNoErr(t, s.RefreshTokens().Create(ctx, sampleRefresh("r1", "fam-1")), "create")
		wantErr(t, s.RefreshTokens().Create(ctx, sampleRefresh("r1", "fam-2")), oauth.ErrConflict, "duplicate")
	})

	t.Run("revoking a family blocks every member including later children", func(t *testing.T) {
		s := newStore(t, f)
		mustNoErr(t, s.RefreshTokens().Create(ctx, sampleRefresh("r1", "fam-1")), "create r1")
		mustNoErr(t, s.RefreshTokens().Create(ctx, sampleRefresh("r2", "fam-1")), "create r2")
		mustNoErr(t, s.RefreshTokens().Create(ctx, sampleRefresh("other", "fam-2")), "create other")

		n, err := s.RefreshTokens().RevokeFamily(ctx, "fam-1", ref)
		mustNoErr(t, err, "revoke")
		if n != 2 {
			t.Fatalf("revoked = %d, want 2", n)
		}
		for _, h := range []string{"r1", "r2"} {
			_, err := s.RefreshTokens().Rotate(ctx, h, ref)
			wantErr(t, err, oauth.ErrAlreadyConsumed, "rotate revoked "+h)
		}
		// A child minted into a revoked family after the revoke (a race with
		// the replay detector) must be unusable too.
		mustNoErr(t, s.RefreshTokens().Create(ctx, sampleRefresh("late", "fam-1")), "create late")
		_, err = s.RefreshTokens().Rotate(ctx, "late", ref)
		wantErr(t, err, oauth.ErrAlreadyConsumed, "rotate late child of revoked family")
		// Other families are untouched.
		_, err = s.RefreshTokens().Rotate(ctx, "other", ref)
		mustNoErr(t, err, "rotate unrelated family")
	})

	t.Run("revoke is idempotent and tolerates unknown families", func(t *testing.T) {
		s := newStore(t, f)
		mustNoErr(t, s.RefreshTokens().Create(ctx, sampleRefresh("r1", "fam-1")), "create")
		n, err := s.RefreshTokens().RevokeFamily(ctx, "fam-1", ref)
		mustNoErr(t, err, "revoke 1")
		if n != 1 {
			t.Fatalf("first revoke = %d, want 1", n)
		}
		n, err = s.RefreshTokens().RevokeFamily(ctx, "fam-1", ref)
		mustNoErr(t, err, "revoke 2")
		if n != 0 {
			t.Fatalf("second revoke = %d, want 0", n)
		}
		n, err = s.RefreshTokens().RevokeFamily(ctx, "ghost", ref)
		mustNoErr(t, err, "revoke unknown")
		if n != 0 {
			t.Fatalf("unknown revoke = %d, want 0", n)
		}
	})

	t.Run("replay of a rotated token can revoke the family", func(t *testing.T) {
		s := newStore(t, f)
		mustNoErr(t, s.RefreshTokens().Create(ctx, sampleRefresh("r1", "fam-1")), "create r1")
		old, err := s.RefreshTokens().Rotate(ctx, "r1", ref)
		mustNoErr(t, err, "rotate r1")
		mustNoErr(t, s.RefreshTokens().Create(ctx, sampleRefresh("r2", "fam-1")), "create child")

		// Attacker replays r1: caller sees ErrAlreadyConsumed and revokes.
		_, err = s.RefreshTokens().Rotate(ctx, "r1", ref)
		wantErr(t, err, oauth.ErrAlreadyConsumed, "replay")
		_, err = s.RefreshTokens().RevokeFamily(ctx, old.FamilyID, ref)
		mustNoErr(t, err, "revoke family")
		_, err = s.RefreshTokens().Rotate(ctx, "r2", ref)
		wantErr(t, err, oauth.ErrAlreadyConsumed, "legitimate child after family revoke")
	})

	t.Run("exactly one of many concurrent rotations wins", func(t *testing.T) {
		s := newStore(t, f)
		mustNoErr(t, s.RefreshTokens().Create(ctx, sampleRefresh("race", "fam-1")), "create")

		const workers = 16
		var wins, replays atomic.Int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, err := s.RefreshTokens().Rotate(ctx, "race", ref)
				switch {
				case err == nil:
					wins.Add(1)
				case errors.Is(err, oauth.ErrAlreadyConsumed):
					replays.Add(1)
				default:
					t.Errorf("unexpected error: %v", err)
				}
			}()
		}
		close(start)
		wg.Wait()
		if wins.Load() != 1 || replays.Load() != workers-1 {
			t.Fatalf("wins=%d replays=%d, want 1/%d", wins.Load(), replays.Load(), workers-1)
		}
	})
}

func testAccessTokens(t *testing.T, f Factory) {
	ctx := context.Background()

	t.Run("create and read back round-trips", func(t *testing.T) {
		s := newStore(t, f)
		want := sampleAccessToken("j1")
		mustNoErr(t, s.AccessTokens().Create(ctx, want), "create")
		got, err := s.AccessTokens().GetByJTI(ctx, "j1")
		mustNoErr(t, err, "get")
		if got.JTI != want.JTI || got.ClientID != want.ClientID || got.UserID != want.UserID ||
			got.Scope != want.Scope || !got.IssuedAt.Equal(want.IssuedAt) || !got.ExpiresAt.Equal(want.ExpiresAt) ||
			!got.RevokedAt.IsZero() {
			t.Fatalf("token mismatch\n got: %+v\nwant: %+v", got, want)
		}
	})

	t.Run("unknown jti is not found", func(t *testing.T) {
		s := newStore(t, f)
		_, err := s.AccessTokens().GetByJTI(ctx, "nope")
		wantErr(t, err, oauth.ErrNotFound, "get unknown")
	})

	t.Run("duplicate jti conflicts", func(t *testing.T) {
		s := newStore(t, f)
		mustNoErr(t, s.AccessTokens().Create(ctx, sampleAccessToken("j1")), "create")
		wantErr(t, s.AccessTokens().Create(ctx, sampleAccessToken("j1")), oauth.ErrConflict, "duplicate")
	})

	t.Run("revoke marks active token revoked once", func(t *testing.T) {
		s := newStore(t, f)
		mustNoErr(t, s.AccessTokens().Create(ctx, sampleAccessToken("j1")), "create")
		revoked, err := s.AccessTokens().Revoke(ctx, "j1", ref)
		mustNoErr(t, err, "revoke")
		if !revoked {
			t.Fatal("first revoke reported no change")
		}
		got, err := s.AccessTokens().GetByJTI(ctx, "j1")
		mustNoErr(t, err, "get after revoke")
		if got.RevokedAt.IsZero() || !got.RevokedAt.Equal(ref) {
			t.Fatalf("RevokedAt = %v, want %v", got.RevokedAt, ref)
		}
		revoked, err = s.AccessTokens().Revoke(ctx, "j1", ref.Add(time.Minute))
		mustNoErr(t, err, "second revoke")
		if revoked {
			t.Fatal("second revoke reported a change on an already-revoked token")
		}
	})

	t.Run("revoking an unknown jti is not an error", func(t *testing.T) {
		s := newStore(t, f)
		revoked, err := s.AccessTokens().Revoke(ctx, "ghost", ref)
		mustNoErr(t, err, "revoke unknown")
		if revoked {
			t.Fatal("revoking an unknown jti reported a change")
		}
	})
}

var errAbort = errors.New("abort transaction")

func testTransactions(t *testing.T, f Factory) {
	ctx := context.Background()

	t.Run("commit makes every write visible", func(t *testing.T) {
		s := newStore(t, f)
		err := s.WithTx(ctx, func(ctx context.Context, tx oauth.Repositories) error {
			if err := tx.Clients().Create(ctx, sampleClient("client-a")); err != nil {
				return err
			}
			return tx.Users().Create(ctx, sampleUser("user-1", "alice"))
		})
		mustNoErr(t, err, "WithTx")
		_, err = s.Clients().Get(ctx, "client-a")
		mustNoErr(t, err, "client after commit")
		_, err = s.Users().GetByUsername(ctx, "alice")
		mustNoErr(t, err, "user after commit")
	})

	t.Run("error rolls back every write and is returned unchanged", func(t *testing.T) {
		s := newStore(t, f)
		err := s.WithTx(ctx, func(ctx context.Context, tx oauth.Repositories) error {
			if err := tx.Clients().Create(ctx, sampleClient("client-a")); err != nil {
				return err
			}
			if err := tx.Users().Create(ctx, sampleUser("user-1", "alice")); err != nil {
				return err
			}
			return errAbort
		})
		wantErr(t, err, errAbort, "WithTx")
		_, err = s.Clients().Get(ctx, "client-a")
		wantErr(t, err, oauth.ErrNotFound, "client after rollback")
		_, err = s.Users().GetByUsername(ctx, "alice")
		wantErr(t, err, oauth.ErrNotFound, "user after rollback")
	})

	t.Run("panic rolls back and re-panics", func(t *testing.T) {
		s := newStore(t, f)
		func() {
			defer func() {
				if r := recover(); r != "boom" {
					t.Fatalf("recovered %v, want boom", r)
				}
			}()
			_ = s.WithTx(ctx, func(ctx context.Context, tx oauth.Repositories) error {
				if err := tx.Clients().Create(ctx, sampleClient("client-a")); err != nil {
					return err
				}
				panic("boom")
			})
			t.Fatal("WithTx swallowed the panic")
		}()
		_, err := s.Clients().Get(ctx, "client-a")
		wantErr(t, err, oauth.ErrNotFound, "client after panic")
		// The store must still be usable (connection not leaked / wedged).
		mustNoErr(t, s.Clients().Create(ctx, sampleClient("client-b")), "create after panic")
	})

	t.Run("transaction reads its own writes", func(t *testing.T) {
		s := newStore(t, f)
		err := s.WithTx(ctx, func(ctx context.Context, tx oauth.Repositories) error {
			if err := tx.Clients().Create(ctx, sampleClient("client-a")); err != nil {
				return err
			}
			_, err := tx.Clients().Get(ctx, "client-a")
			return err
		})
		mustNoErr(t, err, "WithTx")
	})

	t.Run("a conflict inside a transaction rolls back earlier writes", func(t *testing.T) {
		s := newStore(t, f)
		mustNoErr(t, s.Clients().Create(ctx, sampleClient("existing")), "seed")
		err := s.WithTx(ctx, func(ctx context.Context, tx oauth.Repositories) error {
			if err := tx.Users().Create(ctx, sampleUser("user-1", "alice")); err != nil {
				return err
			}
			return tx.Clients().Create(ctx, sampleClient("existing"))
		})
		wantErr(t, err, oauth.ErrConflict, "WithTx")
		_, err = s.Users().GetByUsername(ctx, "alice")
		wantErr(t, err, oauth.ErrNotFound, "user from rolled-back tx")
	})

	t.Run("code consumption and token issuance are atomic", func(t *testing.T) {
		// The shape of the authorization-code grant: burn the code and mint
		// the refresh token together, or neither.
		s := newStore(t, f)
		mustNoErr(t, s.AuthCodes().Create(ctx, sampleCode("h1")), "create code")

		err := s.WithTx(ctx, func(ctx context.Context, tx oauth.Repositories) error {
			if _, err := tx.AuthCodes().Consume(ctx, "h1", ref); err != nil {
				return err
			}
			if err := tx.RefreshTokens().Create(ctx, sampleRefresh("r1", "fam-1")); err != nil {
				return err
			}
			return errAbort // token issuance "failed"
		})
		wantErr(t, err, errAbort, "WithTx")

		// The code must still be redeemable: the failed exchange burned nothing.
		_, err = s.AuthCodes().Consume(ctx, "h1", ref)
		mustNoErr(t, err, "consume after rolled-back exchange")
		_, err = s.RefreshTokens().Rotate(ctx, "r1", ref)
		wantErr(t, err, oauth.ErrNotFound, "token from rolled-back exchange")
	})

	t.Run("concurrent transactions redeem a code once", func(t *testing.T) {
		s := newStore(t, f)
		mustNoErr(t, s.AuthCodes().Create(ctx, sampleCode("h1")), "create code")

		const workers = 8
		var wins, replays atomic.Int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				err := s.WithTx(ctx, func(ctx context.Context, tx oauth.Repositories) error {
					if _, err := tx.AuthCodes().Consume(ctx, "h1", ref); err != nil {
						return err
					}
					return tx.RefreshTokens().Create(ctx, sampleRefresh(fmt.Sprintf("r-%d", i), "fam-1"))
				})
				switch {
				case err == nil:
					wins.Add(1)
				case errors.Is(err, oauth.ErrAlreadyConsumed):
					replays.Add(1)
				default:
					t.Errorf("unexpected error: %v", err)
				}
			}()
		}
		close(start)
		wg.Wait()
		if wins.Load() != 1 || replays.Load() != workers-1 {
			t.Fatalf("wins=%d replays=%d, want 1/%d", wins.Load(), replays.Load(), workers-1)
		}
		// Exactly one refresh token exists: the losers' inserts rolled back.
		n, err := s.RefreshTokens().RevokeFamily(ctx, "fam-1", ref)
		mustNoErr(t, err, "count family")
		if n != 1 {
			t.Fatalf("family has %d tokens, want 1", n)
		}
	})

	t.Run("canceled context aborts and leaves no writes", func(t *testing.T) {
		s := newStore(t, f)
		cctx, cancel := context.WithCancel(ctx)
		err := s.WithTx(cctx, func(ctx context.Context, tx oauth.Repositories) error {
			if err := tx.Clients().Create(ctx, sampleClient("client-a")); err != nil {
				return err
			}
			cancel()
			return ctx.Err()
		})
		if err == nil {
			t.Fatal("WithTx succeeded on a canceled context")
		}
		_, err = s.Clients().Get(ctx, "client-a")
		wantErr(t, err, oauth.ErrNotFound, "client after canceled tx")
	})
}

func testPersistence(t *testing.T, f Factory) {
	if f.NewPersistent == nil {
		t.Skip("adapter has no durable mode")
	}
	ctx := context.Background()

	t.Run("records survive close and reopen", func(t *testing.T) {
		open := f.NewPersistent(t)

		s1 := open(t)
		mustNoErr(t, s1.Clients().Create(ctx, sampleClient("client-a")), "create client")
		mustNoErr(t, s1.Users().Create(ctx, sampleUser("user-1", "alice")), "create user")
		mustNoErr(t, s1.AuthCodes().Create(ctx, sampleCode("h1")), "create code")
		mustNoErr(t, s1.RefreshTokens().Create(ctx, sampleRefresh("r1", "fam-1")), "create refresh")
		mustNoErr(t, s1.AccessTokens().Create(ctx, sampleAccessToken("j1")), "create access")
		mustNoErr(t, s1.Close(), "close")

		s2 := open(t)
		defer s2.Close()
		got, err := s2.Clients().Get(ctx, "client-a")
		mustNoErr(t, err, "client after reopen")
		assertClient(t, got, sampleClient("client-a"))
		_, err = s2.Users().GetByUsername(ctx, "alice")
		mustNoErr(t, err, "user after reopen")
		_, err = s2.AuthCodes().Consume(ctx, "h1", ref)
		mustNoErr(t, err, "code after reopen")
		_, err = s2.RefreshTokens().Rotate(ctx, "r1", ref)
		mustNoErr(t, err, "refresh after reopen")
		at, err := s2.AccessTokens().GetByJTI(ctx, "j1")
		mustNoErr(t, err, "access after reopen")
		if at.JTI != "j1" || at.ClientID != "client-a" {
			t.Fatalf("access token mismatch after reopen: %+v", at)
		}
	})

	t.Run("single-use state survives restart", func(t *testing.T) {
		// The replay guarantees must be persistent, not process-local: a code
		// burned before a restart stays burned after it.
		open := f.NewPersistent(t)

		s1 := open(t)
		mustNoErr(t, s1.AuthCodes().Create(ctx, sampleCode("h1")), "create code")
		_, err := s1.AuthCodes().Consume(ctx, "h1", ref)
		mustNoErr(t, err, "consume before restart")
		mustNoErr(t, s1.RefreshTokens().Create(ctx, sampleRefresh("r1", "fam-1")), "create r1")
		mustNoErr(t, s1.RefreshTokens().Create(ctx, sampleRefresh("r2", "fam-2")), "create r2")
		_, err = s1.RefreshTokens().Rotate(ctx, "r1", ref)
		mustNoErr(t, err, "rotate before restart")
		_, err = s1.RefreshTokens().RevokeFamily(ctx, "fam-2", ref)
		mustNoErr(t, err, "revoke before restart")
		mustNoErr(t, s1.AccessTokens().Create(ctx, sampleAccessToken("j1")), "create access")
		_, err = s1.AccessTokens().Revoke(ctx, "j1", ref)
		mustNoErr(t, err, "revoke access before restart")
		mustNoErr(t, s1.Close(), "close")

		s2 := open(t)
		defer s2.Close()
		_, err = s2.AuthCodes().Consume(ctx, "h1", ref)
		wantErr(t, err, oauth.ErrAlreadyConsumed, "code replay after restart")
		_, err = s2.RefreshTokens().Rotate(ctx, "r1", ref)
		wantErr(t, err, oauth.ErrAlreadyConsumed, "rotation replay after restart")
		_, err = s2.RefreshTokens().Rotate(ctx, "r2", ref)
		wantErr(t, err, oauth.ErrAlreadyConsumed, "revoked family after restart")
		at, err := s2.AccessTokens().GetByJTI(ctx, "j1")
		mustNoErr(t, err, "access after restart")
		if at.RevokedAt.IsZero() {
			t.Fatal("access token revocation did not survive restart")
		}
	})

	t.Run("a rolled-back transaction is not persisted", func(t *testing.T) {
		open := f.NewPersistent(t)
		s1 := open(t)
		err := s1.WithTx(ctx, func(ctx context.Context, tx oauth.Repositories) error {
			if err := tx.Clients().Create(ctx, sampleClient("client-a")); err != nil {
				return err
			}
			return errAbort
		})
		wantErr(t, err, errAbort, "WithTx")
		mustNoErr(t, s1.Close(), "close")

		s2 := open(t)
		defer s2.Close()
		_, err = s2.Clients().Get(ctx, "client-a")
		wantErr(t, err, oauth.ErrNotFound, "client after reopen")
	})

	t.Run("two handles over the same data see each other's commits", func(t *testing.T) {
		open := f.NewPersistent(t)
		a, b := open(t), open(t)
		defer a.Close()
		defer b.Close()
		mustNoErr(t, a.AuthCodes().Create(ctx, sampleCode("h1")), "create via a")
		_, err := b.AuthCodes().Consume(ctx, "h1", ref)
		mustNoErr(t, err, "consume via b")
		_, err = a.AuthCodes().Consume(ctx, "h1", ref)
		wantErr(t, err, oauth.ErrAlreadyConsumed, "replay via a")
	})

	t.Run("exactly one of two handles redeems a code", func(t *testing.T) {
		// Cross-handle atomicity stands in for cross-replica atomicity.
		open := f.NewPersistent(t)
		a, b := open(t), open(t)
		defer a.Close()
		defer b.Close()
		mustNoErr(t, a.AuthCodes().Create(ctx, sampleCode("race")), "create")

		var wins, replays atomic.Int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := range 16 {
			s := a
			if i%2 == 1 {
				s = b
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, err := s.AuthCodes().Consume(ctx, "race", ref)
				switch {
				case err == nil:
					wins.Add(1)
				case errors.Is(err, oauth.ErrAlreadyConsumed):
					replays.Add(1)
				default:
					t.Errorf("unexpected error: %v", err)
				}
			}()
		}
		close(start)
		wg.Wait()
		if wins.Load() != 1 || replays.Load() != 15 {
			t.Fatalf("wins=%d replays=%d, want 1/15", wins.Load(), replays.Load())
		}
	})
}

func testLifecycle(t *testing.T, f Factory) {
	ctx := context.Background()

	t.Run("ping succeeds on an open store", func(t *testing.T) {
		s := newStore(t, f)
		mustNoErr(t, s.Ping(ctx), "ping")
	})

	t.Run("ping fails after close", func(t *testing.T) {
		s := f.New(t)
		mustNoErr(t, s.Close(), "close")
		if err := s.Ping(ctx); err == nil {
			t.Fatal("Ping succeeded on a closed store")
		}
	})

	t.Run("close is idempotent", func(t *testing.T) {
		s := f.New(t)
		mustNoErr(t, s.Close(), "first close")
		mustNoErr(t, s.Close(), "second close")
	})

	t.Run("operations on a closed store fail", func(t *testing.T) {
		s := f.New(t)
		mustNoErr(t, s.Close(), "close")
		if err := s.Clients().Create(ctx, sampleClient("client-a")); err == nil {
			t.Fatal("Create succeeded on a closed store")
		}
		if err := s.WithTx(ctx, func(context.Context, oauth.Repositories) error { return nil }); err == nil {
			t.Fatal("WithTx succeeded on a closed store")
		}
	})
}
