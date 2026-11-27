package storagetest

import (
	"context"
	"testing"
	"time"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
)

func sampleSession(id, username string) oauth.Session {
	return oauth.Session{ID: id, Username: username, ExpiresAt: ref.Add(8 * time.Hour)}
}

func testSessions(t *testing.T, f Factory) {
	ctx := context.Background()

	t.Run("a created session is active for its user until expiry", func(t *testing.T) {
		s := newStore(t, f)
		mustNoErr(t, s.Sessions().Create(ctx, sampleSession("s1", "alice")), "create")
		ok, err := s.Sessions().Active(ctx, "s1", "alice", ref)
		mustNoErr(t, err, "active")
		if !ok {
			t.Fatal("fresh session must be active")
		}
		ok, err = s.Sessions().Active(ctx, "s1", "alice", ref.Add(8*time.Hour))
		mustNoErr(t, err, "active at expiry")
		if ok {
			t.Fatal("session must not be active at its expiry")
		}
	})

	t.Run("unknown id or another username is not active", func(t *testing.T) {
		s := newStore(t, f)
		mustNoErr(t, s.Sessions().Create(ctx, sampleSession("s1", "alice")), "create")
		for _, c := range []struct{ id, user string }{{"nope", "alice"}, {"s1", "bob"}} {
			ok, err := s.Sessions().Active(ctx, c.id, c.user, ref)
			mustNoErr(t, err, "active")
			if ok {
				t.Fatalf("%+v must not be active", c)
			}
		}
	})

	t.Run("duplicate id conflicts", func(t *testing.T) {
		s := newStore(t, f)
		mustNoErr(t, s.Sessions().Create(ctx, sampleSession("s1", "alice")), "create")
		wantErr(t, s.Sessions().Create(ctx, sampleSession("s1", "bob")), oauth.ErrConflict, "duplicate")
	})

	t.Run("revoke ends one session, is idempotent and tolerates unknown ids", func(t *testing.T) {
		s := newStore(t, f)
		mustNoErr(t, s.Sessions().Create(ctx, sampleSession("s1", "alice")), "create s1")
		mustNoErr(t, s.Sessions().Create(ctx, sampleSession("s2", "alice")), "create s2")
		mustNoErr(t, s.Sessions().Revoke(ctx, "s1", ref), "revoke")
		mustNoErr(t, s.Sessions().Revoke(ctx, "s1", ref), "revoke again")
		mustNoErr(t, s.Sessions().Revoke(ctx, "unknown", ref), "revoke unknown")
		if ok, _ := s.Sessions().Active(ctx, "s1", "alice", ref); ok {
			t.Fatal("revoked session must not be active")
		}
		if ok, _ := s.Sessions().Active(ctx, "s2", "alice", ref); !ok {
			t.Fatal("revoking one session must not end another")
		}
	})

	t.Run("revoke all ends every session of the user only", func(t *testing.T) {
		s := newStore(t, f)
		mustNoErr(t, s.Sessions().Create(ctx, sampleSession("a1", "alice")), "create a1")
		mustNoErr(t, s.Sessions().Create(ctx, sampleSession("a2", "alice")), "create a2")
		mustNoErr(t, s.Sessions().Create(ctx, sampleSession("b1", "bob")), "create b1")
		mustNoErr(t, s.Sessions().RevokeAllForUser(ctx, "alice", ref), "revoke all")
		for _, id := range []string{"a1", "a2"} {
			if ok, _ := s.Sessions().Active(ctx, id, "alice", ref); ok {
				t.Fatalf("%s must be revoked", id)
			}
		}
		if ok, _ := s.Sessions().Active(ctx, "b1", "bob", ref); !ok {
			t.Fatal("another user's session must survive")
		}
	})
}
