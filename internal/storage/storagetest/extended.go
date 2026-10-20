package storagetest

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
)

func sampleDevice(dh, uh string) oauth.DeviceCode {
	return oauth.DeviceCode{
		DeviceCodeHash: dh, UserCodeHash: uh, ClientID: "client-dev", Scope: "read",
		Status: oauth.DevicePending, ExpiresAt: ref.Add(10 * time.Minute), Interval: 5,
	}
}

func samplePushed(h string) oauth.PushedRequest {
	return oauth.PushedRequest{
		URIHash: h, ClientID: "client-a", RedirectURI: "https://client.example/callback",
		Scope: "read", State: "s", CodeChallenge: "challenge", Nonce: "n", ExpiresAt: ref.Add(time.Minute),
	}
}

func testDeviceCodes(t *testing.T, f Factory) {
	ctx := context.Background()

	t.Run("create and read back round-trips", func(t *testing.T) {
		s := newStore(t, f)
		want := sampleDevice("d1", "u1")
		mustNoErr(t, s.DeviceCodes().Create(ctx, want), "create")
		got, err := s.DeviceCodes().GetByHash(ctx, "d1")
		mustNoErr(t, err, "get")
		if got.UserCodeHash != "u1" || got.ClientID != "client-dev" || got.Scope != "read" ||
			got.Status != oauth.DevicePending || got.Interval != 5 || !got.ExpiresAt.Equal(want.ExpiresAt) || !got.LastPoll.IsZero() {
			t.Fatalf("mismatch: %+v", got)
		}
	})

	t.Run("unknown hash is not found", func(t *testing.T) {
		s := newStore(t, f)
		_, err := s.DeviceCodes().GetByHash(ctx, "nope")
		wantErr(t, err, oauth.ErrNotFound, "get")
		_, err = s.DeviceCodes().Decide(ctx, "nope", oauth.DeviceApproved, "user-1")
		wantErr(t, err, oauth.ErrNotFound, "decide")
		_, err = s.DeviceCodes().Consume(ctx, "nope", ref)
		wantErr(t, err, oauth.ErrNotFound, "consume")
	})

	t.Run("duplicate device or user code conflicts", func(t *testing.T) {
		s := newStore(t, f)
		mustNoErr(t, s.DeviceCodes().Create(ctx, sampleDevice("d1", "u1")), "create")
		wantErr(t, s.DeviceCodes().Create(ctx, sampleDevice("d1", "u2")), oauth.ErrConflict, "dup device code")
		wantErr(t, s.DeviceCodes().Create(ctx, sampleDevice("d2", "u1")), oauth.ErrConflict, "dup user code")
	})

	t.Run("decide latches once", func(t *testing.T) {
		s := newStore(t, f)
		mustNoErr(t, s.DeviceCodes().Create(ctx, sampleDevice("d1", "u1")), "create")
		got, err := s.DeviceCodes().Decide(ctx, "u1", oauth.DeviceApproved, "user-1")
		mustNoErr(t, err, "decide")
		if got.Status != oauth.DeviceApproved || got.UserID != "user-1" {
			t.Fatalf("decided record: %+v", got)
		}
		// A second decision, in either direction, is refused and changes nothing.
		_, err = s.DeviceCodes().Decide(ctx, "u1", oauth.DeviceDenied, "user-2")
		wantErr(t, err, oauth.ErrAlreadyConsumed, "second decide")
		again, err := s.DeviceCodes().GetByHash(ctx, "d1")
		mustNoErr(t, err, "get")
		if again.Status != oauth.DeviceApproved || again.UserID != "user-1" {
			t.Fatalf("decision was overwritten: %+v", again)
		}
	})

	t.Run("exactly one concurrent decide wins", func(t *testing.T) {
		s := newStore(t, f)
		mustNoErr(t, s.DeviceCodes().Create(ctx, sampleDevice("d1", "u1")), "create")
		var wins atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := s.DeviceCodes().Decide(ctx, "u1", oauth.DeviceApproved, "user-1"); err == nil {
					wins.Add(1)
				}
			}()
		}
		wg.Wait()
		if wins.Load() != 1 {
			t.Fatalf("%d winners, want exactly 1", wins.Load())
		}
	})

	t.Run("consume needs approval and is single use", func(t *testing.T) {
		s := newStore(t, f)
		mustNoErr(t, s.DeviceCodes().Create(ctx, sampleDevice("d1", "u1")), "create")
		_, err := s.DeviceCodes().Consume(ctx, "d1", ref)
		wantErr(t, err, oauth.ErrAlreadyConsumed, "consume while pending")
		_, err = s.DeviceCodes().Decide(ctx, "u1", oauth.DeviceApproved, "user-1")
		mustNoErr(t, err, "approve")
		got, err := s.DeviceCodes().Consume(ctx, "d1", ref)
		mustNoErr(t, err, "consume")
		if got.UserID != "user-1" {
			t.Fatalf("consumed record: %+v", got)
		}
		_, err = s.DeviceCodes().Consume(ctx, "d1", ref)
		wantErr(t, err, oauth.ErrAlreadyConsumed, "second consume")
	})

	t.Run("a denied authorization can never be consumed", func(t *testing.T) {
		s := newStore(t, f)
		mustNoErr(t, s.DeviceCodes().Create(ctx, sampleDevice("d1", "u1")), "create")
		_, err := s.DeviceCodes().Decide(ctx, "u1", oauth.DeviceDenied, "user-1")
		mustNoErr(t, err, "deny")
		_, err = s.DeviceCodes().Consume(ctx, "d1", ref)
		wantErr(t, err, oauth.ErrAlreadyConsumed, "consume denied")
	})

	t.Run("record poll persists time and interval", func(t *testing.T) {
		s := newStore(t, f)
		mustNoErr(t, s.DeviceCodes().Create(ctx, sampleDevice("d1", "u1")), "create")
		mustNoErr(t, s.DeviceCodes().RecordPoll(ctx, "d1", ref, 10), "record")
		got, err := s.DeviceCodes().GetByHash(ctx, "d1")
		mustNoErr(t, err, "get")
		if got.Interval != 10 || !got.LastPoll.Equal(ref) {
			t.Fatalf("poll state: %+v", got)
		}
	})
}

func testPushedRequests(t *testing.T, f Factory) {
	ctx := context.Background()

	t.Run("create and read back round-trips", func(t *testing.T) {
		s := newStore(t, f)
		want := samplePushed("p1")
		mustNoErr(t, s.PushedRequests().Create(ctx, want), "create")
		got, err := s.PushedRequests().GetByHash(ctx, "p1")
		mustNoErr(t, err, "get")
		if got.ClientID != want.ClientID || got.RedirectURI != want.RedirectURI || got.Scope != want.Scope ||
			got.State != want.State || got.CodeChallenge != want.CodeChallenge || got.Nonce != want.Nonce ||
			!got.ExpiresAt.Equal(want.ExpiresAt) {
			t.Fatalf("mismatch: %+v", got)
		}
	})

	t.Run("unknown hash is not found", func(t *testing.T) {
		s := newStore(t, f)
		_, err := s.PushedRequests().GetByHash(ctx, "nope")
		wantErr(t, err, oauth.ErrNotFound, "get")
		_, err = s.PushedRequests().Consume(ctx, "nope", ref)
		wantErr(t, err, oauth.ErrNotFound, "consume")
	})

	t.Run("duplicate hash conflicts", func(t *testing.T) {
		s := newStore(t, f)
		mustNoErr(t, s.PushedRequests().Create(ctx, samplePushed("p1")), "create")
		wantErr(t, s.PushedRequests().Create(ctx, samplePushed("p1")), oauth.ErrConflict, "duplicate")
	})

	t.Run("consume is single use and hides the request afterwards", func(t *testing.T) {
		s := newStore(t, f)
		mustNoErr(t, s.PushedRequests().Create(ctx, samplePushed("p1")), "create")
		_, err := s.PushedRequests().Consume(ctx, "p1", ref)
		mustNoErr(t, err, "first consume")
		_, err = s.PushedRequests().Consume(ctx, "p1", ref)
		wantErr(t, err, oauth.ErrAlreadyConsumed, "second consume")
		_, err = s.PushedRequests().GetByHash(ctx, "p1")
		wantErr(t, err, oauth.ErrNotFound, "get after consume")
	})

	t.Run("exactly one concurrent consume wins", func(t *testing.T) {
		s := newStore(t, f)
		mustNoErr(t, s.PushedRequests().Create(ctx, samplePushed("p1")), "create")
		var wins atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := s.PushedRequests().Consume(ctx, "p1", ref); err == nil {
					wins.Add(1)
				}
			}()
		}
		wg.Wait()
		if wins.Load() != 1 {
			t.Fatalf("%d winners, want exactly 1", wins.Load())
		}
	})
}
