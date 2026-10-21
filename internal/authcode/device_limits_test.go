package authcode_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
)

func TestDeviceLimiterHoldsUnderConcurrentGuesses(t *testing.T) {
	e := newEnv(t)
	addDeviceClients(t, e)
	ctx := context.Background()
	var wg sync.WaitGroup
	var tooMany, rejected atomic.Int32
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := e.svc.DecideDevice(ctx, e.user, "BCDF-GHJK", true)
			var oe *oauth.Error
			switch {
			case errors.As(err, &oe) && oe.HTTPStatus() == 429:
				tooMany.Add(1)
			case err != nil:
				rejected.Add(1)
			}
		}()
	}
	wg.Wait()
	if rejected.Load() != 5 || tooMany.Load() != 35 {
		t.Fatalf("rejected=%d tooMany=%d, want exactly 5 guesses then 35 lockouts", rejected.Load(), tooMany.Load())
	}
}

func TestDeviceSuccessDoesNotCountAgainstLimit(t *testing.T) {
	e := newEnv(t)
	addDeviceClients(t, e)
	ctx := context.Background()
	for i := 0; i < 8; i++ {
		d := startDevice(t, e)
		if err := e.svc.DecideDevice(ctx, e.user, d.UserCode, true); err != nil {
			t.Fatalf("approval %d: %v", i, err)
		}
	}
}

func TestDeviceConsumedCodeDoesNotAnswerSlowDown(t *testing.T) {
	e := newEnv(t)
	addDeviceClients(t, e)
	d := startDevice(t, e)
	if err := e.svc.DecideDevice(context.Background(), e.user, d.UserCode, true); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(6_000_000_000)
	if _, err := pollDevice(e, t, "client-dev", d.DeviceCode); err != nil {
		t.Fatalf("redeem: %v", err)
	}
	// Polling the spent code straight away is invalid_grant, not slow_down.
	_, err := pollDevice(e, t, "client-dev", d.DeviceCode)
	wantCode(t, err, oauth.CodeInvalidGrant)
}

func TestDeniedCodeDoesNotAnswerSlowDown(t *testing.T) {
	e := newEnv(t)
	addDeviceClients(t, e)
	d := startDevice(t, e)
	if err := e.svc.DecideDevice(context.Background(), e.user, d.UserCode, false); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		_, err := pollDevice(e, t, "client-dev", d.DeviceCode)
		wantCode(t, err, oauth.CodeAccessDenied)
	}
}

func TestDeviceSlowDownIntervalIsCapped(t *testing.T) {
	e := newEnv(t)
	addDeviceClients(t, e)
	d := startDevice(t, e)
	_, _ = pollDevice(e, t, "client-dev", d.DeviceCode)
	for i := 0; i < 30; i++ {
		_, err := pollDevice(e, t, "client-dev", d.DeviceCode)
		wantCode(t, err, oauth.CodeSlowDown)
	}
	sum := sha256.Sum256([]byte(d.DeviceCode))
	rec, err := e.store.DeviceCodes().GetByHash(context.Background(), hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Interval > 60 {
		t.Fatalf("interval = %d, want capped at 60", rec.Interval)
	}
}
