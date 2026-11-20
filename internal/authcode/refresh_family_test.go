package authcode_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ianlintner/go-oauth2-server/internal/authcode"
	"github.com/ianlintner/go-oauth2-server/internal/oauth"
)

const day = 24 * time.Hour

func refreshParams(t *testing.T, rt string) oauth.Params {
	t.Helper()
	return params(t, "grant_type", "refresh_token", "refresh_token", rt)
}

func TestRefreshFamilyCannotOutliveMaxFamilyAge(t *testing.T) {
	e := newEnvWith(t, func(c *authcode.Config) {
		c.MaxConcurrentHashes = -1
		c.MaxRefreshFamilyAge = 90 * day
	})
	auth := basic("client-a", "test-only-secret")
	ctx := context.Background()

	cur, err := e.token(auth, codeParams(t, e.issue(t, "client-a", callback)))
	if err != nil || cur.RefreshToken == "" {
		t.Fatalf("initial grant = %+v, %v", cur, err)
	}
	members := []string{cur.RefreshToken}
	for i := 0; i < 3; i++ {
		e.clock.Advance(25 * day)
		cur, err = e.token(auth, refreshParams(t, cur.RefreshToken))
		if err != nil {
			t.Fatalf("rotation %d: %v", i+1, err)
		}
		members = append(members, cur.RefreshToken)
	}
	first, err := e.store.RefreshTokens().GetByHash(ctx, hashTokenHex(members[0]))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range members {
		r, err := e.store.RefreshTokens().GetByHash(ctx, hashTokenHex(m))
		if err != nil || r.FamilyID != first.FamilyID {
			t.Fatalf("member family = %q (err %v), want %q", r.FamilyID, err, first.FamilyID)
		}
	}

	e.clock.Advance(25 * day) // day 100
	_, err = e.token(auth, refreshParams(t, cur.RefreshToken))
	wantCode(t, err, oauth.CodeInvalidGrant)
	for _, m := range members {
		_, err = e.token(auth, refreshParams(t, m))
		wantCode(t, err, oauth.CodeInvalidGrant)
	}
}

func TestRefreshRotationDoesNotExtendFamilyPastCap(t *testing.T) {
	e := newEnvWith(t, func(c *authcode.Config) {
		c.MaxConcurrentHashes = -1
		c.MaxRefreshFamilyAge = 90 * day
	})
	auth := basic("client-a", "test-only-secret")
	start := e.clock.Now()

	cur, err := e.token(auth, codeParams(t, e.issue(t, "client-a", callback)))
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range []time.Duration{25 * day, 25 * day, 25 * day, 5 * day} { // days 25, 50, 75, 80
		e.clock.Advance(step)
		if cur, err = e.token(auth, refreshParams(t, cur.RefreshToken)); err != nil {
			t.Fatalf("rotation: %v", err)
		}
	}
	r, err := e.store.RefreshTokens().GetByHash(context.Background(), hashTokenHex(cur.RefreshToken))
	if err != nil {
		t.Fatal(err)
	}
	if limit := start.Add(90 * day); r.ExpiresAt.After(limit) {
		t.Fatalf("ExpiresAt %v is past the family cap %v", r.ExpiresAt, limit)
	}
	if !r.FamilyCreatedAt.Equal(start) {
		t.Fatalf("FamilyCreatedAt = %v, want %v", r.FamilyCreatedAt, start)
	}
}

// The per-token TTL and the family cap are independent limits. A token whose
// own expiry lies beyond the family cap (for example written while a longer
// cap was configured) is still refused once the family is too old, and the
// family is revoked rather than merely refused.
func TestRefreshFamilyCapRevokesFamilyWhenTokenStillLive(t *testing.T) {
	e := newEnvWith(t, func(c *authcode.Config) {
		c.MaxConcurrentHashes = -1
		c.MaxRefreshFamilyAge = 90 * day
	})
	auth := basic("client-a", "test-only-secret")
	ctx := context.Background()
	now := e.clock.Now()

	for _, h := range []string{"fam-old-1", "fam-old-2"} {
		err := e.store.RefreshTokens().Create(ctx, oauth.RefreshToken{
			TokenHash: hashTokenHex(h), FamilyID: "fam-old", ClientID: "client-a", UserID: "user-1",
			Scope: "openid", ExpiresAt: now.Add(100 * day), FamilyCreatedAt: now.Add(-100 * day),
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err := e.token(auth, refreshParams(t, "fam-old-1"))
	wantCode(t, err, oauth.CodeInvalidGrant)

	// The whole family is revoked: the sibling is latched too.
	_, err = e.store.RefreshTokens().Rotate(ctx, hashTokenHex("fam-old-2"), now)
	if !errors.Is(err, oauth.ErrAlreadyConsumed) {
		t.Fatalf("sibling Rotate = %v, want ErrAlreadyConsumed", err)
	}
}

func TestCodeGrantIssuesNoRefreshTokenWithoutTheGrant(t *testing.T) {
	e := newEnv(t)
	c := e.issue(t, "client-codeonly", callback)
	resp, err := e.token(basic("client-codeonly", "codeonly-secret"), codeParams(t, c))
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatal("no access token")
	}
	if resp.RefreshToken != "" {
		t.Fatal("refresh_token issued to a client without the refresh_token grant")
	}
}

func TestCodeGrantStillIssuesRefreshTokenForRegisteredClient(t *testing.T) {
	e := newEnv(t)
	auth := basic("client-a", "test-only-secret")
	resp, err := e.token(auth, codeParams(t, e.issue(t, "client-a", callback)))
	if err != nil || resp.RefreshToken == "" {
		t.Fatalf("resp = %+v, err = %v", resp, err)
	}
	if _, err := e.token(auth, refreshParams(t, resp.RefreshToken)); err != nil {
		t.Fatalf("rotation: %v", err)
	}
}
