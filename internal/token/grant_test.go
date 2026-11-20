package token_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
	"github.com/ianlintner/go-oauth2-server/internal/token"
)

// seedGrantRefresh stores a refresh token that belongs to grantID.
func seedGrantRefresh(t *testing.T, st oauth.Store, value, familyID, grantID, clientID string, exp time.Time) string {
	t.Helper()
	rec := oauth.RefreshToken{
		TokenHash: refreshHash(value),
		FamilyID:  familyID,
		GrantID:   grantID,
		ClientID:  clientID,
		UserID:    "u",
		Scope:     "read",
		ExpiresAt: exp,
	}
	if err := st.RefreshTokens().Create(context.Background(), rec); err != nil {
		t.Fatalf("create refresh token: %v", err)
	}
	return value
}

// issueInGrant mints an access token linked to grantID and returns its jti.
func issueInGrant(t *testing.T, svc *token.Service, clientID, grantID string) string {
	t.Helper()
	res, err := svc.Issue(context.Background(), token.IssueParams{
		ClientID: clientID,
		Subject:  "u",
		Scope:    "read",
		Audience: []string{testIssuer},
		GrantID:  grantID,
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return res.JTI
}

func accessRevoked(t *testing.T, st oauth.Store, jti string) bool {
	t.Helper()
	rec, err := st.AccessTokens().GetByJTI(context.Background(), jti)
	if err != nil {
		t.Fatalf("get access token %s: %v", jti, err)
	}
	return !rec.RevokedAt.IsZero()
}

func TestRefreshReplayRevokesFamilyAccessTokens(t *testing.T) {
	ks := newKeySet(t)
	st := newStore(t)
	svc, clk := newService(t, ks, st)
	ctx := context.Background()

	inGrant := issueInGrant(t, svc, "c1", "g1")
	otherGrant := issueInGrant(t, svc, "c1", "g2")
	unlinked := issueInGrant(t, svc, "c1", "")
	seedGrantRefresh(t, st, "rt-a", "f1", "g1", "c1", clk.t.Add(time.Hour))
	seedGrantRefresh(t, st, "rt-b", "f1", "g1", "c1", clk.t.Add(time.Hour))

	if _, err := svc.RotateRefresh(ctx, refreshHash("rt-a"), "f1"); err != nil {
		t.Fatalf("first rotate: %v", err)
	}
	if accessRevoked(t, st, inGrant) {
		t.Fatal("access token revoked by a legitimate rotation")
	}
	if _, err := svc.RotateRefresh(ctx, refreshHash("rt-a"), "f1"); !errors.Is(err, oauth.ErrAlreadyConsumed) {
		t.Fatalf("replay error = %v, want ErrAlreadyConsumed", err)
	}
	if !accessRevoked(t, st, inGrant) {
		t.Fatal("access token of the replayed grant is still active")
	}
	if accessRevoked(t, st, otherGrant) || accessRevoked(t, st, unlinked) {
		t.Fatal("replay revoked a token of another grant or an unlinked token")
	}
	// The sibling refresh token died with the family.
	if _, err := svc.RotateRefresh(ctx, refreshHash("rt-b"), "f1"); !errors.Is(err, oauth.ErrAlreadyConsumed) {
		t.Fatalf("sibling refresh token still redeemable: %v", err)
	}
}

func TestRevokeRefreshTokenRevokesItsAccessTokens(t *testing.T) {
	ks := newKeySet(t)
	st := newStore(t)
	svc, clk := newService(t, ks, st)
	ctx := context.Background()

	inGrant := issueInGrant(t, svc, "c1", "g1")
	otherGrant := issueInGrant(t, svc, "c1", "g2")
	raw := seedGrantRefresh(t, st, "rt-a", "f1", "g1", "c1", clk.t.Add(time.Hour))

	// Another client may not end the grant.
	if err := svc.Revoke(ctx, raw, "c2", ""); err != nil {
		t.Fatalf("revoke by other client: %v", err)
	}
	if accessRevoked(t, st, inGrant) {
		t.Fatal("a different client revoked the grant")
	}

	if err := svc.Revoke(ctx, raw, "c1", "refresh_token"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if !accessRevoked(t, st, inGrant) {
		t.Fatal("access token of the revoked refresh token's grant is still active")
	}
	if accessRevoked(t, st, otherGrant) {
		t.Fatal("revocation reached a token of another grant")
	}
	// Idempotent.
	if err := svc.Revoke(ctx, raw, "c1", "refresh_token"); err != nil {
		t.Fatalf("second revoke: %v", err)
	}
}

// failingTx fails every transaction, standing in for a store whose grant
// revocation cannot be applied.
type failingTx struct{ oauth.Store }

func (failingTx) WithTx(context.Context, func(context.Context, oauth.Repositories) error) error {
	return errors.New("revocation unavailable")
}

func TestReplayWithFailingRevocationFailsClosed(t *testing.T) {
	ks := newKeySet(t)
	st := newStore(t)
	_, clk := newService(t, ks, st)
	svc, _ := newService(t, ks, failingTx{st})
	ctx := context.Background()

	seedGrantRefresh(t, st, "rt-a", "f1", "g1", "c1", clk.t.Add(time.Hour))
	if _, err := svc.RotateRefresh(ctx, refreshHash("rt-a"), "f1"); err != nil {
		t.Fatalf("first rotate: %v", err)
	}
	_, err := svc.RotateRefresh(ctx, refreshHash("rt-a"), "f1")
	var oe *oauth.Error
	if !errors.As(err, &oe) || oe.Code != oauth.CodeServerError {
		t.Fatalf("replay with failing revocation = %v, want server_error", err)
	}
	if errors.Is(err, oauth.ErrAlreadyConsumed) {
		t.Fatal("failed revocation was reported as a handled replay")
	}

	// Explicit revocation fails closed too.
	raw := seedGrantRefresh(t, st, "rt-c", "f2", "g2", "c1", clk.t.Add(time.Hour))
	err = svc.Revoke(ctx, raw, "c1", "refresh_token")
	if !errors.As(err, &oe) || oe.Code != oauth.CodeServerError {
		t.Fatalf("revoke with failing revocation = %v, want server_error", err)
	}
}

func TestLegacyRefreshWithoutGrantFallsBackToFamily(t *testing.T) {
	ks := newKeySet(t)
	st := newStore(t)
	svc, clk := newService(t, ks, st)
	ctx := context.Background()

	// A record that predates grant linking: no grant id, so the family id
	// stands in for it.
	linked := issueInGrant(t, svc, "c1", "f-old")
	raw := seedGrantRefresh(t, st, "rt-old", "f-old", "", "c1", clk.t.Add(time.Hour))
	if err := svc.Revoke(ctx, raw, "c1", ""); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if !accessRevoked(t, st, linked) {
		t.Fatal("access token linked by family id survived revocation")
	}
}
