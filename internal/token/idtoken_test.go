package token_test

import (
	"context"
	"testing"
	"time"

	"github.com/ianlintner/go-oauth2-server/internal/jwt"
	"github.com/ianlintner/go-oauth2-server/internal/token"
)

func newIDService(t *testing.T) *token.Service {
	t.Helper()
	ks := newKeySet(t)
	svc, err := token.New(token.Config{
		Issuer:     testIssuer,
		Signer:     jwt.NewSigner(ks, jwt.WithType("at+jwt")),
		Verifier:   jwt.NewVerifier(ks, jwt.WithRequiredType("at+jwt")),
		IDSigner:   jwt.NewSigner(ks),
		IDVerifier: jwt.NewVerifier(ks),
		Keys:       ks,
		Store:      newStore(t),
		Clock:      &fixedClock{t: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)},
		Random:     &seqRandom{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestIssueIDTokenClaims(t *testing.T) {
	svc := newIDService(t)
	idt, err := svc.IssueIDToken(context.Background(), token.IDTokenParams{ClientID: "client-a", Subject: "user-1", Nonce: "n-0S6"})
	if err != nil {
		t.Fatal(err)
	}
	c := rawClaims(t, idt)
	if c["iss"] != testIssuer || c["sub"] != "user-1" || c["aud"] != "client-a" || c["nonce"] != "n-0S6" {
		t.Fatalf("claims = %v", c)
	}
	iat, _ := c["iat"].(float64)
	exp, _ := c["exp"].(float64)
	if iat == 0 || exp <= iat {
		t.Fatalf("iat=%v exp=%v", iat, exp)
	}
}

func TestIssueIDTokenOmitsEmptyNonce(t *testing.T) {
	svc := newIDService(t)
	idt, err := svc.IssueIDToken(context.Background(), token.IDTokenParams{ClientID: "client-a", Subject: "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rawClaims(t, idt)["nonce"]; ok {
		t.Fatal("nonce present without request nonce")
	}
}

func TestIssueIDTokenFailsClosedWithoutSigner(t *testing.T) {
	svc, _ := newService(t, newKeySet(t), newStore(t))
	if _, err := svc.IssueIDToken(context.Background(), token.IDTokenParams{ClientID: "c", Subject: "u"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestVerifyIDTokenHintRoundTripAndForeignIssuer(t *testing.T) {
	svc := newIDService(t)
	idt, _ := svc.IssueIDToken(context.Background(), token.IDTokenParams{ClientID: "client-a", Subject: "u"})
	c, err := svc.VerifyIDTokenHint(context.Background(), idt)
	if err != nil || c["aud"] != "client-a" {
		t.Fatalf("claims=%v err=%v", c, err)
	}
	if _, err := svc.VerifyIDTokenHint(context.Background(), "garbage"); err == nil {
		t.Fatal("garbage accepted")
	}
}
