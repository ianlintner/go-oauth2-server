package token_test

import (
	"context"
	"testing"

	"github.com/ianlintner/go-oauth2-server/internal/token"
)

func TestActClaimRoundTripsThroughVerifyAndIntrospect(t *testing.T) {
	svc, _ := newService(t, newKeySet(t), newStore(t))
	act := map[string]any{"sub": "agent", "iss": "https://issuer.test", "act": map[string]any{"sub": "svc", "iss": "https://issuer.test"}}
	at, err := svc.Issue(context.Background(), token.IssueParams{ClientID: "c", Subject: "alice", Scope: "read", Audience: []string{"https://issuer.test"}, Act: act})
	if err != nil {
		t.Fatal(err)
	}
	v, err := svc.VerifyAccessToken(context.Background(), at.Value)
	if err != nil {
		t.Fatal(err)
	}
	if d, ok := token.ActDepth(v.Act); !ok || d != 2 || v.Act["sub"] != "agent" {
		t.Fatalf("act = %v (depth %d, ok %v)", v.Act, d, ok)
	}
	info, err := svc.Introspect(context.Background(), at.Value)
	if err != nil || info.Act["sub"] != "agent" {
		t.Fatalf("introspect = %+v, %v", info, err)
	}
}

func TestIssueRejectsMalformedActChains(t *testing.T) {
	svc, _ := newService(t, newKeySet(t), newStore(t))
	deep := map[string]any{"sub": "s", "iss": "i"}
	for i := 0; i < token.MaxActDepth; i++ {
		deep = map[string]any{"sub": "s", "iss": "i", "act": deep}
	}
	for name, act := range map[string]map[string]any{
		"missing sub":   {"iss": "i"},
		"missing iss":   {"sub": "s"},
		"non-object":    {"sub": "s", "iss": "i", "act": "x"},
		"nested no sub": {"sub": "s", "iss": "i", "act": map[string]any{"iss": "i"}},
		"too deep":      deep,
	} {
		if _, err := svc.Issue(context.Background(), token.IssueParams{ClientID: "c", Subject: "a", Audience: []string{"https://issuer.test"}, Act: act}); err == nil {
			t.Errorf("%s: Issue accepted a malformed act claim", name)
		}
	}
}

func TestActDepth(t *testing.T) {
	if d, ok := token.ActDepth(nil); !ok || d != 0 {
		t.Fatalf("nil = %d %v", d, ok)
	}
	if d, ok := token.ActDepth(map[string]any{"sub": "s", "iss": "i"}); !ok || d != 1 {
		t.Fatalf("single = %d %v", d, ok)
	}
}
