package authcode_test

import (
	"context"
	"testing"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
)

func TestAuthorizeScopeExceedsUserScopes(t *testing.T) {
	e := newEnv(t)
	client, redirect, err := e.svc.ResolveClient(context.Background(), params(t, "client_id", "client-scoped", "redirect_uri", callback))
	if err != nil {
		t.Fatal(err)
	}
	req, err := e.svc.ValidateRequest(client, redirect, params(t,
		"response_type", "code", "client_id", "client-scoped", "redirect_uri", callback,
		"scope", "write", "code_challenge", challenge, "code_challenge_method", "S256"))
	if err != nil {
		t.Fatalf("the client may request write: %v", err)
	}
	user := oauth.User{ID: "u", Username: "u", Scopes: []string{"read"}}
	err = e.svc.CheckUserScope(user, req.Scope)
	if oe := oauth.AsError(err); oe == nil || oe.Code != oauth.CodeInvalidScope {
		t.Fatalf("CheckUserScope = %v, want invalid_scope", err)
	}
	if err := e.svc.CheckUserScope(user, "read"); err != nil {
		t.Fatalf("a scope the user may grant was refused: %v", err)
	}
	// A user with no scopes configured places no restriction of its own.
	if err := e.svc.CheckUserScope(oauth.User{ID: "u2"}, "write"); err != nil {
		t.Fatalf("unrestricted user refused: %v", err)
	}
}

func TestApprovalIsExplicitAndScoped(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ok, err := e.svc.Approved(ctx, e.user.ID, "client-scoped", "read")
	if err != nil || ok {
		t.Fatalf("Approved with no row = %v, %v; a missing row must never approve", ok, err)
	}
	if err := e.svc.RecordApproval(ctx, e.user.ID, "client-scoped", "read"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := e.svc.Approved(ctx, e.user.ID, "client-scoped", "read"); !ok {
		t.Fatal("recorded approval not honoured")
	}
	if ok, _ := e.svc.Approved(ctx, e.user.ID, "client-scoped", "read write"); ok {
		t.Fatal("approval of read covered read+write")
	}
	if ok, _ := e.svc.Approved(ctx, e.user.ID, "client-a", "read"); ok {
		t.Fatal("approval of one client covered another")
	}
}
