package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// authorizeLocation returns the redirect path of an authorization request made
// with the given cookie: /auth/login when nobody is signed in, the client
// callback when a session is live.
func authorizeLocation(t *testing.T, e *handlerEnv, c string) string {
	t.Helper()
	rec := e.get("/oauth/authorize?"+authQuery("client-public", callback, nil), cookie(c))
	return location(t, rec).Path
}

func TestLogoutEndsTheSession(t *testing.T) {
	e := newHandlerEnv(t)
	c := e.login(t)

	if got := authorizeLocation(t, e, c); got == "/auth/login" {
		t.Fatalf("a signed-in session must not be sent to login, got %q", got)
	}

	rec := e.postForm("/auth/logout", "", cookie(c))
	if rec.Code != http.StatusOK && rec.Code != http.StatusNoContent {
		t.Fatalf("logout = %d %q", rec.Code, rec.Body.String())
	}
	cs := rec.Result().Cookies()
	if len(cs) != 1 || cs[0].Value != "" || cs[0].MaxAge >= 0 || cs[0].Path != "/" || !cs[0].Secure {
		t.Fatalf("logout must clear the cookie with the attributes it was set with, got %+v", cs)
	}

	// The browser dropped the cookie, but a copy of the old value must be dead too.
	if got := authorizeLocation(t, e, c); got != "/auth/login" {
		t.Fatalf("an ended session must lead back to login, got %q", got)
	}
}

func TestLogoutIsIdempotentAndWorksWithoutASession(t *testing.T) {
	e := newHandlerEnv(t)
	c := e.login(t)
	for i := 0; i < 2; i++ {
		if rec := e.postForm("/auth/logout", "", cookie(c)); rec.Code != http.StatusOK {
			t.Fatalf("logout #%d = %d", i+1, rec.Code)
		}
	}
	if rec := e.postForm("/auth/logout", ""); rec.Code != http.StatusOK {
		t.Fatalf("logout without a cookie = %d", rec.Code)
	}
}

func TestLogoutLeavesOtherSessionsOfTheSameUser(t *testing.T) {
	e := newHandlerEnv(t)
	c1, c2 := e.login(t), e.login(t)
	if rec := e.postForm("/auth/logout", "", cookie(c1)); rec.Code != http.StatusOK {
		t.Fatalf("logout = %d", rec.Code)
	}
	if got := authorizeLocation(t, e, c1); got != "/auth/login" {
		t.Fatalf("ended session still live: %q", got)
	}
	if got := authorizeLocation(t, e, c2); got == "/auth/login" {
		t.Fatal("logging out one session must not end another")
	}
}

func TestLogoutRefusesCrossSiteBrowserPosts(t *testing.T) {
	e := newHandlerEnv(t)
	c := e.login(t)
	rec := e.postForm("/auth/logout", "", cookie(c), header("Sec-Fetch-Site", "cross-site"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-site logout = %d, want 403", rec.Code)
	}
	if got := authorizeLocation(t, e, c); got == "/auth/login" {
		t.Fatal("a refused logout must not end the session")
	}
}

func TestLogoutRejectsNonPOST(t *testing.T) {
	e := newHandlerEnv(t)
	if rec := e.get("/auth/logout"); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /auth/logout = %d, want 405", rec.Code)
	}
}

func TestLogoutIsNotMountedOutsideConformanceMode(t *testing.T) {
	e := newEnvMode(t, false)
	if rec := e.postForm("/auth/logout", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("POST /auth/logout without conformance = %d, want 404", rec.Code)
	}
}

func TestSessionEndsWhenThePasswordChanges(t *testing.T) {
	e := newHandlerEnv(t)
	// A session issued under a different credential than the one now stored
	// (the user changed their password since) must not be honoured.
	rec := httptest.NewRecorder()
	if err := e.sess.Issue(context.Background(), rec, "alice", "an-earlier-password-hash"); err != nil {
		t.Fatal(err)
	}
	old := rec.Result().Cookies()[0]
	if got := authorizeLocation(t, e, old.Name+"="+old.Value); got != "/auth/login" {
		t.Fatalf("a session from before a credential change must lead to login, got %q", got)
	}
	// A fresh login under the current credential works.
	if got := authorizeLocation(t, e, e.login(t)); got == "/auth/login" {
		t.Fatal("a fresh login must be honoured")
	}
}

func TestSessionRevokedForUserEndsEveryCookie(t *testing.T) {
	e := newHandlerEnv(t)
	c1, c2 := e.login(t), e.login(t)
	if err := e.sess.RevokeAllForUser(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{c1, c2} {
		if got := authorizeLocation(t, e, c); got != "/auth/login" {
			t.Fatalf("revoked session still live: %q", got)
		}
	}
}
