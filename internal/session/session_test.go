package session_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ianlintner/go-oauth2-server/internal/session"
	"github.com/ianlintner/go-oauth2-server/internal/storage/sqlite"
)

type fixedClock struct{ t time.Time }

func (c *fixedClock) Now() time.Time { return c.t }

const testKey = "0123456789abcdef0123456789abcdef"

func newStore(t *testing.T) *sqlite.Store {
	t.Helper()
	st, err := sqlite.Open(sqlite.MemoryDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func newManager(t *testing.T, clk *fixedClock, secure bool) *session.Manager {
	t.Helper()
	m, err := session.New([]byte(testKey), clk, secure, newStore(t).Sessions())
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func issue(t *testing.T, m *session.Manager, user string) *http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	if err := m.Issue(context.Background(), rec, user, "pw-hash"); err != nil {
		t.Fatal(err)
	}
	cs := rec.Result().Cookies()
	if len(cs) != 1 {
		t.Fatalf("Issue set %d cookies, want 1", len(cs))
	}
	return cs[0]
}

func request(c *http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if c != nil {
		r.AddCookie(c)
	}
	return r
}

func TestRoundTrip(t *testing.T) {
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0)}
	m := newManager(t, clk, true)
	c := issue(t, m, "alice|with|pipes")

	got, ok := m.Username(request(c))
	if !ok || got != "alice|with|pipes" {
		t.Fatalf("Username = %q, %v", got, ok)
	}
}

func TestCookieAttributes(t *testing.T) {
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0)}
	c := issue(t, newManager(t, clk, true), "alice")
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" {
		t.Fatalf("cookie attrs = %+v, want HttpOnly Secure SameSite=Lax Path=/", c)
	}
	if insecure := issue(t, newManager(t, clk, false), "alice"); insecure.Secure {
		t.Fatal("Secure must follow the configuration")
	}
}

func TestRejectsMissingTamperedAndForeignCookies(t *testing.T) {
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0)}
	m := newManager(t, clk, true)
	good := issue(t, m, "alice")

	if _, ok := m.Username(request(nil)); ok {
		t.Fatal("no cookie must not authenticate")
	}

	payload, mac, _ := strings.Cut(good.Value, ".")
	forged := []string{
		"",
		"nodot",
		payload + ".",
		"." + mac,
		payload + "." + strings.ToUpper(mac),
		payload[:len(payload)-1] + "A." + mac,
		payload + "." + mac[:len(mac)-1],
	}
	for _, v := range forged {
		c := &http.Cookie{Name: good.Name, Value: v}
		if _, ok := m.Username(request(c)); ok {
			t.Errorf("forged cookie %q authenticated", v)
		}
	}

	other, err := session.New([]byte("ffffffffffffffffffffffffffffffff"), clk, true, newStore(t).Sessions())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := other.Username(request(good)); ok {
		t.Fatal("a cookie signed with another secret must not authenticate")
	}
}

func TestExpires(t *testing.T) {
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0)}
	m := newManager(t, clk, true)
	c := issue(t, m, "alice")

	clk.t = clk.t.Add(session.TTL - time.Second)
	if _, ok := m.Username(request(c)); !ok {
		t.Fatal("session must still be valid just before expiry")
	}
	clk.t = clk.t.Add(2 * time.Second)
	if _, ok := m.Username(request(c)); ok {
		t.Fatal("session must expire")
	}
}

func TestNewRejectsShortKey(t *testing.T) {
	if _, err := session.New([]byte("short"), &fixedClock{}, true, newStore(t).Sessions()); err == nil {
		t.Fatal("a short key must be refused")
	}
}

func TestNewRequiresAStore(t *testing.T) {
	if _, err := session.New([]byte(testKey), &fixedClock{}, true, nil); err == nil {
		t.Fatal("a nil store must be refused")
	}
}

func TestFormTokenBindsSessionPurposeAndExpiry(t *testing.T) {
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0)}
	m := newManager(t, clk, true)
	req := request(issue(t, m, "alice"))

	tok, ok := m.FormToken(req, "p1")
	if !ok || tok == "" {
		t.Fatal("no token for a signed-in request")
	}
	if !m.VerifyFormToken(req, "p1", tok) {
		t.Fatal("fresh token must verify")
	}
	if m.VerifyFormToken(req, "p2", tok) {
		t.Fatal("token must not verify for another purpose")
	}
	if m.VerifyFormToken(req, "p1", tok+"x") || m.VerifyFormToken(req, "p1", "") {
		t.Fatal("altered or empty token must not verify")
	}
	clk.t = clk.t.Add(time.Second)
	otherReq := request(issue(t, m, "alice"))
	if m.VerifyFormToken(otherReq, "p1", tok) {
		t.Fatal("token must not verify under another session cookie")
	}
	if _, ok := m.FormToken(httptest.NewRequest("GET", "/", nil), "p1"); ok {
		t.Fatal("no session, no token")
	}
	clk.t = clk.t.Add(session.FormTokenTTL)
	if m.VerifyFormToken(req, "p1", tok) {
		t.Fatal("token must expire")
	}
}

func TestEndRevokesTheSessionServerSide(t *testing.T) {
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0)}
	m := newManager(t, clk, true)
	c := issue(t, m, "alice")
	if _, ok := m.Username(request(c)); !ok {
		t.Fatal("fresh session must be live")
	}

	if err := m.End(httptest.NewRecorder(), request(c)); err != nil {
		t.Fatal(err)
	}
	// A copy of the cookie value must stop working, not just the browser's.
	if _, ok := m.Username(request(c)); ok {
		t.Fatal("an ended session must not authenticate")
	}
	if _, ok := m.FormToken(request(c), "p"); ok {
		t.Fatal("an ended session must not mint form tokens")
	}
}

func TestEndClearsTheCookieWithTheAttributesItWasSetWith(t *testing.T) {
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0)}
	for _, secure := range []bool{true, false} {
		m := newManager(t, clk, secure)
		set := issue(t, m, "alice")
		rec := httptest.NewRecorder()
		if err := m.End(rec, request(set)); err != nil {
			t.Fatal(err)
		}
		cs := rec.Result().Cookies()
		if len(cs) != 1 {
			t.Fatalf("End set %d cookies, want 1", len(cs))
		}
		c := cs[0]
		if c.Name != set.Name || c.Path != set.Path || c.Secure != set.Secure || c.Value != "" || c.MaxAge >= 0 {
			t.Fatalf("clearing cookie %+v does not match set cookie %+v", c, set)
		}
	}
}

func TestEndWithoutASessionStillClearsAndSucceeds(t *testing.T) {
	m := newManager(t, &fixedClock{t: time.Unix(1_700_000_000, 0)}, true)
	rec := httptest.NewRecorder()
	if err := m.End(rec, request(nil)); err != nil {
		t.Fatal(err)
	}
	if len(rec.Result().Cookies()) != 1 {
		t.Fatal("logout without a session must still emit the clearing cookie")
	}
}

func TestRevokeAllForUserEndsEverySessionOfThatUserOnly(t *testing.T) {
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0)}
	m := newManager(t, clk, true)
	a1, a2, b := issue(t, m, "alice"), issue(t, m, "alice"), issue(t, m, "bob")
	if err := m.RevokeAllForUser(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
	for _, c := range []*http.Cookie{a1, a2} {
		if _, ok := m.Username(request(c)); ok {
			t.Fatal("every session of the user must end")
		}
	}
	if _, ok := m.Username(request(b)); !ok {
		t.Fatal("another user's session must survive")
	}
}

func TestSignedCookieWithoutAServerRecordIsRefused(t *testing.T) {
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0)}
	c := issue(t, newManager(t, clk, true), "alice")
	// Same key, different (empty) store: a validly signed cookie with no
	// server-side record must not authenticate.
	if _, ok := newManager(t, clk, true).Username(request(c)); ok {
		t.Fatal("a valid signature alone must not authenticate")
	}
}

func TestCredentialCurrentTracksThePasswordHash(t *testing.T) {
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0)}
	m := newManager(t, clk, true)
	info, ok := m.Lookup(request(issue(t, m, "alice")))
	if !ok {
		t.Fatal("no session")
	}
	if !m.CredentialCurrent(info, "pw-hash") {
		t.Fatal("session must match the hash it was issued under")
	}
	if m.CredentialCurrent(info, "new-pw-hash") {
		t.Fatal("session must not match a changed credential")
	}
}
