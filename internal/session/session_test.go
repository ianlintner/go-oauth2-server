package session_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ianlintner/go-oauth2-server/internal/session"
)

type fixedClock struct{ t time.Time }

func (c *fixedClock) Now() time.Time { return c.t }

const testKey = "0123456789abcdef0123456789abcdef"

func newManager(t *testing.T, clk *fixedClock, secure bool) *session.Manager {
	t.Helper()
	m, err := session.New([]byte(testKey), clk, secure)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func issue(t *testing.T, m *session.Manager, user string) *http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Issue(rec, user)
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

	other, err := session.New([]byte("ffffffffffffffffffffffffffffffff"), clk, true)
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
	if _, err := session.New([]byte("short"), &fixedClock{}, true); err == nil {
		t.Fatal("a short key must be refused")
	}
}
