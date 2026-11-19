package server_test

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
	"github.com/ianlintner/go-oauth2-server/internal/secret"
)

// newUser creates a resource owner with no stored approvals and returns a
// logged-in cookie for them.
func (e *handlerEnv) newUser(t *testing.T, id, name string, scopes ...string) string {
	t.Helper()
	h, err := secret.Hash(oauth.CryptoRandom{}, "test-only-password")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.store.Users().Create(context.Background(), oauth.User{ID: id, Username: name, PasswordHash: h, Scopes: scopes}); err != nil {
		t.Fatal(err)
	}
	rec := e.postForm("/auth/login", url.Values{"username": {name}, "password": {"test-only-password"}}.Encode())
	cs := rec.Result().Cookies()
	if rec.Code >= 400 || len(cs) != 1 {
		t.Fatalf("login = %d", rec.Code)
	}
	return cs[0].Name + "=" + cs[0].Value
}

var hiddenField = regexp.MustCompile(`name="(return_query|csrf)" value="([^"]*)"`)

// consentFields reads the hidden fields from a rendered approval page.
func consentFields(t *testing.T, body string) url.Values {
	t.Helper()
	v := url.Values{}
	for _, m := range hiddenField.FindAllStringSubmatch(body, -1) {
		v.Set(m[1], strings.NewReplacer("&amp;", "&", "&#34;", `"`, "&#39;", "'").Replace(m[2]))
	}
	if v.Get("csrf") == "" || v.Get("return_query") == "" {
		t.Fatalf("approval page has no token: %s", body)
	}
	return v
}

func TestAuthorizeDoesNotIssueCodeWithoutApproval(t *testing.T) {
	e := newHandlerEnv(t)
	c := e.newUser(t, "user-2", "bob")
	rec := e.get("/oauth/authorize?"+authQuery("client-a", callback, nil), cookie(c))
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	loc := location(t, rec)
	if loc.Path != "/auth/consent" || loc.Host != "" || loc.Query().Has("code") || strings.Contains(rec.Header().Get("Location"), "code=") {
		t.Fatalf("Location = %q, want the same-origin approval page and no code", loc)
	}
}

func TestConsentApprovalIssuesCodeAndIsRemembered(t *testing.T) {
	e := newHandlerEnv(t)
	c := e.newUser(t, "user-2", "bob")
	q := authQuery("client-a", callback, nil)

	page := e.get(location(t, e.get("/oauth/authorize?"+q, cookie(c))).String(), cookie(c))
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "client-a") {
		t.Fatalf("approval page = %d %s", page.Code, page.Body.String())
	}
	f := consentFields(t, page.Body.String())
	f.Set("decision", "approve")
	rec := e.postForm("/auth/consent", f.Encode(), cookie(c))
	if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), "/oauth/authorize?") {
		t.Fatalf("approve = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	done := e.get(rec.Header().Get("Location"), cookie(c))
	if loc := location(t, done); loc.Host != "client.example" || loc.Query().Get("code") == "" || loc.Query().Get("state") != "s1" {
		t.Fatalf("after approval Location = %q", loc)
	}
	// Remembered: the same request no longer detours.
	again := e.get("/oauth/authorize?"+q, cookie(c))
	if location(t, again).Query().Get("code") == "" {
		t.Fatalf("second request Location = %q", again.Header().Get("Location"))
	}
}

func TestConsentRefusesForgedOrMismatchedToken(t *testing.T) {
	e := newHandlerEnv(t)
	c := e.newUser(t, "user-2", "bob")
	q := authQuery("client-a", callback, nil)
	page := e.get(location(t, e.get("/oauth/authorize?"+q, cookie(c))).String(), cookie(c))
	f := consentFields(t, page.Body.String())

	post := func(mut func(url.Values), opts ...reqOpt) *http.Response {
		v := url.Values{}
		for k, vs := range f {
			v[k] = append([]string(nil), vs...)
		}
		v.Set("decision", "approve")
		mut(v)
		return e.postForm("/auth/consent", v.Encode(), opts...).Result()
	}
	if r := post(func(v url.Values) { v.Del("csrf") }, cookie(c)); r.StatusCode != http.StatusForbidden {
		t.Fatalf("missing token = %d", r.StatusCode)
	}
	if r := post(func(v url.Values) { v.Set("csrf", "forged") }, cookie(c)); r.StatusCode != http.StatusForbidden {
		t.Fatalf("forged token = %d", r.StatusCode)
	}
	// A token minted for one request cannot approve a different one.
	if r := post(func(v url.Values) { v.Set("return_query", authQuery("client-public", callback, nil)) }, cookie(c)); r.StatusCode != http.StatusForbidden {
		t.Fatalf("token reused for another client = %d", r.StatusCode)
	}
	// Another user's token is not valid for this session.
	other := e.newUser(t, "user-3", "carol")
	if r := post(func(v url.Values) {}, cookie(other)); r.StatusCode != http.StatusForbidden {
		t.Fatalf("token of another user = %d", r.StatusCode)
	}
	if r := post(func(v url.Values) {}, cookie(c), header("Sec-Fetch-Site", "cross-site")); r.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site post = %d", r.StatusCode)
	}
	if r := post(func(v url.Values) {}); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous post = %d", r.StatusCode)
	}
	// None of the refusals stored an approval.
	if _, err := e.store.Approvals().Get(context.Background(), "user-2", "client-a"); err == nil {
		t.Fatal("a refused approval was stored")
	}
}

func TestConsentDenyRedirectsAccessDeniedWithoutCode(t *testing.T) {
	e := newHandlerEnv(t)
	c := e.newUser(t, "user-2", "bob")
	page := e.get(location(t, e.get("/oauth/authorize?"+authQuery("client-a", callback, nil), cookie(c))).String(), cookie(c))
	f := consentFields(t, page.Body.String())
	f.Set("decision", "deny")
	rec := e.postForm("/auth/consent", f.Encode(), cookie(c))
	loc := location(t, rec)
	if loc.Host != "client.example" || loc.Query().Get("error") != "access_denied" || loc.Query().Has("code") || loc.Query().Get("state") != "s1" {
		t.Fatalf("deny Location = %q", loc)
	}
	if _, err := e.store.Approvals().Get(context.Background(), "user-2", "client-a"); err == nil {
		t.Fatal("deny stored an approval")
	}
}

func TestApprovalForNarrowerScopeDoesNotCoverWiderRequest(t *testing.T) {
	e := newExtEnv(t, false)
	c := e.newUser(t, "user-2", "bob")
	if err := e.store.Approvals().Put(context.Background(), oauth.Approval{UserID: "user-2", ClientID: "client-a", Scopes: []string{}, GrantedAt: e.clock.Now()}); err != nil {
		t.Fatal(err)
	}
	rec := e.get("/oauth/authorize?"+authQuery("client-a", callback, map[string]string{"scope": "read"}), cookie(c))
	if loc := location(t, rec); loc.Path != "/auth/consent" || loc.Query().Has("code") {
		t.Fatalf("wider request Location = %q, want the approval page", loc)
	}
	a, err := e.store.Approvals().Get(context.Background(), "user-2", "client-a")
	if err != nil || len(a.Scopes) != 0 {
		t.Fatalf("stored approval was widened silently: %+v %v", a, err)
	}
}

func TestAuthorizeRefusesScopeTheUserMayNotGrant(t *testing.T) {
	e := newExtEnv(t, false)
	c := e.newUser(t, "user-2", "bob", "other")
	// The client may request read, the user may only grant "other".
	if err := e.store.Approvals().Put(context.Background(), oauth.Approval{UserID: "user-2", ClientID: "client-a", Scopes: []string{"read"}, GrantedAt: e.clock.Now()}); err != nil {
		t.Fatal(err)
	}
	rec := e.get("/oauth/authorize?"+authQuery("client-a", callback, map[string]string{"scope": "read"}), cookie(c))
	loc := location(t, rec)
	if loc.Host != "client.example" || loc.Query().Get("error") != "invalid_scope" || loc.Query().Has("code") {
		t.Fatalf("Location = %q, want invalid_scope", loc)
	}
}

func TestPushedAuthorizationAlsoRequiresApproval(t *testing.T) {
	e := newExtEnv(t, false)
	c := e.newUser(t, "user-2", "bob")
	ru := pushHTTP(t, e)
	q := url.Values{"client_id": {"client-a"}, "request_uri": {ru}}.Encode()

	rec := e.get("/oauth/authorize?"+q, cookie(c))
	loc := location(t, rec)
	if rec.Code != http.StatusFound || loc.Path != "/auth/consent" || loc.Host != "" || strings.Contains(rec.Header().Get("Location"), "code=") {
		t.Fatalf("pushed authorize = %d %q, want the approval page", rec.Code, loc)
	}
	// The detour did not spend the request: approve, then it redeems once.
	page := e.get(loc.String(), cookie(c))
	if page.Code != http.StatusOK {
		t.Fatalf("approval page = %d %s", page.Code, page.Body.String())
	}
	f := consentFields(t, page.Body.String())
	f.Set("decision", "approve")
	ap := e.postForm("/auth/consent", f.Encode(), cookie(c))
	if ap.Code != http.StatusFound {
		t.Fatalf("approve = %d %s", ap.Code, ap.Body.String())
	}
	done := e.get(ap.Header().Get("Location"), cookie(c))
	if l := location(t, done); l.Host != "client.example" || l.Query().Get("code") == "" || l.Query().Get("state") != "s-par" {
		t.Fatalf("after approval Location = %q", l)
	}
}
