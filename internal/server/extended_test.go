package server_test

import (
	"context"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ianlintner/go-oauth2-server/internal/authcode"
	"github.com/ianlintner/go-oauth2-server/internal/oauth"
	"github.com/ianlintner/go-oauth2-server/internal/secret"
	"github.com/ianlintner/go-oauth2-server/internal/server"
	"github.com/ianlintner/go-oauth2-server/internal/session"
	"github.com/ianlintner/go-oauth2-server/internal/storage/sqlite"
)

const (
	devGrant = "urn:ietf:params:oauth:grant-type:device_code"
	devPass  = "test-only-dev-secret"
	parPass  = "test-only-secret"
)

// newExtEnv builds a server with a device client, a scoped PAR client, open
// registration and the conformance login, on a controllable clock.
func newExtEnv(t *testing.T, registration bool) *handlerEnv {
	return newExtEnvMode(t, registration, true)
}

func newExtEnvMode(t *testing.T, registration, conformance bool) *handlerEnv {
	t.Helper()
	st, err := sqlite.Open(sqlite.MemoryDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	rnd := oauth.CryptoRandom{}
	ctx := context.Background()
	hash := func(s string) string {
		h, e := secret.Hash(rnd, s)
		if e != nil {
			t.Fatal(e)
		}
		return h
	}
	for _, c := range []oauth.Client{
		{ID: "client-dev", Name: "Living Room TV", SecretHash: hash(devPass), AuthMethod: "client_secret_basic", RedirectURIs: []string{callback}, Scopes: []string{"read"}, GrantTypes: []string{devGrant}},
		{ID: "client-a", SecretHash: hash(parPass), AuthMethod: "client_secret_basic", RedirectURIs: []string{callback}, Scopes: []string{"read"}, GrantTypes: []string{"authorization_code"}},
		{ID: "client-enc", SecretHash: hash("other-secret"), AuthMethod: "client_secret_basic", RedirectURIs: []string{callback}, Scopes: []string{"read"}, GrantTypes: []string{"authorization_code"}},
	} {
		if err := st.Clients().Create(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Users().Create(ctx, oauth.User{ID: "user-1", Username: "alice", PasswordHash: hash("test-only-password")}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"client-dev", "client-a", "client-enc"} {
		approveClient(t, st, "user-1", id, "read")
	}
	clk := &hClock{t: time.Unix(1_700_000_000, 0).UTC()}
	svc, err := authcode.New(authcode.Config{Store: st, Clock: clk, Random: rnd})
	if err != nil {
		t.Fatal(err)
	}
	sess, err := session.New([]byte("0123456789abcdef0123456789abcdef"), clk, true)
	if err != nil {
		t.Fatal(err)
	}
	deps := server.Deps{
		Service: svc, Sessions: sess, Issuer: issuer, Conformance: conformance,
		RegistrationEnabled: registration, RegistrationScopes: []string{"openid", "read"},
	}
	return &handlerEnv{h: server.New(deps), store: st, clock: clk, deps: deps, sess: sess}
}

func (e *handlerEnv) postJSON(target, body string, opts ...reqOpt) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	for _, o := range opts {
		o(r)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, r)
	return rec
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("body %q is not JSON: %v", rec.Body.String(), err)
	}
	return m
}

func wantErrBody(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status = %d (%s), want %d", rec.Code, rec.Body.String(), status)
	}
	if got := decode(t, rec)["error"]; got != code {
		t.Fatalf("error = %v, want %s", got, code)
	}
}

func startDeviceHTTP(t *testing.T, e *handlerEnv) map[string]any {
	t.Helper()
	rec := e.postForm("/oauth/device_authorization", "client_id=client-dev&scope=read", basic("client-dev", devPass))
	if rec.Code != 200 {
		t.Fatalf("device_authorization = %d %s", rec.Code, rec.Body.String())
	}
	return decode(t, rec)
}

var csrfField = regexp.MustCompile(`name="csrf_token" value="([^"]*)"`)

// deviceForm fetches the verification page for code as the cookie's session
// and returns the anti-forgery value the page embeds.
func deviceForm(t *testing.T, e *handlerEnv, c, code string) string {
	t.Helper()
	rec := e.get("/oauth/device/verify?user_code="+url.QueryEscape(code), cookie(c))
	if rec.Code != 200 {
		t.Fatalf("verify page = %d %s", rec.Code, rec.Body.String())
	}
	m := csrfField.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("page has no form token: %s", rec.Body.String())
	}
	return html.UnescapeString(m[1])
}

func decideBody(code, action, token string) string {
	v := url.Values{"user_code": {code}, "csrf_token": {token}}
	if action != "" {
		v.Set("action", action)
	}
	return v.Encode()
}

func pollHTTP(e *handlerEnv, dc string) *httptest.ResponseRecorder {
	return e.postForm("/oauth/token", url.Values{"grant_type": {devGrant}, "device_code": {dc}, "client_id": {"client-dev"}}.Encode(), basic("client-dev", devPass))
}

// ---- device grant ----

func TestDeviceHTTPFullFlow(t *testing.T) {
	e := newExtEnv(t, false)
	d := startDeviceHTTP(t, e)
	for _, k := range []string{"device_code", "user_code", "verification_uri", "expires_in", "interval"} {
		if d[k] == nil {
			t.Fatalf("response lacks %s: %v", k, d)
		}
	}
	if d["verification_uri"] != issuer+"/oauth/device/verify" {
		t.Fatalf("verification_uri = %v", d["verification_uri"])
	}
	dc := d["device_code"].(string)

	wantErrBody(t, pollHTTP(e, dc), 400, "authorization_pending")

	c := e.login(t)
	uc := d["user_code"].(string)
	rec := e.postForm("/oauth/device/verify", decideBody(uc, "approve", deviceForm(t, e, c, uc)), cookie(c))
	if rec.Code != 200 {
		t.Fatalf("verify = %d %s", rec.Code, rec.Body.String())
	}
	e.clock.t = e.clock.t.Add(6 * time.Second)

	rec = pollHTTP(e, dc)
	if rec.Code != 200 {
		t.Fatalf("poll after approve = %d %s", rec.Code, rec.Body.String())
	}
	body := decode(t, rec)
	if body["access_token"] == nil || body["token_type"] != "Bearer" {
		t.Fatalf("token response = %v", body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("token response must not be cacheable")
	}
}

func TestDeviceHTTPDeniedIs400(t *testing.T) {
	e := newExtEnv(t, false)
	d := startDeviceHTTP(t, e)
	c := e.login(t)
	uc := d["user_code"].(string)
	rec := e.postForm("/oauth/device/verify", decideBody(uc, "deny", deviceForm(t, e, c, uc)), cookie(c))
	if rec.Code != 200 {
		t.Fatalf("verify = %d", rec.Code)
	}
	wantErrBody(t, pollHTTP(e, d["device_code"].(string)), 400, "access_denied")
}

func TestDeviceHTTPSlowDown(t *testing.T) {
	e := newExtEnv(t, false)
	d := startDeviceHTTP(t, e)
	dc := d["device_code"].(string)
	wantErrBody(t, pollHTTP(e, dc), 400, "authorization_pending")
	wantErrBody(t, pollHTTP(e, dc), 400, "slow_down")
}

func TestDeviceHTTPExpired(t *testing.T) {
	e := newExtEnv(t, false)
	d := startDeviceHTTP(t, e)
	e.clock.t = e.clock.t.Add(authcode.DefaultDeviceCodeTTL + time.Second)
	wantErrBody(t, pollHTTP(e, d["device_code"].(string)), 400, "expired_token")
}

func TestDeviceHTTPAuthorizationRejects(t *testing.T) {
	e := newExtEnv(t, false)
	cases := []struct {
		name   string
		target string
		body   string
		opts   []reqOpt
		status int
		code   string
	}{
		{"missing client", "/oauth/device_authorization", "scope=read", nil, 400, "invalid_request"},
		{"unknown client", "/oauth/device_authorization", "client_id=nobody", nil, 401, "invalid_client"},
		{"wrong secret", "/oauth/device_authorization", "client_id=client-dev", []reqOpt{basic("client-dev", "bad")}, 401, "invalid_client"},
		{"duplicate param", "/oauth/device_authorization", "client_id=client-dev&client_id=client-a", []reqOpt{basic("client-dev", devPass)}, 400, "invalid_request"},
		{"query string", "/oauth/device_authorization?client_id=client-dev", "", []reqOpt{basic("client-dev", devPass)}, 400, "invalid_request"},
		{"scope not allowed", "/oauth/device_authorization", "client_id=client-dev&scope=admin", []reqOpt{basic("client-dev", devPass)}, 400, "invalid_scope"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wantErrBody(t, e.postForm(c.target, c.body, c.opts...), c.status, c.code)
		})
	}
}

func TestDeviceHTTPIgnoresEmptyAndUnknownParams(t *testing.T) {
	e := newExtEnv(t, false)
	rec := e.postForm("/oauth/device_authorization", "client_id=client-dev&scope=&bogus_param=x", basic("client-dev", devPass))
	if rec.Code != 200 {
		t.Fatalf("status = %d %s", rec.Code, rec.Body.String())
	}
}

func TestDeviceHTTPGetNotAllowed(t *testing.T) {
	e := newExtEnv(t, false)
	if rec := e.get("/oauth/device_authorization"); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET status = %d", rec.Code)
	}
}

func TestDeviceVerifyRequiresLogin(t *testing.T) {
	e := newExtEnv(t, false)
	d := startDeviceHTTP(t, e)
	// Not signed in: cannot decide, and the device stays pending.
	rec := e.postForm("/oauth/device/verify", url.Values{"user_code": {d["user_code"].(string)}, "action": {"approve"}}.Encode())
	if rec.Code != 401 {
		t.Fatalf("anonymous verify = %d, want 401", rec.Code)
	}
	e.clock.t = e.clock.t.Add(6 * time.Second)
	wantErrBody(t, pollHTTP(e, d["device_code"].(string)), 400, "authorization_pending")
	// GET sends an anonymous browser to the login form.
	if rec := e.get("/oauth/device/verify"); rec.Code != 302 || rec.Header().Get("Location") != "/auth/login" {
		t.Fatalf("anonymous GET = %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestDeviceVerifyRefusesCrossSiteAndBadAction(t *testing.T) {
	e := newExtEnv(t, false)
	d := startDeviceHTTP(t, e)
	c := e.login(t)
	uc := d["user_code"].(string)
	tok := deviceForm(t, e, c, uc)
	if rec := e.postForm("/oauth/device/verify", decideBody(uc, "approve", tok), cookie(c), header("Sec-Fetch-Site", "cross-site")); rec.Code != 403 {
		t.Fatalf("cross-site verify = %d, want 403", rec.Code)
	}
	wantErrBody(t, e.postForm("/oauth/device/verify", decideBody(uc, "maybe", tok), cookie(c)), 400, "invalid_request")
	// Neither attempt decided anything.
	e.clock.t = e.clock.t.Add(6 * time.Second)
	wantErrBody(t, pollHTTP(e, d["device_code"].(string)), 400, "authorization_pending")
}

func TestDeviceVerifyWithoutActionDoesNotApprove(t *testing.T) {
	e := newExtEnv(t, false)
	d := startDeviceHTTP(t, e)
	c := e.login(t)
	uc := d["user_code"].(string)
	rec := e.postForm("/oauth/device/verify", decideBody(uc, "", deviceForm(t, e, c, uc)), cookie(c))
	wantErrBody(t, rec, 400, "invalid_request")
	e.clock.t = e.clock.t.Add(6 * time.Second)
	wantErrBody(t, pollHTTP(e, d["device_code"].(string)), 400, "authorization_pending")
}

func TestDeviceVerifyRejectsMissingForgeryToken(t *testing.T) {
	e := newExtEnv(t, false)
	d := startDeviceHTTP(t, e)
	c := e.login(t)
	uc := d["user_code"].(string)
	other := startDeviceHTTP(t, e)["user_code"].(string)
	for name, body := range map[string]string{
		"absent":           decideBody(uc, "approve", ""),
		"garbage":          decideBody(uc, "approve", "a.b.c"),
		"other code token": decideBody(uc, "approve", deviceForm(t, e, c, other)),
	} {
		if rec := e.postForm("/oauth/device/verify", body, cookie(c)); rec.Code != 403 {
			t.Fatalf("%s: status = %d, want 403", name, rec.Code)
		}
	}
	// A token minted for another session is refused too.
	e2 := e.login2(t)
	if rec := e.postForm("/oauth/device/verify", decideBody(uc, "approve", deviceForm(t, e, e2, uc)), cookie(c)); rec.Code != 403 {
		t.Fatalf("foreign-session token: status = %d, want 403", rec.Code)
	}
	e.clock.t = e.clock.t.Add(6 * time.Second)
	wantErrBody(t, pollHTTP(e, d["device_code"].(string)), 400, "authorization_pending")
}

func TestDeviceVerifyTokenExpires(t *testing.T) {
	e := newExtEnv(t, false)
	d := startDeviceHTTP(t, e)
	c := e.login(t)
	uc := d["user_code"].(string)
	tok := deviceForm(t, e, c, uc)
	e.clock.t = e.clock.t.Add(session.FormTokenTTL + time.Second)
	if rec := e.postForm("/oauth/device/verify", decideBody(uc, "approve", tok), cookie(c)); rec.Code != 403 {
		t.Fatalf("expired token: status = %d, want 403", rec.Code)
	}
}

func TestDeviceVerifyPageShowsClientAndScope(t *testing.T) {
	e := newExtEnv(t, false)
	d := startDeviceHTTP(t, e)
	uc := d["user_code"].(string)
	c1 := e.login(t)
	rec := e.get("/oauth/device/verify?user_code="+url.QueryEscape(uc), cookie(c1))
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, "Living Room TV") || !strings.Contains(body, "read") {
		t.Fatalf("page = %d %s", rec.Code, body)
	}
	t1 := deviceForm(t, e, c1, uc)
	e.clock.t = e.clock.t.Add(time.Second)
	t2 := deviceForm(t, e, e.login2(t), uc)
	if t1 == "" || t1 == t2 {
		t.Fatalf("form tokens must differ between sessions: %q %q", t1, t2)
	}
}

func TestDeviceVerifyPageUnknownCodeAndNoSession(t *testing.T) {
	e := newExtEnv(t, false)
	c := e.login(t)
	wantErrBody(t, e.get("/oauth/device/verify?user_code=BCDF-GHJK", cookie(c)), 400, "invalid_request")
	if rec := e.get("/oauth/device/verify?user_code=BCDF-GHJK"); rec.Code != 302 {
		t.Fatalf("anonymous = %d, want 302", rec.Code)
	}
}

func TestDeviceVerifyAnsweredRequestShowsNoForm(t *testing.T) {
	e := newExtEnv(t, false)
	d := startDeviceHTTP(t, e)
	c := e.login(t)
	uc := d["user_code"].(string)
	tok := deviceForm(t, e, c, uc)
	if rec := e.postForm("/oauth/device/verify", decideBody(uc, "approve", tok), cookie(c)); rec.Code != 200 {
		t.Fatalf("approve = %d", rec.Code)
	}
	// Replaying the same submission cannot decide again.
	wantErrBody(t, e.postForm("/oauth/device/verify", decideBody(uc, "deny", tok), cookie(c)), 400, "invalid_request")
	rec := e.get("/oauth/device/verify?user_code="+url.QueryEscape(uc), cookie(c))
	if strings.Contains(rec.Body.String(), `value="approve"`) {
		t.Fatalf("answered request still offers a decision form: %s", rec.Body.String())
	}
}

func TestDeviceVerifyUnknownCodeIsRejected(t *testing.T) {
	e := newExtEnv(t, false)
	c := e.login(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Cookie", c)
	tok, ok := e.sess.FormToken(req, "device:BCDFGHJK")
	if !ok {
		t.Fatal("no token")
	}
	rec := e.postForm("/oauth/device/verify", decideBody("BCDF-GHJK", "approve", tok), cookie(c))
	wantErrBody(t, rec, 400, "invalid_request")
}

// ---- metadata ----

func TestMetadataAdvertisesExtendedEndpoints(t *testing.T) {
	e := newExtEnv(t, true)
	m := decode(t, e.get("/.well-known/oauth-authorization-server"))
	if m["device_authorization_endpoint"] != issuer+"/oauth/device_authorization" {
		t.Fatalf("device endpoint = %v", m["device_authorization_endpoint"])
	}
	if m["pushed_authorization_request_endpoint"] != issuer+"/oauth/par" {
		t.Fatalf("par endpoint = %v", m["pushed_authorization_request_endpoint"])
	}
	if m["registration_endpoint"] != issuer+"/connect/register" {
		t.Fatalf("registration endpoint = %v", m["registration_endpoint"])
	}
	off := decode(t, newExtEnv(t, false).get("/.well-known/oauth-authorization-server"))
	if _, ok := off["registration_endpoint"]; ok {
		t.Fatal("registration_endpoint advertised although registration is off")
	}
}

// ---- PAR ----

func parBody(extra map[string]string) string {
	v := url.Values{
		"client_id": {"client-a"}, "response_type": {"code"}, "redirect_uri": {callback},
		"scope": {"read"}, "state": {"s-par"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	for k, val := range extra {
		if val == "" {
			v.Del(k)
		} else {
			v.Set(k, val)
		}
	}
	return v.Encode()
}

func pushHTTP(t *testing.T, e *handlerEnv) string {
	t.Helper()
	rec := e.postForm("/oauth/par", parBody(nil), basic("client-a", parPass))
	if rec.Code != 201 {
		t.Fatalf("par = %d %s", rec.Code, rec.Body.String())
	}
	b := decode(t, rec)
	if b["request_uri"] == nil || b["expires_in"] == nil {
		t.Fatalf("par response = %v", b)
	}
	return b["request_uri"].(string)
}

func TestPARHTTPCreatedAndSingleUse(t *testing.T) {
	e := newExtEnv(t, false)
	ru := pushHTTP(t, e)
	c := e.login(t)
	q := url.Values{"client_id": {"client-a"}, "request_uri": {ru}}.Encode()

	rec := e.get("/oauth/authorize?"+q, cookie(c))
	if rec.Code != 302 {
		t.Fatalf("authorize with request_uri = %d %s", rec.Code, rec.Body.String())
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Host != "client.example" || loc.Query().Get("code") == "" || loc.Query().Get("state") != "s-par" || loc.Query().Get("iss") != issuer {
		t.Fatalf("redirect = %s", loc)
	}
	// Second use is refused and is NOT a redirect.
	wantErrBody(t, e.get("/oauth/authorize?"+q, cookie(c)), 400, "invalid_request_uri")
}

func TestPARHTTPLoginDetourDoesNotSpendRequest(t *testing.T) {
	e := newExtEnv(t, false)
	ru := pushHTTP(t, e)
	q := url.Values{"client_id": {"client-a"}, "request_uri": {ru}}.Encode()

	rec := e.get("/oauth/authorize?" + q)
	if rec.Code != 302 || !strings.HasPrefix(rec.Header().Get("Location"), "/auth/login?return_query=") {
		t.Fatalf("anonymous authorize = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	// The round trip through the login form still resolves the request_uri.
	login := e.postForm("/auth/login", url.Values{"username": {"alice"}, "password": {"test-only-password"}, "return_query": {q}}.Encode())
	if login.Code != 302 || !strings.HasPrefix(login.Header().Get("Location"), "/oauth/authorize?") {
		t.Fatalf("login = %d %q", login.Code, login.Header().Get("Location"))
	}
	cs := login.Result().Cookies()
	final := e.get(login.Header().Get("Location"), cookie(cs[0].Name+"="+cs[0].Value))
	if final.Code != 302 || !strings.Contains(final.Header().Get("Location"), "code=") {
		t.Fatalf("authorize after login = %d %q", final.Code, final.Header().Get("Location"))
	}
}

func TestPARHTTPClientBound(t *testing.T) {
	e := newExtEnv(t, false)
	ru := pushHTTP(t, e)
	q := url.Values{"client_id": {"client-enc"}, "request_uri": {ru}}.Encode()
	rec := e.get("/oauth/authorize?"+q, cookie(e.login(t)))
	wantErrBody(t, rec, 400, "invalid_request_uri")
	if rec.Header().Get("Location") != "" {
		t.Fatal("a rejected request_uri must never redirect")
	}
}

func TestPARHTTPExpired(t *testing.T) {
	e := newExtEnv(t, false)
	ru := pushHTTP(t, e)
	e.clock.t = e.clock.t.Add(authcode.DefaultPushedRequestTTL + time.Second)
	q := url.Values{"client_id": {"client-a"}, "request_uri": {ru}}.Encode()
	wantErrBody(t, e.get("/oauth/authorize?"+q, cookie(e.login(t))), 400, "invalid_request_uri")
}

func TestPARHTTPRejects(t *testing.T) {
	e := newExtEnv(t, false)
	cases := []struct {
		name   string
		body   string
		opts   []reqOpt
		status int
		code   string
	}{
		{"client auth required", parBody(nil), nil, 401, "invalid_client"},
		{"wrong secret", parBody(nil), []reqOpt{basic("client-a", "bad")}, 401, "invalid_client"},
		{"missing response_type", parBody(map[string]string{"response_type": ""}), []reqOpt{basic("client-a", parPass)}, 400, "invalid_request"},
		{"request_uri forbidden", parBody(map[string]string{"request_uri": "urn:ietf:params:oauth:request_uri:abc"}), []reqOpt{basic("client-a", parPass)}, 400, "invalid_request"},
		{"unregistered redirect", parBody(map[string]string{"redirect_uri": "https://evil.example/cb"}), []reqOpt{basic("client-a", parPass)}, 400, "invalid_request"},
		{"implicit response type", parBody(map[string]string{"response_type": "token"}), []reqOpt{basic("client-a", parPass)}, 400, "unsupported_response_type"},
		{"duplicate parameter", parBody(nil) + "&state=other", []reqOpt{basic("client-a", parPass)}, 400, "invalid_request"},
		{"plain PKCE", parBody(map[string]string{"code_challenge_method": "plain"}), []reqOpt{basic("client-a", parPass)}, 400, "invalid_request"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wantErrBody(t, e.postForm("/oauth/par", c.body, c.opts...), c.status, c.code)
		})
	}
}

func TestPARHTTPRequestURIIsHighEntropy(t *testing.T) {
	e := newExtEnv(t, false)
	a, b := pushHTTP(t, e), pushHTTP(t, e)
	if a == b || !strings.HasPrefix(a, authcode.RequestURIPrefix) || len(a) < len(authcode.RequestURIPrefix)+32 {
		t.Fatalf("request_uri values %q %q", a, b)
	}
}

// ---- registration ----

// The OIDC nonce must survive the login round trip, or an id_token issued
// after login would silently lose it.
func TestAuthorizeCarriesNonceAcrossLogin(t *testing.T) {
	e := newExtEnv(t, false)
	q := authQuery("client-a", callback, map[string]string{"nonce": "n-0S6_WzA2Mj", "scope": "read"})
	rec := e.get("/oauth/authorize?" + q)
	if rec.Code != 302 {
		t.Fatalf("anonymous authorize = %d", rec.Code)
	}
	rq := location(t, rec).Query().Get("return_query")
	if !strings.Contains(rq, "nonce=n-0S6_WzA2Mj") {
		t.Fatalf("return_query %q lost the nonce", rq)
	}
}

func TestRegistrationNotMountedWhenDisabled(t *testing.T) {
	e := newExtEnv(t, false)
	rec := e.postJSON("/connect/register", `{"redirect_uris":["https://client.example/dyn"]}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("disabled registration = %d, want 404", rec.Code)
	}
}

func TestRegistrationHTTPCreates(t *testing.T) {
	e := newExtEnv(t, true)
	rec := e.postJSON("/connect/register", `{"redirect_uris":["https://client.example/dyn"],"client_name":"conformance-dyn","token_endpoint_auth_method":"client_secret_basic","grant_types":["authorization_code"]}`)
	if rec.Code != 201 {
		t.Fatalf("register = %d %s", rec.Code, rec.Body.String())
	}
	b := decode(t, rec)
	if b["client_id"] == nil || b["client_secret"] == nil || b["client_secret_expires_at"] == nil || b["client_name"] != "conformance-dyn" {
		t.Fatalf("response = %v", b)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("registration response carries a secret and must not be cacheable")
	}
	// The new client works end to end: PAR with the issued credentials.
	id, sec := b["client_id"].(string), b["client_secret"].(string)
	body := url.Values{"client_id": {id}, "response_type": {"code"}, "redirect_uri": {"https://client.example/dyn"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}.Encode()
	if p := e.postForm("/oauth/par", body, basic(id, sec)); p.Code != 201 {
		t.Fatalf("PAR with registered client = %d %s", p.Code, p.Body.String())
	}
}

func TestRegistrationHTTPRejects(t *testing.T) {
	e := newExtEnv(t, true)
	cases := []struct {
		name string
		body string
		ct   string
		code string
	}{
		{"invalid redirect uri", `{"redirect_uris":["not a uri"],"client_name":"bad"}`, "application/json", "invalid_redirect_uri"},
		{"missing redirect uris", `{"client_name":"bad"}`, "application/json", "invalid_redirect_uri"},
		{"redirect_uris wrong type", `{"redirect_uris":"https://x.example/cb"}`, "application/json", "invalid_redirect_uri"},
		{"jwks_uri understood but unsupported", `{"redirect_uris":["https://x.example/cb"],"jwks_uri":"https://x.example/jwks"}`, "application/json", "invalid_client_metadata"},
		{"jwks understood but unsupported", `{"redirect_uris":["https://x.example/cb"],"jwks":{"keys":[]}}`, "application/json", "invalid_client_metadata"},
		{"software statement", `{"redirect_uris":["https://x.example/cb"],"software_statement":"a.b.c"}`, "application/json", "invalid_client_metadata"},
		{"client_credentials", `{"redirect_uris":["https://x.example/cb"],"grant_types":["client_credentials"]}`, "application/json", "invalid_client_metadata"},
		{"not json", `not json`, "application/json", "invalid_client_metadata"},
		{"json array", `[]`, "application/json", "invalid_client_metadata"},
		{"wrong content type", `redirect_uris=https://x.example/cb`, "application/x-www-form-urlencoded", "invalid_client_metadata"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/connect/register", strings.NewReader(c.body))
			r.Header.Set("Content-Type", c.ct)
			rec := httptest.NewRecorder()
			e.h.ServeHTTP(rec, r)
			wantErrBody(t, rec, 400, c.code)
		})
	}
}

// RFC 7591 §2: the server must ignore metadata it does not understand.
func TestRegistrationHTTPIgnoresUnknownMetadata(t *testing.T) {
	e := newExtEnv(t, true)
	body := `{"redirect_uris":["https://x.example/cb"],"client_name":"ok","x_vendor_ext":{"a":1},"totally_unknown":"v"}`
	r := httptest.NewRequest(http.MethodPost, "/connect/register", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, r)
	if rec.Code != 201 {
		t.Fatalf("unknown metadata = %d %s, want 201", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "x_vendor_ext") || strings.Contains(rec.Body.String(), "totally_unknown") {
		t.Fatalf("response echoes ignored metadata: %s", rec.Body.String())
	}
}

func TestRegistrationHTTPBodyIsBounded(t *testing.T) {
	e := newExtEnv(t, true)
	huge := `{"redirect_uris":["https://x.example/cb"],"client_name":"` + strings.Repeat("a", 200_000) + `"}`
	wantErrBody(t, e.postJSON("/connect/register", huge), 400, "invalid_client_metadata")
}

// login2 signs in again one second later, yielding a distinct session cookie.
func (e *handlerEnv) login2(t *testing.T) string {
	t.Helper()
	e.clock.t = e.clock.t.Add(time.Second)
	return e.login(t)
}

// A link followed from another site must not spend the signed-in user's
// failure budget, while codes typed on the page itself still count.
func TestDeviceVerifyCrossSiteNavigationDoesNotSpendFailureBudget(t *testing.T) {
	e := newExtEnv(t, false)
	d := startDeviceHTTP(t, e)
	uc := d["user_code"].(string)
	c := e.login(t)

	for _, site := range []string{"cross-site", "same-site"} {
		for i := 0; i < 10; i++ {
			rec := e.get("/oauth/device/verify?user_code=BCDF-GHJK", cookie(c), header("Sec-Fetch-Site", site))
			if rec.Code != 200 || strings.Contains(rec.Body.String(), `value="approve"`) {
				t.Fatalf("%s navigation = %d %s, want the plain entry form", site, rec.Code, rec.Body.String())
			}
		}
	}
	// The budget is intact: the real code still works.
	e.postForm("/oauth/device/verify", decideBody(uc, "approve", deviceForm(t, e, c, uc)), cookie(c))
	e.clock.t = e.clock.t.Add(6 * time.Second)
	if rec := pollHTTP(e, d["device_code"].(string)); rec.Code != 200 {
		t.Fatalf("poll after approve = %d %s", rec.Code, rec.Body.String())
	}

	// Same-origin guesses are still limited.
	c2 := e.login2(t)
	for i := 0; i < 5; i++ {
		e.get("/oauth/device/verify?user_code=BCDF-GHJK", cookie(c2), header("Sec-Fetch-Site", "same-origin"))
	}
	if rec := e.get("/oauth/device/verify?user_code=BCDF-GHJK", cookie(c2), header("Sec-Fetch-Site", "same-origin")); rec.Code != 429 {
		t.Fatalf("sixth same-origin guess = %d, want 429", rec.Code)
	}
}

func TestDeviceVerifyHeaderlessNavigationDoesNotSpendDecisionBudget(t *testing.T) {
	e := newExtEnv(t, false)
	d := startDeviceHTTP(t, e)
	uc := d["user_code"].(string)
	c := e.login(t)

	for i := 0; i < 10; i++ {
		e.get("/oauth/device/verify?user_code=BCDF-GHJK", cookie(c))
	}
	// A correct lookup and decision still work for the user.
	e.clock.t = e.clock.t.Add(6 * time.Second)
	page := e.get("/oauth/device/verify?user_code="+url.QueryEscape(uc), cookie(c), header("Sec-Fetch-Site", "same-origin"))
	m := csrfField.FindStringSubmatch(page.Body.String())
	if page.Code != 200 || m == nil {
		t.Fatalf("same-origin lookup after headerless navigations = %d %s", page.Code, page.Body.String())
	}
	e.postForm("/oauth/device/verify", decideBody(uc, "approve", html.UnescapeString(m[1])), cookie(c))
	e.clock.t = e.clock.t.Add(6 * time.Second)
	if rec := pollHTTP(e, d["device_code"].(string)); rec.Code != 200 {
		t.Fatalf("poll after approve = %d %s", rec.Code, rec.Body.String())
	}
}

func TestDeviceVerifyHeaderlessLockoutFallsBackToTokenProtectedEntry(t *testing.T) {
	e := newExtEnv(t, false)
	d := startDeviceHTTP(t, e)
	uc := d["user_code"].(string)
	c := e.login(t)

	// Unsolicited headerless lookups use up the lookup-only window.
	var entry *httptest.ResponseRecorder
	for i := 0; i < 10; i++ {
		entry = e.get("/oauth/device/verify?user_code=BCDF-GHJK", cookie(c))
	}
	// The user is not locked out: they get the entry form, never a 429.
	m := csrfField.FindStringSubmatch(entry.Body.String())
	if entry.Code != 200 || m == nil || !strings.Contains(entry.Body.String(), `value="lookup"`) {
		t.Fatalf("exhausted headerless lookup = %d %s, want the token-protected entry form", entry.Code, entry.Body.String())
	}
	entryTok := html.UnescapeString(m[1])

	// A lookup without a valid entry token is refused and costs nothing.
	for i := 0; i < 10; i++ {
		v := url.Values{"user_code": {"BCDF-GHJK"}, "action": {"lookup"}}.Encode()
		if rec := e.postForm("/oauth/device/verify", v, cookie(c)); rec.Code != 403 {
			t.Fatalf("tokenless lookup = %d, want 403", rec.Code)
		}
	}
	// A code-bound decision token is not an entry token.
	// The typed lookup with the entry token works and shows the client.
	v := url.Values{"user_code": {uc}, "action": {"lookup"}, "csrf_token": {entryTok}}.Encode()
	page := e.postForm("/oauth/device/verify", v, cookie(c))
	pm := csrfField.FindStringSubmatch(page.Body.String())
	if page.Code != 200 || pm == nil || !strings.Contains(page.Body.String(), "read") {
		t.Fatalf("typed lookup = %d %s", page.Code, page.Body.String())
	}
	// The entry token cannot decide.
	if rec := e.postForm("/oauth/device/verify", decideBody(uc, "approve", entryTok), cookie(c)); rec.Code != 403 {
		t.Fatalf("decision with entry token = %d, want 403", rec.Code)
	}
	if rec := e.postForm("/oauth/device/verify", decideBody(uc, "approve", html.UnescapeString(pm[1])), cookie(c)); rec.Code != 200 {
		t.Fatalf("approve = %d %s", rec.Code, rec.Body.String())
	}
	e.clock.t = e.clock.t.Add(6 * time.Second)
	if rec := pollHTTP(e, d["device_code"].(string)); rec.Code != 200 {
		t.Fatalf("poll after approve = %d %s", rec.Code, rec.Body.String())
	}
}
