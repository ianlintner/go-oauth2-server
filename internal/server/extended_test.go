package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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
		{ID: "client-dev", SecretHash: hash(devPass), AuthMethod: "client_secret_basic", RedirectURIs: []string{callback}, Scopes: []string{"read"}, GrantTypes: []string{devGrant}},
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
	clk := &hClock{t: time.Unix(1_700_000_000, 0).UTC()}
	svc, err := authcode.New(authcode.Config{Store: st, Clock: clk, Random: rnd})
	if err != nil {
		t.Fatal(err)
	}
	sess, err := session.New([]byte("0123456789abcdef0123456789abcdef"), clk, true)
	if err != nil {
		t.Fatal(err)
	}
	h := server.New(server.Deps{
		Service: svc, Sessions: sess, Issuer: issuer, Conformance: true,
		RegistrationEnabled: registration, RegistrationScopes: []string{"openid", "read"},
	})
	return &handlerEnv{h: h, store: st, clock: clk}
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
	rec := e.postForm("/oauth/device/verify", url.Values{"user_code": {d["user_code"].(string)}, "action": {"approve"}}.Encode(), cookie(c))
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
	rec := e.postForm("/oauth/device/verify", url.Values{"user_code": {d["user_code"].(string)}, "action": {"deny"}}.Encode(), cookie(e.login(t)))
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
	body := url.Values{"user_code": {d["user_code"].(string)}, "action": {"approve"}}.Encode()
	if rec := e.postForm("/oauth/device/verify", body, cookie(c), header("Sec-Fetch-Site", "cross-site")); rec.Code != 403 {
		t.Fatalf("cross-site verify = %d, want 403", rec.Code)
	}
	bad := url.Values{"user_code": {d["user_code"].(string)}, "action": {"maybe"}}.Encode()
	wantErrBody(t, e.postForm("/oauth/device/verify", bad, cookie(c)), 400, "invalid_request")
	// Neither attempt decided anything.
	e.clock.t = e.clock.t.Add(6 * time.Second)
	wantErrBody(t, pollHTTP(e, d["device_code"].(string)), 400, "authorization_pending")
}

func TestDeviceVerifyUnknownCodeIsRejected(t *testing.T) {
	e := newExtEnv(t, false)
	rec := e.postForm("/oauth/device/verify", "user_code=BCDF-GHJK&action=approve", cookie(e.login(t)))
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
		{"unknown member", `{"redirect_uris":["https://x.example/cb"],"jwks_uri":"https://x.example/jwks"}`, "application/json", "invalid_client_metadata"},
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

func TestRegistrationHTTPBodyIsBounded(t *testing.T) {
	e := newExtEnv(t, true)
	huge := `{"redirect_uris":["https://x.example/cb"],"client_name":"` + strings.Repeat("a", 200_000) + `"}`
	wantErrBody(t, e.postJSON("/connect/register", huge), 400, "invalid_client_metadata")
}
