package server_test

import (
	"context"
	"encoding/base64"
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
	issuer    = "https://issuer.example"
	callback  = "https://client.example/callback"
	verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

type hClock struct{ t time.Time }

func (c *hClock) Now() time.Time { return c.t }

type handlerEnv struct {
	h     http.Handler
	store oauth.Store
	clock *hClock
}

func newHandlerEnv(t *testing.T) *handlerEnv { return newEnvMode(t, true) }

func newEnvMode(t *testing.T, conformance bool) *handlerEnv {
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
	clients := []oauth.Client{
		{ID: "client-a", SecretHash: hash("test-only-secret"), AuthMethod: "client_secret_basic", RedirectURIs: []string{callback}, GrantTypes: []string{"authorization_code"}},
		{ID: "client-public", Public: true, AuthMethod: "none", RedirectURIs: []string{callback}, GrantTypes: []string{"authorization_code"}},
		{ID: "client-loop", Public: true, AuthMethod: "none", RedirectURIs: []string{"http://127.0.0.1/cb"}, GrantTypes: []string{"authorization_code"}},
		{ID: "client-query", Public: true, AuthMethod: "none", RedirectURIs: []string{"https://client.example/cb?tenant=7"}, GrantTypes: []string{"authorization_code"}},
	}
	for _, c := range clients {
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
	h := server.New(server.Deps{Service: svc, Sessions: sess, Issuer: issuer, Conformance: conformance})
	return &handlerEnv{h: h, store: st, clock: clk}
}

type reqOpt func(*http.Request)

func header(k, v string) reqOpt { return func(r *http.Request) { r.Header.Set(k, v) } }
func cookie(c string) reqOpt {
	return func(r *http.Request) {
		if c != "" {
			r.Header.Set("Cookie", c)
		}
	}
}

func (e *handlerEnv) get(target string, opts ...reqOpt) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	for _, o := range opts {
		o(r)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, r)
	return rec
}

func (e *handlerEnv) postForm(target, body string, opts ...reqOpt) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, o := range opts {
		o(r)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, r)
	return rec
}

func basic(id, sec string) reqOpt {
	return header("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(id+":"+sec)))
}

func (e *handlerEnv) login(t *testing.T) string {
	t.Helper()
	rec := e.postForm("/auth/login", "username=alice&password=test-only-password")
	if rec.Code >= 400 {
		t.Fatalf("login = %d %q", rec.Code, rec.Body.String())
	}
	cs := rec.Result().Cookies()
	if len(cs) != 1 {
		t.Fatalf("login set %d cookies", len(cs))
	}
	return cs[0].Name + "=" + cs[0].Value
}

func authQuery(clientID, redirect string, override map[string]string) string {
	v := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirect},
		"state": {"s1"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	for k, val := range override {
		if val == "" {
			v.Del(k)
		} else {
			v.Set(k, val)
		}
	}
	return v.Encode()
}

func jsonBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v: %q", err, rec.Body.String())
	}
	return body
}

func location(t *testing.T, rec *httptest.ResponseRecorder) *url.URL {
	t.Helper()
	raw := rec.Header().Get("Location")
	u, err := url.Parse(raw)
	if err != nil || raw == "" {
		t.Fatalf("Location %q: %v", raw, err)
	}
	return u
}

func (e *handlerEnv) issueCode(t *testing.T, clientID, redirect string) string {
	t.Helper()
	c := e.login(t)
	rec := e.get("/oauth/authorize?"+authQuery(clientID, redirect, nil), cookie(c))
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize = %d %q", rec.Code, rec.Body.String())
	}
	code := location(t, rec).Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %q", rec.Header().Get("Location"))
	}
	return code
}

func codeForm(code string, kv ...string) string {
	v := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {callback}, "code_verifier": {verifier}}
	for i := 0; i < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	return v.Encode()
}

// ---- authorization endpoint ----

func TestAuthorizeRedirectsAnonymousBrowserToLoginPreservingTheRequest(t *testing.T) {
	e := newHandlerEnv(t)
	rec := e.get("/oauth/authorize?" + authQuery("client-a", callback, nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	loc := location(t, rec)
	if loc.Path != "/auth/login" || loc.Host != "" {
		t.Fatalf("login redirect must be same-origin /auth/login, got %q", loc.String())
	}
	if loc.Query().Get("return_query") != authQuery("client-a", callback, nil) {
		t.Fatalf("return_query = %q", loc.Query().Get("return_query"))
	}
}

func TestAuthorizeIssuesCodeWithStateAndIssuerForALoggedInUser(t *testing.T) {
	e := newHandlerEnv(t)
	rec := e.get("/oauth/authorize?"+authQuery("client-a", callback, nil), cookie(e.login(t)))
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	loc := location(t, rec)
	if loc.Scheme+"://"+loc.Host+loc.Path != callback {
		t.Fatalf("redirect target = %q", loc.String())
	}
	q := loc.Query()
	if q.Get("code") == "" || q.Get("state") != "s1" || q.Get("iss") != issuer || q.Has("error") {
		t.Fatalf("query = %v", q)
	}
	// RFC 9207 §2.1: iss is form-urlencoded on the wire.
	if !strings.Contains(loc.RawQuery, "iss=https%3A%2F%2Fissuer.example") {
		t.Fatalf("raw query = %q, iss must be form-urlencoded", loc.RawQuery)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q", cc)
	}
}

func TestAuthorizeKeepsExistingQueryOfRegisteredRedirectURI(t *testing.T) {
	e := newHandlerEnv(t)
	rec := e.get("/oauth/authorize?"+authQuery("client-query", "https://client.example/cb?tenant=7", nil), cookie(e.login(t)))
	loc := location(t, rec)
	if loc.Query().Get("tenant") != "7" || loc.Query().Get("code") == "" || strings.Count(loc.RawQuery, "?") != 0 {
		t.Fatalf("Location = %q", loc.String())
	}
}

func TestAuthorizeLoopbackRedirectUsesTheRequestedPort(t *testing.T) {
	e := newHandlerEnv(t)
	rec := e.get("/oauth/authorize?"+authQuery("client-loop", "http://127.0.0.1:9999/cb", nil), cookie(e.login(t)))
	if got := rec.Header().Get("Location"); !strings.HasPrefix(got, "http://127.0.0.1:9999/cb?") {
		t.Fatalf("Location = %q", got)
	}
}

func TestAuthorizeNeverRedirectsOnClientOrRedirectURIErrors(t *testing.T) {
	e := newHandlerEnv(t)
	tests := []struct {
		name   string
		query  string
		status int
		code   string
	}{
		{"missing client_id", authQuery("", callback, map[string]string{"client_id": ""}), 400, "invalid_request"},
		{"unknown client", authQuery("nobody", callback, nil), 401, "invalid_client"},
		{"unregistered redirect", authQuery("client-a", "https://evil.example/cb", nil), 400, "invalid_request"},
		{"http redirect for https registration", authQuery("client-a", "http://client.example/callback", nil), 400, "invalid_request"},
		{"missing redirect_uri", authQuery("client-a", "", map[string]string{"redirect_uri": ""}), 400, "invalid_request"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := e.get("/oauth/authorize?"+tc.query, cookie(e.login(t)))
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d (%q)", rec.Code, tc.status, rec.Body.String())
			}
			if rec.Header().Get("Location") != "" {
				t.Fatalf("must not redirect, got Location %q", rec.Header().Get("Location"))
			}
			if got := jsonBody(t, rec)["error"]; got != tc.code {
				t.Fatalf("error = %v, want %s", got, tc.code)
			}
		})
	}
}

func TestAuthorizeDeliversRequestErrorsByRedirectWithStateAndIssuer(t *testing.T) {
	e := newHandlerEnv(t)
	tests := []struct {
		name string
		q    map[string]string
		code string
	}{
		{"implicit token", map[string]string{"response_type": "token", "code_challenge": "", "code_challenge_method": ""}, "unsupported_response_type"},
		{"missing response_type", map[string]string{"response_type": ""}, "invalid_request"},
		{"missing challenge", map[string]string{"code_challenge": ""}, "invalid_request"},
		{"method without challenge", map[string]string{"code_challenge": ""}, "invalid_request"},
		{"plain method", map[string]string{"code_challenge_method": "plain", "code_challenge": verifier}, "invalid_request"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Errors are delivered before (and without) any login.
			rec := e.get("/oauth/authorize?" + authQuery("client-public", callback, tc.q))
			if rec.Code != http.StatusFound {
				t.Fatalf("status = %d, want 302", rec.Code)
			}
			loc := location(t, rec)
			if loc.Scheme+"://"+loc.Host+loc.Path != callback {
				t.Fatalf("Location = %q", loc.String())
			}
			q := loc.Query()
			if q.Get("error") != tc.code || q.Get("state") != "s1" || q.Get("iss") != issuer || q.Has("code") {
				t.Fatalf("query = %v", q)
			}
		})
	}
}

func TestAuthorizeRejectsDuplicatedParametersBeforeReadingAnyValue(t *testing.T) {
	e := newHandlerEnv(t)
	base := authQuery("client-a", callback, nil)
	cookieHdr := cookie(e.login(t))
	for _, dup := range []string{
		"client_id=client-public",              // second client_id
		"redirect_uri=https://evil.example/cb", // second redirect_uri
		"state=other",
		"code_challenge=" + challenge,
		"code_challenge_method=S256",
		"response_type=code",
		"scope=read&scope=read",
	} {
		t.Run(dup, func(t *testing.T) {
			rec := e.get("/oauth/authorize?"+base+"&"+dup, cookieHdr)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
			if rec.Header().Get("Location") != "" {
				t.Fatalf("a request with duplicated parameters must never be redirected: %q", rec.Header().Get("Location"))
			}
			if got := jsonBody(t, rec)["error"]; got != "invalid_request" {
				t.Fatalf("error = %v", got)
			}
		})
	}
}

func TestAuthorizeRejectsMalformedQuery(t *testing.T) {
	e := newHandlerEnv(t)
	rec := e.get("/oauth/authorize?client_id=%zz")
	if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
		t.Fatalf("status = %d location = %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestAuthorizeIgnoresSessionOfAnUnknownUser(t *testing.T) {
	e := newHandlerEnv(t)
	sess, _ := session.New([]byte("0123456789abcdef0123456789abcdef"), e.clock, true)
	rec := httptest.NewRecorder()
	sess.Issue(rec, "ghost")
	c := rec.Result().Cookies()[0]
	out := e.get("/oauth/authorize?"+authQuery("client-a", callback, nil), cookie(c.Name+"="+c.Value))
	if loc := location(t, out); loc.Path != "/auth/login" {
		t.Fatalf("a session for a deleted user must lead back to login, got %q", loc.String())
	}
}

func TestAuthorizeRejectsNonGET(t *testing.T) {
	e := newHandlerEnv(t)
	rec := e.postForm("/oauth/authorize", authQuery("client-a", callback, nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

// ---- token endpoint ----

func TestTokenEndpointRedeemsOnceAndSendsNoStore(t *testing.T) {
	e := newHandlerEnv(t)
	code := e.issueCode(t, "client-a", callback)

	rec := e.postForm("/oauth/token", codeForm(code), basic("client-a", "test-only-secret"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d %q", rec.Code, rec.Body.String())
	}
	body := jsonBody(t, rec)
	if body["access_token"] == "" || body["token_type"] != "Bearer" {
		t.Fatalf("body = %v", body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("headers = %v", rec.Header())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type = %q", ct)
	}

	replay := e.postForm("/oauth/token", codeForm(code), basic("client-a", "test-only-secret"))
	if replay.Code != http.StatusBadRequest || jsonBody(t, replay)["error"] != "invalid_grant" {
		t.Fatalf("replay = %d %q", replay.Code, replay.Body.String())
	}
}

func TestTokenEndpointRejectsDuplicatedParametersWithoutBurningTheCode(t *testing.T) {
	e := newHandlerEnv(t)
	code := e.issueCode(t, "client-a", callback)
	auth := basic("client-a", "test-only-secret")

	for _, dup := range []string{
		"&code_verifier=" + verifier,
		"&code=" + code,
		"&redirect_uri=" + url.QueryEscape(callback),
		"&grant_type=authorization_code",
		"&client_id=client-a&client_id=client-a",
	} {
		rec := e.postForm("/oauth/token", codeForm(code)+dup, auth)
		if rec.Code != http.StatusBadRequest || jsonBody(t, rec)["error"] != "invalid_request" {
			t.Fatalf("dup %q: %d %q", dup, rec.Code, rec.Body.String())
		}
	}
	// The malformed requests never reached redemption: the code is still good.
	if rec := e.postForm("/oauth/token", codeForm(code), auth); rec.Code != http.StatusOK {
		t.Fatalf("code was burned by a rejected request: %d %q", rec.Code, rec.Body.String())
	}
}

func TestTokenEndpointRejectsParametersInTheQueryString(t *testing.T) {
	e := newHandlerEnv(t)
	rec := e.postForm("/oauth/token?client_secret=test-only-secret", "grant_type=authorization_code", basic("client-a", "test-only-secret"))
	if rec.Code != http.StatusBadRequest || jsonBody(t, rec)["error"] != "invalid_request" {
		t.Fatalf("%d %q", rec.Code, rec.Body.String())
	}
}

func TestTokenEndpointRequiresFormContentType(t *testing.T) {
	e := newHandlerEnv(t)
	for _, ct := range []string{"", "application/json", "text/plain"} {
		r := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(`{"grant_type":"authorization_code"}`))
		if ct != "" {
			r.Header.Set("Content-Type", ct)
		}
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, r)
		if rec.Code != http.StatusBadRequest || jsonBody(t, rec)["error"] != "invalid_request" {
			t.Fatalf("content-type %q: %d %q", ct, rec.Code, rec.Body.String())
		}
	}
}

func TestTokenEndpointBoundsTheBody(t *testing.T) {
	e := newHandlerEnv(t)
	rec := e.postForm("/oauth/token", "grant_type=authorization_code&code="+strings.Repeat("a", 1<<20))
	if rec.Code != http.StatusBadRequest || jsonBody(t, rec)["error"] != "invalid_request" {
		t.Fatalf("%d %q", rec.Code, rec.Body.String()[:min(80, rec.Body.Len())])
	}
}

func TestTokenEndpointRejectsNonPOST(t *testing.T) {
	e := newHandlerEnv(t)
	rec := e.get("/oauth/token")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestTokenEndpointFailedBasicAuthChallenges(t *testing.T) {
	e := newHandlerEnv(t)
	rec := e.postForm("/oauth/token", "grant_type=authorization_code", basic("client-a", "wrong"))
	if rec.Code != http.StatusUnauthorized || jsonBody(t, rec)["error"] != "invalid_client" {
		t.Fatalf("%d %q", rec.Code, rec.Body.String())
	}
	if !strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "Basic ") {
		t.Fatalf("WWW-Authenticate = %q", rec.Header().Get("WWW-Authenticate"))
	}
}

func TestTokenErrorsNeverEchoTheSecret(t *testing.T) {
	e := newHandlerEnv(t)
	rec := e.postForm("/oauth/token", "grant_type=authorization_code", basic("client-a", "super-secret-attempt"))
	if strings.Contains(rec.Body.String(), "super-secret-attempt") {
		t.Fatalf("secret echoed: %q", rec.Body.String())
	}
}

// ---- login ----

func TestLoginFormEscapesTheReturnQuery(t *testing.T) {
	e := newHandlerEnv(t)
	evil := `"><script>alert(1)</script>`
	rec := e.get("/auth/login?return_query=" + url.QueryEscape(evil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "<script>") {
		t.Fatalf("return_query was not escaped: %q", rec.Body.String())
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q", cc)
	}
}

func TestLoginSuccessSetsHardenedSessionCookie(t *testing.T) {
	e := newHandlerEnv(t)
	rec := e.postForm("/auth/login", "username=alice&password=test-only-password")
	cs := rec.Result().Cookies()
	if len(cs) != 1 || !cs[0].HttpOnly || !cs[0].Secure || cs[0].SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookies = %+v", cs)
	}
}

func TestLoginResumesTheAuthorizationRequestWithoutOpenRedirect(t *testing.T) {
	e := newHandlerEnv(t)
	q := authQuery("client-a", callback, nil)
	rec := e.postForm("/auth/login", url.Values{"username": {"alice"}, "password": {"test-only-password"}, "return_query": {q}}.Encode())
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d", rec.Code)
	}
	loc := location(t, rec)
	if loc.Host != "" || loc.Path != "/oauth/authorize" || loc.RawQuery != q {
		t.Fatalf("Location = %q", loc.String())
	}
}

func TestLoginRejectsBadCredentialsAndMalformedBodies(t *testing.T) {
	e := newHandlerEnv(t)
	tests := []struct {
		name   string
		body   string
		status int
	}{
		{"wrong password", "username=alice&password=nope", 403},
		{"unknown user", "username=mallory&password=x", 403},
		{"empty password", "username=alice&password=", 403},
		{"empty body", "", 403},
		{"duplicate password", "username=alice&password=test-only-password&password=x", 400},
		{"duplicate username", "username=alice&username=bob&password=test-only-password", 400},
		{"malformed encoding", "username=%zz", 400},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := e.postForm("/auth/login", tc.body)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d", rec.Code, tc.status)
			}
			if len(rec.Result().Cookies()) != 0 {
				t.Fatal("a failed login must not set a session")
			}
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("Cache-Control = %q", rec.Header().Get("Cache-Control"))
			}
		})
	}
}

func TestLoginRefusesCrossSiteBrowserPosts(t *testing.T) {
	e := newHandlerEnv(t)
	rec := e.postForm("/auth/login", "username=alice&password=test-only-password", header("Sec-Fetch-Site", "cross-site"))
	if rec.Code != http.StatusForbidden || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("status = %d cookies = %v", rec.Code, rec.Result().Cookies())
	}
	same := e.postForm("/auth/login", "username=alice&password=test-only-password", header("Sec-Fetch-Site", "same-origin"))
	if same.Code >= 400 {
		t.Fatalf("same-origin login refused: %d", same.Code)
	}
}

// ---- metadata and headers ----

func TestMetadataAdvertisesTheConfiguredIssuerAndTheSupportedFeatures(t *testing.T) {
	e := newHandlerEnv(t)
	rec := e.get("/.well-known/oauth-authorization-server")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	m := jsonBody(t, rec)
	if m["issuer"] != issuer || m["authorization_endpoint"] != issuer+"/oauth/authorize" || m["token_endpoint"] != issuer+"/oauth/token" {
		t.Fatalf("metadata = %v", m)
	}
	if m["authorization_response_iss_parameter_supported"] != true {
		t.Fatalf("iss support not advertised: %v", m)
	}
	methods, _ := m["code_challenge_methods_supported"].([]any)
	if len(methods) != 1 || methods[0] != "S256" {
		t.Fatalf("code_challenge_methods_supported = %v", m["code_challenge_methods_supported"])
	}
	for _, grants := range [][]any{m["grant_types_supported"].([]any)} {
		for _, g := range grants {
			if g == "password" || g == "implicit" {
				t.Fatalf("advertises an unsupported grant: %v", g)
			}
		}
	}
}

func TestResponsesCarryHardeningHeaders(t *testing.T) {
	e := newHandlerEnv(t)
	for _, target := range []string{"/auth/login", "/oauth/authorize?client_id=x", "/.well-known/oauth-authorization-server"} {
		rec := e.get(target)
		h := rec.Header()
		if h.Get("X-Content-Type-Options") != "nosniff" ||
			!strings.Contains(h.Get("Content-Security-Policy"), "frame-ancestors 'none'") ||
			h.Get("Referrer-Policy") != "no-referrer" {
			t.Fatalf("%s headers = %v", target, h)
		}
	}
}

// Outside conformance mode no credential-entry surface exists: the login form
// is the contract's test-mode interface and must not be reachable otherwise.
func TestLoginIsNotRoutedOutsideConformanceMode(t *testing.T) {
	e := newEnvMode(t, false)
	if rec := e.get("/auth/login"); rec.Code != http.StatusNotFound {
		t.Fatalf("GET /auth/login = %d, want 404", rec.Code)
	}
	if rec := e.postForm("/auth/login", "username=alice&password=test-only-password"); rec.Code != http.StatusNotFound {
		t.Fatalf("POST /auth/login = %d, want 404", rec.Code)
	}
	// Without a login the authorization endpoint cannot authenticate anyone, so
	// it answers with an access_denied redirect rather than issuing a code.
	rec := e.get("/oauth/authorize?" + authQuery("client-a", callback, nil))
	loc := location(t, rec)
	if loc.Query().Get("error") != "access_denied" || loc.Query().Has("code") {
		t.Fatalf("Location = %q", loc.String())
	}
}
