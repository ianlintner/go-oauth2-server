package authcode_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ianlintner/go-oauth2-server/internal/authcode"
	"github.com/ianlintner/go-oauth2-server/internal/oauth"
	"github.com/ianlintner/go-oauth2-server/internal/secret"
	"github.com/ianlintner/go-oauth2-server/internal/storage/sqlite"
)

const (
	verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	callback  = "https://client.example/callback"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type env struct {
	svc   *authcode.Service
	store oauth.Store
	clock *clock
	user  oauth.User
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st, err := sqlite.Open(sqlite.MemoryDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	rnd := oauth.CryptoRandom{}
	ctx := context.Background()

	hash := func(s string) string {
		h, err := secret.Hash(rnd, s)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	clients := []oauth.Client{
		{ID: "client-a", SecretHash: hash("test-only-secret"), AuthMethod: "client_secret_basic", RedirectURIs: []string{callback}, GrantTypes: []string{"authorization_code", "refresh_token"}},
		{ID: "client-post", SecretHash: hash("post-secret"), AuthMethod: "client_secret_post", RedirectURIs: []string{callback}, GrantTypes: []string{"authorization_code", "client_credentials"}},
		{ID: "client-cc", SecretHash: hash("test-only-cc-secret"), AuthMethod: "client_secret_basic", RedirectURIs: []string{callback}, GrantTypes: []string{"client_credentials"}},
		{ID: "client-enc", SecretHash: hash("p@ss:w+rd %"), AuthMethod: "client_secret_basic", RedirectURIs: []string{callback}, GrantTypes: []string{"authorization_code", "client_credentials"}},
		{ID: "client-public", Public: true, AuthMethod: "none", RedirectURIs: []string{callback}, GrantTypes: []string{"authorization_code"}},
		{ID: "client-loop", Public: true, AuthMethod: "none", RedirectURIs: []string{"http://127.0.0.1/cb"}, GrantTypes: []string{"authorization_code"}},
		{ID: "client-nogrants", Public: true, AuthMethod: "none", RedirectURIs: []string{callback}},
		{ID: "client-scoped", Public: true, AuthMethod: "none", RedirectURIs: []string{callback}, Scopes: []string{"read", "write"}, GrantTypes: []string{"authorization_code"}},
	}
	for _, c := range clients {
		if err := st.Clients().Create(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	user := oauth.User{ID: "user-1", Username: "alice", PasswordHash: hash("test-only-password")}
	if err := st.Users().Create(ctx, user); err != nil {
		t.Fatal(err)
	}

	clk := &clock{t: time.Unix(1_700_000_000, 0).UTC()}
	svc, err := authcode.New(authcode.Config{Store: st, Clock: clk, Random: rnd})
	if err != nil {
		t.Fatal(err)
	}
	return &env{svc: svc, store: st, clock: clk, user: user}
}

func params(t *testing.T, kv ...string) oauth.Params {
	t.Helper()
	v := url.Values{}
	for i := 0; i < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	p, err := oauth.ParseParams(v.Encode())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func basic(id, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(id+":"+secret))
}

// basicEncoded applies the RFC 6749 §2.3.1 form-urlencoding to both parts.
func basicEncoded(id, secret string) string {
	return basic(url.QueryEscape(id), url.QueryEscape(secret))
}

func code(t *testing.T, err error) oauth.Code {
	t.Helper()
	var oe *oauth.Error
	if !errors.As(err, &oe) {
		t.Fatalf("err = %v, want *oauth.Error", err)
	}
	return oe.Code
}

func wantCode(t *testing.T, err error, want oauth.Code) *oauth.Error {
	t.Helper()
	if got := code(t, err); got != want {
		t.Fatalf("error code = %q (%v), want %q", got, err, want)
	}
	var oe *oauth.Error
	_ = errors.As(err, &oe)
	return oe
}

// issue runs the authorization side for clientID and returns the code.
func (e *env) issue(t *testing.T, clientID, redirect string) string {
	t.Helper()
	ctx := context.Background()
	p := params(t, "response_type", "code", "client_id", clientID, "redirect_uri", redirect,
		"state", "s1", "code_challenge", challenge, "code_challenge_method", "S256")
	c, uri, err := e.svc.ResolveClient(ctx, p)
	if err != nil {
		t.Fatalf("ResolveClient: %v", err)
	}
	req, err := e.svc.ValidateRequest(c, uri, p)
	if err != nil {
		t.Fatalf("ValidateRequest: %v", err)
	}
	got, err := e.svc.IssueCode(ctx, req, e.user.ID)
	if err != nil {
		t.Fatalf("IssueCode: %v", err)
	}
	return got
}

func (e *env) token(auth string, p oauth.Params) (authcode.TokenResponse, error) {
	return e.svc.Token(context.Background(), auth, p)
}

// ---- authorization request: non-redirectable errors ----

func TestResolveClientErrorsAreNeverRedirectable(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	tests := []struct {
		name   string
		p      oauth.Params
		code   oauth.Code
		status int
	}{
		{"missing client_id", params(t, "redirect_uri", callback), oauth.CodeInvalidRequest, http.StatusBadRequest},
		{"unknown client", params(t, "client_id", "nope", "redirect_uri", callback), oauth.CodeInvalidClient, http.StatusUnauthorized},
		{"missing redirect_uri", params(t, "client_id", "client-a"), oauth.CodeInvalidRequest, http.StatusBadRequest},
		{"unregistered redirect_uri", params(t, "client_id", "client-a", "redirect_uri", "https://evil.example/cb"), oauth.CodeInvalidRequest, http.StatusBadRequest},
		{"redirect_uri port added", params(t, "client_id", "client-a", "redirect_uri", "https://client.example:9999/callback"), oauth.CodeInvalidRequest, http.StatusBadRequest},
		{"http downgrade of registered https", params(t, "client_id", "client-a", "redirect_uri", "http://client.example/callback"), oauth.CodeInvalidRequest, http.StatusBadRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := e.svc.ResolveClient(ctx, tc.p)
			oe := wantCode(t, err, tc.code)
			if oe.HTTPStatus() != tc.status {
				t.Fatalf("status = %d, want %d", oe.HTTPStatus(), tc.status)
			}
			if oe.ClientAuthAttempted {
				t.Fatal("no client authentication was attempted at the authorization endpoint")
			}
		})
	}
}

func TestResolveClientReturnsRequestedLoopbackURI(t *testing.T) {
	e := newEnv(t)
	_, uri, err := e.svc.ResolveClient(context.Background(),
		params(t, "client_id", "client-loop", "redirect_uri", "http://127.0.0.1:9999/cb"))
	if err != nil || uri != "http://127.0.0.1:9999/cb" {
		t.Fatalf("uri = %q, err = %v", uri, err)
	}
}

// ---- authorization request: redirectable errors ----

func TestValidateRequestRejectionsAreRedirectableInvalidRequests(t *testing.T) {
	e := newEnv(t)
	base := func(extra ...string) oauth.Params {
		return params(t, append([]string{"response_type", "code", "client_id", "client-public", "redirect_uri", callback,
			"code_challenge", challenge, "code_challenge_method", "S256"}, extra...)...)
	}
	without := func(drop string) oauth.Params {
		v := url.Values{"response_type": {"code"}, "client_id": {"client-public"}, "redirect_uri": {callback},
			"code_challenge": {challenge}, "code_challenge_method": {"S256"}}
		v.Del(drop)
		p, err := oauth.ParseParams(v.Encode())
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	tests := []struct {
		name string
		p    oauth.Params
		want oauth.Code
	}{
		{"missing response_type", without("response_type"), oauth.CodeInvalidRequest},
		{"implicit token", params(t, "response_type", "token", "client_id", "client-public", "redirect_uri", callback), oauth.CodeUnsupportedResponseType},
		{"id_token", params(t, "response_type", "id_token", "client_id", "client-public", "redirect_uri", callback), oauth.CodeUnsupportedResponseType},
		{"code token hybrid", params(t, "response_type", "code token", "client_id", "client-public", "redirect_uri", callback), oauth.CodeUnsupportedResponseType},
		{"missing code_challenge", without("code_challenge"), oauth.CodeInvalidRequest},
		{"method without challenge", params(t, "response_type", "code", "client_id", "client-public", "redirect_uri", callback, "code_challenge_method", "S256"), oauth.CodeInvalidRequest},
		{"missing code_challenge_method", without("code_challenge_method"), oauth.CodeInvalidRequest},
		{"plain method", params(t, "response_type", "code", "client_id", "client-public", "redirect_uri", callback, "code_challenge", verifier, "code_challenge_method", "plain"), oauth.CodeInvalidRequest},
		{"lowercase s256", params(t, "response_type", "code", "client_id", "client-public", "redirect_uri", callback, "code_challenge", challenge, "code_challenge_method", "s256"), oauth.CodeInvalidRequest},
		{"malformed challenge", params(t, "response_type", "code", "client_id", "client-public", "redirect_uri", callback, "code_challenge", "short", "code_challenge_method", "S256"), oauth.CodeInvalidRequest},
		{"request object", base("request", "eyJhbGciOiJub25lIn0.e30."), oauth.CodeInvalidRequest},
		{"request_uri", base("request_uri", "urn:ietf:params:oauth:request_uri:x"), oauth.CodeInvalidRequest},
		{"client without authorization_code grant", params(t, "response_type", "code", "client_id", "client-cc", "redirect_uri", callback, "code_challenge", challenge, "code_challenge_method", "S256"), oauth.CodeUnauthorizedClient},
		{"scope not registered for client", base("scope", "admin"), oauth.CodeInvalidScope},
		{"malformed scope token", params(t, "response_type", "code", "client_id", "client-scoped", "redirect_uri", callback, "scope", "read \"quoted\"", "code_challenge", challenge, "code_challenge_method", "S256"), oauth.CodeInvalidScope},
		{"scope outside registration", params(t, "response_type", "code", "client_id", "client-scoped", "redirect_uri", callback, "scope", "read admin", "code_challenge", challenge, "code_challenge_method", "S256"), oauth.CodeInvalidScope},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cid := tc.p.Get("client_id")
			if cid == "" {
				cid = "client-public"
			}
			c, err := e.store.Clients().Get(context.Background(), cid)
			if err != nil {
				t.Fatal(err)
			}
			_, err = e.svc.ValidateRequest(c, callback, tc.p)
			wantCode(t, err, tc.want)
		})
	}
}

func TestValidateRequestAcceptsGoodRequestAndKeepsState(t *testing.T) {
	e := newEnv(t)
	c, _ := e.store.Clients().Get(context.Background(), "client-scoped")
	p := params(t, "response_type", "code", "client_id", "client-scoped", "redirect_uri", callback,
		"state", "abc 123", "scope", "read write", "code_challenge", challenge, "code_challenge_method", "S256")
	req, err := e.svc.ValidateRequest(c, callback, p)
	if err != nil {
		t.Fatal(err)
	}
	if req.State != "abc 123" || req.Scope != "read write" || req.RedirectURI != callback || req.Client.ID != "client-scoped" || req.CodeChallenge != challenge {
		t.Fatalf("request = %+v", req)
	}
}

func TestClientWithoutRegisteredGrantsDefaultsToAuthorizationCode(t *testing.T) {
	e := newEnv(t)
	c, _ := e.store.Clients().Get(context.Background(), "client-nogrants")
	p := params(t, "response_type", "code", "client_id", "client-nogrants", "redirect_uri", callback,
		"code_challenge", challenge, "code_challenge_method", "S256")
	if _, err := e.svc.ValidateRequest(c, callback, p); err != nil {
		t.Fatalf("authorization_code is the RFC 7591 default grant: %v", err)
	}
}

// ---- code issuance ----

func TestIssueCodeStoresOnlyAHashBoundToTheRequest(t *testing.T) {
	e := newEnv(t)
	c1 := e.issue(t, "client-a", callback)
	c2 := e.issue(t, "client-a", callback)
	if c1 == c2 {
		t.Fatal("codes must be unique")
	}
	if len(c1) < 43 {
		t.Fatalf("code %q has fewer than 256 bits of entropy", c1)
	}
	ctx := context.Background()
	if _, err := e.store.AuthCodes().Consume(ctx, c1, e.clock.Now()); !errors.Is(err, oauth.ErrNotFound) {
		t.Fatalf("plaintext code must not be a storage key: %v", err)
	}
	sum := sha256.Sum256([]byte(c1))
	rec, err := e.store.AuthCodes().Consume(ctx, hex.EncodeToString(sum[:]), e.clock.Now())
	if err != nil {
		t.Fatalf("hash lookup: %v", err)
	}
	if rec.ClientID != "client-a" || rec.UserID != e.user.ID || rec.RedirectURI != callback ||
		rec.CodeChallenge != challenge || rec.CodeChallengeMethod != "S256" {
		t.Fatalf("stored record = %+v", rec)
	}
	if want := e.clock.Now().Add(authcode.DefaultCodeTTL); !rec.ExpiresAt.Equal(want) {
		t.Fatalf("expires = %v, want %v", rec.ExpiresAt, want)
	}
}

// ---- token endpoint: authorization_code ----

func codeParams(t *testing.T, c string, extra ...string) oauth.Params {
	t.Helper()
	return params(t, append([]string{"grant_type", "authorization_code", "code", c,
		"redirect_uri", callback, "code_verifier", verifier}, extra...)...)
}

func TestConfidentialClientRedeemsCodeOnce(t *testing.T) {
	e := newEnv(t)
	c := e.issue(t, "client-a", callback)
	auth := basic("client-a", "test-only-secret")

	tok, err := e.token(auth, codeParams(t, c))
	if err != nil {
		t.Fatalf("first redemption: %v", err)
	}
	if tok.AccessToken == "" || tok.TokenType != "Bearer" || tok.ExpiresIn <= 0 {
		t.Fatalf("token = %+v", tok)
	}

	// Replay: same code, correct everything else.
	_, err = e.token(auth, codeParams(t, c))
	wantCode(t, err, oauth.CodeInvalidGrant)
}

func TestPublicClientRedeemsWithPKCEAlone(t *testing.T) {
	e := newEnv(t)
	c := e.issue(t, "client-public", callback)
	tok, err := e.token("", codeParams(t, c, "client_id", "client-public"))
	if err != nil || tok.AccessToken == "" {
		t.Fatalf("tok = %+v, err = %v", tok, err)
	}
}

func TestConcurrentRedemptionsYieldExactlyOneToken(t *testing.T) {
	e := newEnv(t)
	c := e.issue(t, "client-public", callback)
	const n = 24
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		ok, bad  int
		badCodes = map[oauth.Code]int{}
	)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.token("", codeParams(t, c, "client_id", "client-public"))
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				ok++
				return
			}
			bad++
			var oe *oauth.Error
			if errors.As(err, &oe) {
				badCodes[oe.Code]++
			}
		}()
	}
	wg.Wait()
	if ok != 1 || bad != n-1 || badCodes[oauth.CodeInvalidGrant] != n-1 {
		t.Fatalf("successes=%d failures=%d codes=%v, want exactly one success and %d invalid_grant", ok, bad, badCodes, n-1)
	}
}

func TestWrongVerifierIsRejectedAndBurnsTheCode(t *testing.T) {
	e := newEnv(t)
	c := e.issue(t, "client-public", callback)
	wrong := "totally-different-verifier-0123456789abcdefghijklmnopqrstuvwxyz"
	_, err := e.token("", params(t, "grant_type", "authorization_code", "code", c, "redirect_uri", callback,
		"client_id", "client-public", "code_verifier", wrong))
	wantCode(t, err, oauth.CodeInvalidGrant)

	// One guess per code: even the right verifier no longer works.
	_, err = e.token("", codeParams(t, c, "client_id", "client-public"))
	wantCode(t, err, oauth.CodeInvalidGrant)
}

func TestChallengeStringIsNotAValidVerifier(t *testing.T) {
	e := newEnv(t)
	c := e.issue(t, "client-public", callback)
	_, err := e.token("", params(t, "grant_type", "authorization_code", "code", c, "redirect_uri", callback,
		"client_id", "client-public", "code_verifier", challenge))
	wantCode(t, err, oauth.CodeInvalidGrant)
}

func TestMissingOrMalformedVerifierIsRejectedWithoutBurningTheCode(t *testing.T) {
	e := newEnv(t)
	c := e.issue(t, "client-public", callback)
	for name, v := range map[string]string{"missing": "", "short": strings.Repeat("A", 42), "long": strings.Repeat("B", 129), "bad charset": strings.Repeat("A", 42) + "+"} {
		kv := []string{"grant_type", "authorization_code", "code", c, "redirect_uri", callback, "client_id", "client-public"}
		if v != "" {
			kv = append(kv, "code_verifier", v)
		}
		_, err := e.token("", params(t, kv...))
		if got := code(t, err); got != oauth.CodeInvalidGrant {
			t.Fatalf("%s verifier: code = %q, want invalid_grant", name, got)
		}
	}
	if _, err := e.token("", codeParams(t, c, "client_id", "client-public")); err != nil {
		t.Fatalf("a request that never reached verification must not burn the code: %v", err)
	}
}

func TestWrongOrMissingRedirectURI(t *testing.T) {
	e := newEnv(t)
	auth := basic("client-a", "test-only-secret")

	c := e.issue(t, "client-a", callback)
	_, err := e.token(auth, params(t, "grant_type", "authorization_code", "code", c,
		"redirect_uri", "https://attacker.example/callback", "code_verifier", verifier))
	wantCode(t, err, oauth.CodeInvalidGrant)

	c = e.issue(t, "client-a", callback)
	_, err = e.token(auth, params(t, "grant_type", "authorization_code", "code", c, "code_verifier", verifier))
	wantCode(t, err, oauth.CodeInvalidRequest)

	// A near-miss is not a match: exact comparison only.
	c = e.issue(t, "client-a", callback)
	_, err = e.token(auth, params(t, "grant_type", "authorization_code", "code", c,
		"redirect_uri", callback+"/", "code_verifier", verifier))
	wantCode(t, err, oauth.CodeInvalidGrant)
}

func TestLoopbackCodeRequiresTheExactPortUsedAtAuthorization(t *testing.T) {
	e := newEnv(t)
	c := e.issue(t, "client-loop", "http://127.0.0.1:9999/cb")
	_, err := e.token("", params(t, "grant_type", "authorization_code", "code", c, "client_id", "client-loop",
		"redirect_uri", "http://127.0.0.1:7777/cb", "code_verifier", verifier))
	wantCode(t, err, oauth.CodeInvalidGrant)

	c = e.issue(t, "client-loop", "http://127.0.0.1:9999/cb")
	if _, err := e.token("", params(t, "grant_type", "authorization_code", "code", c, "client_id", "client-loop",
		"redirect_uri", "http://127.0.0.1:9999/cb", "code_verifier", verifier)); err != nil {
		t.Fatal(err)
	}
}

func TestCodeIsBoundToTheClientThatRequestedIt(t *testing.T) {
	e := newEnv(t)
	c := e.issue(t, "client-public", callback)
	// A different, authenticated client presents the stolen code.
	_, err := e.token(basic("client-a", "test-only-secret"), codeParams(t, c))
	wantCode(t, err, oauth.CodeInvalidGrant)
}

func TestExpiredCodeIsRejected(t *testing.T) {
	e := newEnv(t)
	c := e.issue(t, "client-public", callback)
	e.clock.Advance(authcode.DefaultCodeTTL + time.Second)
	_, err := e.token("", codeParams(t, c, "client_id", "client-public"))
	wantCode(t, err, oauth.CodeInvalidGrant)
}

func TestUnknownCodeIsRejected(t *testing.T) {
	e := newEnv(t)
	_, err := e.token(basic("client-a", "test-only-secret"), codeParams(t, "00000000-0000-0000-0000-000000000000"))
	wantCode(t, err, oauth.CodeInvalidGrant)
}

func TestCodeGrantRequiresCodeParameter(t *testing.T) {
	e := newEnv(t)
	_, err := e.token(basic("client-a", "test-only-secret"),
		params(t, "grant_type", "authorization_code", "redirect_uri", callback, "code_verifier", verifier))
	wantCode(t, err, oauth.CodeInvalidRequest)
}

func TestClientMustBePermittedTheGrant(t *testing.T) {
	e := newEnv(t)
	// client-cc may only use client_credentials.
	_, err := e.token(basic("client-cc", "test-only-cc-secret"), codeParams(t, "whatever"))
	wantCode(t, err, oauth.CodeUnauthorizedClient)
	// client-a may not use client_credentials.
	_, err = e.token(basic("client-a", "test-only-secret"), params(t, "grant_type", "client_credentials"))
	wantCode(t, err, oauth.CodeUnauthorizedClient)
}

// ---- client authentication ----

func TestClientAuthenticationFailures(t *testing.T) {
	e := newEnv(t)
	cc := func(extra ...string) oauth.Params {
		return params(t, append([]string{"grant_type", "client_credentials"}, extra...)...)
	}
	tests := []struct {
		name      string
		auth      string
		p         oauth.Params
		want      oauth.Code
		status    int
		challenge bool
	}{
		{"wrong secret via basic", basic("client-cc", "wrong"), cc(), oauth.CodeInvalidClient, 401, true},
		{"unknown client via basic", basic("nobody", "x"), cc(), oauth.CodeInvalidClient, 401, true},
		{"unknown client via post", "", cc("client_id", "nobody", "client_secret", "x"), oauth.CodeInvalidClient, 401, false},
		{"wrong secret via post", "", cc("client_id", "client-post", "client_secret", "wrong"), oauth.CodeInvalidClient, 401, false},
		{"no credentials at all", "", cc(), oauth.CodeInvalidClient, 401, false},
		{"client_id only for a confidential client", "", cc("client_id", "client-post"), oauth.CodeInvalidClient, 401, false},
		{"basic used where post is registered", basic("client-post", "post-secret"), cc(), oauth.CodeInvalidClient, 401, true},
		{"post used where basic is registered", "", cc("client_id", "client-cc", "client_secret", "test-only-cc-secret"), oauth.CodeInvalidClient, 401, false},
		{"empty secret", basic("client-cc", ""), cc(), oauth.CodeInvalidClient, 401, true},
		{"malformed base64", "Basic !!!not-base64!!!", cc(), oauth.CodeInvalidClient, 401, true},
		{"no colon", "Basic " + base64.StdEncoding.EncodeToString([]byte("client-cc")), cc(), oauth.CodeInvalidClient, 401, true},
		{"bad percent-encoding", basic("client-cc", "%zz"), cc(), oauth.CodeInvalidClient, 401, true},
		{"empty client id", basic("", "x"), cc(), oauth.CodeInvalidClient, 401, true},
		{"public client presenting a secret in the body", "", params(t, "grant_type", "authorization_code", "code", "c", "redirect_uri", callback, "code_verifier", verifier, "client_id", "client-public", "client_secret", "x"), oauth.CodeInvalidClient, 401, false},
		{"public client presenting basic", basic("client-public", "x"), params(t, "grant_type", "authorization_code", "code", "c", "redirect_uri", callback, "code_verifier", verifier), oauth.CodeInvalidClient, 401, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := e.token(tc.auth, tc.p)
			oe := wantCode(t, err, tc.want)
			if oe.HTTPStatus() != tc.status {
				t.Fatalf("status = %d, want %d", oe.HTTPStatus(), tc.status)
			}
			if oe.ClientAuthAttempted != tc.challenge {
				t.Fatalf("ClientAuthAttempted = %v, want %v", oe.ClientAuthAttempted, tc.challenge)
			}
		})
	}
}

func TestMultipleClientAuthenticationMethodsAreRejected(t *testing.T) {
	e := newEnv(t)
	// RFC 6749 §2.3: a client MUST NOT use more than one authentication method.
	_, err := e.token(basic("client-cc", "test-only-cc-secret"),
		params(t, "grant_type", "client_credentials", "client_id", "client-cc", "client_secret", "test-only-cc-secret"))
	wantCode(t, err, oauth.CodeInvalidRequest)

	// client_id in the body that disagrees with the Basic identity is also ambiguous.
	_, err = e.token(basic("client-cc", "test-only-cc-secret"),
		params(t, "grant_type", "client_credentials", "client_id", "client-a"))
	wantCode(t, err, oauth.CodeInvalidRequest)

	// An agreeing client_id alongside Basic is not a second method.
	if _, err := e.token(basic("client-cc", "test-only-cc-secret"),
		params(t, "grant_type", "client_credentials", "client_id", "client-cc")); err != nil {
		t.Fatalf("redundant but consistent client_id must be accepted: %v", err)
	}
}

func TestClientSecretPostAndFormEncodedBasic(t *testing.T) {
	e := newEnv(t)
	if _, err := e.token("", params(t, "grant_type", "client_credentials", "client_id", "client-post", "client_secret", "post-secret")); err != nil {
		t.Fatalf("client_secret_post: %v", err)
	}
	// RFC 6749 §2.3.1: id and secret are form-urlencoded before base64.
	if _, err := e.token(basicEncoded("client-enc", "p@ss:w+rd %"), params(t, "grant_type", "client_credentials")); err != nil {
		t.Fatalf("form-urlencoded Basic credentials: %v", err)
	}
	// The un-encoded spelling of the same secret is a different (wrong) secret.
	_, err := e.token(basic("client-enc", "p@ss:w+rd %"), params(t, "grant_type", "client_credentials"))
	wantCode(t, err, oauth.CodeInvalidClient)
}

func TestNonBasicAuthorizationSchemeIsRejected(t *testing.T) {
	e := newEnv(t)
	_, err := e.token("Bearer abc", params(t, "grant_type", "client_credentials"))
	wantCode(t, err, oauth.CodeInvalidRequest)
}

func TestBasicSchemeIsCaseInsensitive(t *testing.T) {
	e := newEnv(t)
	a := "basic " + strings.TrimPrefix(basic("client-cc", "test-only-cc-secret"), "Basic ")
	if _, err := e.token(a, params(t, "grant_type", "client_credentials")); err != nil {
		t.Fatal(err)
	}
}

// ---- grant dispatch ----

func TestGrantTypeHandling(t *testing.T) {
	e := newEnv(t)
	auth := basic("client-a", "test-only-secret")
	tests := []struct {
		name string
		auth string
		p    oauth.Params
		want oauth.Code
	}{
		{"missing grant_type", "", params(t, "client_id", "nobody"), oauth.CodeInvalidRequest},
		{"unknown grant_type", auth, params(t, "grant_type", "urn:example:bogus"), oauth.CodeUnsupportedGrantType},
		{"unknown grant_type without credentials", "", params(t, "grant_type", "urn:example:bogus"), oauth.CodeUnsupportedGrantType},
		{"ROPC is not supported", "", params(t, "grant_type", "password", "username", "alice", "password", "test-only-password", "client_id", "client-a", "client_secret", "test-only-secret"), oauth.CodeUnsupportedGrantType},
		{"refresh_token is not part of this slice", auth, params(t, "grant_type", "refresh_token", "refresh_token", "x"), oauth.CodeUnsupportedGrantType},
		{"implicit-style value", auth, params(t, "grant_type", "implicit"), oauth.CodeUnsupportedGrantType},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := e.token(tc.auth, tc.p)
			wantCode(t, err, tc.want)
		})
	}
}

func TestClientCredentialsGrant(t *testing.T) {
	e := newEnv(t)
	tok, err := e.token(basic("client-cc", "test-only-cc-secret"), params(t, "grant_type", "client_credentials"))
	if err != nil || tok.AccessToken == "" || tok.TokenType != "Bearer" {
		t.Fatalf("tok = %+v err = %v", tok, err)
	}
	// Public clients cannot authenticate, so they cannot hold this grant.
	_, err = e.token("", params(t, "grant_type", "client_credentials", "client_id", "client-public"))
	if c := code(t, err); c != oauth.CodeUnauthorizedClient {
		t.Fatalf("code = %q, want unauthorized_client", c)
	}
}

func TestAccessTokensAreUnique(t *testing.T) {
	e := newEnv(t)
	seen := map[string]bool{}
	for range 5 {
		tok, err := e.token(basic("client-cc", "test-only-cc-secret"), params(t, "grant_type", "client_credentials"))
		if err != nil {
			t.Fatal(err)
		}
		if seen[tok.AccessToken] {
			t.Fatal("duplicate access token")
		}
		seen[tok.AccessToken] = true
	}
}

// ---- resource owner login ----

func TestAuthenticateUser(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	u, err := e.svc.AuthenticateUser(ctx, "alice", "test-only-password")
	if err != nil || u.ID != e.user.ID {
		t.Fatalf("u = %+v err = %v", u, err)
	}
	for name, cred := range map[string][2]string{
		"wrong password": {"alice", "nope"},
		"unknown user":   {"mallory", "test-only-password"},
		"empty password": {"alice", ""},
		"empty user":     {"", "x"},
	} {
		if _, err := e.svc.AuthenticateUser(ctx, cred[0], cred[1]); !errors.Is(err, authcode.ErrInvalidCredentials) {
			t.Fatalf("%s: err = %v, want ErrInvalidCredentials", name, err)
		}
	}
}

func TestUserByUsername(t *testing.T) {
	e := newEnv(t)
	u, err := e.svc.UserByUsername(context.Background(), "alice")
	if err != nil || u.ID != e.user.ID {
		t.Fatalf("u = %+v err = %v", u, err)
	}
	if _, err := e.svc.UserByUsername(context.Background(), "ghost"); !errors.Is(err, authcode.ErrInvalidCredentials) {
		t.Fatalf("err = %v, want ErrInvalidCredentials", err)
	}
}

func TestNewRequiresDependencies(t *testing.T) {
	if _, err := authcode.New(authcode.Config{}); err == nil {
		t.Fatal("New must fail closed without a store, clock and random source")
	}
}
