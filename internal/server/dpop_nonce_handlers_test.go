package server_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ianlintner/go-oauth2-server/internal/dpop"
	"github.com/ianlintner/go-oauth2-server/internal/dpop/dpoptest"
	"github.com/ianlintner/go-oauth2-server/internal/oauth"
	"github.com/ianlintner/go-oauth2-server/internal/server"
)

// nonceEnv is a tokenEnv with DPoP server nonces on. resources selects the
// OAUTH2_DPOP_NONCE=all behavior; false is =token.
type nonceEnv struct {
	*tokenEnv
	nonces *dpop.NonceSource
}

func newNonceEnv(t *testing.T, resources bool) *nonceEnv {
	t.Helper()
	ne := &nonceEnv{}
	ne.tokenEnv = newTokenEnvDeps(t,
		func(clk oauth.Clock) dpop.ReplayStore { return dpop.NewMemoryReplayStore(clk, 1000) },
		func(clk oauth.Clock, d *server.Deps) {
			s, err := dpop.NewNonceSource(clk, []byte("0123456789abcdef0123456789abcdef-n"), 5*time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			ne.nonces = s
			d.DPoPNonces, d.DPoPNonceResources = s, resources
		})
	return ne
}

func (e *nonceEnv) tokenReq(t *testing.T, k dpoptest.Key, nonce string) (code int, hdr http.Header, body map[string]any) {
	t.Helper()
	s := e.spec("POST", tokenEndpoint)
	s.Nonce = nonce
	rec := e.postForm("/oauth/token", ccForm(), basic("client-cc", "test-only-secret"), header("DPoP", k.Proof(t, s)))
	return rec.Code, rec.Header(), jsonBody(t, rec)
}

func TestTokenEndpointDemandsNonceThenAcceptsIt(t *testing.T) {
	e := newNonceEnv(t, false)
	k := dpoptest.NewKey(t)

	code, hdr, body := e.tokenReq(t, k, "")
	if code != http.StatusBadRequest || body["error"] != "use_dpop_nonce" {
		t.Fatalf("no nonce: %d %v, want 400 use_dpop_nonce", code, body)
	}
	nonce := hdr.Get("DPoP-Nonce")
	if nonce == "" || !e.nonces.Valid(nonce) {
		t.Fatalf("DPoP-Nonce = %q, want a valid nonce", nonce)
	}

	code, hdr, body = e.tokenReq(t, k, nonce)
	if code != http.StatusOK || body["token_type"] != "DPoP" {
		t.Fatalf("with nonce: %d %v", code, body)
	}
	if hdr.Get("DPoP-Nonce") == "" {
		t.Error("success response carries no fresh DPoP-Nonce")
	}
}

func TestTokenEndpointStaleOrForgedNonceGetsFreshOne(t *testing.T) {
	e := newNonceEnv(t, false)
	k := dpoptest.NewKey(t)
	stale := e.nonces.Next()
	e.clock.t = e.clock.t.Add(10 * time.Minute)

	for name, n := range map[string]string{"stale": stale, "forged": "AAAA" + stale[4:]} {
		code, hdr, body := e.tokenReq(t, k, n)
		if code != http.StatusBadRequest || body["error"] != "use_dpop_nonce" {
			t.Fatalf("%s: %d %v, want 400 use_dpop_nonce", name, code, body)
		}
		if got := hdr.Get("DPoP-Nonce"); got == stale || !e.nonces.Valid(got) {
			t.Fatalf("%s: DPoP-Nonce = %q, want a fresh valid nonce", name, got)
		}
	}
}

func TestTokenEndpointNonceRejectionDoesNotBurnTheJTI(t *testing.T) {
	e := newNonceEnv(t, false)
	k := dpoptest.NewKey(t)
	s := e.spec("POST", tokenEndpoint)
	s.JTI = "fixed-jti"
	rec := e.postForm("/oauth/token", ccForm(), basic("client-cc", "test-only-secret"), header("DPoP", k.Proof(t, s)))
	if rec.Code != http.StatusBadRequest || jsonBody(t, rec)["error"] != "use_dpop_nonce" {
		t.Fatalf("first = %d %q", rec.Code, rec.Body.String())
	}
	s.Nonce = rec.Header().Get("DPoP-Nonce")
	rec = e.postForm("/oauth/token", ccForm(), basic("client-cc", "test-only-secret"), header("DPoP", k.Proof(t, s)))
	if rec.Code != http.StatusOK {
		t.Fatalf("retry with the same jti and the nonce = %d %q, want 200", rec.Code, rec.Body.String())
	}
}

func TestTokenEndpointNonceModeLeavesBearerRequestsAlone(t *testing.T) {
	e := newNonceEnv(t, false)
	rec := e.postForm("/oauth/token", ccForm(), basic("client-cc", "test-only-secret"))
	if rec.Code != http.StatusOK || jsonBody(t, rec)["token_type"] != "Bearer" {
		t.Fatalf("bearer request = %d %q", rec.Code, rec.Body.String())
	}
}

func TestNonceOffNeverEmitsNonceHeaders(t *testing.T) {
	e := newTokenEnv(t)
	k := dpoptest.NewKey(t)
	rec := e.postForm("/oauth/token", ccForm(), basic("client-cc", "test-only-secret"), header("DPoP", k.Proof(t, e.spec("POST", tokenEndpoint))))
	if rec.Code != http.StatusOK || rec.Header().Get("DPoP-Nonce") != "" {
		t.Fatalf("status = %d, DPoP-Nonce = %q; nonces are off", rec.Code, rec.Header().Get("DPoP-Nonce"))
	}
}

// boundToken fetches a DPoP-bound token for k through the nonce handshake.
func (e *nonceEnv) boundToken(t *testing.T, k dpoptest.Key) string {
	t.Helper()
	code, hdr, _ := e.tokenReq(t, k, "")
	if code != http.StatusBadRequest {
		t.Fatalf("handshake step 1 = %d", code)
	}
	code, _, body := e.tokenReq(t, k, hdr.Get("DPoP-Nonce"))
	if code != http.StatusOK {
		t.Fatalf("handshake step 2 = %d %v", code, body)
	}
	return body["access_token"].(string)
}

func (e *nonceEnv) userinfo(t *testing.T, k dpoptest.Key, at, nonce string) *httptest.ResponseRecorder {
	t.Helper()
	s := e.spec("GET", userinfoEndpoint)
	s.AccessToken, s.Nonce = at, nonce
	return e.get("/oauth/userinfo", header("Authorization", "DPoP "+at), header("DPoP", k.Proof(t, s)))
}

func TestResourceDoesNotRequireNonceInTokenMode(t *testing.T) {
	e := newNonceEnv(t, false)
	k := dpoptest.NewKey(t)
	// UserInfo requires an openid-scoped user token; the token-endpoint
	// handshake is covered by the tests above.
	at := e.dpopUserToken(t, k)
	rec := e.userinfo(t, k, at, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("userinfo = %d %q, want 200 (nonce=token leaves resources alone)", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("DPoP-Nonce") != "" {
		t.Error("resource emitted DPoP-Nonce in token mode")
	}
}

func TestResourceDemandsNonceInAllMode(t *testing.T) {
	e := newNonceEnv(t, true)
	k := dpoptest.NewKey(t)
	at := e.dpopUserToken(t, k)

	rec := e.userinfo(t, k, at, "")
	if rec.Code != http.StatusUnauthorized || jsonBody(t, rec)["error"] != "use_dpop_nonce" {
		t.Fatalf("no nonce: %d %q, want 401 use_dpop_nonce", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("WWW-Authenticate"); !strings.HasPrefix(got, `DPoP error="use_dpop_nonce"`) {
		t.Fatalf("WWW-Authenticate = %q", got)
	}
	nonce := rec.Header().Get("DPoP-Nonce")
	if nonce == "" || !e.nonces.Valid(nonce) {
		t.Fatalf("DPoP-Nonce = %q", nonce)
	}

	rec = e.userinfo(t, k, at, nonce)
	if rec.Code != http.StatusOK || jsonBody(t, rec)["sub"] != "user-1" {
		t.Fatalf("with nonce: %d %q", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("DPoP-Nonce") == "" {
		t.Error("resource success carries no fresh DPoP-Nonce")
	}
}

func TestResourceStaleNonceInAllModeGetsFreshOne(t *testing.T) {
	e := newNonceEnv(t, true)
	k := dpoptest.NewKey(t)
	stale := e.nonces.Next()
	e.clock.t = e.clock.t.Add(10 * time.Minute)
	// The bound access token must outlive the clock jump for this to isolate
	// the nonce: re-mint at the new time through the handshake.
	at := e.boundToken(t, k)
	rec := e.userinfo(t, k, at, stale)
	if rec.Code != http.StatusUnauthorized || jsonBody(t, rec)["error"] != "use_dpop_nonce" {
		t.Fatalf("stale: %d %q, want 401 use_dpop_nonce", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("DPoP-Nonce"); got == stale || !e.nonces.Valid(got) {
		t.Fatalf("DPoP-Nonce = %q, want fresh", got)
	}
}

func TestResourceNonceRejectionDoesNotBurnTheJTI(t *testing.T) {
	e := newNonceEnv(t, true)
	k := dpoptest.NewKey(t)
	at := e.dpopUserToken(t, k)
	s := e.spec("GET", userinfoEndpoint)
	s.AccessToken, s.JTI = at, "resource-jti"
	rec := e.get("/oauth/userinfo", header("Authorization", "DPoP "+at), header("DPoP", k.Proof(t, s)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("first = %d", rec.Code)
	}
	s.Nonce = rec.Header().Get("DPoP-Nonce")
	rec = e.get("/oauth/userinfo", header("Authorization", "DPoP "+at), header("DPoP", k.Proof(t, s)))
	if rec.Code != http.StatusOK {
		t.Fatalf("retry = %d %q, want 200", rec.Code, rec.Body.String())
	}
}
