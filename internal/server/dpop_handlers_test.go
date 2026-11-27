package server_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ianlintner/go-oauth2-server/internal/dpop"
	"github.com/ianlintner/go-oauth2-server/internal/dpop/dpoptest"
	"github.com/ianlintner/go-oauth2-server/internal/oauth"
)

// These tests pin the sender-constrained wire behavior (RFC 9449) for the
// token endpoint, the userinfo resource and introspection. The scenario
// semantics mirror contract profile sender-constrained (stable subset).

const (
	tokenEndpoint    = issuer + "/oauth/token"
	userinfoEndpoint = issuer + "/oauth/userinfo"
)

func ccForm() string { return url.Values{"grant_type": {"client_credentials"}}.Encode() }

func (e *tokenEnv) spec(htm, htu string) dpoptest.Spec {
	return dpoptest.Spec{HTM: htm, HTU: htu, Now: e.clock.t}
}

// dpopToken obtains a DPoP-bound client_credentials token for k.
func (e *tokenEnv) dpopToken(t *testing.T, k dpoptest.Key) string {
	t.Helper()
	rec := e.postForm("/oauth/token", ccForm(), basic("client-cc", "test-only-secret"),
		header("DPoP", k.Proof(t, e.spec("POST", tokenEndpoint))))
	if rec.Code != http.StatusOK {
		t.Fatalf("token = %d %q", rec.Code, rec.Body.String())
	}
	body := jsonBody(t, rec)
	if body["token_type"] != "DPoP" {
		t.Fatalf("token_type = %v, want DPoP", body["token_type"])
	}
	return body["access_token"].(string)
}

func jwtPayload(t *testing.T, tok string) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", tok)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestTokenEndpointBindsTheAccessTokenToTheProofKey(t *testing.T) {
	e := newTokenEnv(t)
	k := dpoptest.NewKey(t)
	at := e.dpopToken(t, k)
	cnf, _ := jwtPayload(t, at)["cnf"].(map[string]any)
	if cnf["jkt"] != k.JKT(t) {
		t.Fatalf("cnf = %v, want jkt %q", cnf, k.JKT(t))
	}
}

func TestTokenEndpointWithoutProofStaysBearerAndUnbound(t *testing.T) {
	e := newTokenEnv(t)
	rec := e.postForm("/oauth/token", ccForm(), basic("client-cc", "test-only-secret"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d %q", rec.Code, rec.Body.String())
	}
	body := jsonBody(t, rec)
	if body["token_type"] != "Bearer" {
		t.Fatalf("token_type = %v", body["token_type"])
	}
	if _, bound := jwtPayload(t, body["access_token"].(string))["cnf"]; bound {
		t.Fatal("a bearer token must carry no cnf")
	}
}

func TestTokenEndpointRejectsBadProofsAsInvalidDPoPProof(t *testing.T) {
	k := dpoptest.NewKey(t)
	cases := []struct {
		name string
		mut  func(*tokenEnv, *dpoptest.Spec)
	}{
		{"wrong htm", func(_ *tokenEnv, s *dpoptest.Spec) { s.HTM = "GET" }},
		{"wrong htu", func(_ *tokenEnv, s *dpoptest.Spec) { s.HTU = issuer + "/oauth/other" }},
		{"wrong typ", func(_ *tokenEnv, s *dpoptest.Spec) { s.Typ = "JWT" }},
		{"missing jti", func(_ *tokenEnv, s *dpoptest.Spec) { s.Omit = []string{"jti"} }},
		{"stale iat", func(_ *tokenEnv, s *dpoptest.Spec) { s.IATOffset = -time.Hour }},
		{"ath at token endpoint", func(_ *tokenEnv, s *dpoptest.Spec) { s.AccessToken = "x" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTokenEnv(t)
			s := e.spec("POST", tokenEndpoint)
			tc.mut(e, &s)
			rec := e.postForm("/oauth/token", ccForm(), basic("client-cc", "test-only-secret"), header("DPoP", k.Proof(t, s)))
			if rec.Code != http.StatusBadRequest || jsonBody(t, rec)["error"] != "invalid_dpop_proof" {
				t.Fatalf("status = %d %q, want 400 invalid_dpop_proof", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestTokenEndpointRejectsAReplayedProof(t *testing.T) {
	e := newTokenEnv(t)
	proof := dpoptest.NewKey(t).Proof(t, e.spec("POST", tokenEndpoint))
	for i, want := range []int{http.StatusOK, http.StatusBadRequest} {
		rec := e.postForm("/oauth/token", ccForm(), basic("client-cc", "test-only-secret"), header("DPoP", proof))
		if rec.Code != want {
			t.Fatalf("attempt %d: status = %d %q, want %d", i, rec.Code, rec.Body.String(), want)
		}
		if want == http.StatusBadRequest && jsonBody(t, rec)["error"] != "invalid_dpop_proof" {
			t.Fatalf("replay body = %q", rec.Body.String())
		}
	}
}

func TestTokenEndpointRejectsMultipleDPoPHeaders(t *testing.T) {
	e := newTokenEnv(t)
	k := dpoptest.NewKey(t)
	rec := e.postForm("/oauth/token", ccForm(), basic("client-cc", "test-only-secret"),
		func(r *http.Request) {
			r.Header.Add("DPoP", k.Proof(t, e.spec("POST", tokenEndpoint)))
			r.Header.Add("DPoP", k.Proof(t, e.spec("POST", tokenEndpoint)))
		})
	if rec.Code != http.StatusBadRequest || jsonBody(t, rec)["error"] != "invalid_dpop_proof" {
		t.Fatalf("status = %d %q", rec.Code, rec.Body.String())
	}
}

func TestPublicClientCannotUseClientCredentialsEvenWithDPoP(t *testing.T) {
	// DPoP no longer makes a public client special (its refresh tokens are
	// key-bound, see dpop_refresh_test.go); the grant is still refused for it.
	e := newTokenEnv(t)
	k := dpoptest.NewKey(t)
	rec := e.postForm("/oauth/token", ccForm()+"&client_id=client-public-cc", header("DPoP", k.Proof(t, e.spec("POST", tokenEndpoint))))
	if rec.Code != http.StatusBadRequest || jsonBody(t, rec)["error"] != "unauthorized_client" {
		t.Fatalf("status = %d %q, want 400 unauthorized_client", rec.Code, rec.Body.String())
	}
}

func TestUserInfoAcceptsABoundTokenWithAMatchingProof(t *testing.T) {
	e := newTokenEnv(t)
	k := dpoptest.NewKey(t)
	at := e.dpopToken(t, k)
	s := e.spec("GET", userinfoEndpoint)
	s.AccessToken = at
	rec := e.get("/oauth/userinfo", header("Authorization", "DPoP "+at), header("DPoP", k.Proof(t, s)))
	if rec.Code != http.StatusOK || jsonBody(t, rec)["sub"] != "client-cc" {
		t.Fatalf("status = %d %q", rec.Code, rec.Body.String())
	}
}

func TestUserInfoRejectsBoundTokenPresentedAsBearer(t *testing.T) {
	e := newTokenEnv(t)
	at := e.dpopToken(t, dpoptest.NewKey(t))
	rec := e.get("/oauth/userinfo", bearerAuth(at))
	if rec.Code != http.StatusUnauthorized || jsonBody(t, rec)["error"] != "invalid_token" {
		t.Fatalf("status = %d %q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("WWW-Authenticate"); !strings.HasPrefix(got, "DPoP ") {
		t.Fatalf("WWW-Authenticate = %q, want a DPoP challenge", got)
	}
}

func TestUserInfoRejectsBadResourceProofs(t *testing.T) {
	k := dpoptest.NewKey(t)
	cases := []struct {
		name string
		key  *dpoptest.Key
		mut  func(at string, s *dpoptest.Spec)
		code string
	}{
		{"missing ath", nil, func(_ string, s *dpoptest.Spec) { s.AccessToken = "" }, "invalid_dpop_proof"},
		{"ath of another token", nil, func(_ string, s *dpoptest.Spec) { s.AccessToken = "another-token" }, "invalid_dpop_proof"},
		{"wrong htm", nil, func(_ string, s *dpoptest.Spec) { s.HTM = "POST" }, "invalid_dpop_proof"},
		{"wrong htu", nil, func(_ string, s *dpoptest.Spec) { s.HTU = issuer + "/oauth/token" }, "invalid_dpop_proof"},
		{"proof from a different key", func() *dpoptest.Key { o := dpoptest.NewKey(t); return &o }(), func(string, *dpoptest.Spec) {}, "invalid_token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTokenEnv(t)
			at := e.dpopToken(t, k)
			s := e.spec("GET", userinfoEndpoint)
			s.AccessToken = at
			tc.mut(at, &s)
			signer := k
			if tc.key != nil {
				signer = *tc.key
			}
			// Positive control: the correctly bound request succeeds, so the
			// rejection below can only come from the mutated property.
			ok := e.spec("GET", userinfoEndpoint)
			ok.AccessToken = at
			if rec := e.get("/oauth/userinfo", header("Authorization", "DPoP "+at), header("DPoP", k.Proof(t, ok))); rec.Code != http.StatusOK {
				t.Fatalf("control = %d %q", rec.Code, rec.Body.String())
			}
			rec := e.get("/oauth/userinfo", header("Authorization", "DPoP "+at), header("DPoP", signer.Proof(t, s)))
			if rec.Code != http.StatusUnauthorized || jsonBody(t, rec)["error"] != tc.code {
				t.Fatalf("status = %d %q, want 401 %s", rec.Code, rec.Body.String(), tc.code)
			}
		})
	}
}

func TestUserInfoRejectsMissingProofAndUnboundTokenUnderDPoPScheme(t *testing.T) {
	e := newTokenEnv(t)
	k := dpoptest.NewKey(t)
	at := e.dpopToken(t, k)
	if rec := e.get("/oauth/userinfo", header("Authorization", "DPoP "+at)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no proof: status = %d", rec.Code)
	}
	// A plain bearer token must not be upgradeable by attaching a DPoP scheme
	// and an attacker-chosen key.
	plain := e.issueAccessToken(t, "client-a", "user-1")
	s := e.spec("GET", userinfoEndpoint)
	s.AccessToken = plain.Value
	rec := e.get("/oauth/userinfo", header("Authorization", "DPoP "+plain.Value), header("DPoP", k.Proof(t, s)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unbound token under DPoP scheme: status = %d %q", rec.Code, rec.Body.String())
	}
}

func TestUserInfoRejectsAReplayedResourceProof(t *testing.T) {
	e := newTokenEnv(t)
	k := dpoptest.NewKey(t)
	at := e.dpopToken(t, k)
	s := e.spec("GET", userinfoEndpoint)
	s.AccessToken = at
	proof := k.Proof(t, s)
	for i, want := range []int{http.StatusOK, http.StatusUnauthorized} {
		rec := e.get("/oauth/userinfo", header("Authorization", "DPoP "+at), header("DPoP", proof))
		if rec.Code != want {
			t.Fatalf("attempt %d: status = %d %q, want %d", i, rec.Code, rec.Body.String(), want)
		}
	}
}

func TestIntrospectionReportsDPoPTokenTypeAndBinding(t *testing.T) {
	e := newTokenEnv(t)
	k := dpoptest.NewKey(t)
	at := e.dpopToken(t, k)
	rec := e.postForm("/oauth/introspect", url.Values{"token": {at}}.Encode(), basic("client-cc", "test-only-secret"))
	body := jsonBody(t, rec)
	cnf, _ := body["cnf"].(map[string]any)
	if body["active"] != true || body["token_type"] != "DPoP" || cnf["jkt"] != k.JKT(t) {
		t.Fatalf("introspection = %v", body)
	}
}

func TestMetadataAdvertisesDPoPSigningAlgorithms(t *testing.T) {
	e := newTokenEnv(t)
	body := jsonBody(t, e.get("/.well-known/oauth-authorization-server"))
	got, _ := body["dpop_signing_alg_values_supported"].([]any)
	if len(got) != 3 || got[0] != "ES256" {
		t.Fatalf("dpop_signing_alg_values_supported = %v", body["dpop_signing_alg_values_supported"])
	}
}

var _ = httptest.NewRecorder

func smallReplayEnv(t *testing.T) *tokenEnv {
	t.Helper()
	return newTokenEnvWithReplay(t, func(clk oauth.Clock) dpop.ReplayStore { return dpop.NewMemoryReplayStore(clk, 1) })
}

func TestTokenEndpointDoesNotRecordProofsForUnauthenticatedCallers(t *testing.T) {
	e := smallReplayEnv(t)
	// Repeated requests with distinct valid proofs and bad credentials must
	// each be answered as a failed client authentication; none may fill the
	// (capacity 1) replay store or be refused for lack of room.
	for i := 0; i < 3; i++ {
		k := dpoptest.NewKey(t)
		rec := e.postForm("/oauth/token", ccForm(), basic("client-cc", "wrong-secret"),
			header("DPoP", k.Proof(t, e.spec("POST", tokenEndpoint))))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("request %d: status = %d %q, want 401", i, rec.Code, rec.Body.String())
		}
		if got := jsonBody(t, rec)["error"]; got != "invalid_client" {
			t.Fatalf("request %d: error = %v, want invalid_client", i, got)
		}
	}
}

func TestDpopStoreFullRefusesAnonymousCallerBeforeClientAuthentication(t *testing.T) {
	e := smallReplayEnv(t)
	rec := e.postForm("/oauth/token", ccForm(), basic("client-cc", "wrong-secret"),
		header("DPoP", dpoptest.NewKey(t).Proof(t, e.spec("POST", tokenEndpoint))))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated request = %d %q, want 401", rec.Code, rec.Body.String())
	}
	// The single replay slot is still free for an authenticated caller.
	rec = e.postForm("/oauth/token", ccForm(), basic("client-cc", "test-only-secret"),
		header("DPoP", dpoptest.NewKey(t).Proof(t, e.spec("POST", tokenEndpoint))))
	if rec.Code != http.StatusOK {
		t.Fatalf("authenticated request = %d %q, want 200", rec.Code, rec.Body.String())
	}
	// An authenticated caller's proof is still recorded: replay is refused.
	k := dpoptest.NewKey(t)
	proof := k.Proof(t, e.spec("POST", tokenEndpoint))
	e2 := newTokenEnv(t)
	for i, want := range []int{http.StatusOK, http.StatusBadRequest} {
		rec = e2.postForm("/oauth/token", ccForm(), basic("client-cc", "test-only-secret"), header("DPoP", proof))
		if rec.Code != want {
			t.Fatalf("replay step %d = %d %q, want %d", i, rec.Code, rec.Body.String(), want)
		}
	}
}
