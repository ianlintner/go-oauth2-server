package server_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/ianlintner/go-oauth2-server/internal/dpop/dpoptest"
	"github.com/ianlintner/go-oauth2-server/internal/oauth"
	"github.com/ianlintner/go-oauth2-server/internal/secret"
)

// RFC 8693 token exchange at the token endpoint. Expected contract scenario
// IDs (draft at the current pin, so no profile claim is added here):
// token-exchange/basic, token-exchange/downscope, token-exchange/delegation-act,
// token-exchange/unauthorized-actor, token-exchange/invalid-subject-token.

const (
	grantExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	ttAccess      = "urn:ietf:params:oauth:token-type:access_token"
	ttJWT         = "urn:ietf:params:oauth:token-type:jwt"
	ttID          = "urn:ietf:params:oauth:token-type:id_token"
	exSecret      = "exchange-test-secret"
	exScopeAll    = "read write admin"
)

// exchangeEnv is a tokenEnv with clients for the exchange scenarios:
//
//	svc-a  issuing client; allows svc-b as an actor
//	svc-b  exchanging/acting client
//	svc-c  exchanging client NOT allowed by svc-a
//	svc-d  self-delegating client (allows itself), for the depth-limit test
type exchangeEnv struct{ *tokenEnv }

func newExchangeEnv(t *testing.T) *exchangeEnv {
	t.Helper()
	e := &exchangeEnv{newTokenEnv(t)}
	h, err := secret.Hash(oauth.CryptoRandom{}, exSecret)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(id string, actors ...string) oauth.Client {
		return oauth.Client{
			ID: id, SecretHash: h, AuthMethod: "client_secret_basic",
			GrantTypes:    []string{"client_credentials", grantExchange},
			Scopes:        []string{"read", "write", "admin"},
			Resources:     []string{resA, resB},
			AllowedActors: actors,
		}
	}
	for _, c := range []oauth.Client{
		mk("svc-a", "svc-b"), mk("svc-b"), mk("svc-c"), mk("svc-d", "svc-d"),
		{ID: "svc-nogrant", SecretHash: h, AuthMethod: "client_secret_basic", GrantTypes: []string{"client_credentials"}, Scopes: []string{"read"}},
		{ID: "pub-ex", Public: true, AuthMethod: "none", GrantTypes: []string{grantExchange}},
	} {
		if err := e.store.Clients().Create(context.Background(), c); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

// cc mints a client_credentials access token for client id.
func (e *exchangeEnv) cc(t *testing.T, id, scope, resource string, opts ...reqOpt) string {
	t.Helper()
	v := url.Values{"grant_type": {"client_credentials"}}
	if scope != "" {
		v.Set("scope", scope)
	}
	if resource != "" {
		v.Set("resource", resource)
	}
	rec := e.postForm("/oauth/token", v.Encode(), append([]reqOpt{basic(id, exSecret)}, opts...)...)
	if rec.Code != http.StatusOK {
		t.Fatalf("client_credentials(%s) = %d %q", id, rec.Code, rec.Body.String())
	}
	return jsonBody(t, rec)["access_token"].(string)
}

// exchange posts an exchange request as client id with extra form pairs.
func (e *exchangeEnv) exchange(t *testing.T, id string, kv map[string]string, opts ...reqOpt) (int, map[string]any) {
	v := url.Values{"grant_type": {grantExchange}}
	for k, val := range kv {
		v.Set(k, val)
	}
	rec := e.postForm("/oauth/token", v.Encode(), append([]reqOpt{basic(id, exSecret)}, opts...)...)
	return rec.Code, jsonBody(t, rec)
}

func (e *exchangeEnv) mustExchange(t *testing.T, id string, kv map[string]string, opts ...reqOpt) map[string]any {
	t.Helper()
	code, body := e.exchange(t, id, kv, opts...)
	if code != http.StatusOK {
		t.Fatalf("exchange as %s = %d %v", id, code, body)
	}
	return body
}

func wantErr(t *testing.T, code int, body map[string]any, wantStatus int, wantCode string) {
	t.Helper()
	if code != wantStatus || body["error"] != wantCode {
		t.Fatalf("got %d %v, want %d %s", code, body, wantStatus, wantCode)
	}
}

// introspectAs introspects tok as client id.
func (e *exchangeEnv) introspectAs(t *testing.T, id, tok string) map[string]any {
	t.Helper()
	rec := e.postForm("/oauth/introspect", "token="+url.QueryEscape(tok), basic(id, exSecret))
	return jsonBody(t, rec)
}

func subj(tok string) map[string]string {
	return map[string]string{"subject_token": tok, "subject_token_type": ttAccess}
}

func with(m map[string]string, kv ...string) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		out[k] = v
	}
	for i := 0; i < len(kv); i += 2 {
		out[kv[i]] = kv[i+1]
	}
	return out
}

func TestExchangeSameClientDownscopesAndReportsIssuedTokenType(t *testing.T) {
	e := newExchangeEnv(t)
	subject := e.cc(t, "svc-a", exScopeAll, resA)
	body := e.mustExchange(t, "svc-a", with(subj(subject), "scope", "read"))
	if body["issued_token_type"] != ttAccess {
		t.Fatalf("issued_token_type = %v", body["issued_token_type"])
	}
	if body["token_type"] != "Bearer" || body["scope"] != "read" {
		t.Fatalf("body = %v", body)
	}
	if _, ok := body["refresh_token"]; ok {
		t.Fatalf("exchange must not issue a refresh token: %v", body)
	}
	if _, ok := body["act"]; ok {
		t.Fatalf("response must not carry act: %v", body)
	}
	if body["access_token"] == subject {
		t.Fatal("exchange must mint a new token")
	}
	in := e.introspectAs(t, "svc-a", body["access_token"].(string))
	if in["active"] != true || in["sub"] != "svc-a" || in["scope"] != "read" || in["aud"] != resA {
		t.Fatalf("introspection = %v", in)
	}
	if _, ok := in["act"]; ok {
		t.Fatalf("no actor token => no act: %v", in)
	}
}

func TestExchangeInheritsSubjectScopeAndAudienceWhenOmitted(t *testing.T) {
	e := newExchangeEnv(t)
	subject := e.cc(t, "svc-a", "read write", resB)
	body := e.mustExchange(t, "svc-a", subj(subject))
	if body["scope"] != "read write" {
		t.Fatalf("scope = %v", body["scope"])
	}
	if in := e.introspectAs(t, "svc-a", body["access_token"].(string)); in["aud"] != resB {
		t.Fatalf("aud = %v, want %s", in["aud"], resB)
	}
}

func TestExchangeCannotWidenScope(t *testing.T) {
	e := newExchangeEnv(t)
	subject := e.cc(t, "svc-a", "read", "")
	code, body := e.exchange(t, "svc-a", with(subj(subject), "scope", "read write"))
	wantErr(t, code, body, http.StatusBadRequest, "invalid_scope")
}

func TestExchangeScopeMustAlsoFitTheExchangingClient(t *testing.T) {
	e := newExchangeEnv(t)
	h, _ := secret.Hash(oauth.CryptoRandom{}, exSecret)
	for _, c := range []oauth.Client{
		{ID: "svc-wide", SecretHash: h, AuthMethod: "client_secret_basic", GrantTypes: []string{"client_credentials"},
			Scopes: []string{"read", "write", "admin"}, AllowedActors: []string{"svc-narrow"}},
		{ID: "svc-narrow", SecretHash: h, AuthMethod: "client_secret_basic", GrantTypes: []string{grantExchange}, Scopes: []string{"read"}},
	} {
		if err := e.store.Clients().Create(context.Background(), c); err != nil {
			t.Fatal(err)
		}
	}
	subject := e.cc(t, "svc-wide", exScopeAll, "")
	// Inheriting scopes the exchanging client is not registered for fails.
	code, body := e.exchange(t, "svc-narrow", subj(subject))
	wantErr(t, code, body, http.StatusBadRequest, "invalid_scope")
	// Asking only for a scope it is registered for succeeds.
	ok := e.mustExchange(t, "svc-narrow", with(subj(subject), "scope", "read"))
	if ok["scope"] != "read" {
		t.Fatalf("scope = %v", ok["scope"])
	}
}

func TestExchangeAudienceNarrowingAndTargets(t *testing.T) {
	e := newExchangeEnv(t)
	subject := e.cc(t, "svc-a", "read", resA)

	// Naming the subject's own audience via `audience` or `resource` works.
	for _, k := range []string{"audience", "resource"} {
		body := e.mustExchange(t, "svc-a", with(subj(subject), k, resA))
		if in := e.introspectAs(t, "svc-a", body["access_token"].(string)); in["aud"] != resA {
			t.Fatalf("%s: aud = %v", k, in["aud"])
		}
	}
	// A resource outside the subject token's audience is refused.
	code, body := e.exchange(t, "svc-a", with(subj(subject), "resource", resB))
	wantErr(t, code, body, http.StatusBadRequest, "invalid_target")
	// Malformed and unregistered targets are refused.
	code, body = e.exchange(t, "svc-a", with(subj(subject), "resource", "not a uri"))
	wantErr(t, code, body, http.StatusBadRequest, "invalid_target")
	code, body = e.exchange(t, "svc-a", with(subj(subject), "audience", "https://unregistered.example/api"))
	wantErr(t, code, body, http.StatusBadRequest, "invalid_target")
}

func TestExchangeAcrossClientsRequiresIssuingClientConsent(t *testing.T) {
	e := newExchangeEnv(t)
	subject := e.cc(t, "svc-a", "read", "")

	// svc-a lists svc-b: allowed; the new token belongs to svc-b, sub kept.
	body := e.mustExchange(t, "svc-b", subj(subject))
	in := e.introspectAs(t, "svc-b", body["access_token"].(string))
	if in["active"] != true || in["client_id"] != "svc-b" || in["sub"] != "svc-a" {
		t.Fatalf("introspection = %v", in)
	}
	if _, ok := in["act"]; ok {
		t.Fatalf("no actor => no act: %v", in)
	}
	// svc-c is not listed: laundering another client's token is refused.
	code, errBody := e.exchange(t, "svc-c", subj(subject))
	wantErr(t, code, errBody, http.StatusBadRequest, "invalid_grant")
}

func TestExchangeDelegationRecordsActClaim(t *testing.T) {
	e := newExchangeEnv(t)
	subject := e.cc(t, "svc-a", "read write", "")
	actor := e.cc(t, "svc-b", "read", "")
	body := e.mustExchange(t, "svc-b", with(subj(subject),
		"actor_token", actor, "actor_token_type", ttAccess, "scope", "read"))
	tok := body["access_token"].(string)

	act, _ := jwtPayload(t, tok)["act"].(map[string]any)
	if act["sub"] != "svc-b" || act["iss"] != issuer || act["act"] != nil {
		t.Fatalf("act = %v", act)
	}
	in := e.introspectAs(t, "svc-b", tok)
	iact, _ := in["act"].(map[string]any)
	if in["sub"] != "svc-a" || iact["sub"] != "svc-b" {
		t.Fatalf("introspection = %v", in)
	}
}

func TestExchangeDelegationRequiresAnAuthorizedActor(t *testing.T) {
	e := newExchangeEnv(t)
	subject := e.cc(t, "svc-a", "read", "")
	actor := e.cc(t, "svc-c", "read", "")
	code, body := e.exchange(t, "svc-c", with(subj(subject), "actor_token", actor, "actor_token_type", ttAccess))
	wantErr(t, code, body, http.StatusBadRequest, "invalid_grant")
}

func TestExchangeActorTokenMustBelongToTheCaller(t *testing.T) {
	e := newExchangeEnv(t)
	subject := e.cc(t, "svc-a", "read", "")
	other := e.cc(t, "svc-a", "read", "") // an actor token issued to a different client
	code, body := e.exchange(t, "svc-b", with(subj(subject), "actor_token", other, "actor_token_type", ttAccess))
	wantErr(t, code, body, http.StatusBadRequest, "invalid_grant")
}

func TestExchangeActorTokenNeedsItsType(t *testing.T) {
	e := newExchangeEnv(t)
	subject := e.cc(t, "svc-a", "read", "")
	actor := e.cc(t, "svc-b", "read", "")
	code, body := e.exchange(t, "svc-b", with(subj(subject), "actor_token", actor))
	wantErr(t, code, body, http.StatusBadRequest, "invalid_request")
}

func TestExchangeChainsActorsAndEnforcesMaxDepth(t *testing.T) {
	e := newExchangeEnv(t)
	tok := e.cc(t, "svc-d", "read", "")
	for depth := 1; depth <= 4; depth++ {
		actor := e.cc(t, "svc-d", "read", "")
		body := e.mustExchange(t, "svc-d", with(subj(tok), "actor_token", actor, "actor_token_type", ttAccess))
		tok = body["access_token"].(string)
		d, level := 0, any(jwtPayload(t, tok)["act"])
		for m, ok := level.(map[string]any); ok; m, ok = m["act"].(map[string]any) {
			d++
		}
		if d != depth {
			t.Fatalf("chain depth = %d, want %d", d, depth)
		}
	}
	actor := e.cc(t, "svc-d", "read", "")
	code, body := e.exchange(t, "svc-d", with(subj(tok), "actor_token", actor, "actor_token_type", ttAccess))
	wantErr(t, code, body, http.StatusBadRequest, "invalid_request")
}

func TestExchangeRejectsBadSubjectTokens(t *testing.T) {
	e := newExchangeEnv(t)
	good := e.cc(t, "svc-a", "read", "")

	code, body := e.exchange(t, "svc-a", map[string]string{"subject_token_type": ttAccess})
	wantErr(t, code, body, http.StatusBadRequest, "invalid_request")
	code, body = e.exchange(t, "svc-a", map[string]string{"subject_token": good})
	wantErr(t, code, body, http.StatusBadRequest, "invalid_request")
	code, body = e.exchange(t, "svc-a", with(subj(good), "subject_token_type", ttID))
	wantErr(t, code, body, http.StatusBadRequest, "invalid_request")
	code, body = e.exchange(t, "svc-a", subj("garbage"))
	wantErr(t, code, body, http.StatusBadRequest, "invalid_grant")

	// Revoked.
	rec := e.postForm("/oauth/revoke", "token="+url.QueryEscape(good), basic("svc-a", exSecret))
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke = %d", rec.Code)
	}
	code, body = e.exchange(t, "svc-a", subj(good))
	wantErr(t, code, body, http.StatusBadRequest, "invalid_grant")

	// Expired.
	fresh := e.cc(t, "svc-a", "read", "")
	e.clock.t = e.clock.t.Add(2 * time.Hour)
	code, body = e.exchange(t, "svc-a", subj(fresh))
	wantErr(t, code, body, http.StatusBadRequest, "invalid_grant")
}

func TestExchangeSubjectJWTTypeAndRequestedTokenType(t *testing.T) {
	e := newExchangeEnv(t)
	subject := e.cc(t, "svc-a", "read", "")
	body := e.mustExchange(t, "svc-a", with(subj(subject), "subject_token_type", ttJWT, "requested_token_type", ttJWT))
	if body["issued_token_type"] != ttJWT {
		t.Fatalf("issued_token_type = %v", body["issued_token_type"])
	}
	body = e.mustExchange(t, "svc-a", with(subj(subject), "requested_token_type", ttAccess))
	if body["issued_token_type"] != ttAccess {
		t.Fatalf("issued_token_type = %v", body["issued_token_type"])
	}
	code, errBody := e.exchange(t, "svc-a", with(subj(subject), "requested_token_type", ttID))
	wantErr(t, code, errBody, http.StatusBadRequest, "invalid_request")
	code, errBody = e.exchange(t, "svc-a", with(subj(subject), "requested_token_type", "urn:ietf:params:oauth:token-type:refresh_token"))
	wantErr(t, code, errBody, http.StatusBadRequest, "invalid_request")
}

func TestExchangeRefusesAuthorizationDetails(t *testing.T) {
	e := newExchangeEnv(t)
	subject := e.cc(t, "svc-a", "read", "")
	code, body := e.exchange(t, "svc-a", with(subj(subject), "authorization_details", `[{"type":"x"}]`))
	wantErr(t, code, body, http.StatusBadRequest, "invalid_request")
}

func TestExchangeClientAuthenticationAndGrantGating(t *testing.T) {
	e := newExchangeEnv(t)
	subject := e.cc(t, "svc-a", "read", "")

	// Wrong secret.
	v := url.Values{"grant_type": {grantExchange}, "subject_token": {subject}, "subject_token_type": {ttAccess}}
	rec := e.postForm("/oauth/token", v.Encode(), basic("svc-a", "wrong"))
	if rec.Code != http.StatusUnauthorized || jsonBody(t, rec)["error"] != "invalid_client" {
		t.Fatalf("wrong secret = %d %q", rec.Code, rec.Body.String())
	}
	// Client not registered for the grant.
	code, body := e.exchange(t, "svc-nogrant", subj(subject))
	wantErr(t, code, body, http.StatusBadRequest, "unauthorized_client")
	// Public client.
	v.Set("client_id", "pub-ex")
	rec = e.postForm("/oauth/token", v.Encode())
	if rec.Code != http.StatusBadRequest && rec.Code != http.StatusUnauthorized {
		t.Fatalf("public = %d %q", rec.Code, rec.Body.String())
	}
	if c := jsonBody(t, rec)["error"]; c != "invalid_client" && c != "unauthorized_client" {
		t.Fatalf("public client error = %v", c)
	}
	// Subject tokens are never accepted from the query string.
	rec = e.postForm("/oauth/token?subject_token=x", v.Encode(), basic("svc-a", exSecret))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("query string = %d", rec.Code)
	}
}

func TestExchangeSenderConstrainedSubjectNeedsMatchingProof(t *testing.T) {
	e := newExchangeEnv(t)
	k := dpoptest.NewKey(t)
	subject := e.cc(t, "svc-a", "read", "",
		header("DPoP", k.Proof(t, e.spec("POST", tokenEndpoint))))
	// Without a proof the bound subject cannot be downgraded to a bearer.
	code, body := e.exchange(t, "svc-a", subj(subject))
	wantErr(t, code, body, http.StatusBadRequest, "invalid_grant")
	// A proof from another key does not match.
	other := dpoptest.NewKey(t)
	code, body = e.exchange(t, "svc-a", subj(subject), header("DPoP", other.Proof(t, e.spec("POST", tokenEndpoint))))
	wantErr(t, code, body, http.StatusBadRequest, "invalid_grant")
	// The holder of the key may exchange; the result stays bound to it.
	ok := e.mustExchange(t, "svc-a", subj(subject), header("DPoP", k.Proof(t, e.spec("POST", tokenEndpoint))))
	if ok["token_type"] != "DPoP" {
		t.Fatalf("token_type = %v", ok["token_type"])
	}
	cnf, _ := jwtPayload(t, ok["access_token"].(string))["cnf"].(map[string]any)
	if cnf["jkt"] != k.JKT(t) {
		t.Fatalf("cnf = %v", cnf)
	}
}

func TestDiscoveryAdvertisesTokenExchange(t *testing.T) {
	e := newExchangeEnv(t)
	m := jsonBody(t, e.get("/.well-known/oauth-authorization-server"))
	found := false
	for _, g := range m["grant_types_supported"].([]any) {
		if g == grantExchange {
			found = true
		}
		if g == "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			t.Fatalf("jwt-bearer advertised but not implemented: %v", m["grant_types_supported"])
		}
	}
	if !found {
		t.Fatalf("token-exchange not advertised: %v", m["grant_types_supported"])
	}
	for _, a := range m["token_endpoint_auth_methods_supported"].([]any) {
		if a == "private_key_jwt" {
			t.Fatalf("private_key_jwt advertised but not implemented")
		}
	}
}
