package server_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
	"github.com/ianlintner/go-oauth2-server/internal/secret"
	"github.com/ianlintner/go-oauth2-server/internal/token"
)

const (
	resA = "https://a.example/api"
	resB = "https://b.example/api"
)

// addResourceClient registers a confidential client that may use the code,
// refresh and client_credentials grants and request only resA.
func addResourceClient(t *testing.T, e *tokenEnv) {
	t.Helper()
	h, err := secret.Hash(oauth.CryptoRandom{}, "res-secret")
	if err != nil {
		t.Fatal(err)
	}
	err = e.store.Clients().Create(context.Background(), oauth.Client{
		ID: "client-res", SecretHash: h, AuthMethod: "client_secret_basic",
		RedirectURIs: []string{callback},
		GrantTypes:   []string{"authorization_code", "refresh_token", "client_credentials"},
		Resources:    []string{resA},
	})
	if err != nil {
		t.Fatal(err)
	}
	pw, err := secret.Hash(oauth.CryptoRandom{}, "test-only-password")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.store.Users().Create(context.Background(), oauth.User{ID: "user-1", Username: "alice", PasswordHash: pw}); err != nil {
		t.Fatal(err)
	}
}

func audOf(t *testing.T, e *tokenEnv, accessToken string) any {
	t.Helper()
	rec := e.postForm("/oauth/introspect", "token="+accessToken, basic("client-res", "res-secret"))
	body := jsonBody(t, rec)
	if body["active"] != true {
		t.Fatalf("token inactive: %v", body)
	}
	return body["aud"]
}

func TestClientCredentialsAudienceDefaultsToIssuer(t *testing.T) {
	e := newTokenEnv(t)
	addResourceClient(t, e)
	rec := e.postForm("/oauth/token", "grant_type=client_credentials", basic("client-res", "res-secret"))
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	at, _ := jsonBody(t, rec)["access_token"].(string)
	if got := audOf(t, e, at); got != issuer {
		t.Fatalf("aud = %v, want %q", got, issuer)
	}
}

func TestClientCredentialsHonoursPermittedResource(t *testing.T) {
	e := newTokenEnv(t)
	addResourceClient(t, e)
	rec := e.postForm("/oauth/token", "grant_type=client_credentials&resource="+url.QueryEscape(resA), basic("client-res", "res-secret"))
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	at, _ := jsonBody(t, rec)["access_token"].(string)
	if got := audOf(t, e, at); got != resA {
		t.Fatalf("aud = %v, want %q", got, resA)
	}
	// A token for resource A is not accepted by the issuer's own endpoint.
	if rec := e.get("/oauth/userinfo", bearerAuth(at)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("userinfo accepted a token for another audience: %d", rec.Code)
	}
}

func TestResourceIsRefusedNeverIgnored(t *testing.T) {
	e := newTokenEnv(t)
	addResourceClient(t, e)
	for name, res := range map[string]string{
		"unregistered": resB,
		"relative":     "/api",
		"fragment":     resA + "#x",
		"not a uri":    "not a uri",
	} {
		rec := e.postForm("/oauth/token", "grant_type=client_credentials&resource="+url.QueryEscape(res), basic("client-res", "res-secret"))
		if rec.Code != http.StatusBadRequest || jsonBody(t, rec)["error"] != "invalid_target" {
			t.Fatalf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
}

func TestUserInfoAcceptsATokenForTheIssuer(t *testing.T) {
	e := newTokenEnv(t)
	at := e.issueAccessToken(t, "client-a", "user-1")
	if rec := e.get("/oauth/userinfo", bearerAuth(at.Value)); rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	other, err := e.tokens.Issue(context.Background(), token.IssueParams{
		ClientID: "client-a", Subject: "user-1", Scope: "read", Audience: []string{resB},
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := e.get("/oauth/userinfo", bearerAuth(other.Value))
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != `Bearer error="invalid_token"` {
		t.Fatalf("%d %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
}

func TestIssueRefusesAnEmptyAudience(t *testing.T) {
	e := newTokenEnv(t)
	for _, aud := range [][]string{nil, {}, {""}} {
		if _, err := e.tokens.Issue(context.Background(), token.IssueParams{ClientID: "c", Subject: "u", Audience: aud}); err == nil {
			t.Fatalf("Issue minted a token with audience %q", aud)
		}
	}
}

func TestAuthorizationCodeCarriesResourceToTokenAndRefresh(t *testing.T) {
	e := newTokenEnv(t)
	addResourceClient(t, e)
	c := e.login(t)
	q := authQuery("client-res", callback, map[string]string{"resource": resA})
	rec := e.get("/oauth/authorize?"+q, cookie(c))
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize = %d %s", rec.Code, rec.Body.String())
	}
	code := location(t, rec).Query().Get("code")

	// A different resource at redemption is refused (the code is spent either
	// way: every check after Consume is one guess per code).
	other := e.get("/oauth/authorize?"+q, cookie(c))
	otherCode := location(t, other).Query().Get("code")
	bad := e.postForm("/oauth/token", codeForm(otherCode, "resource", resB), basic("client-res", "res-secret"))
	if bad.Code != http.StatusBadRequest || jsonBody(t, bad)["error"] != "invalid_target" {
		t.Fatalf("%d %s", bad.Code, bad.Body.String())
	}
	rec = e.postForm("/oauth/token", codeForm(code), basic("client-res", "res-secret"))
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	body := jsonBody(t, rec)
	at, _ := body["access_token"].(string)
	rt, _ := body["refresh_token"].(string)
	if got := audOf(t, e, at); got != resA {
		t.Fatalf("aud = %v, want %q", got, resA)
	}

	// Refresh may not widen the audience...
	wide := e.postForm("/oauth/token", "grant_type=refresh_token&refresh_token="+rt+"&resource="+url.QueryEscape(issuer), basic("client-res", "res-secret"))
	if wide.Code != http.StatusBadRequest || jsonBody(t, wide)["error"] != "invalid_target" {
		t.Fatalf("%d %s", wide.Code, wide.Body.String())
	}
	// ...and an omitted resource keeps the bound one.
	rec = e.postForm("/oauth/token", "grant_type=refresh_token&refresh_token="+rt, basic("client-res", "res-secret"))
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	at2, _ := jsonBody(t, rec)["access_token"].(string)
	if got := audOf(t, e, at2); got != resA {
		t.Fatalf("refreshed aud = %v, want %q", got, resA)
	}
}

func TestAuthorizeRefusesAResourceTheClientMayNotRequest(t *testing.T) {
	e := newTokenEnv(t)
	addResourceClient(t, e)
	c := e.login(t)
	rec := e.get("/oauth/authorize?"+authQuery("client-res", callback, map[string]string{"resource": resB}), cookie(c))
	if rec.Code != http.StatusFound {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if got := location(t, rec).Query().Get("error"); got != "invalid_target" {
		t.Fatalf("error = %q in %q", got, rec.Header().Get("Location"))
	}
}

func TestResourceSurvivesTheLoginRoundTrip(t *testing.T) {
	e := newTokenEnv(t)
	addResourceClient(t, e)
	q := authQuery("client-res", callback, map[string]string{"resource": resA})
	rec := e.get("/oauth/authorize?" + q)
	if rec.Code != http.StatusFound {
		t.Fatalf("%d", rec.Code)
	}
	rq := location(t, rec).Query().Get("return_query")
	if !strings.Contains(rq, "resource=") {
		t.Fatalf("return_query dropped resource: %q", rq)
	}
}
