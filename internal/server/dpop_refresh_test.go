package server_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"testing"

	"github.com/ianlintner/go-oauth2-server/internal/dpop/dpoptest"
	"github.com/ianlintner/go-oauth2-server/internal/oauth"
	"github.com/ianlintner/go-oauth2-server/internal/secret"
)

// These tests pin RFC 9449 §5: a public client's refresh token is bound to the
// DPoP key of the request that issued it, and a refresh must prove possession
// of the same key. Confidential clients' refresh tokens stay unbound.

const (
	pubDPoPClient = "client-public-rt"
	confRTClient  = "client-conf-rt"
	confRTSecret  = "conf-rt-secret"
)

// addRefreshClients registers a public and a confidential client that may use
// the authorization-code and refresh grants, plus the user who logs in.
func addRefreshClients(t *testing.T, e *tokenEnv) {
	t.Helper()
	ctx := context.Background()
	h, err := secret.Hash(oauth.CryptoRandom{}, confRTSecret)
	if err != nil {
		t.Fatal(err)
	}
	grants := []string{"authorization_code", "refresh_token"}
	for _, c := range []oauth.Client{
		{ID: pubDPoPClient, Public: true, AuthMethod: "none", RedirectURIs: []string{callback}, GrantTypes: grants},
		{ID: confRTClient, SecretHash: h, AuthMethod: "client_secret_basic", RedirectURIs: []string{callback}, GrantTypes: grants},
	} {
		if err := e.store.Clients().Create(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	pw, err := secret.Hash(oauth.CryptoRandom{}, "test-only-password")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.store.Users().Create(ctx, oauth.User{ID: "user-1", Username: "alice", PasswordHash: pw}); err != nil {
		t.Fatal(err)
	}
	// Main's consent gate requires an explicit approval before an authorize
	// request issues a code; these clients model a previously consented user.
	for _, id := range []string{pubDPoPClient, confRTClient} {
		approveClient(t, e.store, "user-1", id)
	}
}

// tokenWithProof posts a token request carrying a fresh proof from k (none
// when k is nil).
func (e *tokenEnv) tokenWithProof(t *testing.T, body string, k *dpoptest.Key, opts ...reqOpt) tokenResult {
	t.Helper()
	if k != nil {
		opts = append(opts, header("DPoP", k.Proof(t, e.spec("POST", tokenEndpoint))))
	}
	rec := e.postForm("/oauth/token", body, opts...)
	r := tokenResult{code: rec.Code}
	if rec.Code == http.StatusOK {
		b := jsonBody(t, rec)
		r.access, _ = b["access_token"].(string)
		r.refresh, _ = b["refresh_token"].(string)
		r.tokenType, _ = b["token_type"].(string)
	} else {
		r.errCode, _ = jsonBody(t, rec)["error"].(string)
	}
	return r
}

type tokenResult struct {
	code                                int
	access, refresh, tokenType, errCode string
}

// issuePair redeems a fresh authorization code for clientID with the given
// key (nil = no proof) and returns the resulting token response.
func (e *tokenEnv) issuePair(t *testing.T, clientID string, k *dpoptest.Key, opts ...reqOpt) tokenResult {
	t.Helper()
	code := e.issueCode(t, clientID, callback)
	form := codeForm(code)
	if clientID == pubDPoPClient {
		form += "&client_id=" + url.QueryEscape(clientID)
	}
	r := e.tokenWithProof(t, form, k, opts...)
	if r.code != http.StatusOK || r.refresh == "" {
		t.Fatalf("code redemption = %+v", r)
	}
	return r
}

// hashHex mirrors the token hash the service persists (SHA-256, hex).
func hashHex(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}

func TestPublicClientRefreshTokenStoresTheProofKeyThumbprint(t *testing.T) {
	e := newTokenEnv(t)
	addRefreshClients(t, e)
	k := dpoptest.NewKey(t)
	first := e.issuePair(t, pubDPoPClient, &k)
	rec, err := e.store.RefreshTokens().GetByHash(context.Background(), hashHex(first.refresh))
	if err != nil {
		t.Fatal(err)
	}
	if rec.DPoPJKT != k.JKT(t) {
		t.Fatalf("stored jkt = %q, want %q", rec.DPoPJKT, k.JKT(t))
	}
}

func refreshForm(rt, clientID string) string {
	v := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}
	if clientID != "" {
		v.Set("client_id", clientID)
	}
	return v.Encode()
}

func TestPublicClientMayUseDPoPAndRefreshWithTheSameKey(t *testing.T) {
	e := newTokenEnv(t)
	addRefreshClients(t, e)
	k := dpoptest.NewKey(t)

	first := e.issuePair(t, pubDPoPClient, &k)
	if first.tokenType != "DPoP" {
		t.Fatalf("token_type = %q, want DPoP", first.tokenType)
	}
	next := e.tokenWithProof(t, refreshForm(first.refresh, pubDPoPClient), &k)
	if next.code != http.StatusOK || next.refresh == "" || next.tokenType != "DPoP" {
		t.Fatalf("refresh with the bound key = %+v", next)
	}
}

func TestPublicClientRefreshRejectsADifferentKey(t *testing.T) {
	e := newTokenEnv(t)
	addRefreshClients(t, e)
	k, thief := dpoptest.NewKey(t), dpoptest.NewKey(t)

	first := e.issuePair(t, pubDPoPClient, &k)
	r := e.tokenWithProof(t, refreshForm(first.refresh, pubDPoPClient), &thief)
	if r.code != http.StatusBadRequest || r.errCode != "invalid_grant" {
		t.Fatalf("wrong key = %+v, want 400 invalid_grant", r)
	}
	// The refusal must not burn the legitimate token.
	ok := e.tokenWithProof(t, refreshForm(first.refresh, pubDPoPClient), &k)
	if ok.code != http.StatusOK {
		t.Fatalf("refresh after a refused thief = %+v, want 200", ok)
	}
}

func TestPublicClientRefreshRequiresAProofWhenBound(t *testing.T) {
	e := newTokenEnv(t)
	addRefreshClients(t, e)
	k := dpoptest.NewKey(t)

	first := e.issuePair(t, pubDPoPClient, &k)
	r := e.tokenWithProof(t, refreshForm(first.refresh, pubDPoPClient), nil)
	if r.code != http.StatusBadRequest || r.errCode != "invalid_grant" {
		t.Fatalf("missing proof = %+v, want 400 invalid_grant", r)
	}
}

func TestPublicClientRefreshBindingSurvivesRotation(t *testing.T) {
	e := newTokenEnv(t)
	addRefreshClients(t, e)
	k, thief := dpoptest.NewKey(t), dpoptest.NewKey(t)

	cur := e.issuePair(t, pubDPoPClient, &k)
	for i := 0; i < 3; i++ {
		cur = e.tokenWithProof(t, refreshForm(cur.refresh, pubDPoPClient), &k)
		if cur.code != http.StatusOK {
			t.Fatalf("rotation %d = %+v", i, cur)
		}
	}
	// The latest member is still bound to k, not to whoever presented last.
	if r := e.tokenWithProof(t, refreshForm(cur.refresh, pubDPoPClient), &thief); r.code != http.StatusBadRequest || r.errCode != "invalid_grant" {
		t.Fatalf("rotated token with wrong key = %+v", r)
	}
	if r := e.tokenWithProof(t, refreshForm(cur.refresh, pubDPoPClient), nil); r.code != http.StatusBadRequest || r.errCode != "invalid_grant" {
		t.Fatalf("rotated token without proof = %+v", r)
	}
}

func TestPublicClientUnboundRefreshTokenCannotBeUpgradedOntoAKey(t *testing.T) {
	// A token issued without DPoP records no key; presenting a proof must not
	// bind it (a thief could otherwise capture it onto their own key).
	e := newTokenEnv(t)
	addRefreshClients(t, e)
	first := e.issuePair(t, pubDPoPClient, nil)

	k := dpoptest.NewKey(t)
	r := e.tokenWithProof(t, refreshForm(first.refresh, pubDPoPClient), &k)
	if r.code != http.StatusBadRequest || r.errCode != "invalid_grant" {
		t.Fatalf("proof on an unbound public token = %+v", r)
	}
	// Plain (non-DPoP) public clients keep working unchanged.
	if ok := e.tokenWithProof(t, refreshForm(first.refresh, pubDPoPClient), nil); ok.code != http.StatusOK || ok.tokenType != "Bearer" {
		t.Fatalf("plain refresh = %+v", ok)
	}
}

func TestPublicClientReplayRevokesTheFamilyRegardlessOfBinding(t *testing.T) {
	// Family revocation is unaffected: replaying a consumed member with the
	// right key revokes the lineage, including the live replacement.
	e := newTokenEnv(t)
	addRefreshClients(t, e)
	k := dpoptest.NewKey(t)

	first := e.issuePair(t, pubDPoPClient, &k)
	live := e.tokenWithProof(t, refreshForm(first.refresh, pubDPoPClient), &k)
	if live.code != http.StatusOK {
		t.Fatalf("rotate = %+v", live)
	}
	if r := e.tokenWithProof(t, refreshForm(first.refresh, pubDPoPClient), &k); r.code != http.StatusBadRequest || r.errCode != "invalid_grant" {
		t.Fatalf("replay = %+v", r)
	}
	if r := e.tokenWithProof(t, refreshForm(live.refresh, pubDPoPClient), &k); r.code != http.StatusBadRequest || r.errCode != "invalid_grant" {
		t.Fatalf("live member after family revoke = %+v", r)
	}
}

func TestConfidentialClientRefreshStaysUnbound(t *testing.T) {
	// RFC 9449 §5: confidential clients authenticate, so their refresh token
	// is not bound; a refresh may present any key (or none).
	e := newTokenEnv(t)
	addRefreshClients(t, e)
	k, other := dpoptest.NewKey(t), dpoptest.NewKey(t)

	first := e.issuePair(t, confRTClient, &k, basic(confRTClient, confRTSecret))
	rec, err := e.store.RefreshTokens().GetByHash(context.Background(), hashHex(first.refresh))
	if err != nil {
		t.Fatal(err)
	}
	if rec.DPoPJKT != "" {
		t.Fatalf("confidential refresh token DPoPJKT = %q, want empty", rec.DPoPJKT)
	}
	second := e.tokenWithProof(t, refreshForm(first.refresh, ""), &other, basic(confRTClient, confRTSecret))
	if second.code != http.StatusOK {
		t.Fatalf("refresh with another key = %+v", second)
	}
	if third := e.tokenWithProof(t, refreshForm(second.refresh, ""), nil, basic(confRTClient, confRTSecret)); third.code != http.StatusOK {
		t.Fatalf("refresh without proof = %+v", third)
	}
}
