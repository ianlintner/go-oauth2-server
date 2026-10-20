package authcode_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ianlintner/go-oauth2-server/internal/authcode"
	"github.com/ianlintner/go-oauth2-server/internal/oauth"
	"github.com/ianlintner/go-oauth2-server/internal/secret"
)

const (
	devSecret = "test-only-dev-secret"
	verifyURI = "https://issuer.example/oauth/device/verify"
)

func addDeviceClients(t *testing.T, e *env) {
	t.Helper()
	h, err := secret.Hash(oauth.CryptoRandom{}, devSecret)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []oauth.Client{
		{ID: "client-dev", SecretHash: h, AuthMethod: "client_secret_basic", RedirectURIs: []string{callback},
			Scopes: []string{"read"}, GrantTypes: []string{authcode.GrantDeviceCode}},
		{ID: "client-dev2", SecretHash: h, AuthMethod: "client_secret_basic", RedirectURIs: []string{callback},
			Scopes: []string{"read"}, GrantTypes: []string{authcode.GrantDeviceCode}},
		{ID: "client-dev-public", Public: true, AuthMethod: "none", RedirectURIs: []string{callback},
			GrantTypes: []string{authcode.GrantDeviceCode}},
	} {
		if err := e.store.Clients().Create(context.Background(), c); err != nil {
			t.Fatal(err)
		}
	}
}

func startDevice(t *testing.T, e *env) authcode.DeviceAuthorization {
	t.Helper()
	d, err := e.svc.AuthorizeDevice(context.Background(), basic("client-dev", devSecret),
		params(t, "client_id", "client-dev", "scope", "read"), verifyURI)
	if err != nil {
		t.Fatalf("AuthorizeDevice: %v", err)
	}
	return d
}

func pollDevice(e *env, t *testing.T, clientID, deviceCode string) (authcode.TokenResponse, error) {
	t.Helper()
	return e.svc.Token(context.Background(), basic(clientID, devSecret), params(t,
		"grant_type", authcode.GrantDeviceCode, "device_code", deviceCode, "client_id", clientID))
}

func TestDeviceAuthorizationResponse(t *testing.T) {
	e := newEnv(t)
	addDeviceClients(t, e)
	d := startDevice(t, e)
	if d.DeviceCode == "" || len(d.DeviceCode) < 40 {
		t.Fatalf("device_code too short: %q", d.DeviceCode)
	}
	if len(d.UserCode) != 9 || d.UserCode[4] != '-' {
		t.Fatalf("user_code = %q, want XXXX-XXXX", d.UserCode)
	}
	if strings.ContainsAny(d.UserCode, "AEIOU01") {
		t.Fatalf("user_code %q contains a vowel or look-alike", d.UserCode)
	}
	if d.VerificationURI != verifyURI || d.ExpiresIn <= 0 || d.Interval < 1 {
		t.Fatalf("response = %+v", d)
	}
}

func TestDeviceAuthorizationRejects(t *testing.T) {
	e := newEnv(t)
	addDeviceClients(t, e)
	ctx := context.Background()

	cases := []struct {
		name string
		auth string
		kv   []string
		want oauth.Code
	}{
		{"missing client", "", []string{"scope", "read"}, oauth.CodeInvalidRequest},
		{"unknown client", "", []string{"client_id", "no-such-client"}, oauth.CodeInvalidClient},
		{"wrong secret", basic("client-dev", "wrong"), []string{"client_id", "client-dev"}, oauth.CodeInvalidClient},
		{"client without the grant", basic("client-a", "test-only-secret"), []string{"client_id", "client-a"}, oauth.CodeUnauthorizedClient},
		{"scope outside registration", basic("client-dev", devSecret), []string{"client_id", "client-dev", "scope", "admin"}, oauth.CodeInvalidScope},
		{"confidential client without auth", "", []string{"client_id", "client-dev"}, oauth.CodeInvalidClient},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := e.svc.AuthorizeDevice(ctx, c.auth, params(t, c.kv...), verifyURI)
			wantCode(t, err, c.want)
		})
	}
}

func TestDevicePublicClientNeedsNoSecret(t *testing.T) {
	e := newEnv(t)
	addDeviceClients(t, e)
	if _, err := e.svc.AuthorizeDevice(context.Background(), "", params(t, "client_id", "client-dev-public"), verifyURI); err != nil {
		t.Fatalf("public client: %v", err)
	}
}

func TestDeviceFlowApproved(t *testing.T) {
	e := newEnv(t)
	addDeviceClients(t, e)
	d := startDevice(t, e)

	// Pending first.
	_, err := pollDevice(e, t, "client-dev", d.DeviceCode)
	wantCode(t, err, oauth.CodeAuthorizationPending)

	// The user types the code in lower case without the dash.
	typed := strings.ToLower(strings.ReplaceAll(d.UserCode, "-", " "))
	if err := e.svc.DecideDevice(context.Background(), e.user, typed, true); err != nil {
		t.Fatalf("DecideDevice: %v", err)
	}
	e.clock.Advance(6 * time.Second)
	tok, err := pollDevice(e, t, "client-dev", d.DeviceCode)
	if err != nil {
		t.Fatalf("poll after approval: %v", err)
	}
	if tok.AccessToken == "" || tok.TokenType != "Bearer" || tok.Scope != "read" {
		t.Fatalf("token response = %+v", tok)
	}

	// The device code is single use.
	e.clock.Advance(6 * time.Second)
	_, err = pollDevice(e, t, "client-dev", d.DeviceCode)
	wantCode(t, err, oauth.CodeInvalidGrant)
}

func TestDeviceFlowDeniedIs400(t *testing.T) {
	e := newEnv(t)
	addDeviceClients(t, e)
	d := startDevice(t, e)
	if err := e.svc.DecideDevice(context.Background(), e.user, d.UserCode, false); err != nil {
		t.Fatal(err)
	}
	_, err := pollDevice(e, t, "client-dev", d.DeviceCode)
	oe := wantCode(t, err, oauth.CodeAccessDenied)
	if oe.HTTPStatus() != 400 {
		t.Fatalf("status = %d, want 400 (RFC 8628 §3.5)", oe.HTTPStatus())
	}
	// A denial is final: a later approval attempt cannot flip it.
	err = e.svc.DecideDevice(context.Background(), e.user, d.UserCode, true)
	wantCode(t, err, oauth.CodeInvalidRequest)
	e.clock.Advance(6 * time.Second)
	_, err = pollDevice(e, t, "client-dev", d.DeviceCode)
	wantCode(t, err, oauth.CodeAccessDenied)
}

func TestDeviceCodeBoundToClient(t *testing.T) {
	e := newEnv(t)
	addDeviceClients(t, e)
	d := startDevice(t, e)
	if err := e.svc.DecideDevice(context.Background(), e.user, d.UserCode, true); err != nil {
		t.Fatal(err)
	}
	_, err := pollDevice(e, t, "client-dev2", d.DeviceCode)
	wantCode(t, err, oauth.CodeInvalidGrant)
	// The legitimate client still gets its token: the stolen-code attempt did
	// not burn the code.
	e.clock.Advance(6 * time.Second)
	if _, err := pollDevice(e, t, "client-dev", d.DeviceCode); err != nil {
		t.Fatalf("legitimate redemption: %v", err)
	}
}

func TestDeviceCodeExpires(t *testing.T) {
	e := newEnv(t)
	addDeviceClients(t, e)
	d := startDevice(t, e)
	if err := e.svc.DecideDevice(context.Background(), e.user, d.UserCode, true); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(authcode.DefaultDeviceCodeTTL + time.Second)
	_, err := pollDevice(e, t, "client-dev", d.DeviceCode)
	wantCode(t, err, oauth.CodeExpiredToken)
}

func TestDeviceUserCodeCannotBeUsedAfterExpiry(t *testing.T) {
	e := newEnv(t)
	addDeviceClients(t, e)
	d := startDevice(t, e)
	e.clock.Advance(authcode.DefaultDeviceCodeTTL + time.Second)
	err := e.svc.DecideDevice(context.Background(), e.user, d.UserCode, true)
	wantCode(t, err, oauth.CodeInvalidRequest)
}

func TestDeviceSlowDownIncreasesInterval(t *testing.T) {
	e := newEnv(t)
	addDeviceClients(t, e)
	d := startDevice(t, e)

	_, err := pollDevice(e, t, "client-dev", d.DeviceCode)
	wantCode(t, err, oauth.CodeAuthorizationPending)

	// Immediately again: too fast.
	_, err = pollDevice(e, t, "client-dev", d.DeviceCode)
	wantCode(t, err, oauth.CodeSlowDown)

	// Waiting only the original interval is no longer enough (+5s).
	e.clock.Advance(time.Duration(authcode.DefaultDeviceInterval)*time.Second + time.Second)
	_, err = pollDevice(e, t, "client-dev", d.DeviceCode)
	wantCode(t, err, oauth.CodeSlowDown)

	// Waiting the new interval works, and shows the real state.
	e.clock.Advance(time.Duration(authcode.DefaultDeviceInterval+10) * time.Second)
	_, err = pollDevice(e, t, "client-dev", d.DeviceCode)
	wantCode(t, err, oauth.CodeAuthorizationPending)
}

func TestDevicePollMissingOrUnknownCode(t *testing.T) {
	e := newEnv(t)
	addDeviceClients(t, e)
	_, err := e.svc.Token(context.Background(), basic("client-dev", devSecret),
		params(t, "grant_type", authcode.GrantDeviceCode, "client_id", "client-dev"))
	wantCode(t, err, oauth.CodeInvalidRequest)
	_, err = pollDevice(e, t, "client-dev", "no-such-device-code")
	wantCode(t, err, oauth.CodeInvalidGrant)
}

func TestDeviceUserCodeBruteForceIsLimited(t *testing.T) {
	e := newEnv(t)
	addDeviceClients(t, e)
	d := startDevice(t, e)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		err := e.svc.DecideDevice(ctx, e.user, "BCDF-GHJK", true)
		wantCode(t, err, oauth.CodeInvalidRequest)
	}
	// Even the correct code is refused while the user is locked out.
	err := e.svc.DecideDevice(ctx, e.user, d.UserCode, true)
	oe := wantCode(t, err, oauth.CodeInvalidRequest)
	if oe.HTTPStatus() != 429 {
		t.Fatalf("lockout status = %d, want 429", oe.HTTPStatus())
	}
	// The lockout ends with the window.
	e.clock.Advance(6 * time.Minute)
	if err := e.svc.DecideDevice(ctx, e.user, d.UserCode, true); err != nil {
		t.Fatalf("after window: %v", err)
	}
}

func TestDeviceUserCodeMalformedInputsAreRejected(t *testing.T) {
	e := newEnv(t)
	addDeviceClients(t, e)
	for _, in := range []string{"", "short", "AEIOU-AEIOU", "BCDF-GHJK-LMNP", "BCDF GHJ!", "0000-0000"} {
		err := e.svc.DecideDevice(context.Background(), oauth.User{ID: "u-" + in}, in, true)
		wantCode(t, err, oauth.CodeInvalidRequest)
	}
}

func TestDeviceGrantIsNotAvailableToOtherClients(t *testing.T) {
	e := newEnv(t)
	addDeviceClients(t, e)
	d := startDevice(t, e)
	// client-a is not registered for the device grant.
	_, err := e.svc.Token(context.Background(), basic("client-a", "test-only-secret"),
		params(t, "grant_type", authcode.GrantDeviceCode, "device_code", d.DeviceCode, "client_id", "client-a"))
	wantCode(t, err, oauth.CodeUnauthorizedClient)
}
