package server_test

import (
	"net/http"
	"testing"

	"github.com/ianlintner/go-oauth2-server/internal/authcode"
)

// Without the resource-owner login (non-conformance/production mode) there is
// no verification page, so the device grant must be fail-closed: unrouted and
// not advertised, rather than issuing a verification_uri that 404s.
func TestDeviceGrantIsFailClosedWithoutLogin(t *testing.T) {
	e := newExtEnvMode(t, false, false)
	if rec := e.postJSON("/oauth/device_authorization", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("device_authorization without login = %d, want 404", rec.Code)
	}
	m := decode(t, e.get("/.well-known/oauth-authorization-server"))
	if _, ok := m["device_authorization_endpoint"]; ok {
		t.Fatal("device endpoint advertised without a verification page")
	}
	for _, g := range m["grant_types_supported"].([]any) {
		if g == authcode.GrantDeviceCode {
			t.Fatal("device grant advertised without a verification page")
		}
	}
}

func TestOIDCScopesSupportedIncludesRead(t *testing.T) {
	e := newExtEnv(t, false)
	m := decode(t, e.get("/.well-known/openid-configuration"))
	found := false
	for _, s := range m["scopes_supported"].([]any) {
		found = found || s == "read"
	}
	if !found {
		t.Fatalf("scopes_supported = %v, want read", m["scopes_supported"])
	}
}
