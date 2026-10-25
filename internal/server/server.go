// Package server assembles the HTTP surface of the OAuth2 server.
//
// Health and readiness are always routed. The authorization-code endpoints
// (authorize, token, metadata) are routed only when a Service is supplied, and
// the resource-owner login form only in conformance mode: this slice has no
// user-management surface, so credential entry exists solely as the shared
// contract's test-mode login (contract/sut-interface.md §3, §5).
package server

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/ianlintner/go-oauth2-server/internal/authcode"
	"github.com/ianlintner/go-oauth2-server/internal/dpop"
	"github.com/ianlintner/go-oauth2-server/internal/health"
	"github.com/ianlintner/go-oauth2-server/internal/observability"
	"github.com/ianlintner/go-oauth2-server/internal/session"
	"github.com/ianlintner/go-oauth2-server/internal/token"
)

// Deps are the collaborators the router needs.
type Deps struct {
	// Metrics is opt-in; /metrics is absent when nil.
	Metrics *observability.Metrics
	// Ping reports whether the backing store is reachable; nil means always up.
	Ping func(context.Context) error
	// Conformance advertises test mode on /health (see internal/conformance)
	// and enables the test-mode login form.
	Conformance bool

	// Service and Sessions enable the OAuth endpoints; both are required
	// together. Issuer is the exact configured issuer identifier (RFC 9207
	// iss, RFC 8414 issuer); it is never normalized.
	Service  *authcode.Service
	Sessions *session.Manager
	Issuer   string

	// Tokens enables the token-lifecycle endpoints (introspection,
	// revocation, JWKS) and discovery extension. When Service/Sessions are
	// supplied it must also be non-nil, or those endpoints answer 500.
	Tokens *token.Service

	// DPoP enables RFC 9449 sender-constrained access tokens at the token
	// endpoint and /oauth/userinfo. Nil leaves DPoP off: a DPoP header on a
	// token request is ignored and bearer tokens are issued.
	DPoP *dpop.Verifier

	// Logger receives internal error causes, which are never sent to clients.
	Logger *slog.Logger

	// RegistrationEnabled mounts RFC 7591 dynamic client registration at
	// POST /connect/register. It is open registration (no initial access
	// token) and is therefore refused in production by internal/config.
	// RegistrationScopes is the ceiling of scopes a registrant may request.
	RegistrationEnabled bool
	RegistrationScopes  []string
}

// NewRouter returns a router with no dependencies, serving liveness only
// semantics for both probes.
func NewRouter() http.Handler { return New(Deps{}) }

// New returns the server's HTTP handler.
//
// It uses the standard library method/path ServeMux (Go 1.22+) rather than a
// framework, keeping protocol behavior explicit and observable. GET /healthz is
// liveness; GET /health is readiness and fails when the store is unreachable.
func New(d Deps) http.Handler {
	ping := d.Ping
	if ping == nil {
		ping = func(context.Context) error { return nil }
	}
	mux := http.NewServeMux()
	mux.Handle("GET /healthz", health.NewHandler())
	mux.Handle("GET /health", health.NewReadyHandler(ping, d.Conformance))
	if d.Metrics != nil {
		mux.Handle("GET /metrics", d.Metrics.Handler())
	}

	if d.Service != nil && d.Sessions != nil {
		h := newOAuthHandlers(d)
		mux.HandleFunc("GET /.well-known/oauth-authorization-server", h.metadata)
		mux.HandleFunc("GET /.well-known/openid-configuration", h.openidConfiguration)
		mux.HandleFunc("GET /.well-known/jwks.json", h.jwks)
		mux.HandleFunc("/oauth/authorize", h.authorize)
		mux.HandleFunc("/oauth/token", h.token)
		mux.HandleFunc("POST /oauth/introspect", h.introspect)
		mux.HandleFunc("POST /oauth/revoke", h.revoke)
		mux.HandleFunc("/oauth/userinfo", h.userinfo)
		mux.HandleFunc("/oauth/par", h.par)
		if d.RegistrationEnabled {
			mux.HandleFunc("/connect/register", h.register)
		}
		if d.Conformance {
			// The device grant needs the verification page, which needs a
			// resource-owner login; both exist only here, so the grant is
			// fail-closed (404, not advertised) elsewhere.
			mux.HandleFunc("/oauth/device_authorization", h.deviceAuthorization)
			mux.HandleFunc("/oauth/device/verify", h.deviceVerify)
			mux.HandleFunc("GET /auth/login", h.loginForm)
			mux.HandleFunc("POST /auth/login", h.loginSubmit)
		}
	}
	handler := hardenHeaders(mux)
	if d.Metrics != nil {
		handler = d.Metrics.Wrap(handler)
	}
	return handler
}

// hardenHeaders sets response headers that are safe on every route: no MIME
// sniffing, no framing (clickjacking of the login form), no referrer leakage
// of authorization URLs, and a CSP that forbids loading anything. The CSP
// deliberately omits form-action: browsers apply it to the redirect chain
// that follows a form post, which would block the login -> authorize ->
// client redirect.
func hardenHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
