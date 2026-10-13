// Package server assembles the HTTP surface of the OAuth2 server.
//
// Skeleton scope: only health and readiness are routed. OAuth grant endpoints
// are added by later implementation cards, so a request for /oauth/token must
// fail loudly (404) rather than appear handled.
package server

import (
	"context"
	"net/http"

	"github.com/ianlintner/go-oauth2-server/internal/health"
)

// Deps are the collaborators the router needs.
type Deps struct {
	// Ping reports whether the backing store is reachable; nil means always up.
	Ping func(context.Context) error
	// Conformance advertises test mode on /health (see internal/conformance).
	Conformance bool
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
	return mux
}
