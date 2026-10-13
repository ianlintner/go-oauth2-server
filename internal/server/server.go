// Package server assembles the HTTP surface of the OAuth2 server.
//
// Bootstrap scope: only the health probe is routed. OAuth grant endpoints are
// added by later implementation cards, so a request for /oauth/token must fail
// loudly (404) rather than appear handled.
package server

import (
	"net/http"

	"github.com/ianlintner/go-oauth2-server/internal/health"
)

// NewRouter returns the server's HTTP handler.
//
// It uses the standard library method/path ServeMux (Go 1.22+) rather than a
// framework, keeping protocol behavior explicit and observable.
func NewRouter() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /healthz", health.NewHandler())
	return mux
}
