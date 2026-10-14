// Package health serves the liveness/readiness probe used by CI and operators.
//
// It intentionally exposes no OAuth protocol behavior: the bootstrap server
// boots and reports health, but every grant endpoint is still absent.
package health

import (
	"context"
	"encoding/json"
	"net/http"
)

// Handler answers health probes. It is an http.Handler so it composes into the
// server mux without a framework.
type Handler struct{}

// NewHandler returns the health handler.
func NewHandler() *Handler {
	return &Handler{}
}

// ServeHTTP reports a fixed "ok" payload. Only GET is accepted so that a
// misconfigured probe (or an accidental write) is visible as 405 rather than
// silently treated as healthy.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// NewReadyHandler returns the readiness handler: 200 only while ping succeeds,
// 503 otherwise. The failure body is generic on purpose; the dependency error
// stays in logs. When conformance is true the body also advertises test mode,
// which the contract's SUT interface lets the runner observe; with it false no
// test-mode detail is exposed.
func NewReadyHandler(ping func(context.Context) error, conformance bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if err := ping(r.Context()); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "unavailable"})
			return
		}
		body := map[string]any{"status": "ok"}
		if conformance {
			body["conformance"] = true
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(body)
	})
}
