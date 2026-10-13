// Package health serves the liveness/readiness probe used by CI and operators.
//
// It intentionally exposes no OAuth protocol behavior: the bootstrap server
// boots and reports health, but every grant endpoint is still absent.
package health

import (
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
