// Package server_test proves the assembled HTTP mux serves health and that the
// server boots through the same handler wiring main uses.
package server_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ianlintner/go-oauth2-server/internal/server"
)

func TestRouterServesHealthz(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)

	server.NewRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
	}

	var body struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if body.Status != "ok" {
		t.Fatalf("status field = %q, want %q", body.Status, "ok")
	}
}

// The bootstrap deliberately exposes no OAuth grants: a token request must not
// be served, so an implementation card cannot mistake the skeleton for working
// OAuth behavior.
func TestRouterDoesNotServeTokenEndpointYet(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", nil)

	server.NewRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("POST /oauth/token status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}
