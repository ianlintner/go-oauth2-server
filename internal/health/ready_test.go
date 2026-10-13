package health_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ianlintner/go-oauth2-server/internal/health"
)

func serve(h http.Handler, method string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, "/health", nil))
	return rec
}

func TestReadyHandlerOKWhenDependencyUp(t *testing.T) {
	rec := serve(health.NewReadyHandler(func(context.Context) error { return nil }, false), http.MethodGet)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "ok" {
		t.Fatalf("body = %v", body)
	}
	if _, ok := body["conformance"]; ok {
		t.Fatalf("test-mode detail present with conformance off: %v", body)
	}
}

func TestReadyHandlerReports503WhenDependencyDown(t *testing.T) {
	down := errors.New("dial tcp 10.1.2.3:5432: password authentication failed for user admin")
	rec := serve(health.NewReadyHandler(func(context.Context) error { return down }, false), http.MethodGet)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if body := rec.Body.String(); contains(body, "10.1.2.3") || contains(body, "password") {
		t.Fatalf("readiness body leaks dependency detail: %s", body)
	}
}

func TestReadyHandlerAdvertisesConformanceMode(t *testing.T) {
	rec := serve(health.NewReadyHandler(func(context.Context) error { return nil }, true), http.MethodGet)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["conformance"] != true {
		t.Fatalf("body = %v, want conformance true", body)
	}
}

func TestReadyHandlerRejectsNonGet(t *testing.T) {
	rec := serve(health.NewReadyHandler(func(context.Context) error { return nil }, false), http.MethodPost)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
