package server_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ianlintner/go-oauth2-server/internal/observability"
	"github.com/ianlintner/go-oauth2-server/internal/server"
)

func TestMetricsExposeBoundedRouteNotSensitivePath(t *testing.T) {
	metrics := observability.New()
	handler := server.New(server.Deps{Metrics: metrics})
	secret := "untrusted-token-value"
	req := httptest.NewRequest(http.MethodGet, "/unknown/"+secret, nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rr.Code != 200 {
		t.Fatalf("metrics status=%d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "oauth2_server_http_requests_total") || !strings.Contains(body, `route="unmatched"`) {
		t.Fatalf("missing route request metric: %s", body)
	}
	if strings.Contains(body, secret) || strings.Contains(body, "/unknown/") {
		t.Fatal("metrics exposed untrusted path")
	}
	if strings.Contains(body, `route="/metrics"`) {
		t.Fatal("scrapes must not recursively count themselves")
	}

}
func TestMetricsDisabledByDefault(t *testing.T) {
	rr := httptest.NewRecorder()
	server.New(server.Deps{}).ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	if rr.Code != 404 {
		t.Fatalf("disabled metrics status=%d", rr.Code)
	}
}
