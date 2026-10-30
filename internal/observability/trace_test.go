package observability

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTraceCorrelationAcceptsOnlyValidTraceparent(t *testing.T) {
	var b bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&b, nil))
	handler := Trace(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	id := "0123456789abcdef0123456789abcdef"
	req := httptest.NewRequest("GET", "/health?token=must-not-log", nil)
	req.Header.Set("traceparent", "00-"+id+"-0123456789abcdef-01")
	handler.ServeHTTP(httptest.NewRecorder(), req)
	if !strings.Contains(b.String(), id) || strings.Contains(b.String(), "must-not-log") {
		t.Fatalf("trace log: %s", b.String())
	}
	b.Reset()
	req.Header.Set("traceparent", "00-invalid-0123456789abcdef-01")
	handler.ServeHTTP(httptest.NewRecorder(), req)
	if strings.Contains(b.String(), "invalid") {
		t.Fatalf("untrusted trace id logged: %s", b.String())
	}
}
