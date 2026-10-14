package server_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
	"github.com/ianlintner/go-oauth2-server/internal/server"
)

func decodeError(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not a JSON object of strings: %v (%q)", err, rec.Body.String())
	}
	return body
}

func TestWriteErrorRFC6749Shape(t *testing.T) {
	rec := httptest.NewRecorder()
	server.WriteError(rec, oauth.UnsupportedGrantType("grant type not supported"))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	if got := rec.Header().Get("Pragma"); got != "no-cache" {
		t.Fatalf("Pragma = %q, want no-cache", got)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q", got)
	}
	body := decodeError(t, rec)
	if body["error"] != "unsupported_grant_type" || body["error_description"] != "grant type not supported" {
		t.Fatalf("body = %v", body)
	}
}

func TestWriteErrorInvalidClientChallenge(t *testing.T) {
	rec := httptest.NewRecorder()
	server.WriteError(rec, oauth.InvalidClient("bad credentials", true))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); !strings.HasPrefix(got, "Basic ") {
		t.Fatalf("WWW-Authenticate = %q, want Basic challenge", got)
	}

	rec = httptest.NewRecorder()
	server.WriteError(rec, oauth.InvalidClient("bad credentials", false))
	if rec.Code != http.StatusBadRequest || rec.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("form-auth invalid_client: status=%d challenge=%q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
}

func TestWriteErrorBearerChallenge(t *testing.T) {
	rec := httptest.NewRecorder()
	server.WriteError(rec, oauth.InvalidToken("expired"))
	got := rec.Header().Get("WWW-Authenticate")
	if !strings.HasPrefix(got, "Bearer ") || !strings.Contains(got, `error="invalid_token"`) {
		t.Fatalf("WWW-Authenticate = %q", got)
	}
}

func TestWriteErrorSanitizesDescription(t *testing.T) {
	rec := httptest.NewRecorder()
	server.WriteError(rec, oauth.InvalidRequest("bad \"quote\" \\ and \n newline é"))
	desc := decodeError(t, rec)["error_description"]
	for _, r := range desc {
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' {
			t.Fatalf("description %q contains RFC 6749 §5.2-disallowed rune %q", desc, r)
		}
	}
}

func TestWriteErrorHidesInternalCause(t *testing.T) {
	rec := httptest.NewRecorder()
	server.WriteError(rec, errors.New("dial tcp 10.0.0.5:5432: password=hunter2"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "hunter2") || strings.Contains(rec.Body.String(), "10.0.0.5") {
		t.Fatalf("internal detail leaked: %s", rec.Body.String())
	}
	if decodeError(t, rec)["error"] != "server_error" {
		t.Fatalf("body = %s", rec.Body.String())
	}
}
