package oauth_test

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
)

func TestErrorStatusMapping(t *testing.T) {
	tests := []struct {
		err    *oauth.Error
		status int
	}{
		{oauth.InvalidRequest("x"), http.StatusBadRequest},
		{oauth.InvalidClient("x", false), http.StatusBadRequest},
		{oauth.InvalidClient("x", true), http.StatusUnauthorized},
		{oauth.InvalidGrant("x"), http.StatusBadRequest},
		{oauth.UnauthorizedClient("x"), http.StatusBadRequest},
		{oauth.UnsupportedGrantType("x"), http.StatusBadRequest},
		{oauth.UnsupportedResponseType("x"), http.StatusBadRequest},
		{oauth.InvalidScope("x"), http.StatusBadRequest},
		{oauth.AccessDenied("x"), http.StatusForbidden},
		{oauth.InvalidToken("x"), http.StatusUnauthorized},
		{oauth.InsufficientScope("x"), http.StatusForbidden},
		{oauth.ServerError(nil), http.StatusInternalServerError},
		{oauth.TemporarilyUnavailable("x"), http.StatusServiceUnavailable},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("%s/%d", tc.err.Code, tc.status), func(t *testing.T) {
			if got := tc.err.HTTPStatus(); got != tc.status {
				t.Fatalf("HTTPStatus() = %d, want %d", got, tc.status)
			}
		})
	}
}

func TestErrorWrapsCauseWithoutExposingItInDescription(t *testing.T) {
	cause := errors.New("sql: connection refused to db.internal:5432")
	e := oauth.ServerError(cause)
	if !errors.Is(e, cause) {
		t.Fatal("ServerError must wrap the cause for logging")
	}
	if e.Description == "" || e.Description == cause.Error() {
		t.Fatalf("description must be generic, got %q", e.Description)
	}
}

func TestAsErrorClassifiesUnknownErrorsAsServerError(t *testing.T) {
	plain := errors.New("boom")
	got := oauth.AsError(plain)
	if got.Code != oauth.CodeServerError {
		t.Fatalf("code = %q, want server_error", got.Code)
	}
	if !errors.Is(got, plain) {
		t.Fatal("cause lost")
	}

	typed := fmt.Errorf("wrapped: %w", oauth.InvalidGrant("expired"))
	if got := oauth.AsError(typed); got.Code != oauth.CodeInvalidGrant {
		t.Fatalf("code = %q, want invalid_grant", got.Code)
	}
	if oauth.AsError(nil) != nil {
		t.Fatal("AsError(nil) must be nil")
	}
}
