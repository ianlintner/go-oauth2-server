// Package oauth is the HTTP- and SQL-independent core of the server: typed
// protocol errors, the injected dependencies (Clock, Random, Signer) and the
// storage ports every adapter implements.
package oauth

import (
	"errors"
	"net/http"
)

// Code is an RFC 6749 §5.2 / RFC 6750 §3.1 error code.
type Code string

// Error codes used by the server. Only codes that a later grant/endpoint card
// will actually emit are listed.
const (
	CodeInvalidRequest          Code = "invalid_request"
	CodeInvalidClient           Code = "invalid_client"
	CodeInvalidGrant            Code = "invalid_grant"
	CodeUnauthorizedClient      Code = "unauthorized_client"
	CodeUnsupportedGrantType    Code = "unsupported_grant_type"
	CodeUnsupportedResponseType Code = "unsupported_response_type"
	CodeInvalidScope            Code = "invalid_scope"
	CodeAccessDenied            Code = "access_denied"
	CodeInvalidToken            Code = "invalid_token"
	CodeInsufficientScope       Code = "insufficient_scope"
	CodeServerError             Code = "server_error"
	CodeTemporarilyUnavailable  Code = "temporarily_unavailable"

	// RFC 8628 §3.5 device grant token-endpoint errors.
	CodeAuthorizationPending Code = "authorization_pending"
	CodeSlowDown             Code = "slow_down"
	CodeExpiredToken         Code = "expired_token"

	// RFC 9126 §4 / OIDC Core §3.1.2.6 request_uri error.
	CodeInvalidRequestURI Code = "invalid_request_uri"

	// RFC 9449 §5 DPoP error for a missing or invalid proof.
	CodeInvalidDPoPProof Code = "invalid_dpop_proof"

	// RFC 7591 §3.2.2 registration errors.
	CodeInvalidRedirectURI    Code = "invalid_redirect_uri"
	CodeInvalidClientMetadata Code = "invalid_client_metadata"
)

// Error is the single typed OAuth error. It is mapped exactly once, in the
// HTTP layer, to status, headers and body. Cause carries an internal error for
// logging only; it is never serialized.
type Error struct {
	Code        Code
	Description string
	// ClientAuthAttempted marks an invalid_client produced when the client
	// authenticated through the Authorization header (RFC 6749 §5.2 requires
	// a 401 with a WWW-Authenticate challenge in that case).
	ClientAuthAttempted bool
	// Status, when nonzero, replaces the code's default HTTP status. Set it
	// only through WithStatus.
	Status int
	Cause  error
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Cause != nil {
		return string(e.Code) + ": " + e.Description + ": " + e.Cause.Error()
	}
	return string(e.Code) + ": " + e.Description
}

// Unwrap exposes the internal cause to errors.Is/As.
func (e *Error) Unwrap() error { return e.Cause }

// HTTPStatus returns the RFC-mandated status for the error code.
func (e *Error) HTTPStatus() int {
	if e.Status != 0 {
		return e.Status
	}
	switch e.Code {
	case CodeInvalidClient:
		if e.ClientAuthAttempted {
			return http.StatusUnauthorized
		}
		return http.StatusBadRequest
	case CodeInvalidToken:
		return http.StatusUnauthorized
	case CodeAccessDenied, CodeInsufficientScope:
		return http.StatusForbidden
	case CodeServerError:
		return http.StatusInternalServerError
	case CodeTemporarilyUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusBadRequest
	}
}

// WithStatus returns a copy of e that answers with status instead of the
// code's default. It does not change the WWW-Authenticate behavior, which
// still depends only on ClientAuthAttempted.
func (e *Error) WithStatus(status int) *Error {
	c := *e
	c.Status = status
	return &c
}

func newError(code Code, description string) *Error {
	return &Error{Code: code, Description: description}
}

// InvalidRequest builds an invalid_request error.
func InvalidRequest(description string) *Error { return newError(CodeInvalidRequest, description) }

// InvalidClient builds an invalid_client error; basicAuth reports whether the
// client attempted HTTP Basic authentication.
func InvalidClient(description string, basicAuth bool) *Error {
	e := newError(CodeInvalidClient, description)
	e.ClientAuthAttempted = basicAuth
	return e
}

// InvalidGrant builds an invalid_grant error.
func InvalidGrant(description string) *Error { return newError(CodeInvalidGrant, description) }

// UnauthorizedClient builds an unauthorized_client error.
func UnauthorizedClient(description string) *Error {
	return newError(CodeUnauthorizedClient, description)
}

// UnsupportedGrantType builds an unsupported_grant_type error.
func UnsupportedGrantType(description string) *Error {
	return newError(CodeUnsupportedGrantType, description)
}

// UnsupportedResponseType builds an unsupported_response_type error.
func UnsupportedResponseType(description string) *Error {
	return newError(CodeUnsupportedResponseType, description)
}

// InvalidScope builds an invalid_scope error.
func InvalidScope(description string) *Error { return newError(CodeInvalidScope, description) }

// AuthorizationPending builds the RFC 8628 §3.5 authorization_pending error.
func AuthorizationPending() *Error {
	return newError(CodeAuthorizationPending, "the user has not yet completed the authorization")
}

// SlowDown builds the RFC 8628 §3.5 slow_down error.
func SlowDown() *Error { return newError(CodeSlowDown, "polling too fast; increase the interval") }

// ExpiredToken builds the RFC 8628 §3.5 expired_token error.
func ExpiredToken() *Error { return newError(CodeExpiredToken, "the device code has expired") }

// InvalidRequestURI builds an invalid_request_uri error (RFC 9126 §4).
func InvalidRequestURI(description string) *Error {
	return newError(CodeInvalidRequestURI, description)
}

// InvalidRedirectURI builds an RFC 7591 invalid_redirect_uri error.
func InvalidRedirectURI(description string) *Error {
	return newError(CodeInvalidRedirectURI, description)
}

// InvalidClientMetadata builds an RFC 7591 invalid_client_metadata error.
func InvalidClientMetadata(description string) *Error {
	return newError(CodeInvalidClientMetadata, description)
}

// InvalidDPoPProof builds an RFC 9449 invalid_dpop_proof error. The public
// description is deliberately generic: which check failed is not disclosed.
func InvalidDPoPProof() *Error {
	return newError(CodeInvalidDPoPProof, "the DPoP proof is missing or invalid")
}

// AccessDenied builds an access_denied error.
func AccessDenied(description string) *Error { return newError(CodeAccessDenied, description) }

// InvalidToken builds an RFC 6750 invalid_token error.
func InvalidToken(description string) *Error { return newError(CodeInvalidToken, description) }

// InsufficientScope builds an RFC 6750 insufficient_scope error.
func InsufficientScope(description string) *Error {
	return newError(CodeInsufficientScope, description)
}

// TemporarilyUnavailable builds a temporarily_unavailable error.
func TemporarilyUnavailable(description string) *Error {
	return newError(CodeTemporarilyUnavailable, description)
}

// ServerError builds a server_error with a generic public description. cause
// is kept for logging and must never reach a response body.
func ServerError(cause error) *Error {
	e := newError(CodeServerError, "the server encountered an unexpected condition")
	e.Cause = cause
	return e
}

// AsError returns err as an *Error. Anything that is not already an *Error
// (including wrapped storage failures) becomes a server_error so internal
// detail cannot leak. AsError(nil) is nil.
func AsError(err error) *Error {
	if err == nil {
		return nil
	}
	var oe *Error
	if errors.As(err, &oe) {
		return oe
	}
	return ServerError(err)
}
