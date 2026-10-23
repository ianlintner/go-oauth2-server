package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
)

// ---- GET /oauth/userinfo ----

// userinfo is the profile's protected resource (RFC 6750 §2). It accepts a
// bearer access token presented in the Authorization header and returns the
// subject it identifies. The RFC 6750 challenge it emits on failure is
// narrower than the token-endpoint challenge: the contract scenarios pin the
// exact header value, so it carries no realm and no error_description.
func (h *oauthHandlers) userinfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
		return
	}
	if h.tokens == nil {
		WriteError(w, oauth.ServerError(errNoTokenService))
		return
	}

	authz := r.Header.Get("Authorization")
	token, dpopScheme := bearerToken(authz), false
	if token == "" {
		token, dpopScheme = schemeToken(authz, "DPoP "), true
	}
	if token == "" {
		// No credentials: a bare Bearer challenge with no error attribute
		// (RFC 6750 §3) and an invalid_request body (RFC 6750 §3.1).
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeBearerError(w, http.StatusUnauthorized, "invalid_request")
		return
	}

	verified, err := h.tokens.VerifyAccessToken(r.Context(), token)
	if err != nil {
		// Any bad, expired, revoked or unknown token is invalid_token.
		if dpopScheme {
			dpopChallenge(w, "invalid_token")
		} else {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		}
		writeBearerError(w, http.StatusUnauthorized, "invalid_token")
		return
	}

	// Sender constraint (RFC 9449 §7). A token bound to a proof key is never
	// honored as a bare Bearer, and a token that is not bound is never
	// upgraded by presenting it under the DPoP scheme: both are invalid_token.
	if (verified.JKT != "") != dpopScheme || (dpopScheme && h.dpop == nil) {
		dpopChallenge(w, "invalid_token")
		writeBearerError(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	if dpopScheme {
		code := h.checkResourceProof(r, token, verified.JKT)
		if code != "" {
			dpopChallenge(w, code)
			writeBearerError(w, http.StatusUnauthorized, code)
			return
		}
	}

	body := map[string]any{
		"sub": verified.Subject,
	}
	writeJSON(w, http.StatusOK, body)
}

// bearerToken extracts a bearer token from an Authorization header exactly as
// RFC 6750 §2.1 prescribes: the scheme must be "Bearer" (case-insensitive)
// followed by a single space and a non-empty token. Any other shape — a
// missing header, a different scheme, or a malformed value — is treated as
// "no credentials", so the caller answers with the bare challenge.
func bearerToken(header string) string { return schemeToken(header, "Bearer ") }

// schemeToken extracts the credential of an Authorization header whose scheme
// (with its trailing single space) is prefix, under the same strictness as
// bearerToken.
func schemeToken(header, prefix string) string {
	if len(header) <= len(prefix) {
		return ""
	}
	if !strings.EqualFold(header[:len(prefix)], prefix) {
		return ""
	}
	token := header[len(prefix):]
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return ""
	}
	return token
}

// writeBearerError writes the RFC 6750 §3.1 JSON error body for a protected
// resource. It is distinct from WriteError, which emits the token-endpoint
// challenge (realm, error_description) that the bearer scenarios must not
// carry.
func writeBearerError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	noStore(w)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}
