package server

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
	"github.com/ianlintner/go-oauth2-server/internal/token"
)

// ---- POST /oauth/introspect ----

// introspect implements the token introspection endpoint (RFC 7662 §2). The
// caller authenticates as a client exactly as at the token endpoint; a token
// is reported active only when it belongs to that client, so one client
// cannot gain information about another's tokens.
func (h *oauthHandlers) introspect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	p, client, err := h.readClientRequest(w, r)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if h.tokens == nil {
		h.fail(w, r, oauth.ServerError(errNoTokenService))
		return
	}

	tokenValue := p.Get("token")
	if tokenValue == "" {
		h.fail(w, r, oauth.InvalidRequest("token is required"))
		return
	}

	info, err := h.tokens.Introspect(r.Context(), tokenValue)
	if err != nil {
		h.fail(w, r, err)
		return
	}

	// Client binding: a caller may only observe its own tokens. A token held
	// by another client is indistinguishable from an inactive one (RFC 7662
	// §2.1: the response says nothing the caller may not know).
	if info.Active && info.ClientID != client.ID {
		info = token.TokenInfo{Active: false}
	}

	writeJSON(w, http.StatusOK, introspectBody(info))
}

// introspectBody renders the RFC 7662 §2.2 response. An inactive token yields
// only "active":false; an active one carries the full token metadata.
func introspectBody(info token.TokenInfo) map[string]any {
	if !info.Active {
		return map[string]any{"active": false}
	}
	body := map[string]any{
		"active":     true,
		"scope":      info.Scope,
		"client_id":  info.ClientID,
		"username":   info.Username,
		"token_type": info.TokenType,
		"sub":        info.Sub,
		"iss":        info.Issuer,
		"jti":        info.JTI,
	}
	if info.ExpiresAt != 0 {
		body["exp"] = info.ExpiresAt
	}
	if info.IssuedAt != 0 {
		body["iat"] = info.IssuedAt
	}
	return body
}

// ---- POST /oauth/revoke ----

// revoke implements the token revocation endpoint (RFC 7009 §2). The caller
// authenticates as a client and may revoke only its own tokens; any other
// outcome still answers 200 so the server never leaks which token belonged to
// which client.
func (h *oauthHandlers) revoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	p, client, err := h.readClientRequest(w, r)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if h.tokens == nil {
		h.fail(w, r, oauth.ServerError(errNoTokenService))
		return
	}

	tokenValue := p.Get("token")
	if tokenValue == "" {
		h.fail(w, r, oauth.InvalidRequest("token is required"))
		return
	}

	if err := h.tokens.Revoke(r.Context(), tokenValue, client.ID); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// ---- GET /.well-known/jwks.json ----

// jwks publishes the server's public signing keys (RFC 7517 §5) so resource
// servers and clients can verify issued access tokens.
func (h *oauthHandlers) jwks(w http.ResponseWriter, _ *http.Request) {
	if h.tokens == nil {
		WriteError(w, oauth.ServerError(errNoTokenService))
		return
	}
	raw, err := h.tokens.JWKS()
	if err != nil {
		WriteError(w, oauth.ServerError(err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

// ---- shared helpers ----

// errNoTokenService reports the server is running without the token-lifecycle
// service wired; a bug in assembly, never something a client causes.
type noTokenServiceError struct{}

func (noTokenServiceError) Error() string { return "server: token service not wired" }

var errNoTokenService error = noTokenServiceError{}

// readClientRequest reads a client-authenticated form request exactly as the
// token endpoint does: form body only, no query string, single Authorization
// header, bounded body, duplicate rejection, then client authentication.
func (h *oauthHandlers) readClientRequest(w http.ResponseWriter, r *http.Request) (oauth.Params, oauth.Client, error) {
	if r.URL.RawQuery != "" {
		return oauth.Params{}, oauth.Client{}, oauth.InvalidRequest("request parameters must be in the request body")
	}
	if !isFormContent(r) {
		return oauth.Params{}, oauth.Client{}, oauth.InvalidRequest("content type must be application/x-www-form-urlencoded")
	}
	if len(r.Header.Values("Authorization")) > 1 {
		return oauth.Params{}, oauth.Client{}, oauth.InvalidRequest("multiple Authorization headers")
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		return oauth.Params{}, oauth.Client{}, oauth.InvalidRequest("request body is unreadable or too large")
	}
	p, err := oauth.ParseParams(string(body))
	if err != nil {
		return oauth.Params{}, oauth.Client{}, err
	}
	client, err := h.svc.AuthenticateClient(r.Context(), r.Header.Get("Authorization"), p)
	if err != nil {
		return oauth.Params{}, oauth.Client{}, err
	}
	return p, client, nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	noStore(w)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
