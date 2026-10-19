package server

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/ianlintner/go-oauth2-server/internal/authcode"
	"github.com/ianlintner/go-oauth2-server/internal/oauth"
	"github.com/ianlintner/go-oauth2-server/internal/session"
	"github.com/ianlintner/go-oauth2-server/internal/token"
)

// maxBodyBytes bounds every request body this package reads. OAuth form
// bodies are a few hundred bytes; the limit only stops memory exhaustion.
const maxBodyBytes = 64 << 10

type oauthHandlers struct {
	svc          *authcode.Service
	sessions     *session.Manager
	tokens       *token.Service
	issuer       string
	loginEnabled bool
	log          *slog.Logger
}

func newOAuthHandlers(d Deps) *oauthHandlers {
	lg := d.Logger
	if lg == nil {
		lg = slog.Default()
	}
	return &oauthHandlers{svc: d.Service, sessions: d.Sessions, tokens: d.Tokens, issuer: d.Issuer, loginEnabled: d.Conformance, log: lg}
}

// fail logs the internal cause of a server_error and writes the typed error.
func (h *oauthHandlers) fail(w http.ResponseWriter, r *http.Request, err error) {
	e := oauth.AsError(err)
	if e != nil && e.Code == oauth.CodeServerError {
		h.log.ErrorContext(r.Context(), "oauth request failed", "path", r.URL.Path, "error", e.Cause)
	}
	WriteError(w, err)
}

func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

// ---- GET /oauth/authorize ----

// authorize implements the authorization endpoint (RFC 6749 §3.1, §4.1.1).
//
// Order matters and is the security contract of this handler:
//
//  1. The query is parsed with duplicate rejection before any value is read.
//  2. Client and redirect URI are validated; failures here are shown to the
//     resource owner and NEVER redirected (RFC 6749 §4.1.2.1).
//  3. Remaining request errors are redirected with state and iss (RFC 9207).
//  4. Only then is the resource owner authenticated and a code issued.
func (h *oauthHandlers) authorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	noStore(w)

	p, err := oauth.ParseParams(r.URL.RawQuery)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	client, redirectURI, err := h.svc.ResolveClient(r.Context(), p)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	req, err := h.svc.ValidateRequest(client, redirectURI, p)
	if err != nil {
		h.redirectError(w, r, redirectURI, p.Get("state"), err)
		return
	}

	user, loggedIn, err := h.currentUser(r)
	if err != nil {
		h.redirectError(w, r, redirectURI, req.State, err)
		return
	}
	if !loggedIn {
		if !h.loginEnabled {
			h.redirectError(w, r, redirectURI, req.State,
				oauth.AccessDenied("no resource owner login is available"))
			return
		}
		w.Header().Set("Location", "/auth/login?return_query="+url.QueryEscape(canonicalQuery(p)))
		w.WriteHeader(http.StatusFound)
		return
	}

	code, err := h.svc.IssueCode(r.Context(), req, user.ID)
	if err != nil {
		h.redirectError(w, r, redirectURI, req.State, err)
		return
	}
	h.redirect(w, redirectURI, url.Values{"code": {code}, "state": nonEmpty(req.State), "iss": {h.issuer}})
}

// currentUser resolves the session cookie to a user. A missing, forged,
// expired or stale (user deleted) session is simply "not logged in".
func (h *oauthHandlers) currentUser(r *http.Request) (u oauth.User, ok bool, err error) {
	name, ok := h.sessions.Username(r)
	if !ok {
		return oauth.User{}, false, nil
	}
	u, err = h.svc.UserByUsername(r.Context(), name)
	switch {
	case errors.Is(err, authcode.ErrInvalidCredentials):
		return oauth.User{}, false, nil
	case err != nil:
		return oauth.User{}, false, err
	}
	return u, true, nil
}

// redirectError delivers an error to the validated redirect URI. state is
// echoed and iss attached so the client can detect mix-up attacks (RFC 9207 §2).
func (h *oauthHandlers) redirectError(w http.ResponseWriter, r *http.Request, redirectURI, state string, err error) {
	e := oauth.AsError(err)
	if e.Code == oauth.CodeServerError {
		h.log.ErrorContext(r.Context(), "authorization request failed", "error", e.Cause)
	}
	v := url.Values{"error": {string(e.Code)}, "iss": {h.issuer}}
	if d := sanitizeDescription(e.Description); d != "" {
		v.Set("error_description", d)
	}
	if state != "" {
		v.Set("state", state)
	}
	h.redirect(w, redirectURI, v)
}

// redirect sends the browser to target with params appended to the target's
// existing query (a registered redirect URI may carry one, RFC 6749 §3.1.2).
func (h *oauthHandlers) redirect(w http.ResponseWriter, target string, params url.Values) {
	loc := target
	sep := "?"
	if strings.Contains(target, "?") {
		sep = "&"
	}
	loc += sep + params.Encode()
	w.Header().Set("Location", loc)
	w.WriteHeader(http.StatusFound)
}

func nonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

// canonicalQuery re-encodes parsed parameters so a value carried through the
// login round trip is a well-formed query string, never attacker-chosen raw
// bytes. Encoding sorts keys, which the authorize endpoint does not care about.
func canonicalQuery(p oauth.Params) string {
	v := url.Values{}
	for _, name := range authorizeParamNames {
		if p.Has(name) {
			v.Set(name, p.Get(name))
		}
	}
	return v.Encode()
}

// authorizeParamNames is the set of authorization request parameters this
// server understands; anything else is not carried across the login.
var authorizeParamNames = []string{
	"response_type", "client_id", "redirect_uri", "scope", "state",
	"code_challenge", "code_challenge_method", "request", "request_uri",
}

// ---- POST /oauth/token ----

// token implements the token endpoint (RFC 6749 §3.2). Parameters come from
// the form body only; a query string, a non-form content type, an oversized
// body or any duplicated parameter is rejected before values are read, so a
// malformed request can never consume a code.
func (h *oauthHandlers) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if r.URL.RawQuery != "" {
		h.fail(w, r, oauth.InvalidRequest("token request parameters must be in the request body"))
		return
	}
	if !isFormContent(r) {
		h.fail(w, r, oauth.InvalidRequest("content type must be application/x-www-form-urlencoded"))
		return
	}
	if len(r.Header.Values("Authorization")) > 1 {
		h.fail(w, r, oauth.InvalidRequest("multiple Authorization headers"))
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		h.fail(w, r, oauth.InvalidRequest("request body is unreadable or too large"))
		return
	}
	p, err := oauth.ParseParams(string(body))
	if err != nil {
		h.fail(w, r, err)
		return
	}

	tok, err := h.svc.Token(r.Context(), r.Header.Get("Authorization"), p)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	hd := w.Header()
	hd.Set("Content-Type", "application/json")
	noStore(w)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(tok)
}

func isFormContent(r *http.Request) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mt == "application/x-www-form-urlencoded"
}

// ---- GET /.well-known/oauth-authorization-server ----

// metadata publishes RFC 8414 authorization server metadata. The issuer is the
// exact configured value, the same one placed in every RFC 9207 iss parameter.
func (h *oauthHandlers) metadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, h.metadataDoc())
}

// openidConfiguration publishes OIDC Discovery 1.0 provider metadata: the RFC
// 8414 document plus the members OIDC Discovery §3 requires of a provider.
func (h *oauthHandlers) openidConfiguration(w http.ResponseWriter, _ *http.Request) {
	doc := h.metadataDoc()
	doc["subject_types_supported"] = []string{"public"}
	doc["id_token_signing_alg_values_supported"] = []string{"RS256"}
	doc["scopes_supported"] = []string{"openid"}
	doc["claims_supported"] = []string{"iss", "sub", "aud", "iat", "exp", "nonce"}
	writeJSON(w, http.StatusOK, doc)
}

func (h *oauthHandlers) metadataDoc() map[string]any {
	base := strings.TrimRight(h.issuer, "/")
	return map[string]any{
		"issuer":                                         h.issuer,
		"authorization_endpoint":                         base + "/oauth/authorize",
		"token_endpoint":                                 base + "/oauth/token",
		"userinfo_endpoint":                              base + "/oauth/userinfo",
		"introspection_endpoint":                         base + "/oauth/introspect",
		"revocation_endpoint":                            base + "/oauth/revoke",
		"jwks_uri":                                       base + "/.well-known/jwks.json",
		"response_types_supported":                       []string{"code"},
		"grant_types_supported":                          []string{authcode.GrantAuthorizationCode, authcode.GrantRefreshToken, authcode.GrantClientCredentials},
		"code_challenge_methods_supported":               []string{oauth.MethodS256},
		"token_endpoint_auth_methods_supported":          []string{authcode.MethodBasic, authcode.MethodPost, "none"},
		"introspection_endpoint_auth_methods_supported":  []string{authcode.MethodBasic, authcode.MethodPost, "none"},
		"revocation_endpoint_auth_methods_supported":     []string{authcode.MethodBasic, authcode.MethodPost, "none"},
		"authorization_response_iss_parameter_supported": true,
	}
}
