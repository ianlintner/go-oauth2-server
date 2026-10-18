package server

import (
	"errors"
	"html/template"
	"io"
	"net/http"

	"github.com/ianlintner/go-oauth2-server/internal/authcode"
	"github.com/ianlintner/go-oauth2-server/internal/oauth"
)

// The login page is intentionally plain: no scripts, styles or external
// resources (the CSP forbids them). html/template escapes every value.
var loginPage = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Sign in</title></head>
<body>
<h1>Sign in</h1>
{{if .Error}}<p role="alert">{{.Error}}</p>{{end}}
<form method="post" action="/auth/login">
<input type="hidden" name="return_query" value="{{.ReturnQuery}}">
<label>Username <input name="username" autocomplete="username" required></label>
<label>Password <input name="password" type="password" autocomplete="current-password" required></label>
<button type="submit">Sign in</button>
</form>
</body></html>
`))

type loginView struct {
	ReturnQuery string
	Error       string
}

func (h *oauthHandlers) renderLogin(w http.ResponseWriter, status int, returnQuery, msg string) {
	noStore(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = loginPage.Execute(w, loginView{ReturnQuery: returnQuery, Error: msg})
}

// loginForm serves the test-mode login form. return_query is carried only if
// it is a well-formed authorization query.
func (h *oauthHandlers) loginForm(w http.ResponseWriter, r *http.Request) {
	h.renderLogin(w, http.StatusOK, h.sanitizeReturnQuery(r.URL.Query().Get("return_query")), "")
}

// loginSubmit authenticates the resource owner and sets the session cookie.
// When return_query is present the browser is sent back to the authorization
// endpoint at the fixed local path /oauth/authorize, so the value can never
// steer a redirect to another origin.
func (h *oauthHandlers) loginSubmit(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	// Login CSRF: a cross-site POST would sign the victim in as the attacker.
	// Browsers announce the initiator; refuse anything but a same-origin (or
	// user-initiated) request. Non-browser clients send no such header.
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		http.Error(w, "cross-site login is not allowed", http.StatusForbidden)
		return
	}
	if !isFormContent(r) {
		h.fail(w, r, oauth.InvalidRequest("content type must be application/x-www-form-urlencoded"))
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
	rq := h.sanitizeReturnQuery(p.Get("return_query"))

	user, err := h.svc.AuthenticateUser(r.Context(), p.Get("username"), p.Get("password"))
	switch {
	case errors.Is(err, authcode.ErrInvalidCredentials):
		h.renderLogin(w, http.StatusForbidden, rq, "Invalid username or password.")
		return
	case err != nil:
		h.fail(w, r, err)
		return
	}

	h.sessions.Issue(w, user.Username)
	if rq != "" {
		w.Header().Set("Location", "/oauth/authorize?"+rq)
		w.WriteHeader(http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, "Signed in.\n")
}

// sanitizeReturnQuery returns the canonical form of a carried authorization
// query, or "" when it is absent, malformed or contains a duplicated parameter.
func (h *oauthHandlers) sanitizeReturnQuery(raw string) string {
	if raw == "" || len(raw) > maxBodyBytes {
		return ""
	}
	p, err := oauth.ParseParams(raw)
	if err != nil {
		return ""
	}
	return canonicalQuery(p)
}
