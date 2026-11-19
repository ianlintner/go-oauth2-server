package server

import (
	"context"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
)

// The approval page is intentionally plain, like the login page: no scripts,
// styles or external resources. html/template escapes every value.
var consentPage = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Authorize application</title></head>
<body>
<h1>Authorize application</h1>
<p>Signed in as <strong>{{.Username}}</strong>.</p>
<p>The application <strong>{{.Client}}</strong> is asking for access to your account{{if .Scopes}} with these permissions:{{else}}.{{end}}</p>
{{if .Scopes}}<ul>{{range .Scopes}}<li>{{.}}</li>{{end}}</ul>{{end}}
<form method="post" action="/auth/consent">
<input type="hidden" name="return_query" value="{{.ReturnQuery}}">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<button type="submit" name="decision" value="approve">Approve</button>
<button type="submit" name="decision" value="deny">Deny</button>
</form>
</body></html>
`))

type consentView struct {
	Username    string
	Client      string
	Scopes      []string
	ReturnQuery string
	CSRF        string
}

// requireApproval is the single gate between a signed-in resource owner and
// code issuance. It reports done=true when it has already written the
// response (a redirect to the approval page, or an error). Only an explicit
// stored approval that covers scope lets the request continue; a missing row
// is never consent.
func (h *oauthHandlers) requireApproval(w http.ResponseWriter, r *http.Request, user oauth.User, clientID, scope, returnQuery string) (done bool) {
	ok, err := h.svc.Approved(r.Context(), user.ID, clientID, scope)
	if err != nil {
		h.fail(w, r, err)
		return true
	}
	if ok {
		return false
	}
	w.Header().Set("Location", "/auth/consent?return_query="+url.QueryEscape(returnQuery))
	w.WriteHeader(http.StatusFound)
	return true
}

// consentRequest resolves the authorization request carried in a sanitized
// return_query to the client and scope the resource owner would approve. A
// pushed request is previewed, never spent.
func (h *oauthHandlers) consentRequest(ctx context.Context, rq string) (oauth.Client, string, string, error) {
	p, err := oauth.ParseParams(rq)
	if err != nil {
		return oauth.Client{}, "", "", err
	}
	if p.Has("request_uri") {
		if p.Has("request") {
			return oauth.Client{}, "", "", oauth.InvalidRequest("request objects are not supported")
		}
		pre, err := h.svc.PreviewPushed(ctx, p.Get("client_id"), p.Get("request_uri"))
		if err != nil {
			return oauth.Client{}, "", "", err
		}
		return pre.Client, pre.Scope, pre.RedirectURI, nil
	}
	client, redirectURI, err := h.svc.ResolveClient(ctx, p)
	if err != nil {
		return oauth.Client{}, "", "", err
	}
	req, err := h.svc.ValidateRequest(client, redirectURI, p)
	if err != nil {
		return oauth.Client{}, "", "", err
	}
	return client, req.Scope, redirectURI, nil
}

// consentForm renders the approval page for the signed-in resource owner.
func (h *oauthHandlers) consentForm(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	user, loggedIn, err := h.currentUser(r)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	rq := h.sanitizeReturnQuery(r.URL.Query().Get("return_query"))
	if rq == "" {
		h.fail(w, r, oauth.InvalidRequest("no authorization request to approve"))
		return
	}
	if !loggedIn {
		w.Header().Set("Location", "/auth/login?return_query="+url.QueryEscape(rq))
		w.WriteHeader(http.StatusFound)
		return
	}
	client, scope, _, err := h.consentRequest(r.Context(), rq)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if err := h.svc.CheckUserScope(user, scope); err != nil {
		h.fail(w, r, err)
		return
	}
	name := client.Name
	if name == "" {
		name = client.ID
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = consentPage.Execute(w, consentView{
		Username: user.Username, Client: name, Scopes: strings.Fields(scope),
		ReturnQuery: rq, CSRF: h.sessions.CSRFToken(user.Username, consentPurpose(rq)),
	})
}

// consentPurpose binds an anti-forgery token to the exact authorization
// request shown on the page, so a token minted for one request cannot approve
// another.
func consentPurpose(rq string) string { return "consent|" + rq }

// consentSubmit records the resource owner's decision. The POST must carry the
// anti-forgery token the page was rendered with; the request is re-derived
// server-side from return_query, so what is approved is exactly what was shown.
func (h *oauthHandlers) consentSubmit(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		http.Error(w, "cross-site approval is not allowed", http.StatusForbidden)
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
	user, loggedIn, err := h.currentUser(r)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if !loggedIn {
		http.Error(w, "sign in required", http.StatusUnauthorized)
		return
	}
	rq := h.sanitizeReturnQuery(p.Get("return_query"))
	if rq == "" || !h.sessions.VerifyCSRF(user.Username, consentPurpose(rq), p.Get("csrf")) {
		http.Error(w, "invalid approval token", http.StatusForbidden)
		return
	}
	client, scope, redirectURI, err := h.consentRequest(r.Context(), rq)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if err := h.svc.CheckUserScope(user, scope); err != nil {
		h.fail(w, r, err)
		return
	}
	switch p.Get("decision") {
	case "approve":
		if err := h.svc.RecordApproval(r.Context(), user.ID, client.ID, scope); err != nil {
			h.fail(w, r, err)
			return
		}
		w.Header().Set("Location", "/oauth/authorize?"+rq)
		w.WriteHeader(http.StatusFound)
	case "deny":
		qp, _ := oauth.ParseParams(rq)
		if qp.Has("request_uri") {
			// A pushed request's redirect target is not shown to the user as a
			// redirect; report the refusal here instead of redirecting.
			http.Error(w, "access denied", http.StatusForbidden)
			return
		}
		h.redirectError(w, r, redirectURI, qp.Get("state"), oauth.AccessDenied("the resource owner denied the request"))
	default:
		h.fail(w, r, oauth.InvalidRequest("decision must be approve or deny"))
	}
}
