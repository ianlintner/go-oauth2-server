package server

import (
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"net/http"
	"strings"

	"github.com/ianlintner/go-oauth2-server/internal/authcode"
	"github.com/ianlintner/go-oauth2-server/internal/oauth"
)

// readFormBody reads a client-authenticated-style form POST exactly as the
// token endpoint does (no query, form content type, one Authorization header,
// bounded body, duplicate rejection) but leaves client authentication to the
// service.
func readFormBody(w http.ResponseWriter, r *http.Request) (oauth.Params, error) {
	if r.URL.RawQuery != "" {
		return oauth.Params{}, oauth.InvalidRequest("request parameters must be in the request body")
	}
	if !isFormContent(r) {
		return oauth.Params{}, oauth.InvalidRequest("content type must be application/x-www-form-urlencoded")
	}
	if len(r.Header.Values("Authorization")) > 1 {
		return oauth.Params{}, oauth.InvalidRequest("multiple Authorization headers")
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		return oauth.Params{}, oauth.InvalidRequest("request body is unreadable or too large")
	}
	return oauth.ParseParams(string(body))
}

// ---- POST /oauth/device_authorization (RFC 8628 §3.1) ----

func (h *oauthHandlers) deviceAuthorization(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	p, err := readFormBody(w, r)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	base := strings.TrimRight(h.issuer, "/")
	resp, err := h.svc.AuthorizeDevice(r.Context(), r.Header.Get("Authorization"), p, base+"/oauth/device/verify")
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// ---- /oauth/device/verify: the user-facing verification page ----

// The page exists only where a resource-owner login exists (conformance
// mode), like /auth/login.
var devicePage = template.Must(template.New("device").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Connect a device</title></head>
<body>
<h1>Connect a device</h1>
{{if .Message}}<p role="status">{{.Message}}</p>{{end}}
<form method="post" action="/oauth/device/verify">
<label>Code <input name="user_code" autocomplete="off" required></label>
<button type="submit" name="action" value="approve">Approve</button>
<button type="submit" name="action" value="deny">Deny</button>
</form>
</body></html>
`))

func (h *oauthHandlers) renderDevice(w http.ResponseWriter, status int, msg string) {
	noStore(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = devicePage.Execute(w, struct{ Message string }{msg})
}

func (h *oauthHandlers) deviceVerify(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		user, ok, err := h.currentUser(r)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		if !ok {
			w.Header().Set("Location", "/auth/login")
			w.WriteHeader(http.StatusFound)
			return
		}
		_ = user
		h.renderDevice(w, http.StatusOK, "")
	case http.MethodPost:
		h.deviceDecide(w, r)
	default:
		methodNotAllowed(w, "GET, POST")
	}
}

func (h *oauthHandlers) deviceDecide(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	// Same login-CSRF guard as the login form: a cross-site POST must not
	// approve an attacker's device on the victim's session.
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		http.Error(w, "cross-site request is not allowed", http.StatusForbidden)
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
	user, ok, err := h.currentUser(r)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if !ok {
		h.fail(w, r, oauth.AccessDenied("sign in before entering a device code").WithStatus(http.StatusUnauthorized))
		return
	}
	var approve bool
	switch p.Get("action") {
	case "approve", "":
		approve = true
	case "deny":
	default:
		h.fail(w, r, oauth.InvalidRequest("action must be approve or deny"))
		return
	}
	if err := h.svc.DecideDevice(r.Context(), user, p.Get("user_code"), approve); err != nil {
		h.fail(w, r, err)
		return
	}
	msg := "Device approved. You can return to your device."
	if !approve {
		msg = "Request denied."
	}
	h.renderDevice(w, http.StatusOK, msg)
}

// ---- POST /oauth/par (RFC 9126 §2) ----

func (h *oauthHandlers) par(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	p, err := readFormBody(w, r)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	resp, err := h.svc.PushAuthorizationRequest(r.Context(), r.Header.Get("Authorization"), p)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, resp)
}

// ---- POST /connect/register (RFC 7591 §3) ----

// registrationFields are the only members accepted; anything else is refused
// so a client never believes unsupported metadata (jwks, software_statement,
// grant types we refuse) was honored.
var registrationFields = map[string]bool{
	"redirect_uris": true, "client_name": true, "token_endpoint_auth_method": true,
	"grant_types": true, "response_types": true, "scope": true,
}

func (h *oauthHandlers) register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if mt := strings.TrimSpace(strings.SplitN(r.Header.Get("Content-Type"), ";", 2)[0]); !strings.EqualFold(mt, "application/json") {
		h.fail(w, r, oauth.InvalidClientMetadata("content type must be application/json"))
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		h.fail(w, r, oauth.InvalidClientMetadata("request body is unreadable or too large"))
		return
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil || raw == nil {
		h.fail(w, r, oauth.InvalidClientMetadata("body must be a JSON object"))
		return
	}
	for k := range raw {
		if !registrationFields[k] {
			h.fail(w, r, oauth.InvalidClientMetadata("unsupported client metadata member"))
			return
		}
	}
	var req authcode.RegistrationRequest
	dec := json.NewDecoder(strings.NewReader(string(body)))
	if err := dec.Decode(&req); err != nil {
		var ute *json.UnmarshalTypeError
		if errors.As(err, &ute) && ute.Field == "redirect_uris" {
			h.fail(w, r, oauth.InvalidRedirectURI("redirect_uris must be an array of strings"))
			return
		}
		h.fail(w, r, oauth.InvalidClientMetadata("client metadata has the wrong type"))
		return
	}
	resp, err := h.svc.Register(r.Context(), req, h.registrationScopes)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, resp)
}
