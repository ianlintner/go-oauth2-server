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
{{if .Confirm}}
<p>The application below is asking to connect a device to your account.</p>
<dl>
<dt>Application</dt><dd>{{if .ClientName}}{{.ClientName}}{{else}}(unnamed application){{end}}</dd>
<dt>Client ID</dt><dd>{{.ClientID}}</dd>
<dt>Requested access</dt><dd>{{if .Scope}}{{.Scope}}{{else}}(no scope){{end}}</dd>
<dt>Code</dt><dd>{{.UserCode}}</dd>
</dl>
<form method="post" action="/oauth/device/verify">
<input type="hidden" name="user_code" value="{{.UserCode}}">
<input type="hidden" name="csrf_token" value="{{.Token}}">
<button type="submit" name="action" value="approve">Approve</button>
<button type="submit" name="action" value="deny">Deny</button>
</form>
{{else if .Token}}
<form method="post" action="/oauth/device/verify">
<input type="hidden" name="csrf_token" value="{{.Token}}">
<label>Code <input name="user_code" autocomplete="off" required></label>
<button type="submit" name="action" value="lookup">Continue</button>
</form>
{{end}}
</body></html>
`))

// deviceView is what the verification page renders. Confirm is set only when
// a live authorization was found for the entered code.
type deviceView struct {
	Message    string
	Confirm    bool
	ClientName string
	ClientID   string
	Scope      string
	UserCode   string
	Token      string
}

func (h *oauthHandlers) renderDevice(w http.ResponseWriter, status int, v deviceView) {
	noStore(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = devicePage.Execute(w, v)
}

// canonicalUserCode is the form a user code takes inside the page and the
// anti-forgery purpose label (case, dash and spaces removed), matching what
// the service normalizes before lookup.
func canonicalUserCode(in string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(in))
}

func deviceTokenPurpose(userCode string) string {
	return "device:" + canonicalUserCode(userCode)
}

// deviceEntryPurpose labels the token carried by the code-entry form. It is
// bound to the session but not to a code, because no code exists yet.
const deviceEntryPurpose = "device-entry"

// renderDeviceEntry shows the code-entry form with a session-bound token, so
// a typed code can be looked up by POST regardless of request metadata.
func (h *oauthHandlers) renderDeviceEntry(w http.ResponseWriter, r *http.Request, msg string) {
	token, ok := h.sessions.FormToken(r, deviceEntryPurpose)
	if !ok {
		h.fail(w, r, oauth.ServerError(errors.New("could not issue form token")))
		return
	}
	h.renderDevice(w, http.StatusOK, deviceView{Message: msg, Token: token})
}

// renderDeviceConfirm shows the client and scope for a live authorization.
func (h *oauthHandlers) renderDeviceConfirm(w http.ResponseWriter, r *http.Request, code string, rec oauth.DeviceCode, client oauth.Client) {
	if rec.Status != oauth.DevicePending {
		h.renderDevice(w, http.StatusOK, deviceView{Message: "This request has already been answered."})
		return
	}
	token, ok := h.sessions.FormToken(r, deviceTokenPurpose(code))
	if !ok {
		h.fail(w, r, oauth.ServerError(errors.New("could not issue form token")))
		return
	}
	h.renderDevice(w, http.StatusOK, deviceView{
		Confirm: true, ClientName: client.Name, ClientID: client.ID,
		Scope: rec.Scope, UserCode: canonicalUserCode(code), Token: token,
	})
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
		code := r.URL.Query().Get("user_code")
		// A link followed from another site must not look codes up on the
		// user's behalf (that would spend their failure budget without their
		// intent): show the plain entry form and let them type the code.
		if site := r.Header.Get("Sec-Fetch-Site"); site == "cross-site" || site == "same-site" {
			code = ""
		}
		if code == "" {
			h.renderDeviceEntry(w, r, "")
			return
		}
		// Only a request the browser marks as same-origin (or typed or
		// bookmarked) is charged to the decision budget; anything without
		// that metadata uses a separate lookup-only window. When that window
		// is used up, fall back to the entry form: its lookup is a POST that
		// needs a session-bound token, so the user is never locked out and
		// nothing off-site can trigger it.
		site := r.Header.Get("Sec-Fetch-Site")
		intent := site == "same-origin" || site == "none"
		rec, client, err := h.svc.DescribeDevice(r.Context(), user, code, intent)
		if err != nil {
			var oe *oauth.Error
			if !intent && errors.As(err, &oe) && oe.HTTPStatus() == http.StatusTooManyRequests {
				h.renderDeviceEntry(w, r, "Enter the code below to continue.")
				return
			}
			h.fail(w, r, err)
			return
		}
		h.renderDeviceConfirm(w, r, code, rec, client)
	case http.MethodPost:
		h.deviceDecide(w, r)
	default:
		methodNotAllowed(w, "GET, POST")
	}
}

func (h *oauthHandlers) deviceDecide(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	// Defence in depth only: the header is optional, so the form token below
	// is the actual cross-site control.
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
	if p.Get("action") == "lookup" {
		// Typed code from the entry form: the session-bound token proves the
		// request came from that form; the lookup is charged to the decision
		// budget like any other guess.
		if !h.sessions.VerifyFormToken(r, deviceEntryPurpose, p.Get("csrf_token")) {
			http.Error(w, "missing or invalid form token", http.StatusForbidden)
			return
		}
		rec, client, err := h.svc.DescribeDevice(r.Context(), user, p.Get("user_code"), true)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		h.renderDeviceConfirm(w, r, p.Get("user_code"), rec, client)
		return
	}
	if !h.sessions.VerifyFormToken(r, deviceTokenPurpose(p.Get("user_code")), p.Get("csrf_token")) {
		http.Error(w, "missing or invalid form token", http.StatusForbidden)
		return
	}
	var approve bool
	switch p.Get("action") {
	case "approve":
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
	h.renderDevice(w, http.StatusOK, deviceView{Message: msg})
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

// unsupportedRegistrationFields are members this server understands but does
// not support. They fail with invalid_client_metadata instead of being dropped,
// so a client never believes key material or a signed statement was honored.
// Members the server does not recognize at all are ignored (RFC 7591 §2).
var unsupportedRegistrationFields = map[string]bool{
	"jwks": true, "jwks_uri": true, "software_statement": true,
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
		if unsupportedRegistrationFields[k] {
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
