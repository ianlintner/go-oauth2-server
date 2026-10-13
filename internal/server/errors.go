package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
)

// WriteError is the single place a typed OAuth error becomes an HTTP response:
// status, WWW-Authenticate, cache headers and the RFC 6749 §5.2 JSON body.
// Errors that are not *oauth.Error are reported as a generic server_error so
// internal detail (SQL, hostnames, secrets) never reaches the client.
func WriteError(w http.ResponseWriter, err error) {
	e := oauth.AsError(err)
	if e == nil {
		return
	}

	h := w.Header()
	h.Set("Content-Type", "application/json")
	// RFC 6749 §5.1/§5.2: token-endpoint responses must not be cached.
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")

	desc := sanitizeDescription(e.Description)
	switch e.Code {
	case oauth.CodeInvalidClient:
		if e.ClientAuthAttempted {
			h.Set("WWW-Authenticate", `Basic realm="oauth2", charset="UTF-8"`)
		}
	case oauth.CodeInvalidToken, oauth.CodeInsufficientScope:
		h.Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="oauth2", error=%q, error_description=%q`, string(e.Code), desc))
	}

	w.WriteHeader(e.HTTPStatus())
	body := map[string]string{"error": string(e.Code)}
	if desc != "" {
		body["error_description"] = desc
	}
	_ = json.NewEncoder(w).Encode(body)
}

// sanitizeDescription restricts error_description to the RFC 6749 §5.2
// character set (%x20-21 / %x23-5B / %x5D-7E): printable ASCII without '"'
// and '\'. Other runes are replaced with a space.
func sanitizeDescription(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' {
			r = ' '
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}
