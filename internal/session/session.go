// Package session holds the resource owner's login across the authorization
// request round trips. It is a stateless, HMAC-SHA256-signed cookie keyed by
// OAUTH2_SESSION_SECRET: it proves "this browser logged in as X until T" and
// carries no OAuth state (codes, PKCE challenges and redirect URIs live only in
// the authorization request and the one-time code row).
package session

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
)

// CookieName is the session cookie. The __Host- prefix makes browsers require
// Secure, Path=/ and no Domain, so it cannot be set by a sibling subdomain.
// Without Secure (development over http) browsers reject that prefix, so the
// unprefixed name is used then.
const (
	cookieNameSecure = "__Host-oauth2_session"
	cookieNameDev    = "oauth2_session"
)

// TTL is how long a login stays valid.
const TTL = 8 * time.Hour

const minKeyLen = 32

var b64 = base64.RawURLEncoding

// Manager issues and verifies session cookies.
type Manager struct {
	key    []byte
	clock  oauth.Clock
	secure bool
}

// New returns a Manager. The key must be at least 32 bytes.
func New(key []byte, clock oauth.Clock, secure bool) (*Manager, error) {
	if len(key) < minKeyLen {
		return nil, errors.New("session: key must be at least 32 bytes")
	}
	if clock == nil {
		return nil, errors.New("session: clock is required")
	}
	return &Manager{key: append([]byte(nil), key...), clock: clock, secure: secure}, nil
}

func (m *Manager) name() string {
	if m.secure {
		return cookieNameSecure
	}
	return cookieNameDev
}

func (m *Manager) sign(payload string) string {
	mac := hmac.New(sha256.New, m.key)
	mac.Write([]byte(payload))
	return b64.EncodeToString(mac.Sum(nil))
}

// Issue sets a fresh session cookie for username.
func (m *Manager) Issue(w http.ResponseWriter, username string) {
	exp := m.clock.Now().Add(TTL)
	payload := b64.EncodeToString([]byte(strconv.FormatInt(exp.Unix(), 10) + "|" + username))
	http.SetCookie(w, &http.Cookie{
		Name:     m.name(),
		Value:    payload + "." + m.sign(payload),
		Path:     "/",
		Expires:  exp,
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// CSRFToken returns an anti-forgery token bound to username and to the
// purpose string (which the caller builds from whatever the protected form
// submits, for example the client and scope being approved). A page on another
// origin cannot read it, so it cannot forge the POST that carries it.
func (m *Manager) CSRFToken(username, purpose string) string {
	return m.sign("csrf|" + username + "|" + purpose)
}

// VerifyCSRF reports whether token is the CSRFToken for username and purpose.
func (m *Manager) VerifyCSRF(username, purpose, token string) bool {
	return token != "" && hmac.Equal([]byte(token), []byte(m.CSRFToken(username, purpose)))
}

// Username returns the logged-in user of the request, or false when the
// cookie is absent, malformed, forged or expired.
func (m *Manager) Username(r *http.Request) (string, bool) {
	c, err := r.Cookie(m.name())
	if err != nil {
		return "", false
	}
	payload, mac, ok := strings.Cut(c.Value, ".")
	if !ok || payload == "" || mac == "" {
		return "", false
	}
	if !hmac.Equal([]byte(mac), []byte(m.sign(payload))) {
		return "", false
	}
	raw, err := b64.DecodeString(payload)
	if err != nil {
		return "", false
	}
	expStr, username, ok := strings.Cut(string(raw), "|")
	if !ok || username == "" {
		return "", false
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || !m.clock.Now().Before(time.Unix(exp, 0)) {
		return "", false
	}
	return username, true
}

// FormTokenTTL is how long an issued form token stays valid.
const FormTokenTTL = 15 * time.Minute

// formMAC binds a form token to the session cookie, a purpose label and the
// token's nonce and expiry. The "form|" prefix keeps these MACs distinct from
// the cookie signature.
func (m *Manager) formMAC(cookieValue, purpose, nonce, exp string) string {
	return m.sign("form|" + cookieValue + "|" + purpose + "|" + nonce + "|" + exp)
}

// FormToken returns an anti-forgery token for a state-changing form, bound to
// the caller's current session cookie and to purpose (for example the exact
// authorization being decided). ok is false when there is no valid session.
func (m *Manager) FormToken(r *http.Request, purpose string) (string, bool) {
	c, err := r.Cookie(m.name())
	if err != nil {
		return "", false
	}
	if _, ok := m.Username(r); !ok {
		return "", false
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", false
	}
	nonce := b64.EncodeToString(raw)
	exp := strconv.FormatInt(m.clock.Now().Add(FormTokenTTL).Unix(), 10)
	return nonce + "." + exp + "." + m.formMAC(c.Value, purpose, nonce, exp), true
}

// VerifyFormToken reports whether token was issued by FormToken for this
// request's session and purpose and has not expired.
func (m *Manager) VerifyFormToken(r *http.Request, purpose, token string) bool {
	c, err := r.Cookie(m.name())
	if err != nil {
		return false
	}
	if _, ok := m.Username(r); !ok {
		return false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	nonce, exp, mac := parts[0], parts[1], parts[2]
	if !hmac.Equal([]byte(mac), []byte(m.formMAC(c.Value, purpose, nonce, exp))) {
		return false
	}
	expUnix, err := strconv.ParseInt(exp, 10, 64)
	return err == nil && m.clock.Now().Before(time.Unix(expUnix, 0))
}
