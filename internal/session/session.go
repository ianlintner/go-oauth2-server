// Package session holds the resource owner's login across the authorization
// request round trips. The cookie is an HMAC-SHA256-signed value keyed by
// OAUTH2_SESSION_SECRET that names a server-side session record: a valid
// signature is necessary but not sufficient, because the record must also be
// live (not expired, not revoked) in the store. The cookie carries no OAuth
// state (codes, PKCE challenges and redirect URIs live only in the
// authorization request and the one-time code row).
package session

import (
	"context"
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
	store  oauth.SessionRepository
}

// Info is a verified, live session.
type Info struct {
	// Username is the resource owner the session was issued to.
	Username string
	// Credential is the credential fingerprint recorded at login. Compare it
	// with CredentialCurrent against the user's present password hash.
	Credential string
}

// New returns a Manager. The key must be at least 32 bytes. The store holds
// the server-side session records.
func New(key []byte, clock oauth.Clock, secure bool, store oauth.SessionRepository) (*Manager, error) {
	if len(key) < minKeyLen {
		return nil, errors.New("session: key must be at least 32 bytes")
	}
	if clock == nil {
		return nil, errors.New("session: clock is required")
	}
	if store == nil {
		return nil, errors.New("session: store is required")
	}
	return &Manager{key: append([]byte(nil), key...), clock: clock, secure: secure, store: store}, nil
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

// credentialTag is a keyed fingerprint of a password hash. It lets a session
// notice that the credential it was issued under has since changed.
func (m *Manager) credentialTag(passwordHash string) string {
	return m.sign("credential|" + passwordHash)
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

// CredentialCurrent reports whether the session was issued under the given
// (current) password hash. A password change makes it false for every session
// issued before the change.
func (m *Manager) CredentialCurrent(info Info, passwordHash string) bool {
	return hmac.Equal([]byte(info.Credential), []byte(m.credentialTag(passwordHash)))
}

// recordID is the stored form of a session identifier: only a hash is kept,
// so a database read does not yield usable cookies.
func recordID(sid string) string {
	sum := sha256.Sum256([]byte(sid))
	return b64.EncodeToString(sum[:])
}

// Issue records a new session for username and sets its cookie. passwordHash
// is the user's current password hash and binds the session to that credential.
func (m *Manager) Issue(ctx context.Context, w http.ResponseWriter, username, passwordHash string) error {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	sid := b64.EncodeToString(raw)
	exp := m.clock.Now().Add(TTL)
	if err := m.store.Create(ctx, oauth.Session{ID: recordID(sid), Username: username, ExpiresAt: exp}); err != nil {
		return err
	}
	// username is last because it may itself contain the separator.
	payload := b64.EncodeToString([]byte(strconv.FormatInt(exp.Unix(), 10) + "|" + sid + "|" + m.credentialTag(passwordHash) + "|" + username))
	http.SetCookie(w, m.cookie(payload+"."+m.sign(payload), exp, 0))
	return nil
}

// cookie builds the session cookie. Issue and End both use it so that a clear
// always repeats the attributes used to set the cookie. Secure follows the
// deployment (m.secure is false only for plain-HTTP conformance runs).
func (m *Manager) cookie(value string, expires time.Time, maxAge int) *http.Cookie {
	// #nosec G124 -- Secure follows the deployment (Manager.secure).
	var c http.Cookie
	c.Name = m.name()
	c.Value = value
	c.Path = "/"
	c.MaxAge = maxAge
	c.Expires = expires
	c.HttpOnly = true
	c.Secure = m.secure
	c.SameSite = http.SameSiteLaxMode
	return &c
}

// parsed is a cookie whose signature verified.
type parsed struct {
	sid, credential, username string
	exp                       time.Time
}

// parse verifies the signature and shape of the request's cookie. It does not
// consult the store or the clock.
func (m *Manager) parse(r *http.Request) (parsed, bool) {
	c, err := r.Cookie(m.name())
	if err != nil {
		return parsed{}, false
	}
	payload, mac, ok := strings.Cut(c.Value, ".")
	if !ok || payload == "" || mac == "" {
		return parsed{}, false
	}
	if !hmac.Equal([]byte(mac), []byte(m.sign(payload))) {
		return parsed{}, false
	}
	raw, err := b64.DecodeString(payload)
	if err != nil {
		return parsed{}, false
	}
	parts := strings.SplitN(string(raw), "|", 4)
	if len(parts) != 4 || parts[1] == "" || parts[3] == "" {
		return parsed{}, false
	}
	exp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return parsed{}, false
	}
	return parsed{sid: parts[1], credential: parts[2], username: parts[3], exp: time.Unix(exp, 0)}, true
}

// Lookup returns the live session of the request, or false when the cookie is
// absent, malformed, forged, expired, revoked or unknown to the store. A store
// failure also yields false: the session is not honoured unless the server
// confirms it.
func (m *Manager) Lookup(r *http.Request) (Info, bool) {
	p, ok := m.parse(r)
	if !ok || !m.clock.Now().Before(p.exp) {
		return Info{}, false
	}
	live, err := m.store.Active(r.Context(), recordID(p.sid), p.username, m.clock.Now())
	if err != nil || !live {
		return Info{}, false
	}
	return Info{Username: p.username, Credential: p.credential}, true
}

// Username returns the logged-in user of the request, or false when there is
// no live session (see Lookup).
func (m *Manager) Username(r *http.Request) (string, bool) {
	info, ok := m.Lookup(r)
	return info.Username, ok
}

// End revokes the request's session in the store and instructs the browser to
// drop the cookie. The clearing cookie repeats the attributes used to set it
// (name, Path, Secure); a mismatched clear is ignored by browsers. The cookie
// is cleared even when the request carries no valid session or the store
// fails; the store error is returned so the caller can report it.
func (m *Manager) End(w http.ResponseWriter, r *http.Request) error {
	var err error
	if p, ok := m.parse(r); ok {
		err = m.store.Revoke(r.Context(), recordID(p.sid), m.clock.Now())
	}
	http.SetCookie(w, m.cookie("", time.Unix(0, 0), -1))
	return err
}

// RevokeAllForUser ends every live session of username, for example after a
// password change.
func (m *Manager) RevokeAllForUser(ctx context.Context, username string) error {
	return m.store.RevokeAllForUser(ctx, username, m.clock.Now())
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
