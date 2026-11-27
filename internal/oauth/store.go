package oauth

import (
	"context"
	"errors"
	"strings"
	"time"
)

// Sentinel storage errors. Adapters must return these (possibly wrapped) so
// callers and the shared contract suite are adapter-independent.
var (
	// ErrNotFound means the requested record does not exist.
	ErrNotFound = errors.New("storage: not found")
	// ErrConflict means a uniqueness constraint was violated.
	ErrConflict = errors.New("storage: conflict")
	// ErrAlreadyConsumed means a single-use record was already consumed (an
	// authorization code redeemed, a refresh token rotated or revoked). The
	// caller treats it as replay.
	ErrAlreadyConsumed = errors.New("storage: already consumed")
)

// Client is a registered OAuth client. SecretHash is a password hash, never a
// plaintext secret; it is empty for public clients.
type Client struct {
	ID           string
	Name         string
	SecretHash   string
	AuthMethod   string // none | client_secret_basic | client_secret_post
	Public       bool
	RedirectURIs []string
	Scopes       []string
	GrantTypes   []string
	// Resources are the resource indicators (RFC 8707) the client may request
	// as the audience of an access token. The issuer itself is always
	// permitted and need not be listed.
	Resources []string
}

// User is a resource owner. PasswordHash is a password hash.
type User struct {
	ID           string
	Username     string
	PasswordHash string
	Email        string
	Scopes       []string
}

// AuthorizationCode is a one-time code. Only the SHA-256 hash of the code
// value is stored, so a database read cannot replay codes.
type AuthorizationCode struct {
	CodeHash            string
	ClientID            string
	UserID              string
	RedirectURI         string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string // OIDC nonce from the authorization request, "" if none
	// GrantID identifies the grant this code starts. Tokens minted from the
	// code carry it, so a replayed code can revoke them. "" marks a record
	// that predates grant linking.
	GrantID string
	// Audience is the resource indicator the code was authorized for; "" for a
	// record written before audiences existed.
	Audience  string
	ExpiresAt time.Time
}

// RefreshToken is one member of a rotation family. Only the token hash is
// stored.
type RefreshToken struct {
	TokenHash string
	FamilyID  string
	// GrantID is the grant the token belongs to; "" marks a record that
	// predates grant linking.
	GrantID  string
	ClientID string
	UserID   string
	Scope    string
	// Audience is the resource the family is bound to; it never widens on
	// rotation. "" for a record written before audiences existed.
	Audience  string
	ExpiresAt time.Time
}

// AccessToken records an issued access token so it can be revoked and
// introspected. The JTI is the JWT's unique id (the "jti" claim) and is the
// primary key; the token value itself is a JWT signed with the server key and
// is never stored, only the jti and its lifecycle metadata.
type AccessToken struct {
	JTI string
	// GrantID is the grant the token was issued under; "" means unlinked
	// (a legacy record) and never matches a grant revocation.
	GrantID   string
	ClientID  string
	UserID    string
	Scope     string
	IssuedAt  time.Time
	ExpiresAt time.Time
	RevokedAt time.Time // zero when active
}

// Device authorization states (RFC 8628).
const (
	DevicePending  = "pending"
	DeviceApproved = "approved"
	DeviceDenied   = "denied"
)

// DeviceCode is one RFC 8628 device authorization. Only SHA-256 hashes of the
// device_code and of the normalized user_code are stored.
type DeviceCode struct {
	DeviceCodeHash string
	UserCodeHash   string
	ClientID       string
	Scope          string
	// Audience is the resource indicator requested at the device authorization
	// request; "" when none was recorded.
	Audience  string
	Status    string // DevicePending | DeviceApproved | DeviceDenied
	UserID    string // set when approved
	ExpiresAt time.Time
	// Interval is the minimum polling interval in seconds; it grows by 5 each
	// time the client polls too fast (RFC 8628 §3.5).
	Interval int
	// LastPoll is the time of the previous token request (zero if none).
	LastPoll time.Time
	// Consumed is true once the approved authorization has been redeemed.
	Consumed bool
}

// PushedRequest is an RFC 9126 pushed authorization request. Only the
// validated authorization-request fields are kept; the request_uri value
// itself is stored as a hash.
type PushedRequest struct {
	URIHash       string
	ClientID      string
	RedirectURI   string
	Scope         string
	State         string
	CodeChallenge string
	Nonce         string
	// Audience is the validated resource indicator, "" when none was pushed.
	Audience  string
	ExpiresAt time.Time
}

// Approval records that a resource owner approved a client for a set of
// scopes. There is at most one row per (UserID, ClientID); a seeded or
// user-granted approval is always an explicit row.
type Approval struct {
	UserID    string
	ClientID  string
	Scopes    []string
	GrantedAt time.Time
}

// Covers reports whether every space-delimited scope in requested is part of
// the approved set. An empty request is covered by any approval.
func (a Approval) Covers(requested string) bool {
	have := make(map[string]bool, len(a.Scopes))
	for _, s := range a.Scopes {
		have[s] = true
	}
	for _, s := range strings.Fields(requested) {
		if !have[s] {
			return false
		}
	}
	return true
}

// ClientRepository stores registered clients.
type ClientRepository interface {
	// Create returns ErrConflict if the client ID exists.
	Create(ctx context.Context, c Client) error
	// Get returns ErrNotFound if absent.
	Get(ctx context.Context, id string) (Client, error)
}

// UserRepository stores resource owners.
type UserRepository interface {
	// Create returns ErrConflict if the ID or username exists.
	Create(ctx context.Context, u User) error
	// GetByUsername returns ErrNotFound if absent.
	GetByUsername(ctx context.Context, username string) (User, error)
}

// Session is a server-side record of one resource-owner login. ID is an opaque
// identifier (the session package stores a hash of the value in the cookie).
type Session struct {
	ID        string
	Username  string
	ExpiresAt time.Time
}

// SessionRepository stores resource-owner login sessions so the server, not
// the browser, decides whether a session is still live.
type SessionRepository interface {
	// Create returns ErrConflict if the ID exists.
	Create(ctx context.Context, s Session) error
	// Active reports whether a session with this ID exists for username, has
	// not expired at now and has not been revoked.
	Active(ctx context.Context, id, username string, now time.Time) (bool, error)
	// Revoke ends one session. It is idempotent and ignores unknown IDs.
	Revoke(ctx context.Context, id string, now time.Time) error
	// RevokeAllForUser ends every live session of username.
	RevokeAllForUser(ctx context.Context, username string, now time.Time) error
}

// AuthCodeRepository stores one-time authorization codes.
type AuthCodeRepository interface {
	// Create returns ErrConflict if the hash exists.
	Create(ctx context.Context, c AuthorizationCode) error
	// Consume atomically marks the code consumed and returns it. Exactly one
	// of any number of concurrent callers succeeds. A second call returns
	// ErrAlreadyConsumed; an unknown hash returns ErrNotFound. Expiry is the
	// caller's decision (an expired code is still burned).
	Consume(ctx context.Context, codeHash string, now time.Time) (AuthorizationCode, error)
	// GetByHash returns the code without consuming it, even when it was
	// already consumed or has expired. It returns ErrNotFound for an unknown
	// hash. It lets a replay be tied back to the grant the code started.
	GetByHash(ctx context.Context, codeHash string) (AuthorizationCode, error)
}

// RefreshTokenRepository stores refresh tokens and their rotation families.
type RefreshTokenRepository interface {
	// Create returns ErrConflict if the hash exists.
	Create(ctx context.Context, t RefreshToken) error
	// GetByHash returns the token without marking it rotated. It returns
	// ErrNotFound when the token does not exist, and the record even when it
	// has been rotated or its family revoked (the caller decides what that
	// means). It lets a grant check client binding and scope against the
	// original token before any consuming rotation.
	GetByHash(ctx context.Context, tokenHash string) (RefreshToken, error)
	// Rotate atomically marks the token rotated and returns it. If it was
	// already rotated or its family revoked it returns ErrAlreadyConsumed;
	// unknown hashes return ErrNotFound.
	Rotate(ctx context.Context, tokenHash string, now time.Time) (RefreshToken, error)
	// RevokeFamily revokes every token in the family and reports how many
	// were newly revoked. Revoking an unknown or already-revoked family is
	// not an error.
	RevokeFamily(ctx context.Context, familyID string, now time.Time) (int, error)
}

// AccessTokenRepository stores issued access tokens for revocation and
// introspection.
type AccessTokenRepository interface {
	// Create returns ErrConflict if the jti exists.
	Create(ctx context.Context, t AccessToken) error
	// GetByJTI returns ErrNotFound if the jti does not exist.
	GetByJTI(ctx context.Context, jti string) (AccessToken, error)
	// Revoke marks the token revoked and reports whether it was newly
	// revoked. Revoking an unknown or already-revoked token is not an error.
	Revoke(ctx context.Context, jti string, now time.Time) (bool, error)
	// RevokeByGrant revokes, in one statement, every active access token
	// issued under grantID and reports how many were newly revoked. Revoking
	// an unknown or already-revoked grant is not an error. An empty grantID
	// matches nothing: "" marks unlinked legacy rows, never a wildcard.
	RevokeByGrant(ctx context.Context, grantID string, now time.Time) (int, error)
}

// ApprovalRepository stores resource-owner approvals of clients.
type ApprovalRepository interface {
	// Get returns ErrNotFound when the user has not approved the client.
	Get(ctx context.Context, userID, clientID string) (Approval, error)
	// Put records the approval, replacing any earlier row for the same
	// (user, client) pair.
	Put(ctx context.Context, a Approval) error
}

// DeviceCodeRepository stores RFC 8628 device authorizations.
type DeviceCodeRepository interface {
	// Create returns ErrConflict if either hash exists.
	Create(ctx context.Context, d DeviceCode) error
	// GetByHash returns ErrNotFound if absent. The record is returned even if
	// it is expired, decided or consumed; the caller decides what that means.
	GetByHash(ctx context.Context, deviceCodeHash string) (DeviceCode, error)
	// GetByUserCodeHash returns ErrNotFound if absent. Like GetByHash it
	// returns the record whatever its state; it never modifies anything.
	GetByUserCodeHash(ctx context.Context, userCodeHash string) (DeviceCode, error)
	// Decide atomically moves the authorization with this user-code hash from
	// pending to approved or denied (status) and records userID. Exactly one of
	// any number of concurrent callers succeeds; a decided or consumed
	// authorization returns ErrAlreadyConsumed, an unknown hash ErrNotFound.
	// Expiry is the caller's decision.
	Decide(ctx context.Context, userCodeHash, status, userID string) (DeviceCode, error)
	// RecordPoll stores the time of a token request and the (possibly
	// increased) interval. The stored interval is never lowered, so a racing
	// poller cannot undo a slow_down increase.
	RecordPoll(ctx context.Context, deviceCodeHash string, at time.Time, interval int) error
	// Consume atomically spends an approved authorization. A second call, or
	// a call on a pending/denied one, returns ErrAlreadyConsumed; an unknown
	// hash returns ErrNotFound.
	Consume(ctx context.Context, deviceCodeHash string, now time.Time) (DeviceCode, error)
}

// PushedRequestRepository stores RFC 9126 pushed authorization requests.
type PushedRequestRepository interface {
	// Create returns ErrConflict if the hash exists.
	Create(ctx context.Context, r PushedRequest) error
	// GetByHash returns the request without consuming it (ErrNotFound if
	// absent or already consumed).
	GetByHash(ctx context.Context, uriHash string) (PushedRequest, error)
	// Consume atomically spends the request. Exactly one of any number of
	// concurrent callers succeeds; later calls return ErrAlreadyConsumed, an
	// unknown hash ErrNotFound. Expiry is the caller's decision.
	Consume(ctx context.Context, uriHash string, now time.Time) (PushedRequest, error)
}

// Repositories groups the repositories. A Store exposes them in autocommit
// mode; WithTx hands the same set bound to one transaction.
type Repositories interface {
	Clients() ClientRepository
	Users() UserRepository
	AuthCodes() AuthCodeRepository
	RefreshTokens() RefreshTokenRepository
	AccessTokens() AccessTokenRepository
	DeviceCodes() DeviceCodeRepository
	PushedRequests() PushedRequestRepository
	Approvals() ApprovalRepository
	Sessions() SessionRepository
}

// Store is the storage port every adapter (SQLite now, PostgreSQL later)
// implements and the shared contract suite verifies.
type Store interface {
	Repositories
	// WithTx runs fn in one transaction: commit if fn returns nil, roll back
	// on error or panic (re-panicking). fn must use only the Repositories it
	// is given.
	WithTx(ctx context.Context, fn func(ctx context.Context, tx Repositories) error) error
	// Ping reports whether the backing store is reachable.
	Ping(ctx context.Context) error
	// Close releases resources.
	Close() error
}

// RevokeGrant ends a grant: it revokes the refresh family and every access
// token issued under it in one transaction, so a failure leaves neither half
// applied. Both steps are idempotent, so repeating the call (including from a
// concurrent request) is safe. familyID or grantID may be empty when the grant
// has no refresh family or no linked access tokens.
func RevokeGrant(ctx context.Context, store Store, familyID, grantID string, now time.Time) error {
	return store.WithTx(ctx, func(ctx context.Context, tx Repositories) error {
		if familyID != "" {
			if _, err := tx.RefreshTokens().RevokeFamily(ctx, familyID, now); err != nil {
				return err
			}
		}
		if grantID != "" {
			if _, err := tx.AccessTokens().RevokeByGrant(ctx, grantID, now); err != nil {
				return err
			}
		}
		return nil
	})
}
