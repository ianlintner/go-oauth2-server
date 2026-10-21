package oauth

import (
	"context"
	"errors"
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
	ExpiresAt           time.Time
}

// RefreshToken is one member of a rotation family. Only the token hash is
// stored.
type RefreshToken struct {
	TokenHash string
	FamilyID  string
	ClientID  string
	UserID    string
	Scope     string
	ExpiresAt time.Time
}

// AccessToken records an issued access token so it can be revoked and
// introspected. The JTI is the JWT's unique id (the "jti" claim) and is the
// primary key; the token value itself is a JWT signed with the server key and
// is never stored, only the jti and its lifecycle metadata.
type AccessToken struct {
	JTI       string
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
	Status         string // DevicePending | DeviceApproved | DeviceDenied
	UserID         string // set when approved
	ExpiresAt      time.Time
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
	ExpiresAt     time.Time
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

// AuthCodeRepository stores one-time authorization codes.
type AuthCodeRepository interface {
	// Create returns ErrConflict if the hash exists.
	Create(ctx context.Context, c AuthorizationCode) error
	// Consume atomically marks the code consumed and returns it. Exactly one
	// of any number of concurrent callers succeeds. A second call returns
	// ErrAlreadyConsumed; an unknown hash returns ErrNotFound. Expiry is the
	// caller's decision (an expired code is still burned).
	Consume(ctx context.Context, codeHash string, now time.Time) (AuthorizationCode, error)
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
}

// DeviceCodeRepository stores RFC 8628 device authorizations.
type DeviceCodeRepository interface {
	// Create returns ErrConflict if either hash exists.
	Create(ctx context.Context, d DeviceCode) error
	// GetByHash returns ErrNotFound if absent. The record is returned even if
	// it is expired, decided or consumed; the caller decides what that means.
	GetByHash(ctx context.Context, deviceCodeHash string) (DeviceCode, error)
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
