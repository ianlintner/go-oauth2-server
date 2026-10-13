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
	// Rotate atomically marks the token rotated and returns it. If it was
	// already rotated or its family revoked it returns ErrAlreadyConsumed;
	// unknown hashes return ErrNotFound.
	Rotate(ctx context.Context, tokenHash string, now time.Time) (RefreshToken, error)
	// RevokeFamily revokes every token in the family and reports how many
	// were newly revoked. Revoking an unknown or already-revoked family is
	// not an error.
	RevokeFamily(ctx context.Context, familyID string, now time.Time) (int, error)
}

// Repositories groups the repositories. A Store exposes them in autocommit
// mode; WithTx hands the same set bound to one transaction.
type Repositories interface {
	Clients() ClientRepository
	Users() UserRepository
	AuthCodes() AuthCodeRepository
	RefreshTokens() RefreshTokenRepository
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
