// Package sqlite is the SQLite storage adapter. It uses modernc.org/sqlite
// (pure Go, no cgo) and the embedded plain-SQL migrations in this package.
// The adapter passes the shared storage contract suite in
// internal/storage/storagetest, which pins the security-relevant guarantees:
// atomic one-time code consumption, refresh rotation and family revocation.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
	sqlitedrv "modernc.org/sqlite"
)

// MemoryDSN is the process-local in-memory database. State is lost on Close,
// so it suits tests and the single-process conformance run, not production.
const MemoryDSN = ":memory:"

// SQLite result-code classes (https://sqlite.org/rescode.html).
const sqliteConstraint = 19

// Store is the SQLite oauth.Store.
type Store struct {
	db *sql.DB
	repos
}

var _ oauth.Store = (*Store)(nil)

// Open opens the database at dsn (":memory:" or a file path, created when
// absent) and applies the embedded migrations. It refuses a database written
// by a newer binary. The caller must Close the Store.
func Open(dsn string) (*Store, error) {
	if dsn == "" {
		return nil, errors.New("sqlite: empty DSN")
	}

	// Every connection gets the same pragmas through the DSN. Transactions
	// start with BEGIN IMMEDIATE so a read-then-write transaction takes the
	// write lock up front instead of failing with SQLITE_BUSY on upgrade;
	// busy_timeout then makes contending writers (including another process)
	// wait their turn.
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Set("_txlock", "immediate")

	var conn string
	maxConns := 1
	if dsn == MemoryDSN {
		// A private in-memory database exists per connection, so a single
		// connection is what keeps it one database. Writers are serialized
		// either way.
		conn = ":memory:?" + q.Encode()
	} else {
		q.Add("_pragma", "journal_mode(WAL)")
		conn = (&url.URL{Scheme: "file", Opaque: (&url.URL{Path: dsn}).EscapedPath(), RawQuery: q.Encode()}).String()
		maxConns = 4
	}

	db, err := sql.Open("sqlite", conn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	db.SetMaxOpenConns(maxConns)
	db.SetMaxIdleConns(maxConns)
	db.SetConnMaxLifetime(0) // never recycle: the memory DB lives on its connection

	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: open %q: %w", dsn, err)
	}
	if err := migrate(ctx, db, embeddedMigrations, "migrations"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: %w", err)
	}
	return &Store{db: db, repos: newRepos(db)}, nil
}

// Ping reports whether the database is reachable.
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

// Close closes the database. It is safe to call more than once.
func (s *Store) Close() error { return s.db.Close() }

// WithTx runs fn in one transaction: it commits when fn returns nil and rolls
// back when fn returns an error or panics (the panic is re-raised). fn must use
// only the repositories it is handed; on the in-memory database a call to the
// Store itself from inside fn would wait forever for the single connection.
func (s *Store) WithTx(ctx context.Context, fn func(context.Context, oauth.Repositories) error) (err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: begin: %w", err)
	}
	committed := false
	defer func() {
		// Rolls back on error and on panic alike; the panic keeps unwinding.
		if !committed {
			_ = tx.Rollback()
		}
	}()

	if err := fn(ctx, newRepos(tx)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlite: commit: %w", err)
	}
	committed = true
	return nil
}

// execer is the part of *sql.DB and *sql.Tx the repositories use, so the same
// code runs in autocommit mode and inside a transaction.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type repos struct {
	clients *clientRepo
	users   *userRepo
	codes   *authCodeRepo
	refresh *refreshRepo
	access  *accessTokenRepo
}

func newRepos(db execer) repos {
	return repos{
		clients: &clientRepo{db},
		users:   &userRepo{db},
		codes:   &authCodeRepo{db},
		refresh: &refreshRepo{db},
		access:  &accessTokenRepo{db},
	}
}

// Clients returns the client repository.
func (r repos) Clients() oauth.ClientRepository { return r.clients }

// Users returns the user repository.
func (r repos) Users() oauth.UserRepository { return r.users }

// AuthCodes returns the authorization-code repository.
func (r repos) AuthCodes() oauth.AuthCodeRepository { return r.codes }

// RefreshTokens returns the refresh-token repository.
func (r repos) RefreshTokens() oauth.RefreshTokenRepository { return r.refresh }

// AccessTokens returns the access-token repository.
func (r repos) AccessTokens() oauth.AccessTokenRepository { return r.access }

// createErr maps a failed INSERT: a constraint violation is a conflict.
func createErr(err error) error {
	if err == nil {
		return nil
	}
	var se *sqlitedrv.Error
	if errors.As(err, &se) && se.Code()&0xff == sqliteConstraint {
		return oauth.ErrConflict
	}
	return err
}
