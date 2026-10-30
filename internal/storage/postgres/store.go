// Package postgres implements the oauth.Store contract using pgx/v5's database/sql driver.
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// Store owns its pool. Each transaction binds its repositories to one SQL transaction.
type Store struct {
	db *sql.DB
	repos
}

var _ oauth.Store = (*Store)(nil)

// Open connects to an existing PostgreSQL database and applies the embedded schema.
// The DSN must be supplied explicitly; it is never logged or included in errors.
func Open(dsn string) (*Store, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("postgres: empty DSN")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: open: %w", err)
	}
	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(16)
	ctx := context.Background()
	if err = db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}
	if err = migrate(ctx, db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("postgres: migrate: %w", err)
	}
	return &Store{db: db, repos: newRepos(rebindDB{db})}, nil
}
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }
func (s *Store) Close() error                   { return s.db.Close() }
func (s *Store) WithTx(ctx context.Context, fn func(context.Context, oauth.Repositories) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("postgres: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err = fn(ctx, newRepos(rebindTx{tx})); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("postgres: commit: %w", err)
	}
	return nil
}

// Adapt positional SQL parameters from the shared repository query vocabulary.
// All SQL is constant, not user-supplied, and contains no quoted question marks.
func bind(query string) string {
	var b strings.Builder
	n := 0
	for _, c := range query {
		if c == '?' {
			n++
			fmt.Fprintf(&b, "$%d", n)
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}

type execer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}
type repos struct {
	clients *clientRepo
	users   *userRepo
	codes   *authCodeRepo
	refresh *refreshRepo
	access  *accessTokenRepo
	device  *deviceRepo
	pushed  *pushedRepo
}

func newRepos(db execer) repos {
	return repos{
		clients: &clientRepo{db}, users: &userRepo{db}, codes: &authCodeRepo{db},
		refresh: &refreshRepo{db}, access: &accessTokenRepo{db}, device: &deviceRepo{db}, pushed: &pushedRepo{db},
	}
}
func (r repos) Clients() oauth.ClientRepository               { return r.clients }
func (r repos) Users() oauth.UserRepository                   { return r.users }
func (r repos) AuthCodes() oauth.AuthCodeRepository           { return r.codes }
func (r repos) RefreshTokens() oauth.RefreshTokenRepository   { return r.refresh }
func (r repos) AccessTokens() oauth.AccessTokenRepository     { return r.access }
func (r repos) DeviceCodes() oauth.DeviceCodeRepository       { return r.device }
func (r repos) PushedRequests() oauth.PushedRequestRepository { return r.pushed }

type rebindDB struct{ *sql.DB }

func (d rebindDB) ExecContext(c context.Context, q string, a ...any) (sql.Result, error) {
	return d.DB.ExecContext(c, bind(q), a...)
}
func (d rebindDB) QueryRowContext(c context.Context, q string, a ...any) *sql.Row {
	return d.DB.QueryRowContext(c, bind(q), a...)
}

type rebindTx struct{ *sql.Tx }

func (d rebindTx) ExecContext(c context.Context, q string, a ...any) (sql.Result, error) {
	return d.Tx.ExecContext(c, bind(q), a...)
}
func (d rebindTx) QueryRowContext(c context.Context, q string, a ...any) *sql.Row {
	return d.Tx.QueryRowContext(c, bind(q), a...)
}

func createErr(err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && (pg.Code == "23505" || pg.Code == "23514") {
		return oauth.ErrConflict
	}
	return err
}
