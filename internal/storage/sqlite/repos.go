package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
)

// Lists are stored as JSON arrays; nil and empty both read back as an empty
// (non-nil) slice, which callers may treat as "none".
func encodeList(v []string) string {
	if v == nil {
		v = []string{}
	}
	b, err := json.Marshal(v)
	if err != nil { // unreachable for []string
		panic(err)
	}
	return string(b)
}

func decodeList(s string) ([]string, error) {
	var v []string
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return nil, fmt.Errorf("sqlite: corrupt list column %q: %w", s, err)
	}
	return v, nil
}

func nanos(t time.Time) int64     { return t.UTC().UnixNano() }
func fromNanos(n int64) time.Time { return time.Unix(0, n).UTC() }

// --- clients ---

type clientRepo struct{ db execer }

func (r *clientRepo) Create(ctx context.Context, c oauth.Client) error {
	public := 0
	if c.Public {
		public = 1
	}
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO clients (id, name, secret_hash, auth_method, public, redirect_uris, scopes, grant_types)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.Name, c.SecretHash, c.AuthMethod, public,
		encodeList(c.RedirectURIs), encodeList(c.Scopes), encodeList(c.GrantTypes))
	return createErr(err)
}

func (r *clientRepo) Get(ctx context.Context, id string) (oauth.Client, error) {
	var (
		c                         oauth.Client
		public                    int
		redirects, scopes, grants string
	)
	err := r.db.QueryRowContext(ctx,
		`SELECT id, name, secret_hash, auth_method, public, redirect_uris, scopes, grant_types
		 FROM clients WHERE id = ?`, id).
		Scan(&c.ID, &c.Name, &c.SecretHash, &c.AuthMethod, &public, &redirects, &scopes, &grants)
	if errors.Is(err, sql.ErrNoRows) {
		return oauth.Client{}, oauth.ErrNotFound
	}
	if err != nil {
		return oauth.Client{}, err
	}
	c.Public = public == 1
	if c.RedirectURIs, err = decodeList(redirects); err != nil {
		return oauth.Client{}, err
	}
	if c.Scopes, err = decodeList(scopes); err != nil {
		return oauth.Client{}, err
	}
	if c.GrantTypes, err = decodeList(grants); err != nil {
		return oauth.Client{}, err
	}
	return c, nil
}

// --- users ---

type userRepo struct{ db execer }

func (r *userRepo) Create(ctx context.Context, u oauth.User) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO users (id, username, password_hash, email, scopes) VALUES (?, ?, ?, ?, ?)`,
		u.ID, u.Username, u.PasswordHash, u.Email, encodeList(u.Scopes))
	return createErr(err)
}

func (r *userRepo) GetByUsername(ctx context.Context, username string) (oauth.User, error) {
	var (
		u      oauth.User
		scopes string
	)
	err := r.db.QueryRowContext(ctx,
		`SELECT id, username, password_hash, email, scopes FROM users WHERE username = ?`, username).
		Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Email, &scopes)
	if errors.Is(err, sql.ErrNoRows) {
		return oauth.User{}, oauth.ErrNotFound
	}
	if err != nil {
		return oauth.User{}, err
	}
	if u.Scopes, err = decodeList(scopes); err != nil {
		return oauth.User{}, err
	}
	return u, nil
}

// --- authorization codes ---

type authCodeRepo struct{ db execer }

func (r *authCodeRepo) Create(ctx context.Context, c oauth.AuthorizationCode) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO auth_codes (code_hash, client_id, user_id, redirect_uri, scope,
		                         code_challenge, code_challenge_method, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		c.CodeHash, c.ClientID, c.UserID, c.RedirectURI, c.Scope,
		c.CodeChallenge, c.CodeChallengeMethod, nanos(c.ExpiresAt))
	return createErr(err)
}

// Consume is one UPDATE ... RETURNING statement: the row is flipped from
// unconsumed to consumed and read back atomically, so exactly one of any number
// of concurrent callers (in this or another process) gets the row.
func (r *authCodeRepo) Consume(ctx context.Context, codeHash string, now time.Time) (oauth.AuthorizationCode, error) {
	var (
		c       oauth.AuthorizationCode
		expires int64
	)
	err := r.db.QueryRowContext(ctx,
		`UPDATE auth_codes SET consumed_at = ?
		 WHERE code_hash = ? AND consumed_at IS NULL
		 RETURNING code_hash, client_id, user_id, redirect_uri, scope,
		           code_challenge, code_challenge_method, expires_at`,
		nanos(now), codeHash).
		Scan(&c.CodeHash, &c.ClientID, &c.UserID, &c.RedirectURI, &c.Scope,
			&c.CodeChallenge, &c.CodeChallengeMethod, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return oauth.AuthorizationCode{}, r.missOrConsumed(ctx, `SELECT 1 FROM auth_codes WHERE code_hash = ?`, codeHash)
	}
	if err != nil {
		return oauth.AuthorizationCode{}, err
	}
	c.ExpiresAt = fromNanos(expires)
	return c, nil
}

// missOrConsumed explains a latch UPDATE that matched nothing: the row either
// never existed (ErrNotFound) or was already consumed (ErrAlreadyConsumed).
func (r *authCodeRepo) missOrConsumed(ctx context.Context, query, key string) error {
	return missOrConsumed(ctx, r.db, query, key)
}

func missOrConsumed(ctx context.Context, db execer, query, key string) error {
	var one int
	err := db.QueryRowContext(ctx, query, key).Scan(&one)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return oauth.ErrNotFound
	case err != nil:
		return err
	default:
		return oauth.ErrAlreadyConsumed
	}
}

// --- refresh tokens ---

type refreshRepo struct{ db execer }

func (r *refreshRepo) Create(ctx context.Context, t oauth.RefreshToken) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO refresh_tokens (token_hash, family_id, client_id, user_id, scope, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		t.TokenHash, t.FamilyID, t.ClientID, t.UserID, t.Scope, nanos(t.ExpiresAt))
	return createErr(err)
}

// Rotate latches the token in one statement that also checks the family is not
// revoked, so a revoke can never interleave between "is it revoked?" and "mark
// it rotated", and a token inserted into an already-revoked family is dead on
// arrival.
func (r *refreshRepo) Rotate(ctx context.Context, tokenHash string, now time.Time) (oauth.RefreshToken, error) {
	var (
		t       oauth.RefreshToken
		expires int64
	)
	err := r.db.QueryRowContext(ctx,
		`UPDATE refresh_tokens SET rotated_at = ?
		 WHERE token_hash = ? AND rotated_at IS NULL
		   AND NOT EXISTS (SELECT 1 FROM refresh_families f WHERE f.family_id = refresh_tokens.family_id)
		 RETURNING token_hash, family_id, client_id, user_id, scope, expires_at`,
		nanos(now), tokenHash).
		Scan(&t.TokenHash, &t.FamilyID, &t.ClientID, &t.UserID, &t.Scope, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return oauth.RefreshToken{}, missOrConsumed(ctx, r.db, `SELECT 1 FROM refresh_tokens WHERE token_hash = ?`, tokenHash)
	}
	if err != nil {
		return oauth.RefreshToken{}, err
	}
	t.ExpiresAt = fromNanos(expires)
	return t, nil
}

// RevokeFamily records the family as revoked (which blocks every member,
// including tokens created later) and returns how many still-live members it
// newly killed. Both statements run under the caller's transaction semantics;
// each is individually atomic and idempotent, so a crash between them is
// repaired by repeating the call.
func (r *refreshRepo) RevokeFamily(ctx context.Context, familyID string, now time.Time) (int, error) {
	if _, err := r.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO refresh_families (family_id, revoked_at) VALUES (?, ?)`,
		familyID, nanos(now)); err != nil {
		return 0, err
	}
	res, err := r.db.ExecContext(ctx,
		`UPDATE refresh_tokens SET rotated_at = ? WHERE family_id = ? AND rotated_at IS NULL`,
		nanos(now), familyID)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

// --- access tokens ---

type accessTokenRepo struct{ db execer }

func (r *accessTokenRepo) Create(ctx context.Context, t oauth.AccessToken) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO access_tokens (jti, client_id, user_id, scope, issued_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		t.JTI, t.ClientID, t.UserID, t.Scope, nanos(t.IssuedAt), nanos(t.ExpiresAt))
	return createErr(err)
}

func (r *accessTokenRepo) GetByJTI(ctx context.Context, jti string) (oauth.AccessToken, error) {
	var (
		t                    oauth.AccessToken
		issued, expires      int64
		revoked              sql.NullInt64
	)
	err := r.db.QueryRowContext(ctx,
		`SELECT jti, client_id, user_id, scope, issued_at, expires_at, revoked_at
		 FROM access_tokens WHERE jti = ?`, jti).
		Scan(&t.JTI, &t.ClientID, &t.UserID, &t.Scope, &issued, &expires, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return oauth.AccessToken{}, oauth.ErrNotFound
	}
	if err != nil {
		return oauth.AccessToken{}, err
	}
	t.IssuedAt = fromNanos(issued)
	t.ExpiresAt = fromNanos(expires)
	if revoked.Valid {
		t.RevokedAt = fromNanos(revoked.Int64)
	}
	return t, nil
}

// Revoke sets revoked_at eagerly and reports whether the token was active. It
// is idempotent: revoking an unknown or already-revoked token is not an error.
func (r *accessTokenRepo) Revoke(ctx context.Context, jti string, now time.Time) (bool, error) {
	res, err := r.db.ExecContext(ctx,
		`UPDATE access_tokens SET revoked_at = ? WHERE jti = ? AND revoked_at IS NULL`,
		nanos(now), jti)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}
