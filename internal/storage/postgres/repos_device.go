package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
)

// --- device codes (RFC 8628) ---

type deviceRepo struct{ db execer }

const deviceCols = `device_code_hash, user_code_hash, client_id, scope, status, user_id, expires_at, poll_interval, last_poll_at, consumed_at IS NOT NULL`

func scanDevice(row *sql.Row) (oauth.DeviceCode, error) {
	var (
		d       oauth.DeviceCode
		expires int64
		poll    sql.NullInt64
	)
	if err := row.Scan(&d.DeviceCodeHash, &d.UserCodeHash, &d.ClientID, &d.Scope, &d.Status, &d.UserID, &expires, &d.Interval, &poll, &d.Consumed); err != nil {
		return oauth.DeviceCode{}, err
	}
	d.ExpiresAt = fromNanos(expires)
	if poll.Valid {
		d.LastPoll = fromNanos(poll.Int64)
	}
	return d, nil
}

func (r *deviceRepo) Create(ctx context.Context, d oauth.DeviceCode) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO device_codes (device_code_hash, user_code_hash, client_id, scope, status, user_id, expires_at, poll_interval)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		d.DeviceCodeHash, d.UserCodeHash, d.ClientID, d.Scope, d.Status, d.UserID, nanos(d.ExpiresAt), d.Interval)
	return createErr(err)
}

func (r *deviceRepo) GetByHash(ctx context.Context, hash string) (oauth.DeviceCode, error) {
	d, err := scanDevice(r.db.QueryRowContext(ctx,
		`SELECT `+deviceCols+` FROM device_codes WHERE device_code_hash = ?`, hash))
	if errors.Is(err, sql.ErrNoRows) {
		return oauth.DeviceCode{}, oauth.ErrNotFound
	}
	return d, err
}

// Decide is one conditional UPDATE: only a pending, unconsumed authorization
// can be decided, and exactly one concurrent caller wins.
func (r *deviceRepo) Decide(ctx context.Context, userCodeHash, status, userID string) (oauth.DeviceCode, error) {
	if status != oauth.DeviceApproved && status != oauth.DeviceDenied {
		return oauth.DeviceCode{}, fmt.Errorf("postgres: invalid device status %q", status)
	}
	d, err := scanDevice(r.db.QueryRowContext(ctx,
		`UPDATE device_codes SET status = ?, user_id = ?
		 WHERE user_code_hash = ? AND status = 'pending' AND consumed_at IS NULL
		 RETURNING `+deviceCols, status, userID, userCodeHash))
	if errors.Is(err, sql.ErrNoRows) {
		return oauth.DeviceCode{}, missOrConsumed(ctx, r.db, `SELECT 1 FROM device_codes WHERE user_code_hash = ?`, userCodeHash)
	}
	return d, err
}

// RecordPoll stores the time of a token request and the (possibly increased)
// interval. The interval is never lowered: a concurrent poller that also
// recorded a larger interval keeps it (RFC 8628 §3.5 slow_down growth).
func (r *deviceRepo) RecordPoll(ctx context.Context, hash string, at time.Time, interval int) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE device_codes
		 SET last_poll_at = ?, poll_interval = GREATEST(poll_interval, ?)
		 WHERE device_code_hash = ?`,
		nanos(at), interval, hash)
	return err
}

func (r *deviceRepo) Consume(ctx context.Context, hash string, now time.Time) (oauth.DeviceCode, error) {
	d, err := scanDevice(r.db.QueryRowContext(ctx,
		`UPDATE device_codes SET consumed_at = ?
		 WHERE device_code_hash = ? AND status = 'approved' AND consumed_at IS NULL
		 RETURNING `+deviceCols, nanos(now), hash))
	if errors.Is(err, sql.ErrNoRows) {
		return oauth.DeviceCode{}, missOrConsumed(ctx, r.db, `SELECT 1 FROM device_codes WHERE device_code_hash = ?`, hash)
	}
	return d, err
}

// --- pushed authorization requests (RFC 9126) ---

type pushedRepo struct{ db execer }

const pushedCols = `uri_hash, client_id, redirect_uri, scope, state, code_challenge, nonce, expires_at`

func scanPushed(row *sql.Row) (oauth.PushedRequest, error) {
	var (
		p       oauth.PushedRequest
		expires int64
	)
	if err := row.Scan(&p.URIHash, &p.ClientID, &p.RedirectURI, &p.Scope, &p.State, &p.CodeChallenge, &p.Nonce, &expires); err != nil {
		return oauth.PushedRequest{}, err
	}
	p.ExpiresAt = fromNanos(expires)
	return p, nil
}

func (r *pushedRepo) Create(ctx context.Context, p oauth.PushedRequest) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO pushed_requests (`+pushedCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		p.URIHash, p.ClientID, p.RedirectURI, p.Scope, p.State, p.CodeChallenge, p.Nonce, nanos(p.ExpiresAt))
	return createErr(err)
}

func (r *pushedRepo) GetByHash(ctx context.Context, hash string) (oauth.PushedRequest, error) {
	p, err := scanPushed(r.db.QueryRowContext(ctx,
		`SELECT `+pushedCols+` FROM pushed_requests WHERE uri_hash = ? AND consumed_at IS NULL`, hash))
	if errors.Is(err, sql.ErrNoRows) {
		return oauth.PushedRequest{}, oauth.ErrNotFound
	}
	return p, err
}

func (r *pushedRepo) Consume(ctx context.Context, hash string, now time.Time) (oauth.PushedRequest, error) {
	p, err := scanPushed(r.db.QueryRowContext(ctx,
		`UPDATE pushed_requests SET consumed_at = ? WHERE uri_hash = ? AND consumed_at IS NULL
		 RETURNING `+pushedCols, nanos(now), hash))
	if errors.Is(err, sql.ErrNoRows) {
		return oauth.PushedRequest{}, missOrConsumed(ctx, r.db, `SELECT 1 FROM pushed_requests WHERE uri_hash = ?`, hash)
	}
	return p, err
}
