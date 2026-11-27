package dpop

import (
	"context"
	"database/sql"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
)

// SQLExecer is the subset of *sql.DB the SQL replay store needs. Queries use
// "?" placeholders; the PostgreSQL adapter passes a wrapper that rebinds them.
type SQLExecer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

const (
	sqlReplayOpTimeout     = 5 * time.Second
	sqlReplayPurgeInterval = time.Minute
)

// SQLReplayStore is a ReplayStore backed by the dpop_replay table of the
// primary database. Because the table lives in the shared database, replay
// protection survives restarts and holds across instances (PostgreSQL) or
// across processes on the same file (SQLite).
//
// Add is one atomic upsert: it inserts the key, or takes over an expired row,
// and reports a replay when a live row already exists. Expired rows are purged
// lazily from Add (at most once per purge interval), so there is no background
// goroutine to manage.
//
// The capacity bound is per instance: each instance counts the live rows it
// last observed plus the rows it inserted since. It exists to keep an
// unauthenticated flood from growing the table without limit and fails closed
// (ErrReplayStoreFull); it is not an exact global cap.
type SQLReplayStore struct {
	db    SQLExecer
	clock oauth.Clock
	max   int64

	live atomic.Int64 // approximate live row count

	purgeMu   sync.Mutex
	lastPurge time.Time
}

// NewSQLReplayStore returns a store holding at most about max live entries.
func NewSQLReplayStore(db SQLExecer, clock oauth.Clock, max int) *SQLReplayStore {
	s := &SQLReplayStore{db: db, clock: clock, max: int64(max)}
	s.lastPurge = clock.Now()
	// Seed the count so a restart under load does not start from zero.
	s.refreshCount()
	return s
}

func (s *SQLReplayStore) refreshCount() {
	ctx, cancel := context.WithTimeout(context.Background(), sqlReplayOpTimeout)
	defer cancel()
	var n int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM dpop_replay WHERE expires_at > ?`, s.clock.Now().UTC().UnixNano()).Scan(&n); err == nil {
		s.live.Store(n)
	}
}

// purge deletes expired rows and resyncs the live count, at most once per
// purge interval.
func (s *SQLReplayStore) purge(now time.Time) {
	s.purgeMu.Lock()
	if now.Sub(s.lastPurge) < sqlReplayPurgeInterval {
		s.purgeMu.Unlock()
		return
	}
	s.lastPurge = now
	s.purgeMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), sqlReplayOpTimeout)
	defer cancel()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM dpop_replay WHERE expires_at <= ?`, now.UTC().UnixNano()); err == nil {
		s.refreshCount()
	}
}

// Add implements ReplayStore. Any database error is returned so verification
// fails closed: a proof that cannot be recorded is not accepted.
func (s *SQLReplayStore) Add(key string, expires time.Time) (bool, error) {
	now := s.clock.Now()
	s.purge(now)
	if s.live.Load() >= s.max {
		// The estimate may include rows that just expired; resync once
		// before refusing.
		s.refreshCount()
		if s.live.Load() >= s.max {
			return false, ErrReplayStoreFull
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), sqlReplayOpTimeout)
	defer cancel()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO dpop_replay (jti_key, expires_at) VALUES (?, ?)
		 ON CONFLICT (jti_key) DO UPDATE SET expires_at = excluded.expires_at
		 WHERE dpop_replay.expires_at <= ?`,
		key, expires.UTC().UnixNano(), now.UTC().UnixNano())
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if n == 0 {
		return false, nil
	}
	s.live.Add(1)
	return true, nil
}
