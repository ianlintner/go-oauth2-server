package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
)

//go:embed migrations/*.sql
var migrations embed.FS

type migration struct {
	version  int
	name     string
	sql      string
	checksum string
}

// migrate applies the numbered migrations in fsys/dir that the database has not
// yet recorded, each in its own transaction. It refuses a database that holds a
// version this binary does not know (a downgrade) or whose recorded checksum no
// longer matches the embedded file (an edited migration).
//
// A session-level advisory lock (pg_advisory_lock, held by the dedicated
// connection this function borrows) serializes concurrent opens for the whole
// run. The previous single-migration scheme used pg_advisory_xact_lock around
// one transaction carrying the whole schema, but a transaction-scoped lock
// releases as soon as that transaction commits, so it cannot guard a run that
// applies several migrations in separate transactions (which is what keeps an
// earlier migration durable when a later one fails). The session lock is the
// same advisory-lock key and forces contenders to line up before any of them
// reads the applied set or applies a migration.
func migrate(ctx context.Context, db *sql.DB, fsys fs.FS, dir string) (err error) {
	migs, err := loadMigrations(fsys, dir)
	if err != nil {
		return err
	}

	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("borrow connection: %w", err)
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock(762945038215)`); err != nil {
		return err
	}
	defer func() {
		// Bound the unlock so a hung or failed unlock cannot stall shutdown; if
		// the caller's ctx was already cancelled it would make ExecContext fail
		// immediately, so use a fresh bounded context for the unlock itself.
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, unlockErr := conn.ExecContext(unlockCtx, `SELECT pg_advisory_unlock(762945038215)`); unlockErr != nil {
			// The session may still hold the advisory lock. Returning it to the
			// idle pool would let a locked session block every subsequent Open,
			// so discard the underlying physical connection instead. Closing the
			// *pgx.Conn and signalling driver.ErrBadConn makes database/sql drop
			// rather than recycle the connection.
			_ = conn.Raw(func(driverConn any) error {
				if c, ok := driverConn.(*stdlib.Conn); ok {
					return c.Conn().Close(context.Background())
				}
				return driver.ErrBadConn
			})
			if err == nil {
				err = fmt.Errorf("release advisory lock: %w", unlockErr)
			}
		}
	}()

	if _, err := conn.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version integer PRIMARY KEY, checksum text NOT NULL)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	applied, err := appliedMigrations(ctx, conn)
	if err != nil {
		return err
	}

	known := make(map[int]migration, len(migs))
	for _, m := range migs {
		known[m.version] = m
	}
	for version := range applied {
		if _, ok := known[version]; !ok {
			return fmt.Errorf("database schema version %d is newer than this binary supports; refusing to start", version)
		}
	}

	// Validate the entire applied history before applying anything new. A
	// tampered checksum on an already-recorded version must abort the run
	// before any pending migration commits, otherwise a noncontiguous history
	// (e.g. 1 and 3 recorded, 2 pending) would let Open modify the schema and
	// then reject the applied history afterwards.
	for version, sum := range applied {
		if m := known[version]; sum != m.checksum {
			return fmt.Errorf("migration %04d_%s: checksum differs from the applied one; applied migrations must not be edited", m.version, m.name)
		}
	}

	for _, m := range migs {
		if _, done := applied[m.version]; done {
			continue
		}
		if err := applyMigration(ctx, conn, m); err != nil {
			return fmt.Errorf("migration %04d_%s: %w", m.version, m.name, err)
		}
	}
	return nil
}

func appliedMigrations(ctx context.Context, conn *sql.Conn) (map[int]string, error) {
	rows, err := conn.QueryContext(ctx, `SELECT version, checksum FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("read schema_migrations: %w", err)
	}
	defer rows.Close()
	applied := map[int]string{}
	for rows.Next() {
		var v int
		var sum string
		if err := rows.Scan(&v, &sum); err != nil {
			return nil, err
		}
		applied[v] = sum
	}
	return applied, rows.Err()
}

func applyMigration(ctx context.Context, conn *sql.Conn, m migration) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, m.sql); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2)`,
		m.version, m.checksum); err != nil {
		return err
	}
	return tx.Commit()
}

func loadMigrations(fsys fs.FS, dir string) ([]migration, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}
	var out []migration
	seen := map[int]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		prefix, name, ok := strings.Cut(strings.TrimSuffix(e.Name(), ".sql"), "_")
		version, convErr := strconv.Atoi(prefix)
		if !ok || convErr != nil || version <= 0 || name == "" {
			return nil, fmt.Errorf("migration file %q must be named NNNN_description.sql", e.Name())
		}
		if prev, dup := seen[version]; dup {
			return nil, fmt.Errorf("migration version %d is used by both %q and %q", version, prev, e.Name())
		}
		seen[version] = e.Name()
		body, err := fs.ReadFile(fsys, path.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("read migration %q: %w", e.Name(), err)
		}
		sum := sha256.Sum256(body)
		out = append(out, migration{version: version, name: name, sql: string(body), checksum: hex.EncodeToString(sum[:])})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}
