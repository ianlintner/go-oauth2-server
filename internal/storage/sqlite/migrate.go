package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var embeddedMigrations embed.FS

type migration struct {
	version  int
	name     string
	sql      string
	checksum string
}

// migrate applies the migrations in fsys/dir that the database has not yet
// recorded, each in its own transaction. It refuses a database that holds a
// version this binary does not know (a downgrade) or whose recorded checksum no
// longer matches the embedded file (an edited migration).
func migrate(ctx context.Context, db *sql.DB, fsys fs.FS, dir string) error {
	migrations, err := loadMigrations(fsys, dir)
	if err != nil {
		return err
	}

	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		name       TEXT NOT NULL,
		checksum   TEXT NOT NULL,
		applied_at INTEGER NOT NULL
	) STRICT`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	applied, err := appliedMigrations(ctx, db)
	if err != nil {
		return err
	}

	known := make(map[int]migration, len(migrations))
	for _, m := range migrations {
		known[m.version] = m
	}
	for version := range applied {
		if _, ok := known[version]; !ok {
			return fmt.Errorf("database schema version %d is newer than this binary supports; refusing to start", version)
		}
	}

	for _, m := range migrations {
		if sum, done := applied[m.version]; done {
			if sum != m.checksum {
				return fmt.Errorf("migration %04d_%s: checksum differs from the applied one; applied migrations must not be edited", m.version, m.name)
			}
			continue
		}
		if err := applyMigration(ctx, db, m); err != nil {
			return fmt.Errorf("migration %04d_%s: %w", m.version, m.name, err)
		}
	}
	return nil
}

func appliedMigrations(ctx context.Context, db *sql.DB) (map[int]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT version, checksum FROM schema_migrations`)
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

func applyMigration(ctx context.Context, db *sql.DB, m migration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, m.sql); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)`,
		m.version, m.name, m.checksum, time.Now().UTC().UnixNano()); err != nil {
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
