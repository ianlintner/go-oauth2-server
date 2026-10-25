package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
)

//go:embed migrations/*.sql
var migrations embed.FS

// migrate checks the immutable schema checksum and serializes concurrent opens.
func migrate(ctx context.Context, db *sql.DB) error {
	body, err := migrations.ReadFile("migrations/0001_initial.sql")
	if err != nil {
		return err
	}
	sum := sha256.Sum256(body)
	checksum := hex.EncodeToString(sum[:])
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	// Transaction-scoped lock is released on commit, rollback or connection loss.
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(762945038215)`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version integer PRIMARY KEY, checksum text NOT NULL)`); err != nil {
		return err
	}
	var version int
	var recorded string
	err = tx.QueryRowContext(ctx, `SELECT version, checksum FROM schema_migrations ORDER BY version DESC LIMIT 1`).Scan(&version, &recorded)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err = tx.ExecContext(ctx, string(body)); err != nil {
			return fmt.Errorf("apply schema: %w", err)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,checksum) VALUES(1,$1)`, checksum); err != nil {
			return err
		}
	case err != nil:
		return err
	case version != 1 || recorded != checksum:
		return fmt.Errorf("postgres: schema version or checksum differs; refusing to start")
	}
	return tx.Commit()
}
