package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

func openRaw(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestMigrateAppliesEmbeddedSchemaAndIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.db")
	for range 2 {
		s, err := Open(path)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
	db := openRaw(t, path)
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("schema_migrations rows = %d, want 3 (re-open must not re-apply)", n)
	}
	for _, table := range []string{"clients", "users", "auth_codes", "refresh_tokens", "refresh_families", "access_tokens"} {
		var name string
		if err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&name); err != nil {
			t.Fatalf("table %s missing: %v", table, err)
		}
	}
}

func TestMigrateRefusesDatabaseNewerThanBinary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	db := openRaw(t, path)
	if _, err := db.Exec(`INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES (999, 'from_the_future', 'x', 0)`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("Open = %v, want a newer-schema refusal", err)
	}
}

func TestMigrateDetectsEditedMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	db := openRaw(t, path)
	if _, err := db.Exec(`UPDATE schema_migrations SET checksum = 'tampered' WHERE version = 1`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("Open = %v, want a checksum refusal", err)
	}
}

func TestMigrateRollsBackAFailingMigration(t *testing.T) {
	db := openRaw(t, filepath.Join(t.TempDir(), "m.db"))
	fsys := fstest.MapFS{
		"migrations/0001_ok.sql":  {Data: []byte(`CREATE TABLE a (x TEXT) STRICT;`)},
		"migrations/0002_bad.sql": {Data: []byte(`CREATE TABLE b (x TEXT) STRICT; THIS IS NOT SQL;`)},
	}
	err := migrate(context.Background(), db, fsys, "migrations")
	if err == nil || !strings.Contains(err.Error(), "0002") {
		t.Fatalf("migrate = %v, want a failure naming 0002", err)
	}
	// 0001 stays applied; 0002's partial CREATE TABLE b must have rolled back.
	var name string
	if err := db.QueryRow(`SELECT name FROM sqlite_master WHERE name='b'`).Scan(&name); err != sql.ErrNoRows {
		t.Fatalf("table b exists after a failed migration (err=%v)", err)
	}
	var applied int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("applied = %d, want 1", applied)
	}
}

func TestMigrateRejectsBadFilenames(t *testing.T) {
	db := openRaw(t, filepath.Join(t.TempDir(), "m.db"))
	for name, files := range map[string]fstest.MapFS{
		"no version": {"migrations/init.sql": {Data: []byte(`SELECT 1;`)}},
		"duplicate":  {"migrations/0001_a.sql": {Data: []byte(`SELECT 1;`)}, "migrations/0001_b.sql": {Data: []byte(`SELECT 1;`)}},
	} {
		if err := migrate(context.Background(), db, files, "migrations"); err == nil {
			t.Errorf("%s: migrate accepted it", name)
		}
	}
}
