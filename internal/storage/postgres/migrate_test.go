package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net/url"
	"os"
	"strings"
	"testing"
	"testing/fstest"
)

func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("OAUTH2_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("set OAUTH2_POSTGRES_TEST_DSN to a disposable PostgreSQL database")
	}
	return dsn
}

// isolatedDSN creates a fresh, uniquely named schema for a test and returns a
// DSN whose search_path points at it, so unrelated tests never share tables or
// migration state. The schema is dropped on test cleanup.
func isolatedDSN(t *testing.T, base string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(t.Name()))
	schema := "oauth2_mig_" + hex.EncodeToString(sum[:8])
	db, err := sql.Open("pgx", base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`CREATE SCHEMA "` + schema + `"`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := db.Exec(`DROP SCHEMA "` + schema + `" CASCADE`); err != nil {
			t.Error(err)
		}
		_ = db.Close()
	})
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	return u.String()
}

func checksumOf(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// TestMigrateFreshAppliesEmbeddedAndIsIdempotent opens the real embedded schema
// twice against the same database and asserts a re-open neither errors nor
// re-applies migrations.
func TestMigrateFreshAppliesEmbeddedAndIsIdempotent(t *testing.T) {
	dsn := isolatedDSN(t, testDSN(t))
	for range 2 {
		s, err := Open(dsn)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("schema_migrations rows = %d, want 1 (re-open must not re-apply)", n)
	}
}

// TestMigrateRefusesNewerVersion asserts the runner refuses a database whose
// recorded version is ahead of any migration this binary knows.
func TestMigrateRefusesNewerVersion(t *testing.T) {
	dsn := isolatedDSN(t, testDSN(t))
	s, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`INSERT INTO schema_migrations (version, checksum) VALUES (999, 'x')`); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dsn); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("Open = %v, want a newer-schema refusal", err)
	}
}

// TestMigrateRefusesEditedAppliedMigration asserts a changed checksum on an
// already-applied migration is refused rather than silently accepted.
func TestMigrateRefusesEditedAppliedMigration(t *testing.T) {
	dsn := isolatedDSN(t, testDSN(t))
	s, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`UPDATE schema_migrations SET checksum = 'tampered' WHERE version = 1`); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dsn); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("Open = %v, want a checksum refusal", err)
	}
}

// TestMigrateAppliesPendingInOrder exercises the runner against an injected
// migration set: a database already at version 1 upgrades to 2 and 3 in order,
// and is idempotent across re-runs.
func TestMigrateAppliesPendingInOrder(t *testing.T) {
	dsn := isolatedDSN(t, testDSN(t))
	ctx := context.Background()

	fsys := fstest.MapFS{
		"migrations/0001_a.sql": {Data: []byte(`CREATE TABLE t1 (x text)`)},
		// Each later migration references its predecessor's table so an
		// out-of-order run fails: 0002 inserts into t1, 0003 reads from t2.
		"migrations/0002_b.sql": {Data: []byte(`CREATE TABLE t2 (x text); INSERT INTO t1 (x) VALUES ('from-0002');`)},
		"migrations/0003_c.sql": {Data: []byte(`CREATE TABLE t3 (x text); INSERT INTO t2 (x) VALUES ('from-0003');`)},
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// First pass applies all three.
	if err := migrate(ctx, db, fsys, "migrations"); err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	for _, tbl := range []string{"t1", "t2", "t3"} {
		var exists bool
		if err := db.QueryRow(`SELECT to_regclass($1) IS NOT NULL`, tbl).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Fatalf("table %s missing after migrate", tbl)
		}
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("schema_migrations rows = %d, want 3", n)
	}

	// Second pass is a no-op.
	if err := migrate(ctx, db, fsys, "migrations"); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("schema_migrations rows after re-run = %d, want 3", n)
	}
}

// TestMigrateRollsBackAFailingMigration asserts an earlier, successful
// migration stays applied when a later one fails: the failing migration's
// transaction (and any partial DDL inside it) is rolled back.
func TestMigrateRollsBackAFailingMigration(t *testing.T) {
	dsn := isolatedDSN(t, testDSN(t))
	ctx := context.Background()

	fsys := fstest.MapFS{
		"migrations/0001_ok.sql":  {Data: []byte(`CREATE TABLE a (x text)`)},
		"migrations/0002_bad.sql": {Data: []byte(`CREATE TABLE b (x text); SELECT 1/0;`)},
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	err = migrate(ctx, db, fsys, "migrations")
	if err == nil || !strings.Contains(err.Error(), "0002") {
		t.Fatalf("migrate = %v, want a failure naming 0002", err)
	}
	// 0001 stays applied; 0002's partial CREATE TABLE b must have rolled back.
	var exists bool
	if err := db.QueryRow(`SELECT to_regclass('b') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("table b exists after a failed migration")
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("schema_migrations rows = %d, want 1 (0001 only)", n)
	}
}

// TestMigrateUpgradesFromV1 asserts the exact upgrade path the card names: a
// database whose schema_migrations already records version 1 with the real
// 0001 checksum continues to start and applies only the newer migrations.
func TestMigrateUpgradesFromV1(t *testing.T) {
	dsn := isolatedDSN(t, testDSN(t))
	ctx := context.Background()

	body, err := migrations.ReadFile("migrations/0001_initial.sql")
	if err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if _, err := db.Exec(`CREATE TABLE schema_migrations (version integer PRIMARY KEY, checksum text NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(string(body)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO schema_migrations (version, checksum) VALUES (1, $1)`, checksumOf(body)); err != nil {
		t.Fatal(err)
	}

	// A no-op 0002 proves the runner advances past a recorded v1 without error.
	fsys := fstest.MapFS{
		"migrations/0001_initial.sql": {Data: body},
		"migrations/0002_noop.sql":    {Data: []byte(`SELECT 1;`)},
	}
	if err := migrate(ctx, db, fsys, "migrations"); err != nil {
		t.Fatalf("migrate from v1: %v", err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("schema_migrations rows = %d, want 2 after upgrading from v1", n)
	}
}

// TestMigrateRejectsBadFilenames asserts malformed migration filenames are
// refused rather than silently skipped.
func TestMigrateRejectsBadFilenames(t *testing.T) {
	dsn := isolatedDSN(t, testDSN(t))
	ctx := context.Background()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	for name, files := range map[string]fstest.MapFS{
		"no version": {"migrations/init.sql": {Data: []byte(`SELECT 1;`)}},
		"duplicate":  {"migrations/0001_a.sql": {Data: []byte(`SELECT 1;`)}, "migrations/0001_b.sql": {Data: []byte(`SELECT 1;`)}},
	} {
		if err := migrate(ctx, db, files, "migrations"); err == nil {
			t.Errorf("%s: migrate accepted it", name)
		}
	}
}

// TestMigrateConcurrentOpensAreSerialized opens the same fresh schema
// concurrently and asserts the advisory lock keeps both idempotent: exactly one
// migration row is recorded, neither open errors.
func TestMigrateConcurrentOpensAreSerialized(t *testing.T) {
	dsn := isolatedDSN(t, testDSN(t))

	done := make(chan error, 2)
	for range 2 {
		go func() {
			s, err := Open(dsn)
			if err == nil {
				err = s.Close()
			}
			done <- err
		}()
	}
	for range 2 {
		if err := <-done; err != nil {
			t.Fatalf("concurrent Open: %v", err)
		}
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("schema_migrations rows after concurrent opens = %d, want 1", n)
	}
}

// TestMigrateRejectsChecksumMismatchBeforeApplyingPending asserts that when a
// database records noncontiguous versions (say 1 and 3) and the binary also
// introduces version 2 but carries a mismatched checksum for version 3, the
// runner rejects the applied history *before* committing the pending migration
// 2. The alternative order (apply 2 first, then discover the 3 mismatch) would
// let Open modify the schema and then fail, leaving the database ahead of a
// refused start.
func TestMigrateRejectsChecksumMismatchBeforeApplyingPending(t *testing.T) {
	dsn := isolatedDSN(t, testDSN(t))
	ctx := context.Background()

	fsys := fstest.MapFS{
		"migrations/0001_a.sql": {Data: []byte(`CREATE TABLE t1 (x text)`)},
		"migrations/0002_b.sql": {Data: []byte(`CREATE TABLE t2 (x text)`)},
		"migrations/0003_c.sql": {Data: []byte(`CREATE TABLE t3 (x text)`)},
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// Seed a noncontiguous history by hand: versions 1 and 3 applied, version 2
	// never applied. Only the 1 and 3 migration SQLs run; t2 is never created.
	if _, err := db.Exec(`CREATE TABLE schema_migrations (version integer PRIMARY KEY, checksum text NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE t1 (x text)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE t3 (x text)`); err != nil {
		t.Fatal(err)
	}
	// Record 1 with its real checksum and 3 with a tampered one, so the runner
	// sees a checksum mismatch on an already-applied version while 2 is pending.
	if _, err := db.Exec(`INSERT INTO schema_migrations (version, checksum) VALUES (1, $1)`, checksumOf([]byte(`CREATE TABLE t1 (x text)`))); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO schema_migrations (version, checksum) VALUES (3, 'tampered')`); err != nil {
		t.Fatal(err)
	}

	// The tampered 0003 is recorded and 0002 is pending. The runner must refuse
	// the edited history before applying the pending migration.
	if err := migrate(ctx, db, fsys, "migrations"); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("migrate = %v, want a checksum refusal before applying the pending migration", err)
	}

	// The pending migration 2 must NOT have been committed on the way out.
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = 2`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("version 2 was applied before the checksum mismatch was detected (rows=%d)", n)
	}
}
