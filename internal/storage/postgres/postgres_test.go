package postgres

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
	"github.com/ianlintner/go-oauth2-server/internal/storage/storagetest"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestStorageContract(t *testing.T) {
	dsn := os.Getenv("OAUTH2_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("set OAUTH2_POSTGRES_TEST_DSN to a disposable PostgreSQL database")
	}
	isolated := func(t *testing.T) string {
		t.Helper()
		// Every subtest uses a distinct schema so durable reopen uses the same data,
		// while separate contract cases never see each other's records.
		sum := sha256.Sum256([]byte(t.Name()))
		schema := "oauth2_test_" + hex.EncodeToString(sum[:8])
		db, err := sql.Open("pgx", dsn)
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
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatal(err)
		}
		q := u.Query()
		q.Set("search_path", schema)
		u.RawQuery = q.Encode()
		return u.String()
	}
	f := storagetest.Factory{
		New: func(t *testing.T) oauth.Store {
			t.Helper()
			s, err := Open(isolated(t))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Close() })
			return s
		},
		NewPersistent: func(t *testing.T) func(*testing.T) oauth.Store {
			d := isolated(t)
			return func(t *testing.T) oauth.Store {
				t.Helper()
				s, err := Open(d)
				if err != nil {
					t.Fatal(err)
				}
				return s
			}
		},
	}
	storagetest.Run(t, f)
}
func TestOpenRejectsMissingDSN(t *testing.T) {
	if _, err := Open(" "); err == nil || !strings.Contains(err.Error(), "empty DSN") {
		t.Fatalf("Open returned %v", err)
	}
}
func TestConnectionErrorDoesNotExposePassword(t *testing.T) {
	_, err := Open("postgres://someone:never-log-this-password@127.0.0.1:1/absent?sslmode=disable&connect_timeout=1")
	if err == nil || strings.Contains(err.Error(), "never-log-this-password") {
		t.Fatal("connection error missing or exposed password")
	}
}
func TestBind(t *testing.T) {
	if got := bind("SELECT ? WHERE x = ?"); got != "SELECT $1 WHERE x = $2" {
		t.Fatal(fmt.Sprint(got))
	}
}
