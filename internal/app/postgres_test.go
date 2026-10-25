package app_test

import (
	"database/sql"
	"net/url"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestStartsWithPostgresStorage(t *testing.T) {
	dsn := os.Getenv("OAUTH2_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL database")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "oauth2_app_test"
	if _, err = db.Exec(`CREATE SCHEMA "` + schema + `"`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, err := db.Exec(`DROP SCHEMA "` + schema + `" CASCADE`)
		if err != nil {
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
	env := devEnv(t)
	env["OAUTH2_STORAGE_DSN"] = u.String()
	r := boot(t, env)
	code, _, body := getJSON(t, r.base+"/health")
	if code != 200 || body["status"] != "ok" {
		t.Fatalf("health: %d %v", code, body)
	}
}
