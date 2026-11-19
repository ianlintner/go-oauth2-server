package config_test

import (
	"strings"
	"testing"

	"github.com/ianlintner/go-oauth2-server/internal/config"
)

func TestPostgresStorageSelection(t *testing.T) {
	m := baseEnv(t)
	m["OAUTH2_STORAGE_DSN"] = "postgres://db.example/oauth?sslmode=require"
	cfg, err := config.Load(env(m))
	if err != nil || cfg.StorageDriver != "postgres" {
		t.Fatalf("driver=%q error=%v", cfg.StorageDriver, err)
	}
	m["OAUTH2_CONFORMANCE_MODE"] = "1"
	m["OAUTH2_CONFORMANCE_SEED"] = "seed.json"
	if _, err = config.Load(env(m)); err == nil || !strings.Contains(err.Error(), "OAUTH2_STORAGE_DSN") {
		t.Fatalf("conformance persistent store accepted: %v", err)
	}
}
func TestProductionPostgresDSNRequiresTLS(t *testing.T) {
	const secret = "s3cret-pw"
	for _, dsn := range []string{
		"postgres://u:" + secret + "@db.example/oauth",
		"postgres://u:" + secret + "@db.example/oauth?sslmode=disable",
		"postgres://u:" + secret + "@db.example/oauth?sslmode=allow",
		"postgres://u:" + secret + "@db.example/oauth?sslmode=prefer",
	} {
		m := productionEnv(t)
		m["OAUTH2_STORAGE_DSN"] = dsn
		_, err := config.Load(env(m))
		if err == nil || !strings.Contains(err.Error(), "sslmode") {
			t.Errorf("dsn %q: err = %v, want an sslmode complaint", dsn, err)
			continue
		}
		if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "db.example") {
			t.Errorf("error leaks DSN contents: %v", err)
		}
	}
	for _, mode := range []string{"require", "verify-ca", "verify-full"} {
		m := productionEnv(t)
		m["OAUTH2_STORAGE_DSN"] = "postgresql://u:p@db.example/oauth?sslmode=" + mode
		if _, err := config.Load(env(m)); err != nil {
			t.Errorf("sslmode=%s: %v", mode, err)
		}
	}
}

func TestNonProductionPostgresDSNKeepsDriverDefault(t *testing.T) {
	m := baseEnv(t)
	m["OAUTH2_STORAGE_DSN"] = "postgres://u:p@db.example/oauth"
	if _, err := config.Load(env(m)); err != nil {
		t.Fatalf("development DSN without sslmode: %v", err)
	}
}

func TestUnsupportedStorageSchemeIsRejected(t *testing.T) {
	m := baseEnv(t)
	m["OAUTH2_STORAGE_DSN"] = "mysql://db.example/oauth"
	if _, err := config.Load(env(m)); err == nil || !strings.Contains(err.Error(), "OAUTH2_STORAGE_DSN") {
		t.Fatalf("unsupported scheme accepted: %v", err)
	}
}
