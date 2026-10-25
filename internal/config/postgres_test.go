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
func TestUnsupportedStorageSchemeIsRejected(t *testing.T) {
	m := baseEnv(t)
	m["OAUTH2_STORAGE_DSN"] = "mysql://db.example/oauth"
	if _, err := config.Load(env(m)); err == nil || !strings.Contains(err.Error(), "OAUTH2_STORAGE_DSN") {
		t.Fatalf("unsupported scheme accepted: %v", err)
	}
}
