package config_test

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ianlintner/go-oauth2-server/internal/config"
)

const goodSession = "0123456789abcdef0123456789abcdef" // 32 bytes

// env builds a lookup function over a map so tests never touch the process
// environment.
func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// baseEnv returns a valid development environment plus a real key file.
func baseEnv(t *testing.T) map[string]string {
	t.Helper()
	key := filepath.Join(t.TempDir(), "signing.pem")
	if err := os.WriteFile(key, []byte("not-a-real-key-but-nonempty"), 0o600); err != nil {
		t.Fatal(err)
	}
	return map[string]string{
		"OAUTH2_ISSUER":           "http://localhost:8080",
		"OAUTH2_SIGNING_KEY_FILE": key,
		"OAUTH2_SESSION_SECRET":   goodSession,
	}
}

// productionEnv returns a valid production environment.
func productionEnv(t *testing.T) map[string]string {
	m := baseEnv(t)
	m["OAUTH2_ENVIRONMENT"] = "production"
	m["OAUTH2_ISSUER"] = "https://auth.example.com"
	m["OAUTH2_STORAGE_DSN"] = filepath.Join(t.TempDir(), "oauth.db")
	return m
}

func TestLoadValidDevelopmentDefaults(t *testing.T) {
	cfg, err := config.Load(env(baseEnv(t)))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Environment != config.EnvDevelopment {
		t.Errorf("Environment = %q, want development", cfg.Environment)
	}
	if cfg.Addr != "127.0.0.1:8080" {
		t.Errorf("Addr = %q, want loopback default", cfg.Addr)
	}
	if cfg.StorageDSN != config.MemoryDSN {
		t.Errorf("StorageDSN = %q, want %q", cfg.StorageDSN, config.MemoryDSN)
	}
	if !cfg.CookieSecure {
		t.Error("CookieSecure must default to true")
	}
	if cfg.AllowInsecureRedirects {
		t.Error("AllowInsecureRedirects must default to false")
	}
}

func TestLoadValidProduction(t *testing.T) {
	cfg, err := config.Load(env(productionEnv(t)))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Environment != config.EnvProduction {
		t.Errorf("Environment = %q", cfg.Environment)
	}
}

func TestLoadEnvironmentIsCaseInsensitive(t *testing.T) {
	m := baseEnv(t)
	m["OAUTH2_ENVIRONMENT"] = " Development "
	cfg, err := config.Load(env(m))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Environment != config.EnvDevelopment {
		t.Fatalf("Environment = %q", cfg.Environment)
	}
}

func TestLoadFailsClosed(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(t *testing.T, m map[string]string)
		wantErr string
	}{
		{"missing issuer", func(_ *testing.T, m map[string]string) { delete(m, "OAUTH2_ISSUER") }, "OAUTH2_ISSUER"},
		{"relative issuer", func(_ *testing.T, m map[string]string) { m["OAUTH2_ISSUER"] = "auth.example.com" }, "OAUTH2_ISSUER"},
		{"issuer with query", func(_ *testing.T, m map[string]string) { m["OAUTH2_ISSUER"] = "https://a.example.com/?x=1" }, "OAUTH2_ISSUER"},
		{"issuer with fragment", func(_ *testing.T, m map[string]string) { m["OAUTH2_ISSUER"] = "https://a.example.com/#x" }, "OAUTH2_ISSUER"},
		{"issuer with userinfo", func(_ *testing.T, m map[string]string) { m["OAUTH2_ISSUER"] = "https://u:p@a.example.com" }, "OAUTH2_ISSUER"},
		{"issuer ftp scheme", func(_ *testing.T, m map[string]string) { m["OAUTH2_ISSUER"] = "ftp://a.example.com" }, "OAUTH2_ISSUER"},
		{"missing signing key file", func(_ *testing.T, m map[string]string) { delete(m, "OAUTH2_SIGNING_KEY_FILE") }, "OAUTH2_SIGNING_KEY_FILE"},
		{"nonexistent signing key file", func(t *testing.T, m map[string]string) {
			m["OAUTH2_SIGNING_KEY_FILE"] = filepath.Join(t.TempDir(), "absent.pem")
		}, "OAUTH2_SIGNING_KEY_FILE"},
		{"empty signing key file", func(t *testing.T, m map[string]string) {
			p := filepath.Join(t.TempDir(), "empty.pem")
			if err := os.WriteFile(p, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			m["OAUTH2_SIGNING_KEY_FILE"] = p
		}, "OAUTH2_SIGNING_KEY_FILE"},
		{"signing key is a directory", func(t *testing.T, m map[string]string) { m["OAUTH2_SIGNING_KEY_FILE"] = t.TempDir() }, "OAUTH2_SIGNING_KEY_FILE"},
		{"missing session secret", func(_ *testing.T, m map[string]string) { delete(m, "OAUTH2_SESSION_SECRET") }, "OAUTH2_SESSION_SECRET"},
		{"short session secret", func(_ *testing.T, m map[string]string) { m["OAUTH2_SESSION_SECRET"] = "short" }, "OAUTH2_SESSION_SECRET"},
		{"unknown environment", func(_ *testing.T, m map[string]string) { m["OAUTH2_ENVIRONMENT"] = "staging" }, "OAUTH2_ENVIRONMENT"},
		{"bad bool", func(_ *testing.T, m map[string]string) { m["OAUTH2_COOKIE_SECURE"] = "maybe" }, "OAUTH2_COOKIE_SECURE"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := baseEnv(t)
			tc.mutate(t, m)
			_, err := config.Load(env(m))
			if err == nil {
				t.Fatal("Load succeeded, want failure")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not name %s", err, tc.wantErr)
			}
		})
	}
}

func TestLoadRejectsInsecureProduction(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(m map[string]string)
		wantErr string
	}{
		{"http issuer", func(m map[string]string) { m["OAUTH2_ISSUER"] = "http://auth.example.com" }, "OAUTH2_ISSUER"},
		{"insecure cookies", func(m map[string]string) { m["OAUTH2_COOKIE_SECURE"] = "false" }, "OAUTH2_COOKIE_SECURE"},
		{"insecure redirects", func(m map[string]string) { m["OAUTH2_ALLOW_INSECURE_REDIRECTS"] = "true" }, "OAUTH2_ALLOW_INSECURE_REDIRECTS"},
		{"process-local storage", func(m map[string]string) { m["OAUTH2_STORAGE_DSN"] = ":memory:" }, "OAUTH2_STORAGE_DSN"},
		{"default storage", func(m map[string]string) { delete(m, "OAUTH2_STORAGE_DSN") }, "OAUTH2_STORAGE_DSN"},
		{"conformance mode", func(m map[string]string) {
			m["OAUTH2_CONFORMANCE_MODE"] = "1"
			m["OAUTH2_CONFORMANCE_SEED"] = "/tmp/seed.yaml"
		}, "OAUTH2_CONFORMANCE_MODE"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := productionEnv(t)
			tc.mutate(m)
			_, err := config.Load(env(m))
			if err == nil {
				t.Fatal("Load succeeded, want failure")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not name %s", err, tc.wantErr)
			}
		})
	}
}

func TestLoadReportsEveryProblemAtOnce(t *testing.T) {
	_, err := config.Load(env(map[string]string{}))
	if err == nil {
		t.Fatal("empty environment accepted")
	}
	for _, key := range []string{"OAUTH2_ISSUER", "OAUTH2_SIGNING_KEY_FILE", "OAUTH2_SESSION_SECRET"} {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("error %q omits %s", err, key)
		}
	}
}

func TestConformanceModeRules(t *testing.T) {
	t.Run("requires seed", func(t *testing.T) {
		m := baseEnv(t)
		m["OAUTH2_CONFORMANCE_MODE"] = "1"
		_, err := config.Load(env(m))
		if err == nil || !strings.Contains(err.Error(), "OAUTH2_CONFORMANCE_SEED") {
			t.Fatalf("err = %v, want seed complaint", err)
		}
	})
	t.Run("seed without mode is rejected", func(t *testing.T) {
		m := baseEnv(t)
		m["OAUTH2_CONFORMANCE_SEED"] = "/tmp/seed.yaml"
		_, err := config.Load(env(m))
		if err == nil || !strings.Contains(err.Error(), "OAUTH2_CONFORMANCE_MODE") {
			t.Fatalf("err = %v, want mode complaint", err)
		}
	})
	t.Run("requires process-local storage", func(t *testing.T) {
		m := baseEnv(t)
		m["OAUTH2_CONFORMANCE_MODE"] = "1"
		m["OAUTH2_CONFORMANCE_SEED"] = "/tmp/seed.yaml"
		m["OAUTH2_STORAGE_DSN"] = filepath.Join(t.TempDir(), "shared.db")
		_, err := config.Load(env(m))
		if err == nil || !strings.Contains(err.Error(), "OAUTH2_STORAGE_DSN") {
			t.Fatalf("err = %v, want storage complaint", err)
		}
	})
	t.Run("enabled in development", func(t *testing.T) {
		m := baseEnv(t)
		m["OAUTH2_CONFORMANCE_MODE"] = "1"
		m["OAUTH2_CONFORMANCE_SEED"] = "/tmp/seed.yaml"
		cfg, err := config.Load(env(m))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if !cfg.ConformanceMode || cfg.ConformanceSeed != "/tmp/seed.yaml" {
			t.Fatalf("cfg = %+v", cfg)
		}
	})
	t.Run("only literal 1 enables it", func(t *testing.T) {
		m := baseEnv(t)
		m["OAUTH2_CONFORMANCE_MODE"] = "true"
		_, err := config.Load(env(m))
		if err == nil || !strings.Contains(err.Error(), "OAUTH2_CONFORMANCE_MODE") {
			t.Fatalf("err = %v, want strict-value complaint", err)
		}
	})
}

func TestSecretsAreRedacted(t *testing.T) {
	cfg, err := config.Load(env(baseEnv(t)))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	renderings := map[string]string{
		"%v":   fmt.Sprintf("%v", cfg),
		"%+v":  fmt.Sprintf("%+v", cfg),
		"%#v":  fmt.Sprintf("%#v", cfg),
		"%s":   fmt.Sprintf("%s", cfg.SessionSecret),
		"json": mustJSON(t, cfg),
	}
	var logged strings.Builder
	slog.New(slog.NewTextHandler(&logged, nil)).Info("cfg", "config", cfg, "secret", cfg.SessionSecret)
	renderings["slog"] = logged.String()

	for name, out := range renderings {
		if strings.Contains(out, goodSession) {
			t.Errorf("%s leaks the session secret: %s", name, out)
		}
	}
	if string(cfg.SessionSecret) != goodSession {
		t.Fatal("Reveal path broke: the secret value itself must stay intact")
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
