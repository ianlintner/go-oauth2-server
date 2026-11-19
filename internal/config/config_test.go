package config_test

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

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
		"OAUTH2_ENVIRONMENT":      "development",
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

func TestUnsetEnvironmentFailsClosedLikeProduction(t *testing.T) {
	m := baseEnv(t)
	delete(m, "OAUTH2_ENVIRONMENT")
	_, err := config.Load(env(m))
	if err == nil || !strings.Contains(err.Error(), "OAUTH2_ISSUER") {
		t.Fatalf("err = %v, want an OAUTH2_ISSUER complaint for an unset environment with an http issuer", err)
	}
	m["OAUTH2_ENVIRONMENT"] = "development"
	if _, err := config.Load(env(m)); err != nil {
		t.Fatalf("explicit development: %v", err)
	}
}

func TestKeyFileMustNotBeGroupOrWorldReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o666, 0o620} {
		m := baseEnv(t)
		if err := os.Chmod(m["OAUTH2_SIGNING_KEY_FILE"], mode); err != nil {
			t.Fatal(err)
		}
		_, err := config.Load(env(m))
		if err == nil || !strings.Contains(err.Error(), "OAUTH2_SIGNING_KEY_FILE") {
			t.Errorf("mode %#o: err = %v, want an OAUTH2_SIGNING_KEY_FILE complaint", mode, err)
		}
	}
	for _, mode := range []os.FileMode{0o600, 0o400} {
		m := baseEnv(t)
		if err := os.Chmod(m["OAUTH2_SIGNING_KEY_FILE"], mode); err != nil {
			t.Fatal(err)
		}
		if _, err := config.Load(env(m)); err != nil {
			t.Errorf("mode %#o: %v", mode, err)
		}
	}
}

func TestServerLimitDefaultsAndOverrides(t *testing.T) {
	cfg, err := config.Load(env(baseEnv(t)))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ReadTimeout <= 0 || cfg.WriteTimeout <= 0 || cfg.IdleTimeout <= 0 || cfg.MaxHeaderBytes <= 0 {
		t.Fatalf("limits must default to positive values: %+v", cfg)
	}
	m := baseEnv(t)
	m["OAUTH2_READ_TIMEOUT"] = "45s"
	m["OAUTH2_WRITE_TIMEOUT"] = "2m"
	m["OAUTH2_IDLE_TIMEOUT"] = "90s"
	m["OAUTH2_MAX_HEADER_BYTES"] = "8192"
	cfg, err = config.Load(env(m))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ReadTimeout != 45*time.Second || cfg.WriteTimeout != 2*time.Minute || cfg.IdleTimeout != 90*time.Second || cfg.MaxHeaderBytes != 8192 {
		t.Fatalf("overrides not applied: %+v", cfg)
	}
}

func TestServerLimitsRejectInvalidValues(t *testing.T) {
	for _, tc := range []struct{ key, val string }{
		{"OAUTH2_READ_TIMEOUT", "0"},
		{"OAUTH2_READ_TIMEOUT", "-5s"},
		{"OAUTH2_WRITE_TIMEOUT", "soon"},
		{"OAUTH2_IDLE_TIMEOUT", "0s"},
		{"OAUTH2_MAX_HEADER_BYTES", "0"},
		{"OAUTH2_MAX_HEADER_BYTES", "big"},
	} {
		m := baseEnv(t)
		m[tc.key] = tc.val
		_, err := config.Load(env(m))
		if err == nil || !strings.Contains(err.Error(), tc.key) {
			t.Errorf("%s=%q: err = %v, want a complaint naming the variable", tc.key, tc.val, err)
		}
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

func TestThrottlingSettings(t *testing.T) {
	m := baseEnv(t)
	cfg, err := config.Load(env(m))
	if err != nil || cfg.MaxConcurrentHashes != 0 || cfg.AuthFailureLimit != 0 {
		t.Fatalf("defaults: cfg = %+v, err = %v", cfg, err)
	}
	m["OAUTH2_MAX_CONCURRENT_HASHES"] = "3"
	m["OAUTH2_AUTH_FAILURES_PER_MINUTE"] = "7"
	if cfg, err = config.Load(env(m)); err != nil || cfg.MaxConcurrentHashes != 3 || cfg.AuthFailureLimit != 7 {
		t.Fatalf("explicit: cfg = %+v, err = %v", cfg, err)
	}
	m["OAUTH2_MAX_CONCURRENT_HASHES"] = "many"
	if _, err = config.Load(env(m)); err == nil {
		t.Fatal("a non-integer limit must be refused")
	}
}
