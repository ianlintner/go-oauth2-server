package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ianlintner/go-oauth2-server/internal/app"
)

const seedBody = `
issuer: http://localhost:8080
clients:
  - client_id: client-a
    client_secret: test-only-secret
    token_endpoint_auth_method: client_secret_basic
    redirect_uris: [https://client.example/callback]
users:
  - username: alice
    password: test-only-password
`

// devEnv is a valid development environment backed by real files in t.TempDir.
func devEnv(t *testing.T) map[string]string {
	t.Helper()
	dir := t.TempDir()
	key := filepath.Join(dir, "signing.key")
	if err := os.WriteFile(key, []byte("placeholder-key-material"), 0o600); err != nil {
		t.Fatal(err)
	}
	return map[string]string{
		"OAUTH2_ISSUER":           "http://localhost:8080",
		"OAUTH2_SIGNING_KEY_FILE": key,
		"OAUTH2_SESSION_SECRET":   "0123456789abcdef0123456789abcdef",
	}
}

func writeSeed(t *testing.T, env map[string]string, body string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "seed.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	env["OAUTH2_CONFORMANCE_MODE"] = "1"
	env["OAUTH2_CONFORMANCE_SEED"] = p
}

type running struct {
	base string
	stop func() error // cancels the context and returns Run's error
}

// boot runs the app on an ephemeral port and returns once Run has started
// serving (or failed). Run's error is available through stop.
func boot(t *testing.T, env map[string]string) running {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- app.Run(ctx, app.Options{
			Getenv:   func(k string) string { return env[k] },
			Listener: ln,
			Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		})
	}()
	// stop is idempotent: a test may call it to assert on Run's result, and
	// Cleanup calls it again so no server outlives the test.
	var (
		once   sync.Once
		runErr error
	)
	stop := func() error {
		once.Do(func() {
			cancel()
			select {
			case runErr = <-done:
			case <-time.After(10 * time.Second):
				runErr = errors.New("Run did not return after cancel")
			}
		})
		return runErr
	}
	t.Cleanup(func() { _ = stop() })
	return running{base: "http://" + ln.Addr().String(), stop: stop}
}

// failing runs the app expecting it to refuse to start.
func failing(t *testing.T, env map[string]string) error {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = app.Run(ctx, app.Options{
		Getenv:   func(k string) string { return env[k] },
		Listener: ln,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err == nil {
		t.Fatal("Run returned nil, want a startup error")
	}
	if ctx.Err() != nil {
		t.Fatalf("Run did not abort promptly: %v", err)
	}
	return err
}

func getJSON(t *testing.T, url string) (int, http.Header, map[string]any) {
	t.Helper()
	var resp *http.Response
	var err error
	for range 50 { // the server goroutine may not be accepting yet
		resp, err = (&http.Client{Timeout: 3 * time.Second}).Get(url)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, resp.Header, body
}

func TestStartsAndServesHealth(t *testing.T) {
	env := devEnv(t)
	r := boot(t, env)

	for _, path := range []string{"/healthz", "/health"} {
		code, _, body := getJSON(t, r.base+path)
		if code != http.StatusOK || body["status"] != "ok" {
			t.Fatalf("GET %s = %d %v, want 200 status ok", path, code, body)
		}
		if _, leaked := body["conformance"]; leaked {
			t.Fatalf("GET %s exposes test-mode detail with conformance mode off: %v", path, body)
		}
	}
}

// The OAuth endpoints are wired, but the credential-entry surface is the
// contract's test-mode login only: outside conformance mode there is no login,
// so no resource owner can authenticate and no code can be issued.
func TestEndpointsAreWiredButLoginIsConformanceOnly(t *testing.T) {
	r := boot(t, devEnv(t))

	code, _, body := getJSON(t, r.base+"/oauth/authorize")
	if code != http.StatusBadRequest || body["error"] != "invalid_request" {
		t.Errorf("GET /oauth/authorize = %d %v, want 400 invalid_request", code, body)
	}
	code, _, _ = getJSON(t, r.base+"/oauth/token")
	if code != http.StatusMethodNotAllowed {
		t.Errorf("GET /oauth/token = %d, want 405", code)
	}
	code, _, body = getJSON(t, r.base+"/.well-known/oauth-authorization-server")
	if code != http.StatusOK || body["issuer"] != "http://localhost:8080" {
		t.Errorf("metadata = %d %v", code, body)
	}
	for _, path := range []string{"/auth/login", "/login"} {
		if code, _, _ := getJSON(t, r.base+path); code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404 outside conformance mode", path, code)
		}
	}
}

func TestConformanceModeAppliesSeedBeforeReady(t *testing.T) {
	env := devEnv(t)
	writeSeed(t, env, seedBody)
	r := boot(t, env)

	code, _, body := getJSON(t, r.base+"/health")
	if code != http.StatusOK || body["conformance"] != true {
		t.Fatalf("/health = %d %v, want 200 with conformance true", code, body)
	}
}

func TestGracefulShutdown(t *testing.T) {
	r := boot(t, devEnv(t))
	getJSON(t, r.base+"/healthz")
	if err := r.stop(); err != nil {
		t.Fatalf("Run after cancel = %v, want nil", err)
	}
	if _, err := http.Get(r.base + "/healthz"); err == nil {
		t.Fatal("server still accepting after shutdown")
	}
}

func TestStartupFailsClosed(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(t *testing.T, env map[string]string)
		wantErr string
	}{
		{"missing issuer", func(_ *testing.T, e map[string]string) { delete(e, "OAUTH2_ISSUER") }, "OAUTH2_ISSUER"},
		{"missing signing key", func(_ *testing.T, e map[string]string) { delete(e, "OAUTH2_SIGNING_KEY_FILE") }, "OAUTH2_SIGNING_KEY_FILE"},
		{"missing session secret", func(_ *testing.T, e map[string]string) { delete(e, "OAUTH2_SESSION_SECRET") }, "OAUTH2_SESSION_SECRET"},
		{"production with conformance mode", func(t *testing.T, e map[string]string) {
			e["OAUTH2_ENVIRONMENT"] = "production"
			e["OAUTH2_ISSUER"] = "https://auth.example.com"
			e["OAUTH2_STORAGE_DSN"] = filepath.Join(t.TempDir(), "p.db")
			writeSeed(t, e, seedBody)
		}, "OAUTH2_CONFORMANCE_MODE"},
		{"conformance seed file missing", func(t *testing.T, e map[string]string) {
			e["OAUTH2_CONFORMANCE_MODE"] = "1"
			e["OAUTH2_CONFORMANCE_SEED"] = filepath.Join(t.TempDir(), "absent.yaml")
		}, "seed"},
		{"conformance seed invalid", func(t *testing.T, e map[string]string) { writeSeed(t, e, "issuer: nope\n") }, "seed"},
		{"seed issuer differs from configured issuer", func(t *testing.T, e map[string]string) {
			writeSeed(t, e, strings.Replace(seedBody, "http://localhost:8080", "http://elsewhere.example", 1))
		}, "issuer"},
		{"unusable storage path", func(t *testing.T, e map[string]string) {
			e["OAUTH2_STORAGE_DSN"] = filepath.Join(t.TempDir(), "no", "such", "dir", "x.db")
		}, "sqlite"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := devEnv(t)
			tc.mutate(t, env)
			err := failing(t, env)
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestFailedStartupDoesNotLeakSecrets(t *testing.T) {
	env := devEnv(t)
	delete(env, "OAUTH2_ISSUER")
	err := failing(t, env)
	for _, secret := range []string{env["OAUTH2_SESSION_SECRET"]} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("startup error leaks a secret: %v", err)
		}
	}
}
