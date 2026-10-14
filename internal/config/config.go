// Package config loads and validates server configuration from the
// environment. Validation is fail-closed: a missing, malformed or insecure
// value aborts startup with every problem listed, and nothing degrades to a
// default that weakens security.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Environment names the deployment class, which selects how strict the
// validation is.
type Environment string

// Supported environments.
const (
	EnvDevelopment Environment = "development"
	EnvTest        Environment = "test"
	EnvProduction  Environment = "production"
)

// MemoryDSN is the process-local SQLite database. It is the default outside
// production and is rejected in production, where state must survive restarts
// and be shared between replicas.
const MemoryDSN = ":memory:"

const (
	defaultAddr = "127.0.0.1:8080"
	// minSessionSecretLen is the minimum length in bytes for the cookie/session
	// secret.
	minSessionSecretLen = 32
)

// Config is the validated runtime configuration.
type Config struct {
	Environment Environment
	Addr        string

	// Issuer is the exact issuer identifier advertised to clients (and put in
	// RFC 9207 iss). It is never normalized.
	Issuer string

	// SigningKeyFile is the path of the persisted token-signing key. Key
	// parsing, rotation and kid assignment belong to the Signer; config only
	// guarantees the file exists, is a regular file and is non-empty so the
	// server never starts with a key it would have to invent.
	SigningKeyFile string
	SessionSecret  Secret

	StorageDSN string

	CookieSecure           bool
	AllowInsecureRedirects bool

	// ConformanceMode enables the contract's test-mode SUT interface. It is
	// off unless explicitly set, and refused in production.
	ConformanceMode bool
	ConformanceSeed string
}

// Load reads configuration through getenv (os.Getenv when nil) and validates
// it. On any problem it returns a zero Config and an error naming every
// offending variable.
func Load(getenv func(string) string) (Config, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	get := func(key string) string { return strings.TrimSpace(getenv(key)) }

	var problems []string
	fail := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	cfg := Config{
		Environment:    Environment(strings.ToLower(get("OAUTH2_ENVIRONMENT"))),
		Addr:           get("OAUTH2_ADDR"),
		Issuer:         get("OAUTH2_ISSUER"),
		SigningKeyFile: get("OAUTH2_SIGNING_KEY_FILE"),
		// The secret is deliberately not trimmed: whitespace is part of it.
		SessionSecret:   Secret(getenv("OAUTH2_SESSION_SECRET")),
		StorageDSN:      get("OAUTH2_STORAGE_DSN"),
		ConformanceSeed: get("OAUTH2_CONFORMANCE_SEED"),
	}

	if cfg.Environment == "" {
		cfg.Environment = EnvDevelopment
	}
	switch cfg.Environment {
	case EnvDevelopment, EnvTest, EnvProduction:
	default:
		fail("OAUTH2_ENVIRONMENT must be development, test or production (got %q)", string(cfg.Environment))
	}
	production := cfg.Environment == EnvProduction

	if cfg.Addr == "" {
		cfg.Addr = defaultAddr
	}

	// Issuer.
	if err := validateIssuer(cfg.Issuer, production); err != nil {
		fail("OAUTH2_ISSUER %v", err)
	}

	// Signing key: the server must never generate one per start.
	if err := validateKeyFile(cfg.SigningKeyFile); err != nil {
		fail("OAUTH2_SIGNING_KEY_FILE %v", err)
	}

	// Session secret.
	switch n := len(cfg.SessionSecret); {
	case n == 0:
		fail("OAUTH2_SESSION_SECRET is required")
	case n < minSessionSecretLen:
		fail("OAUTH2_SESSION_SECRET must be at least %d bytes (got %d)", minSessionSecretLen, n)
	}

	// Secure-by-default switches.
	var err error
	if cfg.CookieSecure, err = boolEnv(get("OAUTH2_COOKIE_SECURE"), true); err != nil {
		fail("OAUTH2_COOKIE_SECURE %v", err)
	}
	if cfg.AllowInsecureRedirects, err = boolEnv(get("OAUTH2_ALLOW_INSECURE_REDIRECTS"), false); err != nil {
		fail("OAUTH2_ALLOW_INSECURE_REDIRECTS %v", err)
	}

	// Conformance mode is a strict "1": no truthy synonyms enable test-mode
	// credentials by accident.
	switch mode := get("OAUTH2_CONFORMANCE_MODE"); mode {
	case "", "0":
	case "1":
		cfg.ConformanceMode = true
	default:
		fail("OAUTH2_CONFORMANCE_MODE must be 1 or unset (got %q)", mode)
	}

	// Storage.
	if cfg.StorageDSN == "" {
		cfg.StorageDSN = MemoryDSN
	}
	switch {
	case production && cfg.StorageDSN == MemoryDSN:
		fail("OAUTH2_STORAGE_DSN must be a persistent database in production (process-local storage loses state and cannot be shared)")
	case cfg.ConformanceMode && cfg.StorageDSN != MemoryDSN:
		fail("OAUTH2_STORAGE_DSN must be %s in conformance mode (test-mode state must not touch a shared or persistent store)", MemoryDSN)
	}

	if production {
		if !cfg.CookieSecure {
			fail("OAUTH2_COOKIE_SECURE=false is not allowed in production")
		}
		if cfg.AllowInsecureRedirects {
			fail("OAUTH2_ALLOW_INSECURE_REDIRECTS=true is not allowed in production")
		}
		if cfg.ConformanceMode {
			fail("OAUTH2_CONFORMANCE_MODE=1 is not allowed in production")
		}
	}

	switch {
	case cfg.ConformanceMode && cfg.ConformanceSeed == "":
		fail("OAUTH2_CONFORMANCE_SEED is required when OAUTH2_CONFORMANCE_MODE=1")
	case !cfg.ConformanceMode && cfg.ConformanceSeed != "":
		fail("OAUTH2_CONFORMANCE_SEED is set but OAUTH2_CONFORMANCE_MODE is not 1; refusing to ignore it silently")
	}

	if len(problems) > 0 {
		return Config{}, fmt.Errorf("invalid configuration: %s", strings.Join(problems, "; "))
	}
	return cfg, nil
}

func validateIssuer(raw string, production bool) error {
	if raw == "" {
		return errors.New("is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("is not a valid URL: %w", err)
	}
	if !u.IsAbs() || u.Host == "" || u.Hostname() == "" {
		return errors.New("must be an absolute URL with a host")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("scheme must be https or http (got %q)", u.Scheme)
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") {
		return errors.New("must not contain userinfo, query or fragment (RFC 8414 §2)")
	}
	if production && u.Scheme != "https" {
		return errors.New("must use https in production")
	}
	return nil
}

func validateKeyFile(path string) error {
	if path == "" {
		return errors.New("is required (signing keys are persisted, never generated per start)")
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("is not readable: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("must be a regular file")
	}
	if info.Size() == 0 {
		return errors.New("is empty")
	}
	return nil
}

func boolEnv(raw string, fallback bool) (bool, error) {
	if raw == "" {
		return fallback, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("must be true or false (got %q)", raw)
	}
	return v, nil
}
