// Package app wires configuration, storage and the HTTP server into a
// runnable process. Everything that can be wrong at startup is checked here
// before the listener accepts a request: the server fails closed rather than
// serving in a degraded or half-configured state.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/ianlintner/go-oauth2-server/internal/authcode"
	"github.com/ianlintner/go-oauth2-server/internal/config"
	"github.com/ianlintner/go-oauth2-server/internal/conformance"
	"github.com/ianlintner/go-oauth2-server/internal/oauth"
	"github.com/ianlintner/go-oauth2-server/internal/server"
	"github.com/ianlintner/go-oauth2-server/internal/session"
	"github.com/ianlintner/go-oauth2-server/internal/storage/sqlite"
)

// shutdownTimeout bounds graceful shutdown so a stuck connection cannot hang
// the process indefinitely.
const shutdownTimeout = 10 * time.Second

// Options are the injectable parts of Run; zero values mean production
// behavior.
type Options struct {
	// Getenv reads configuration (os.Getenv when nil).
	Getenv func(string) string
	// Listener, when set, replaces listening on the configured address. Tests
	// pass an ephemeral-port listener; Run takes ownership and closes it.
	Listener net.Listener
	// Logger defaults to slog.Default().
	Logger *slog.Logger
	// Random seeds password hashing; crypto/rand when nil.
	Random oauth.Random
}

// Run validates configuration, opens storage, applies the conformance seed when
// that mode is on, and serves until ctx is canceled. It returns nil after a
// clean shutdown and an error for any startup or serve failure. The server does
// not listen on the configured address until every check has passed.
func Run(ctx context.Context, opts Options) error {
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	rnd := opts.Random
	if rnd == nil {
		rnd = oauth.CryptoRandom{}
	}

	closeListener := func() {
		if opts.Listener != nil {
			_ = opts.Listener.Close()
		}
	}

	cfg, err := config.Load(opts.Getenv)
	if err != nil {
		closeListener()
		return err
	}

	st, err := sqlite.Open(cfg.StorageDSN)
	if err != nil {
		closeListener()
		return fmt.Errorf("open storage: %w", err)
	}
	defer func() { _ = st.Close() }()

	if cfg.ConformanceMode {
		seed, err := conformance.LoadSeed(cfg.ConformanceSeed)
		if err != nil {
			closeListener()
			return err
		}
		// RFC 9207 iss must equal the advertised issuer; a mismatch would make
		// every conformance verdict meaningless, so refuse to start.
		if seed.Issuer != cfg.Issuer {
			closeListener()
			return fmt.Errorf("conformance seed issuer %q does not match OAUTH2_ISSUER %q", seed.Issuer, cfg.Issuer)
		}
		if err := conformance.Apply(ctx, st, rnd, seed); err != nil {
			closeListener()
			return fmt.Errorf("apply conformance seed: %w", err)
		}
		log.Warn("conformance mode enabled: seeded test credentials are active; never use in production")
	}

	svc, err := authcode.New(authcode.Config{
		Store:                  st,
		Clock:                  oauth.SystemClock{},
		Random:                 rnd,
		AllowInsecureRedirects: cfg.AllowInsecureRedirects,
	})
	if err != nil {
		closeListener()
		return fmt.Errorf("authorization service: %w", err)
	}
	sessions, err := session.New([]byte(cfg.SessionSecret), oauth.SystemClock{}, cfg.CookieSecure)
	if err != nil {
		closeListener()
		return fmt.Errorf("session manager: %w", err)
	}

	listener := opts.Listener
	if listener == nil {
		listener, err = net.Listen("tcp", cfg.Addr)
		if err != nil {
			return fmt.Errorf("listen on %s: %w", cfg.Addr, err)
		}
	}

	srv := &http.Server{
		Handler: server.New(server.Deps{
			Ping:        st.Ping,
			Conformance: cfg.ConformanceMode,
			Service:     svc,
			Sessions:    sessions,
			Issuer:      cfg.Issuer,
			Logger:      log,
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}

	serveErr := make(chan error, 1)
	go func() {
		// The listener is already open, so the logged address is the real one
		// (important when :0 is requested by CI).
		log.Info("oauth2-server listening", "addr", listener.Addr().String(), "environment", string(cfg.Environment))
		if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		log.Info("shutdown signal received, draining connections")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("graceful shutdown: %w", err)
		}
		return <-serveErr
	}
}

// Main is the process entry used by cmd/oauth2-server: it runs until SIGINT or
// SIGTERM and returns the process exit code.
func Main(ctx context.Context) int {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)
	if err := Run(ctx, Options{Logger: logger}); err != nil {
		logger.Error("server exited with error", "error", err)
		return 1
	}
	return 0
}
