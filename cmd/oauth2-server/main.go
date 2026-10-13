// Command oauth2-server runs the Go OAuth2 authorization server.
//
// Bootstrap scope: it boots an HTTP listener serving the health probe only.
// No OAuth grants are implemented yet, and this command deliberately makes no
// claim of spec compliance. Grant endpoints arrive in later implementation
// cards (see docs/architecture-proposal.md).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ianlintner/go-oauth2-server/internal/server"
)

// shutdownTimeout bounds graceful shutdown so a stuck connection cannot hang
// the process indefinitely.
const shutdownTimeout = 10 * time.Second

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("server exited with error", "error", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("oauth2-server", flag.ContinueOnError)
	addr := fs.String("addr", envOr("OAUTH2_SERVER_ADDR", "127.0.0.1:8080"), "host:port to listen on")
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", *addr, err)
	}

	srv := &http.Server{
		Handler:           server.NewRouter(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() {
		// The listener is already open, so the address in use is the real one
		// (important when :0 is requested by CI).
		logger.Info("oauth2-server listening", "addr", listener.Addr().String())
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
		logger.Info("shutdown signal received, draining connections")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("graceful shutdown: %w", err)
		}
		return <-serveErr
	}
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
