// Command oauth2-server runs the Go OAuth2 authorization server.
//
// Skeleton scope: it validates configuration, opens storage and serves the
// health probes only. No OAuth grants are implemented yet, and this command
// deliberately makes no claim of spec compliance. Grant endpoints arrive in
// later implementation cards (see docs/architecture-proposal.md).
//
// Configuration is read from the environment; see internal/config.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/ianlintner/go-oauth2-server/internal/app"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := app.Main(ctx)
	stop()
	os.Exit(code)
}
