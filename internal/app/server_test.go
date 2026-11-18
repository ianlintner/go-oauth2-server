package app

import (
	"net/http"
	"testing"
	"time"

	"github.com/ianlintner/go-oauth2-server/internal/config"
)

func TestServerSetsEveryTimeout(t *testing.T) {
	cfg := config.Config{
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   60 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 32 << 10,
	}
	srv := newServer(http.NotFoundHandler(), cfg)
	if srv.ReadHeaderTimeout <= 0 {
		t.Error("ReadHeaderTimeout is not set")
	}
	if srv.ReadTimeout != cfg.ReadTimeout || srv.ReadTimeout <= 0 {
		t.Errorf("ReadTimeout = %v, want %v", srv.ReadTimeout, cfg.ReadTimeout)
	}
	if srv.WriteTimeout != cfg.WriteTimeout || srv.WriteTimeout <= 0 {
		t.Errorf("WriteTimeout = %v, want %v", srv.WriteTimeout, cfg.WriteTimeout)
	}
	if srv.IdleTimeout != cfg.IdleTimeout || srv.IdleTimeout <= 0 {
		t.Errorf("IdleTimeout = %v, want %v", srv.IdleTimeout, cfg.IdleTimeout)
	}
	if srv.MaxHeaderBytes != cfg.MaxHeaderBytes || srv.MaxHeaderBytes <= 0 {
		t.Errorf("MaxHeaderBytes = %d, want %d", srv.MaxHeaderBytes, cfg.MaxHeaderBytes)
	}
}
