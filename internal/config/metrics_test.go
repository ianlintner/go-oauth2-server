package config_test

import (
	"strings"
	"testing"

	"github.com/ianlintner/go-oauth2-server/internal/config"
)

func TestMetricsAreOptIn(t *testing.T) {
	m := baseEnv(t)
	cfg, err := config.Load(env(m))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MetricsEnabled {
		t.Fatal("metrics enabled without opt-in")
	}
	m["OAUTH2_METRICS_ENABLED"] = "true"
	cfg, err = config.Load(env(m))
	if err != nil || !cfg.MetricsEnabled {
		t.Fatalf("metrics disabled: %v", err)
	}
	m["OAUTH2_METRICS_ENABLED"] = "perhaps"
	if _, err = config.Load(env(m)); err == nil || !strings.Contains(err.Error(), "OAUTH2_METRICS_ENABLED") {
		t.Fatalf("bad boolean accepted: %v", err)
	}
}
