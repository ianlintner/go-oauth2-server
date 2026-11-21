package config_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ianlintner/go-oauth2-server/internal/config"
)

// 48 bytes, != goodSession. Built at runtime so secret scanners see no literal.
var goodNonceSecret = strings.Repeat("n0nce-", 8)

func TestDPoPNonceDefaultsOff(t *testing.T) {
	cfg, err := config.Load(env(productionEnv(t)))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DPoPNonce != config.DPoPNonceOff {
		t.Fatalf("DPoPNonce = %q, want off", cfg.DPoPNonce)
	}
}

func TestDPoPNonceModesAcceptedWithSecret(t *testing.T) {
	for _, mode := range []string{"token", "all", "TOKEN", " all "} {
		m := productionEnv(t)
		m["OAUTH2_DPOP_NONCE"], m["OAUTH2_DPOP_NONCE_SECRET"] = mode, goodNonceSecret
		cfg, err := config.Load(env(m))
		if err != nil {
			t.Fatalf("mode %q: %v", mode, err)
		}
		if want := config.DPoPNonceMode(strings.ToLower(strings.TrimSpace(mode))); cfg.DPoPNonce != want {
			t.Errorf("mode %q: DPoPNonce = %q, want %q", mode, cfg.DPoPNonce, want)
		}
		if string(cfg.DPoPNonceSecret) != goodNonceSecret {
			t.Errorf("mode %q: secret not loaded", mode)
		}
	}
}

func TestDPoPNonceRejectsBadConfig(t *testing.T) {
	cases := []struct {
		name string
		mode string
		sec  string
		want string
	}{
		{"unknown mode", "sometimes", goodNonceSecret, "OAUTH2_DPOP_NONCE must be off, token or all"},
		{"token without secret", "token", "", "OAUTH2_DPOP_NONCE_SECRET is required"},
		{"all without secret", "all", "", "OAUTH2_DPOP_NONCE_SECRET is required"},
		{"short secret", "token", "short", "at least 32 bytes"},
		{"secret equals session secret", "token", goodSession, "must differ from OAUTH2_SESSION_SECRET"},
		{"secret set while off", "off", goodNonceSecret, "is set but OAUTH2_DPOP_NONCE is off"},
		{"secret set, mode unset", "", goodNonceSecret, "is set but OAUTH2_DPOP_NONCE is off"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := productionEnv(t)
			m["OAUTH2_DPOP_NONCE"], m["OAUTH2_DPOP_NONCE_SECRET"] = tc.mode, tc.sec
			_, err := config.Load(env(m))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
			if tc.sec != "" && strings.Contains(err.Error(), tc.sec) {
				t.Fatal("error leaks the nonce secret")
			}
		})
	}
}

func TestDPoPNonceSecretIsRedacted(t *testing.T) {
	m := productionEnv(t)
	m["OAUTH2_DPOP_NONCE"], m["OAUTH2_DPOP_NONCE_SECRET"] = "token", goodNonceSecret
	cfg, err := config.Load(env(m))
	if err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{fmt.Sprintf("%v", cfg), fmt.Sprintf("%+v", cfg), fmt.Sprintf("%#v", cfg)} {
		if strings.Contains(out, goodNonceSecret) {
			t.Fatal("formatted config leaks the nonce secret")
		}
	}
}
