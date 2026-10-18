package oauth_test

import (
	"testing"

	"github.com/ianlintner/go-oauth2-server/internal/oauth"
)

func TestMatchRedirectURI(t *testing.T) {
	const (
		https  = "https://client.example/callback"
		v4     = "http://127.0.0.1/cb"
		v6     = "http://[::1]/cb"
		local  = "http://localhost/cb"
		scheme = "com.example.app:/oauth2redirect"
	)
	tests := []struct {
		name       string
		registered []string
		requested  string
		insecure   bool
		want       bool
	}{
		{"exact https", []string{https}, https, false, true},
		{"trailing slash differs", []string{https}, https + "/", false, false},
		{"host case differs", []string{https}, "https://CLIENT.example/callback", false, false},
		{"extra query rejected", []string{https}, https + "?x=1", false, false},
		{"fragment rejected", []string{https}, https + "#frag", false, false},
		{"port added rejected", []string{https}, "https://client.example:9999/callback", false, false},
		{"scheme downgrade rejected", []string{https}, "http://client.example/callback", false, false},
		{"unregistered host", []string{https}, "https://evil.example/cb", false, false},
		{"prefix of registered rejected", []string{https + "/deep"}, https, false, false},
		{"registered is prefix of requested rejected", []string{https}, https + "/deep", false, false},
		{"empty requested", []string{https}, "", false, false},
		{"no registrations", nil, https, false, false},
		{"one of several", []string{"https://a.example/x", https}, https, false, true},

		{"ipv4 loopback any port", []string{v4}, "http://127.0.0.1:9999/cb", false, true},
		{"ipv4 loopback no port", []string{v4}, v4, false, true},
		{"ipv6 loopback any port", []string{v6}, "http://[::1]:9999/cb", false, true},
		{"loopback path must match", []string{v4}, "http://127.0.0.1:9999/other", false, false},
		{"loopback scheme must match", []string{v4}, "https://127.0.0.1:9999/cb", false, false},
		{"loopback families distinct v4 as v6", []string{v4}, "http://[::1]:9999/cb", false, false},
		{"loopback families distinct v6 as v4", []string{v6}, "http://127.0.0.1:9999/cb", false, false},
		{"loopback query must match", []string{v4}, "http://127.0.0.1:9999/cb?x=1", false, false},
		{"loopback userinfo rejected", []string{v4}, "http://user@127.0.0.1:9999/cb", false, false},
		{"loopback port zero rejected", []string{v4}, "http://127.0.0.1:0/cb", false, false},
		{"loopback port out of range rejected", []string{v4}, "http://127.0.0.1:70000/cb", false, false},
		{"loopback non-numeric port rejected", []string{v4}, "http://127.0.0.1:abc/cb", false, false},
		{"loopback other literal rejected", []string{v4}, "http://127.0.0.2:9999/cb", false, false},
		{"loopback uppercase scheme rejected", []string{v4}, "HTTP://127.0.0.1:9999/cb", false, false},
		{"registered explicit port is exact", []string{"http://127.0.0.1:8000/cb"}, "http://127.0.0.1:9999/cb", false, false},
		{"registered explicit port matches itself", []string{"http://127.0.0.1:8000/cb"}, "http://127.0.0.1:8000/cb", false, true},

		{"localhost exact", []string{local}, local, false, true},
		{"localhost gets no wildcard", []string{local}, "http://localhost:9999/cb", false, false},

		{"private scheme exact", []string{scheme}, scheme, false, true},
		{"private scheme path differs", []string{scheme}, "com.example.app:/other", false, false},

		{"http non-loopback registered is refused by default", []string{"http://client.example/cb"}, "http://client.example/cb", false, false},
		{"http non-loopback allowed when explicitly enabled", []string{"http://client.example/cb"}, "http://client.example/cb", true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := oauth.MatchRedirectURI(tc.registered, tc.requested, tc.insecure); got != tc.want {
				t.Fatalf("MatchRedirectURI(%v, %q, insecure=%v) = %v, want %v", tc.registered, tc.requested, tc.insecure, got, tc.want)
			}
		})
	}
}
