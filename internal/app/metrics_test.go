package app_test

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestAppMetricsOptIn(t *testing.T) {
	env := devEnv(t)
	env["OAUTH2_METRICS_ENABLED"] = "true"
	r := boot(t, env)
	getJSON(t, r.base+"/health")
	resp, err := http.Get(r.base + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || !strings.Contains(string(body), "oauth2_server_http_requests_total") {
		t.Fatalf("metrics response %d %s", resp.StatusCode, body)
	}
}
