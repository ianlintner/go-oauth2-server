package observability

import (
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
)

// Trace correlates valid W3C traceparent IDs with route-level request logs.
// It does not export spans or install a collector; no raw URL, header or token
// is included in telemetry. Invalid upstream trace context is ignored.
func Trace(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		if id := traceID(r.Header.Get("traceparent")); id != "" {
			route := r.Pattern
			if route == "" {
				route = "unmatched"
			}
			log.InfoContext(r.Context(), "http request trace", "trace_id", id, "route", route)
		}
	})
}
func traceID(value string) string {
	parts := strings.Split(value, "-")
	if len(parts) != 4 || parts[0] != "00" || len(parts[1]) != 32 || len(parts[2]) != 16 || len(parts[3]) != 2 {
		return ""
	}
	for _, part := range parts[1:] {
		raw, err := hex.DecodeString(part)
		if err != nil || hex.EncodeToString(raw) != part {
			return ""
		}
	}
	if parts[1] == strings.Repeat("0", 32) || parts[2] == strings.Repeat("0", 16) {
		return ""
	}
	return parts[1]
}
