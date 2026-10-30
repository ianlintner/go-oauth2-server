// Package observability supplies bounded HTTP metrics without an external stack.
package observability

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics owns an independent registry so server instances do not share state.
type Metrics struct {
	registry *prometheus.Registry
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
}

func New() *Metrics {
	m := &Metrics{registry: prometheus.NewRegistry(),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "oauth2_server", Name: "http_requests_total", Help: "HTTP requests by bounded route and status class."}, []string{"method", "route", "status_class"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{Namespace: "oauth2_server", Name: "http_request_duration_seconds", Help: "HTTP request duration by bounded route and status class.", Buckets: prometheus.DefBuckets}, []string{"method", "route", "status_class"}),
	}
	m.registry.MustRegister(m.requests, m.duration)
	return m
}
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
		w.ResponseWriter.WriteHeader(code)
	}
}
func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Wrap uses ServeMux's matched pattern, never the request URL, as a label.
// Scrapes are excluded so polling frequency cannot dominate service telemetry.
func (m *Metrics) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		if sw.status == 0 {
			sw.status = http.StatusOK
		}
		route := r.Pattern
		if route == "" {
			route = "unmatched"
		}
		method := r.Method
		if method != http.MethodGet && method != http.MethodPost {
			method = "other"
		}
		statusClass := string('0'+rune(sw.status/100)) + "xx"
		labels := []string{method, route, statusClass}
		m.requests.WithLabelValues(labels...).Inc()
		m.duration.WithLabelValues(labels...).Observe(time.Since(start).Seconds())
	})
}
