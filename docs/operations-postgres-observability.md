# PostgreSQL and HTTP telemetry (v0.6 operations slice)

`OAUTH2_STORAGE_DSN` accepts a `postgres://` or `postgresql://` URL for pgx/v5 storage. Other values remain SQLite paths or `:memory:`. The PostgreSQL adapter owns a bounded connection pool and applies an embedded SQL schema under a transaction-scoped advisory lock; it refuses an unknown schema version or changed migration checksum. Set up and back up the database outside this process. Do not put a password in logs, source control, or CI fixtures. The CI PostgreSQL service is ephemeral test infrastructure, not a production deployment. `OAUTH2_CONFORMANCE_MODE=1` continues to require `:memory:` to prevent seed credentials reaching durable storage.

`OAUTH2_METRICS_ENABLED=true` opts in to Prometheus text at `GET /metrics` on the **same configured listener**. It is off by default; only enable it behind network access controls if the public OAuth listener is reachable. Metrics cover HTTP request count and latency by bounded method, ServeMux route pattern and status class. Raw paths, query strings, client IDs, tokens and credentials are never metric labels. `/metrics` scrapes are excluded from counting. The app also logs a validated W3C `traceparent` trace ID with the route pattern when present; malformed IDs are ignored, and raw URLs/headers are not logged by this middleware.

This is **not** full parity with the Rust observability crate: no OpenTelemetry span exporter, DB query instrumentation, domain-specific issuance/denial counters, dashboards, collector, or tracing backend are shipped. Those would need an explicit use case and privacy review, not an implied deployment. The shared contract pin currently has no stable `operations` profile, so this slice does not claim that profile or spec compliance. PostgreSQL runs the existing shared storage contract suite locally and in CI; the pinned black-box conformance runner exercises the existing claimed HTTP profiles with SQLite's isolated conformance seed.

Local disposable database test:

```sh
OAUTH2_POSTGRES_TEST_DSN='postgres://test-user@127.0.0.1:5432/disposable?sslmode=disable' go test -race ./internal/storage/postgres ./internal/app
```

The test role needs `CREATE SCHEMA` and drops only the schemas it creates. Never point the test DSN at a production database.
