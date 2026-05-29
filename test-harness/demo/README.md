# demo — Grafana visualisation stack for ngx-otel-rust

A self-contained **OTel Collector → Prometheus → Grafana** stack that
visualises the metrics produced by the `ngx-otel-rust` module, plus
pre-wired (but dormant) **Loki** (logs) and **Tempo** (traces) paths for
Phase 2 and beyond.

```
 nginx + module (host)  --OTLP/gRPC-->  collector  --/metrics scrape-->  Prometheus  -->  Grafana
        :9400                            :14317                            :19090            :3000
```

The demo ships **OTLP/gRPC** (`otel_metric_protocol otlp_grpc;`) to the
collector's gRPC receiver at host port **14317**.  (The previous OTLP/HTTP
path on `:14318` is still available but no longer used by the demo.)

Everything binds `127.0.0.1` only and uses **offset ports** so it never
collides with the test-harness collector (`4317/4318`).

## Quick start

```sh
cd test-harness/demo
./run-demo.sh up        # build module if needed + start stack + nginx + traffic
# open http://localhost:3000  (anonymous; lands on the dashboard)
./run-demo.sh status
./run-demo.sh down      # stop everything (traffic, nginx, containers)
```

`run-demo.sh up` starts a light background traffic generator hitting `/`,
`/big`, and `/api/` (proxied to a local upstream) so every metric
populates. Allow ~10 s for the 2 s export interval + 5 s scrape to fill
the dashboard.

| Service | URL |
|---|---|
| Grafana | http://localhost:3000 |
| Prometheus | http://localhost:19090 |
| Collector Prometheus endpoint | http://localhost:18889/metrics |
| Collector OTLP/gRPC (nginx target) | http://127.0.0.1:14317 |
| Collector OTLP/HTTP (still available) | http://127.0.0.1:14318 |
| nginx front server | http://127.0.0.1:9400/ (also `/big`, `/api/`) |

## Files

| File | Purpose |
|---|---|
| `docker-compose.demo.yml` | collector + prometheus + grafana; loki/tempo behind profiles |
| `otel-collector-demo.yaml` | collector config: OTLP in, Prometheus exporter out (+ commented logs/traces) |
| `prometheus/prometheus.yml` | scrapes `collector:8889` |
| `grafana/provisioning/` | datasources (Prometheus default; Loki/Tempo ready) + dashboard provider |
| `grafana/dashboards/ngx-otel-rust-overview.json` | the dashboard |
| `nginx-demo.conf.template` | demo nginx config (front + proxied upstream) |
| `run-demo.sh` | one-command up/down/status |

## How the metrics map to Prometheus

The module emits **every** metric as an OTLP **Histogram** (the
stub_status counters/gauges are single-bucket histograms). The collector's
Prometheus exporter is configured with `add_metric_suffixes: false`, so
names are a predictable dotted→underscore transform with the standard
histogram series:

| Module (OTLP) | Prometheus series |
|---|---|
| `nginx.requests.total` | `nginx_requests_total_sum` (cumulative req count) |
| `nginx.connections.active` (+reading/writing/waiting) | `nginx_connections_*_sum` (gauge) |
| `nginx.connections.accepted` / `.handled` | `nginx_connections_{accepted,handled}_sum` |
| `http.server.request.duration` | `http_server_request_duration_{bucket,sum,count}` |
| `http.server.{request,response}.body.size` | `http_server_*_body_size_{bucket,sum,count}` |
| `http.server.upstream.*` | `http_server_upstream_*_{bucket,sum,count}` |

`resource_to_telemetry_conversion` promotes `service.name` →
`service_name` label.

## Findings — two module issues this demo surfaced (both fixed)

This stack originally uncovered two pre-existing issues in the module's
metric output. Both have been fixed in `ngx-otel-rust` main; the demo
no longer needs any collector-side workarounds.

1. **Instrumented `http.*` metrics were cumulative but tagged DELTA.**
   Their `Count`/`Sum` grew monotonically but carried
   `AggregationTemporality = DELTA` and a zero `StartTimestamp`. Effects:
   * `deltatocumulative` re-added the running total each export → ~100×
     inflation;
   * the Prometheus exporter's own delta accumulation **froze** after the
     first window (all points shared `StartTimestamp=0`).
   **Fixed in commit `3ea552e`** (`metrics_fix(temporality)`): the module
   now emits `AggregationTemporality = CUMULATIVE` with a fixed
   `start_time_unix_nano` anchored to the exporter start. The collector-
   side `transform/fix_temporality` workaround has been removed from
   `otel-collector-demo.yaml`.

2. **`http.server.request.duration` previously overflowed to `+Inf`.**
   Each request recorded ~2.6e8 ms against millisecond bounds (max 10000),
   so every observation landed in the overflow bucket and p99 pinned at
   10000 ms. Root cause: `ngx_current_msec` (monotonic timer since nginx
   start) was subtracted from `r->start_msec` (millisecond fraction
   0–999) — two incompatible clocks. Duration panels were intentionally
   omitted until this was resolved.
   **Fixed in commit `9e2138e`** (`metrics_fix(duration)`): the module now
   uses the nginx `$request_time` idiom:
   `(tp->sec - r->start_sec)*1000 + (tp->msec - r->start_msec)` via
   `ngx_timeofday()`. Duration panels are back; p99 returns a real
   sub-second value.

## Future: logs (Phase 2) and traces

The module does not emit logs or traces yet (logs are Phase 2). The
plumbing is pre-wired so it's a config flip when they land:

* **Logs → Loki (recommended).** Grafana has no native "OTLP logs"
  datasource — it needs a log store. The lightest demo-grade option is
  **Loki 3.x**, which ingests **OTLP logs natively** at `/otlp/v1/logs`
  (no Promtail, no format translation). The collector's `otlphttp/loki`
  exporter ships straight to it; the **Loki datasource is already
  provisioned**. Enable with:

  ```sh
  docker compose -f docker-compose.demo.yml --profile logs up -d
  ```
  then uncomment the `otlphttp/loki` exporter + `logs:` pipeline in
  `otel-collector-demo.yaml`.

  *Alternatives if Loki isn't desired:* ClickHouse (`clickhouse`
  exporter + Grafana ClickHouse plugin) or Elasticsearch/OpenSearch.
  All require a store behind Grafana — none let Grafana read OTLP logs
  directly.

* **Traces → Tempo.** Same pattern: `--profile traces`, uncomment the
  `otlp/tempo` exporter + `traces:` pipeline. Tempo datasource is
  provisioned.

## Notes

* Grafana runs with anonymous Admin and no login form — **demo only**.
* The collector image/tag matches the test harness
  (`otel/opentelemetry-collector-contrib:0.152.0`).
* Don't run the test harness and this demo at the same time if you change
  the demo to use ports `4317/4318`; the offset ports avoid that by default.
