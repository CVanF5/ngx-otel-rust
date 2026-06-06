# demo — Grafana visualisation stack for ngx-otel-rust

A self-contained **OTel Collector → Prometheus + Loki → Grafana** stack that
visualises everything the `ngx-otel-rust` module emits today: **metrics**
(incl. native-histogram latency + **exemplars**) and **logs** (access exception
tail + coalesced error log). A **Tempo** (traces) path is pre-wired but dormant
for Phase 3.

```
                                   --remote-write-->  Prometheus :19090 --\
 nginx + module (host) --OTLP/gRPC--> collector :14317                     >-- Grafana :3000
        :9400                              \--OTLP/HTTP-->  Loki :13100 ---/
```

Metrics go to Prometheus via **remote-write** (not scrape — see below), logs to
**Loki** via native OTLP ingest. The demo ships **OTLP/gRPC**
(`otel_export_protocol otlp_grpc;`) to the collector's gRPC receiver at host
port **14317**.

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
`/big`, `/api/` (proxied upstream), `/client-error` (4xx), `/server-error`
(5xx), and `/backend-down` (dead upstream → real `connect() failed` error-log
lines). **Each request carries a unique W3C `traceparent`** so a `trace_id`
flows to both the latency-histogram exemplar and the access tail log — that's
the join key behind the exemplar drill-down. Allow ~10 s for the 2 s export
interval to fill the dashboard.

| Service | URL |
|---|---|
| Grafana | http://localhost:3000 |
| Prometheus | http://localhost:19090 |
| Loki | http://localhost:13100 |
| Collector OTLP/gRPC (nginx target) | http://127.0.0.1:14317 |
| nginx front server | http://127.0.0.1:9400/ (also `/big`, `/api/`, `/client-error`, `/server-error`, `/backend-down`) |

## Dashboard layout

One dashboard, four collapsible rows:

* **Default NGINX (stub_status)** — what vanilla nginx exposes: request rate,
  total requests, active connections + connection state (the baseline).
* **Enhanced — Traffic & Latency** — status/method breakdowns, the native-
  histogram latency panel **with exemplars**, duration heatmap, slowest routes,
  per-upstream timing, body/upstream throughput.
* **Enhanced — Logs (Loki)** — the **Exemplar → Request Log** panel (see below),
  coalesced error log (`×N` = events collapsed), interesting (4xx/5xx) and
  sampled access logs, log rate.
* **Exporter Health** — export interval, send failures, dropped records.

## Exemplars: the metric → log drill-down

The request-duration histogram carries **exemplars** (Phase 2.2.4): each is one
sampled real request, tagged with its `trace_id`, `url.path`, and value. The
access tail **LogRecord** carries the **same `trace_id`**. So a point on the
latency graph and a log line are two views of one request, joined by `trace_id`.

To see it on the **"Request Latency by Status … ⬦ exemplars"** panel:

1. **Hover** an exemplar diamond (⬦) — its y-position is the request's latency
   (its histogram bucket); the tooltip shows `trace_id`, `url.path`, and value.
2. **Click "Show this request's log ↓"** — this sets the dashboard's `trace_id`
   variable, and the **"Exemplar → Request Log"** Loki panel (top of the Logs
   row) filters to that exact request's tail log.
3. *Bulletproof alternative:* read the `trace_id` from the tooltip and paste it
   into the **Trace ID (exemplar)** textbox at the top of the dashboard.

This works because exemplars and the access tail share `trace_id`. The link
drives an **on-dashboard variable** rather than a datasource link, because
Grafana's exemplar→datasource links only do trace-lookup for *trace*
datasources (Tempo); Loki isn't one, so the variable approach keeps the whole
flow on a single screen (and is what Phase 3 / Tempo will complement, not
replace).

## How the metrics reach Prometheus (remote-write + native histograms)

Metrics are **pushed** to Prometheus via the collector's
`prometheusremotewrite` exporter, **not scraped**. This is required because the
latency family (`http.server.request.duration{,.by_route,.by_upstream}`) are
**exponential histograms** (µs): the classic scrape exporter collapses an
exp-histogram to a single `le="+Inf"` bucket and **drops its exemplars**.
Remote-write carries exp-histograms as Prometheus **native histograms** and
ships their exemplars. Prometheus runs with
`--web.enable-remote-write-receiver --enable-feature=native-histograms,exemplar-storage`.

`add_metric_suffixes: false` keeps names a predictable dotted→underscore
transform; `resource_to_telemetry_conversion` promotes `service.name` →
`service_name`.

| Module (OTLP) | Instrument | Query in Prometheus |
|---|---|---|
| `http.server.request.duration` (+`.by_route`, `.by_upstream`) | exp-histogram → **native histogram** | `histogram_quantile(…, sum(rate(http_server_request_duration[…])))`, `histogram_count(…)`, `histogram_sum(…)` — **on the base name, no `_bucket`** |
| `http.server.{request,response}.body.size`, `http.server.upstream.*` | explicit histogram | classic `_bucket`/`_sum`/`_count` |
| `nginx.requests.total`, `nginx.connections.{accepted,handled}` | counter (single-bucket histogram) | `nginx_requests_total_sum`, `nginx_connections_{accepted,handled}_sum` (cumulative; use `rate()`) |
| `nginx.connections.{active,reading,writing,waiting}` | **Gauge** | `nginx_connections_{active,…}` (**no `_sum`** — real gauge) |

> Note on units: the duration metrics are in **microseconds (µs)** — panels are
> set accordingly. (An earlier beautify mislabeled them `ms`; fixed.)

## Logs (live) and traces (future)

* **Logs → Loki — on by default.** Loki 3.x ingests **OTLP logs natively** at
  `/otlp/v1/logs` (no Promtail). The collector's `otlphttp/loki` exporter ships
  straight there; the Loki datasource is provisioned. OTLP attributes land as
  Loki **structured metadata** (filter with a pipeline stage `| field="…"`, not
  in the `{}` stream selector — only `service_name` is a stream label). The
  module emits two log signals: the **access exception tail** (4xx/5xx +
  latency outliers + sampled, carrying `trace_id`/`url.path`) and the
  **coalesced error log** (`nginx.error`, deduped per drain window with a
  `coalesced_count` the dashboard renders as `×N`).
* **Traces → Tempo — Phase 3.** Same pattern: `--profile traces`, uncomment the
  `otlp/tempo` exporter + `traces:` pipeline. Tempo datasource is provisioned.

## Findings — module issues this demo surfaced (all fixed)

This stack has repeatedly exposed metric/log modelling issues that pass the
file-exporter test harness but break against a real backend ("reasoned ≠
verified"). All fixed on `main`:

1. **Temporality** (`3ea552e`) — `http.*` were cumulative but tagged DELTA with
   `StartTimestamp=0`, causing ~100× inflation / frozen accumulation. Now
   CUMULATIVE with a fixed start anchored to exporter start.
2. **Duration overflow** (`9e2138e`) — request duration mixed two clocks and
   pinned p99 at the +Inf bucket. Now uses the `$request_time` idiom via
   `ngx_timeofday()`.
3. **Error-log timestamps** (`8ee5c5b`) — error LogRecords were stamped with
   the **monotonic** `ngx_current_msec`, so Loki read them as 1970 and **400'd
   the whole batch** (silently dropping co-batched access logs too). Now uses
   the cached **wall-clock** `ngx_cached_time`.
4. **stub_status gauges as fake histograms** (`32b3425`) — `gauge_metric()`
   emitted `count=1` single-bucket histograms for the connection gauges, which
   Prometheus remote-write drops (non-monotonic). Now real OTLP **Gauge**s, so
   the Default-NGINX connection panels render under remote-write.

## Notes

* Grafana runs with anonymous Admin and no login form — **demo only**.
* Collector/Prometheus/Grafana/Loki images match the test harness
  (`otel/opentelemetry-collector-contrib:0.152.0`, etc.).
* Prometheus logs benign "out-of-order exemplars" warnings — the per-worker
  exemplar reservoir re-sends across intervals; fresh exemplars still store.
* `run-demo.sh` backgrounds host nginx; if you restart nginx by hand, use
  `nohup` so it survives the shell exiting.
