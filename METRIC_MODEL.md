# ngx-otel-rust — Metric Model

This document defines the metrics the module emits, in the style of the
[OpenTelemetry Semantic Conventions for metrics][semconv]. It is the
producer-side contract: metric names, instruments, units, temporality, and
the attribute set the OTAP collector dictionary-encodes downstream
(proposal §6.4, "Producer-side cardinality discipline").

> **Currency.** Reflects the shipped module through **Phase 2.3** (error-log
> §6.6.2, June 2026): the request-duration histogram is an OTel
> **exponential histogram in microseconds**, the `fix3b` dimensions are **live**,
> per-route / per-upstream series were added, the temporality mislabel is
> **fixed (Cumulative)**, and the Phase 2.3 companion error-rate metric
> (`ngx_otel.error_log.events`) is now **implemented** (Step 2.3.4 — pointer
> wired to init_process in Step 2.3.5).

## Provenance — read this first

The metric **model** (which signals to collect from each request, and how
to derive them) was ported from the F5 **AVR nginx module**
(`avr-module/`, sibling repo). The metric **names and units** follow the
OpenTelemetry HTTP semantic conventions. Keep both lineages intact:

- **Signals / derivation → `avr-module/`.** When adding or changing a
  metric, the avr source is the precedent — read it, don't guess. The
  per-request data model is `avr-module/src/ngx_http_avr_data_sources.h:69-92`
  (`ngx_avr_data_t`); the duration idiom is
  `avr-module/src/ngx_http_avr_data_sources.c:10-13` (`get_request_time`);
  the aggregation + dimension model is
  `avr-module/src/ngx_http_avr_output.c:111-177` (time-slice buckets,
  per-request `hitcount`, dictionary-encoded entity IDs).
- **Names / units → OTel semconv.** So the OTAP collector-side classifier
  recognises them and the cardinality stays bounded.

> The duration defect fixed in the metrics-correctness loop was a *drift*
> from the avr model: `LogPhaseHandler` reimplemented request duration as
> `ngx_current_msec - r->start_msec` instead of avr's `get_request_time`.
> This doc exists so that lineage is not lost again.

## Resource and scope

| Field | Value | Source |
|---|---|---|
| Resource `service.name` | from `otel_service_name` directive | `src/config.rs` |
| Resource `service.instance.id` | master pid by default (operator-overridable) | `src/export/mod.rs` |
| Resource (extra) | from `otel_resource_attr` k/v pairs | `src/export/mod.rs` |
| Instrumentation scope name | `ngx-otel-rust` | `src/export/mod.rs` |
| Instrumentation scope version | crate version (`CARGO_PKG_VERSION`) | `src/export/mod.rs` |

## Aggregation temporality

All instrumented `http.*` metrics are aggregated per-worker in shared memory
as cumulative running totals (workers bump; the exporter snapshots without
resetting) and are emitted **Cumulative** with a fixed
`start_time_unix_nano`, matching the `nginx.*` counters.

> **Resolved (metrics-correctness loop).** An earlier build emitted `Delta`
> temporality with a zero `StartTimestamp` while carrying cumulative values —
> a mislabel. Fixed: every `http.*` data point now sets
> `aggregation_temporality = Cumulative` (`src/encoder/mod.rs`,
> `src/metric_source/instrumented.rs`).

---

## HTTP server request duration (exponential histogram, µs)

Derived per request in `LogPhaseHandler`
(`src/metric_source/instrumented.rs`). Phase 2.2 (DP-F) switched the request
duration from an explicit-bucket `ms` histogram to an **OTel exponential
histogram recorded in microseconds**, for native sub-millisecond quantiles
in the ~90–200µs operating regime. Source values come from avr's
`get_request_time` idiom (`data_sources.c:10-13`), now in µs.

The duration is emitted as **three decomposed series** (not a cross-product —
proposal §6.6.1): a base series carrying the bounded `{method × status-class ×
protocol}` dimensions, plus independent per-route and per-upstream series.
Each is its own `ExpHistogramSlot` table in `WorkerSlots` (`src/shm.rs`).

| Metric | Instrument | Unit | Temporality | Attributes (data-point keys) |
|---|---|---|---|---|
| `http.server.request.duration` | ExponentialHistogram | `us` | Cumulative | `http.request.method`, `http.response.status_code`, `network.protocol.version` — **only when `otel_metric_status_code_class on`**; otherwise a single unattributed data point |
| `http.server.request.duration.by_route` | ExponentialHistogram | `us` | Cumulative | `http.route` (matched `location` name) |
| `http.server.request.duration.by_upstream` | ExponentialHistogram | `us` | Cumulative | `nginx.upstream.zone` (declared upstream `zone`) |

- The base series emits up to **160** data points (`N_HTTP_METHODS(8) ×
  N_STATUS_CLASSES(5) × N_PROTO_VERSIONS(4)`); empty combos are skipped.
  `http.response.status_code` carries the **status-class representative**
  (100/200/300/400/500), not the raw code — class bucketing keeps the column
  WithinU8 (proposal §6.4).
- `by_route` / `by_upstream` are **always** emitted (independent of
  `otel_metric_status_code_class`). Route names are the matched `location`
  name (never the raw URI), bounded `ROUTE_CAP = 64` + an `"other"` slot;
  upstream zones are bounded `UPSTREAM_CAP = 32` + `"other"` / no-upstream.
- **Exemplars:** the base series attaches reservoir-sampled exemplars
  (value + `trace_id`/`span_id` + `filtered_attributes`) per combo, populated
  from the access-log sampling path (`otel_access_log_sample`).

### Exponential histogram parameters (`src/shm.rs`)

- **Scale:** `EXP_HISTOGRAM_SCALE = 3` → base = 2^(2^-3) ≈ 1.091 (8 buckets
  per power-of-two µs). 90µs / 150µs / 200µs land in distinct buckets.
- **Buckets:** `N_EXP_BUCKETS = 192`, `positive_offset = 0`, covering
  ≈ [1µs, 2^24µs ≈ 16.7s); values above clamp to the last bucket; 0µs →
  `zero_count`.

---

## HTTP server size + upstream metrics (explicit-bucket histograms)

These were **not** changed by Phase 2.2 — they remain explicit-bucket
`Histogram<N>` (`src/shm.rs`), single unattributed data point each (no
method/route/zone decomposition). Recorded in `LogPhaseHandler`; upstream
metrics only when an upstream was used (from `ngx_http_upstream_state_t`).

| Metric | Instrument | Unit | Temporality | avr-module source |
|---|---|---|---|---|
| `http.server.request.body.size` | Histogram (explicit) | `By` | Cumulative | `bytes_in` (`data_sources.h:78`) |
| `http.server.response.body.size` | Histogram (explicit) | `By` | Cumulative | `bytes_out` (`data_sources.h:79`) |
| `http.server.upstream.response.duration` | Histogram (explicit) | `ms` | Cumulative | `uppstream_response_time` (`data_sources.h:88`) |
| `http.server.upstream.header.duration` | Histogram (explicit) | `ms` | Cumulative | `uppstream_header_time` (`data_sources.h:86`) |
| `http.server.upstream.connect.duration` | Histogram (explicit) | `ms` | Cumulative | `uppstream_connect_time` (`data_sources.h:87`) |
| `http.server.upstream.bytes.received` | Histogram (explicit) | `By` | Cumulative | `uppstream_bytes_received` (`data_sources.h:83`) |
| `http.server.upstream.bytes.sent` | Histogram (explicit) | `By` | Cumulative | `uppstream_bytes_sent` (`data_sources.h:84`) |

## NGINX connection / request metrics

Read from nginx's `stub_status` globals each export interval
(`src/metric_source/stub_status.rs`). Emitted as single-bucket histograms
today; semantically counters (monotonic Sum) and gauges.

| Name | Instrument | Unit (UCUM) | Temporality | Stability |
|---|---|---|---|---|
| `nginx.requests.total` | Counter (Sum, monotonic) | `{request}` | Cumulative | experimental |
| `nginx.connections.accepted` | Counter (Sum, monotonic) | `{connection}` | Cumulative | experimental |
| `nginx.connections.handled` | Counter (Sum, monotonic) | `{connection}` | Cumulative | experimental |
| `nginx.connections.active` | Gauge | `{connection}` | — | experimental |
| `nginx.connections.reading` | Gauge | `{connection}` | — | experimental |
| `nginx.connections.writing` | Gauge | `{connection}` | — | experimental |
| `nginx.connections.waiting` | Gauge | `{connection}` | — | experimental |

These are not part of the avr model; they come from nginx core
`stub_status` and are already temporality-correct.

---

## Attributes (implemented — `fix3b` shipped, Phase 2.1; route/zone, Phase 2.2)

The duration series attach the bounded, semconv-aligned dimensions below.
All are **WithinU8 cardinality** so the OTAP collector-side classifier can
dictionary-encode each per-point column at u8 key width (proposal §6.4). The
closed-cardinality enums live in `src/shm.rs` (`HttpMethod`, `StatusClass`,
`ProtoVersion`).

| Attribute | On series | Cardinality | avr-module source |
|---|---|---|---|
| `http.request.method` | base duration | 8 (`HttpMethod`, 7 + `_OTHER`) | `method` → `avr_lookup_or_insert_method` (`output.c:144-148`) |
| `http.response.status_code` | base duration | 5 status classes (representative value) | `rcode`/`status` (`output.c:129-131`) |
| `network.protocol.version` | base duration | 4 (`ProtoVersion`) | `http_version` (`output.c:132-134`) |
| `http.route` | `…by_route` | ≤ 64 + `other` (location name) | matched `location` name (cf. C++ module `clcf->name`) |
| `nginx.upstream.zone` | `…by_upstream` | ≤ 32 + `other`/none | declared upstream `zone` (NGINX Plus model) |

> **High-cardinality detail is NOT a metric dimension.** `url.path`,
> `user_agent.original`, and `client.address` were considered (avr keys on
> them) but are deliberately kept **off** the metrics. As of Phase 2.2 they
> ride on **access-log exemplars + the exception tail** (proposal §6.6.1),
> reachable via the exemplar → trace drill-down, never as histogram
> attributes (that would break the WithinU8 budget).

## Histogram bucket boundaries (`src/shm.rs`)

- **Request duration** — exponential (see parameters above): scale 3, µs,
  192 buckets, offset 0. **Not** the explicit `ms` boundaries below.
- **Upstream durations (`ms`)** — explicit, `DURATION_BOUNDS_MS`, 14 + overflow:
  `5, 10, 25, 50, 75, 100, 250, 500, 750, 1000, 2500, 5000, 7500, 10000`
- **Byte sizes (`By`)** — explicit, `BYTES_BOUNDS`, 6 + overflow:
  `128, 512, 4096, 65536, 524288, 4194304`

---

## Phase 2.3 error-rate metric (`ngx_otel.error_log.events`) — **implemented**

The companion error-rate metric emitted alongside the coalesced error `LogRecord`s.
Implemented in Step 2.3.4; wire to init_process in Step 2.3.5 (pointer set null until then).

| Metric | Instrument | Unit | Temporality | Attributes |
|---|---|---|---|---|
| `ngx_otel.error_log.events` | Counter (Sum, monotonic) | `{error}` | Cumulative | `severity_class` only |

Severity classes (5 values, WithinU8 cardinality):

| `severity_class` | nginx levels | level names |
|---|---|---|
| `"fatal"` | 1–3 | emerg, alert, crit |
| `"error"` | 4 | error |
| `"warn"` | 5 | warn |
| `"info"` | 6–7 | notice, info |
| `"debug"` | 8 | debug |

> **Scope boundary (decided 2026-06-05 — DP-B).** The error metric is keyed on
> `severity_class` **only** — no `http.route` / `nginx.upstream.zone` and no
> `trace_id`. The `ngx_log_writer_pt` seam hands the writer its own log node,
> not the connection's `c->log`, so the request context is structurally
> unreachable on the error path (the access path is unaffected). "Which
> upstream/route" remains readable in the error sample's **body text**.
> Per-template counts ride on the `LogRecord`'s `nginx.error.coalesced_count`
> attribute, never on the metric.

## avr-module signals not yet ported

Present in the avr model but not currently emitted by ngx-otel-rust —
candidates for future metrics, listed so they aren't forgotten:

| avr field | Note |
|---|---|
| `client_rtt` / `clientside_network_latency` | client-side RTT (TCP info) |
| `client_ttfb` | composite client time-to-first-byte (`output.c:126`) |
| `serverside_network_latency` | from `uppstream_connect_time` (`output.c:123`) |
| `uppstream_status` | upstream response status code |
| `uppstream_response_length` | upstream response content length |
| `uppstream_addr` | upstream peer address (high-card; sample/exemplar only) |
| `is_ssl` | TLS yes/no (dimension) |

## References

- [OpenTelemetry Semantic Conventions — HTTP metrics][semconv]
- Reference model: `avr-module/src/ngx_http_avr_data_sources.{h,c}`,
  `ngx_http_avr_output.c`
- Producer-side cardinality discipline: proposal §6.4; logs-as-summary §6.6
- Shared-memory layout + histograms: `src/shm.rs`
- Emission + attributes: `src/metric_source/instrumented.rs`, `src/encoder/mod.rs`

[semconv]: https://opentelemetry.io/docs/specs/semconv/http/http-metrics/
