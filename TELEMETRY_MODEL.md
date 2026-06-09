# ngx-otel-rust — Telemetry Model

This document is the **producer-side contract for everything the module emits** —
metrics, logs, and (Phase 3) traces — in the style of the
[OpenTelemetry Semantic Conventions][semconv]: signal names, instruments/record
shapes, units, temporality, and the bounded attribute set the OTAP collector
dictionary-encodes downstream (proposal §6.4, "Producer-side cardinality
discipline"). **If you are building a dashboard, alert, or pipeline against this
module and do not have the proposal, this file is the source of truth** — the repo
is meant to be self-describing for *what it emits*; the proposal covers *why*.

## Signals at a glance

| Signal | Status | Enabled by | Where |
|---|---|---|---|
| **Metrics** | shipped (1.1–2.2) | on by default (`otel_metrics`) | [Metrics](#metrics) |
| **Logs — access (tail + exemplars)** | shipped (2.1–2.2) | `otel_access_log_sample <n>` | [Logs](#logs) |
| **Logs — error (coalesced + rate metric)** | shipped (2.3) | `otel_error_log [level]` | [Logs](#logs) |
| **Traces** | shipped (Phase 3) | `otel_trace <expr>` per location | [Traces](#traces-phase-3) |

**Conventions shared by all signals:** the [Resource and scope](#resource-and-scope)
below applies to every signal; all attributes are drawn from OTel semconv and kept
**WithinU8 cardinality** (§6.4) so the collector dictionary-encodes per-point columns
at u8 key width; high-cardinality detail (`url.path`, `client.address`,
`user_agent.original`, upstream peer addr) never becomes a metric dimension — it rides
on exemplars, the access tail, or error-record bodies. Transport is OTLP (HTTP or
gRPC, `otel_export_protocol`) from the dedicated `nginx: otel exporter` process.

## Metrics

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
- **Boundary convention (note):** our bucket index uses a lower-inclusive
  boundary `[base^k, base^(k+1))`, whereas the OTel exp-histogram spec defines
  bucket `k` as the upper-inclusive `(base^k, base^(k+1)]`. The two differ for
  exactly one input: a value landing *precisely* on a boundary `base^k` (e.g.
  2µs, 4µs) is counted in bucket `k` here vs `k-1` per spec — an off-by-one of
  a single bucket only at exact powers. For general integer-µs latencies the
  bucketing is identical, so the practical effect is negligible. We keep the
  lower-inclusive form deliberately: it is what the verified low-end bucketing
  fix (left-shift mantissa for `n < scale`) is built around, and changing the
  boundary side risks reintroducing that bug. Documented, not "fixed."

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
(`src/metric_source/stub_status.rs`). The connection **gauges**
(active/reading/writing/waiting) are emitted as real OTLP **Gauge** metrics;
the **counters** (accepted/handled/requests) are still single-bucket
cumulative histograms today (semantically a monotonic Sum). Modelling a gauge
as a `count=1` histogram is dropped by Prometheus remote-write, so the gauges
were corrected to true Gauges (the counters round-trip fine as-is).

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

---

## Logs

OTel logs are **orthogonal to nginx's own `access_log`/`error_log`** (the module emits
via its own directives; core file logging is untouched and remains the on-box
transcript). The OTel stream carries "summary + samples", not a per-request firehose
(proposal §6.6).

### Access log — exemplars + thin exception tail (§6.6.1)

The bulk of access information is the **metrics** above. Per-event access output is
**gated by `otel_access_log_sample <reservoir-size>`** (absent ⇒ off) and is two
things, never a per-request log:

- **Exemplars** on the `http.server.request.duration` base series: reservoir-sampled
  representative requests, each carrying the measured value + `trace_id`/`span_id`
  (from the inbound W3C `traceparent`, when present) + `filtered_attributes` (the
  high-cardinality detail `url.path`, `client.address`, `user_agent.original`). This is
  the metric → exemplar → trace drill-down pivot. (`src/metric_source/instrumented.rs`,
  encoder `Exemplar`.)
- **Exception-tail `LogRecord`s**: emitted ONLY for "interesting" requests (status
  ≥ 4xx, latency outliers — an is-interesting gate), carrying the same high-cardinality
  attributes + `trace_id`/`span_id` + request duration. Substrate is the per-worker SPSC ring.
  (`src/logs/access.rs`, `src/logs/ring.rs`.)

  | Attribute key | Type | Value |
  |---|---|---|
  | `http.request.method` | string | HTTP method (e.g. `GET`) |
  | `http.response.status_code` | int | HTTP status code |
  | `http.server.request.body.size` | int | bytes |
  | `http.server.response.body.size` | int | bytes |
  | `client.address` | string | client IP / address text |
  | `url.path` | string | request path (truncated to 64 bytes) |
  | `user_agent.original` | string | User-Agent value (truncated to 128 bytes) |
  | `http.server.request.duration` | double | request duration **in seconds** (OTel semconv unit; derived from µs measurement, sub-ms precision) |

A common (2xx, fast) request produces **neither** — only the histogram `fetch_add`.

> **Exemplars are best-effort hints, not an authoritative record.** Each exemplar
> slot is written lock-free from the worker hot path with no per-field commit
> barrier (the reader gates on an atomic count, but the string fields — `url.path`,
> `user_agent.original` — and the `trace_id` are filled with `Relaxed`/byte
> copies). Under concurrent overwrite a reader can observe a *torn* exemplar
> (e.g. a `url.path` spliced from two requests, or a `trace_id` paired with the
> wrong data point). This is an intentional hot-path trade-off: exemplars are
> sampling hints for drill-down, so a rare torn string is acceptable. Do not
> treat an individual exemplar's high-cardinality fields as ground truth; the
> aggregate histogram and the exception-tail `LogRecord`s are the authoritative
> surfaces.

### Error log — coalesced `LogRecord`s (§6.6.2)

Enabled by `otel_error_log [level]`. Logs-primary (the message body is the payload).
Floods of identical lines are collapsed at the producer.

| `LogRecord` field | Value |
|---|---|
| `severity_number` / `severity_text` | nginx level → OTel mapping (`src/logs/severity.rs`) |
| `event_name` | `nginx.error` |
| `body` | the verbatim nginx error line (already includes `, client:/request:/upstream:` context text) |
| attr `nginx.error.template_hash` | stable-core hash; joins a sample to its coalesced count group |
| attr `nginx.error.coalesced_count` | flood size for this template this interval (present when > 1) |

- **No** `http.route` / `nginx.upstream.zone` / `trace_id` / `span_id` — the
  `ngx_log_writer_pt` seam can't reach request context (see the error-rate metric
  scope-boundary note above). "Which upstream/route" is in the **body text**.
- **Volume controls:** a **severity floor** (fixed `NGX_LOG_ERR` default, decoupled
  from core `error_log`; override with the level arg); producer-side **exact-hash
  coalescing** on the extracted stable core (one verbatim sample per template per
  interval, plus always-verbatim high-severity crit/alert/emerg and never-before-seen
  templates); **`otel_error_log_coalesce off`** opts into best-effort verbatim
  streaming (lossy under load — see the directive doc).
- **Companion:** the `ngx_otel.error_log.events` rate metric (in [Metrics](#metrics)
  above) is the always-on summary. Master / config-load / shutdown / exporter-context
  errors fall through to nginx's own `error_log` (structural; not exported over OTel).
- Source: `src/logs/error_writer.rs`, `src/logs/coalesce.rs`, drain in `src/export/mod.rs`.

## Traces (Phase 3)

OTel **server spans** are emitted for requests where `otel_trace` is configured.
Source: `src/metric_source/span_start.rs` (REWRITE phase), `src/metric_source/instrumented.rs`
(LOG phase), `src/traces/mod.rs` (ring + drain), `src/transport/`.

### Enabling and controlling traces

All trace directives are valid in `http`, `server`, and `location` blocks; the inner
location wins on merge.

| Directive | Default | Purpose |
|---|---|---|
| `otel_trace <expr>` | absent (tracing disabled) | Enable tracing for this location. A complex value — use a literal `on`/`1`/`$var` or a `split_clients` variable for ratio sampling. Absent ⇒ zero-cost: the REWRITE handler does nothing. |
| `otel_trace_context ignore\|extract\|inject\|propagate` | `extract` | W3C `traceparent` propagation mode. `extract` = read inbound, don't write outbound. `inject` = write outbound (fresh trace), don't read. `propagate` = both. `ignore` = neither. |
| `otel_span_name <expr>` | `"METHOD location_name"` | Per-location span name override; evaluated as a complex value (supports nginx variables). |
| `otel_span_attr <key> <value>` | (none) | Add a custom attribute to every span emitted from this location. Repeatable. |

### nginx variables (registered in `preconfiguration`)

| Variable | Type | Value |
|---|---|---|
| `$otel_trace_id` | string (32-char hex) | trace ID from the current request's `SpanCtx`, or empty string when tracing is disabled. |
| `$otel_parent_sampled` | string `"1"` / `"0"` | `"1"` when the inbound `traceparent` has the sampled flag set; `"0"` otherwise (empty when no traceparent). |

### Span shape

One OTel **server span** per sampled request.

| Field | Value | Source |
|---|---|---|
| `name` | `"METHOD route_name"` or `otel_span_name` override | `src/traces/mod.rs` |
| `start_time_unix_nano` | wall-clock at REWRITE phase entry (vDSO `SystemTime::now()`) | `src/metric_source/span_start.rs` |
| `end_time_unix_nano` | wall-clock at LOG phase entry | `src/metric_source/instrumented.rs` |
| `trace_id` | extracted from inbound `traceparent` (propagate/extract), or freshly generated | `src/traces/ctx.rs` |
| `span_id` | freshly generated per request | `src/traces/ctx.rs` |
| `parent_span_id` | from inbound `traceparent` (when `extract` or `propagate`), else zero | `src/metric_source/span_start.rs` |
| `flags` | W3C trace flags byte (propagated from inbound header, or `0x01` for root spans) | `src/metric_source/span_start.rs` |
| `kind` | `SERVER` | `src/traces/mod.rs` |
| `status` | `OK` (2xx) or `ERROR` (≥ 4xx) | `src/metric_source/instrumented.rs` |

### Span attributes

Standard OTel HTTP semconv attributes recorded on every span:

| Attribute | Value | Source |
|---|---|---|
| `http.request.method` | HTTP method string | `r->method_name` |
| `url.path` | request URI path (≤ `MAX_SPAN_URL_PATH` bytes) | `r->unparsed_uri` |
| `http.response.status_code` | raw status code | `r->headers_out.status` |
| `http.server.request.duration` | request duration **in seconds** (derived from µs measurement; same field, same unit as the access-tail LogRecord — enables coherent metric→exemplar→log→trace drill-down) | `src/traces/mod.rs` |
| `http.route` | matched location name | `clcf->name` via `route_from_location` |
| `network.protocol.version` | `"1.0"` / `"1.1"` / `"2.0"` / `"3.0"` | `r->http_version` |
| `user_agent.original` | User-Agent header value (≤ `MAX_SPAN_USER_AGENT` bytes) | `headers_in.user_agent` |
| Custom attrs | from `otel_span_attr` directives | `src/metric_source/location_conf.rs` |

### Sampling

**Worker-side only; no tail sampling.**

- **Parent-based:** when an inbound `traceparent` header is present (and `trace_context`
  is `extract` or `propagate`), the W3C `sampled` flag (`flags & 0x01`) is honoured.
  Sampled → emit span record. Unsampled → allocate `SpanCtx` (for `traceparent` propagation,
  if `inject`/`propagate`) but **no span record, no ring push**.
- **Ratio / head-sampling:** when no inbound `traceparent` is present, the `otel_trace`
  complex value is re-read at decision time. A `split_clients`-managed variable (e.g.
  `$otel_trace_sample`) returning `"1"` → sampled; `"0"` / `"off"` → unsampled.
  Currently defaults to `sampled=true` for any truthy value.
- **Probe / health-check drop:** a configurable `probe_drop` pipeline `Processor`
  (`src/processor/mod.rs`) drops spans whose `url.path` matches the configured set
  (defaults: `/healthz`, `/readyz`, `/livez`, `/ping`, `/metrics`). Configured via the
  exporter `processor` block (independent of sampling).

### Hot-path budget

- **Zero cost when disabled:** `otel_trace` absent on a location ⇒ REWRITE handler
  returns immediately — no allocation, no header scan.
- **Bounded when unsampled:** `otel_trace on` + unsampled ⇒ `SpanCtx` pool-alloc
  (bump pointer, effectively free) + one header scan + sampling branch +
  optional `traceparent` inject. **No span record, no spans-ring push, no second scan.**
- **LOG phase:** sampled requests push a `SpanRecord` to the worker-local spans SPSC ring
  (`src/shm.rs`, drain in `src/export/mod.rs`). The exporter builds the OTLP proto in the
  cold path.

### Trace–metric–log correlation

- **Exemplars** on `http.server.request.duration` now carry `trace_id`/`span_id` from the
  module's own spans (when `otel_access_log_sample` + `otel_trace` are both configured).
  This is the metric→exemplar→**Tempo trace** drill-down pivot (proposal §6.6.5).
- **Access tail `LogRecord`s** carry the same `trace_id`/`span_id` as the span.
- **Error `LogRecord`s** do NOT carry trace context (the `ngx_log_writer_pt` seam can't
  reach request context — see the error-log scope note in [Logs](#logs)).

### Transport

OTLP via the same dedicated `nginx: otel exporter` process as metrics and logs.
Spans are sent to `/v1/traces` (OTLP/HTTP) or on the traces gRPC endpoint
(`otlp_grpc`). All span encoding and I/O happen on the cold path.

> **Structural correctness verified (Phase 3 S5).** The TSAN gate
> (`tests/RESULTS-tsan-2026-06-08-traces.txt`) exercises the spans-ring writer + REWRITE
> `SpanCtx` shared state on Linux/arm64 with zero races.

---

## Exporter self-observability metrics (`SelfMetricsSource`)

The exporter process emits its own health metrics every export interval
(`src/export/mod.rs`, `SelfMetricsSource`). All Sums are monotonic cumulative.

| Metric | Instrument | Unit | Description |
|---|---|---|---|
| `ngx_otel.dropped_records` | Sum (monotonic) | `{point}` | Metric data points dropped due to a full retry buffer |
| `ngx_otel.send_failures` | Sum (monotonic) | `{failure}` | Cumulative export send failures since worker startup |
| `ngx_otel.bidi_backpressure_drops` | Sum (monotonic) | `{message}` | Bidi outbound messages dropped due to channel backpressure |
| `ngx_otel.logs.access.dropped_records` | Sum (monotonic) | `{record}` | Access log records dropped because the per-worker ring was full |
| `ngx_otel.logs.error.dropped_records` | Sum (monotonic) | `{record}` | Error log records dropped because the per-worker ring was full |
| `ngx_otel.logs.send_failures` | Sum (monotonic) | `{failure}` | Cumulative logs transport send failures since exporter startup |
| `ngx_otel.traces.dropped_records` | Sum (monotonic) | `{record}` | Span records dropped because the per-worker spans ring was full (P3 pre-promote fix — was written to `TRACES_DROPPED_RECORDS` but never emitted) |
| `ngx_otel.export_interval` | Gauge | `ms` | Configured metric export interval |

---

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

## Dashboard

A reference Grafana dashboard is committed at
`test-harness/demo/grafana/dashboards/ngx-otel-rust-overview.json`. It covers the
current surface: request rate / avg latency by method · status-class · route
(`by_route`, topk) · upstream zone (`by_upstream`); body-size and upstream-timing
quantiles (those are explicit-bucket, so `histogram_quantile(…, _bucket … by le)`);
nginx `stub_status`; the exporter self-metrics (incl. the Phase-2 log drop / send-failure
counters); and a Loki panel for 4xx/5xx access logs.

**Open iteration items (the dashboard is a working base, not final):**
- **Request-duration percentiles** are shown as **averages** (`rate(_sum)/rate(_count)`),
  NOT p50/p90/p99. The duration metric is an OTel **exponential histogram (µs)**; true
  quantiles need the collector→Prometheus **native-histogram** path
  (`histogram_quantile(0.99, sum(rate(metric[range])))`, no `le`) or an exp→classic
  bucket conversion. Wiring this is what validates DP-F's sub-ms quantile benefit
  (tied to the §6.6.5 demo plan). Until then, averages can hide the tail.
- **Exemplar → Tempo pivot** (Phase 3, wired): `exemplarTraceIdDestinations` is now
  configured in the Tempo datasource in the demo dashboard; clicking an exemplar on the
  `http.server.request.duration` panel opens the corresponding nginx server span in Tempo.
  Requires the demo Tempo instance to receive spans from the module.
- **Traces panel** added to the dashboard pointing at the Tempo datasource (service = `otel_service_name`).
- **Error-rate panel** (`ngx_otel.error_log.events`): present in the dashboard since Phase 2.3.
- **Provisioning reconciliation:** the committed file uses the new Grafana **dynamic
  dashboard schema** (`elements`/`layout`); set a stable `uid` (`ngx-otel-rust-overview`),
  a generic title, and reconcile datasource UIDs with the demo provisioning + confirm
  the demo Grafana version supports the schema before relying on auto-load.

**Connecting metrics ↔ logs in Grafana (design direction):** two mechanisms, both
serve the §6.6.3 "drill-down without SSH" story:
1. **Grafana Correlations / data links (label-based, available now):** click a metric
   panel → open Explore in Loki filtered by the shared labels (`service_name`,
   `http.route`, …) at the clicked time range. Works for *any* logs (access tail AND
   error), needs no traces. The dashboard's existing "Explore service logs" link is a
   basic form; a Correlation makes it click-through from a spike.
2. **Exemplar → trace → log (richer, Phase 3):** exemplars on the duration histogram
   carry `trace_id`; Grafana's `exemplarTraceIdDestinations` links them to Tempo, and
   Tempo→Loki via `trace_id`. Works for the **access** path (its tail/exemplars carry
   `trace_id`); **error** logs are NOT trace-linked (the writer can't reach request
   context — see Logs above), so error correlation stays label-based (#1).

## References

- [OpenTelemetry Semantic Conventions — HTTP metrics][semconv]
- Reference model: `avr-module/src/ngx_http_avr_data_sources.{h,c}`,
  `ngx_http_avr_output.c`
- Producer-side cardinality discipline: proposal §6.4; logs-as-summary §6.6
- Shared-memory layout + histograms: `src/shm.rs`
- Metrics emission + attributes: `src/metric_source/instrumented.rs`, `src/encoder/mod.rs`
- Logs: `src/logs/{access,ring,error_writer,coalesce,severity}.rs`; drain in `src/export/mod.rs`
- Traces: `src/metric_source/span_start.rs` (REWRITE), `src/metric_source/instrumented.rs` (LOG), `src/traces/mod.rs`, `src/metric_source/location_conf.rs`
- Configuration directives: see the project `README.md`

[semconv]: https://opentelemetry.io/docs/specs/semconv/http/http-metrics/
