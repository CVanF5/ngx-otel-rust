# ngx-otel-rust — Telemetry Model

This document is the **producer-side contract for everything the module emits** —
metrics, logs, and traces — in the style of the
[OpenTelemetry Semantic Conventions][semconv]: signal names, instruments/record
shapes, units, temporality, and the small fixed set of attribute values the module
keeps to (so a downstream collector can compress them — see Conventions, below).
**If you are building a dashboard, alert, or pipeline
against this module, this file is the source of truth for *what* it emits** — the
proposal covers *why*.

## Signals at a glance

| Signal | Enabled by | Where |
|---|---|---|
| **Metrics** | on by default (`otel_metrics`) | [Metrics](#metrics) |
| **Logs — access (exception tail)** | `otel_log_export on \| if=<expr>` | [Logs](#logs) |
| **Metric exemplars** | trace sampling (`otel_trace`) | [Metrics](#metrics) |
| **Logs — error (coalesced + rate metric)** | `otel_error_log [level]` | [Logs](#logs) |
| **Traces** | `otel_trace <expr>` per location | [Traces](#traces) |

**Conventions shared by all signals.** The [Resource and scope](#resource-and-scope)
below applies to every signal. Every attribute name comes from the OpenTelemetry
semantic conventions. Just as important, every attribute is restricted to a small,
fixed set of possible values — at most 256 distinct values for any one attribute.
This is deliberate. With a small fixed value set, a downstream collector can store
each attribute as a small integer index into a lookup table — a compact "dictionary"
encoding — instead of repeating the full string on every data point. To stay inside
that budget, genuinely open-ended detail is kept off the metrics entirely: the
request path (`url.path`), the client address (`client.address`), the User-Agent
string (`user_agent.original`), and the upstream peer address are never used as a
metric attribute. That detail rides instead on the access-log exception tail, in
error-record bodies, and — for `url.path` — on the per-request span. The metric
exemplars themselves do **not** carry it: an exemplar holds only a `trace_id` /
`span_id` pointer, and you reach the detail by following that pointer into the trace. Transport is OTLP (HTTP or
gRPC, `otel_export_protocol`) from the dedicated `nginx: otel exporter` process.
Both transports support `https://` (TLS; configured via `ssl_certificate`,
`ssl_certificate_key`, `ssl_verify`, and `trusted_certificate` inside
`otel_exporter {}`); OTLP/HTTP additionally supports `http://` and `unix:`
endpoints. OTLP/gRPC over `https://` negotiates HTTP/2 via ALPN `h2`; over
`http://` it uses plaintext h2c.

## Feature summary

Status: **Shipped** = emitted by the current module; **Planned** = designed, not yet
emitted; **Roadmap** = later phase. Nothing in the "Logs" rows is exported by default —
log export is opt-in (privacy).

| Feature | What it does | Status |
|---|---|---|
| Core + HTTP metrics | nginx connection/request gauges + per-request latency as an exponential histogram (µs) | Shipped |
| Trace-linked exemplars | `trace_id` on the duration histogram for metric → trace drill-down | Shipped |
| Distributed traces | one OTel server span per request; W3C `traceparent` propagation (`otel_trace`) | Shipped |
| **Logs: nothing exported by default** | no request-level log data leaves nginx unless configured (privacy) | Shipped |
| Access exception-tail logs | full `LogRecord`s for operator-selected requests (`otel_log_export on \| if=<expr>`) | Shipped |
| Metric exemplars | uniformly-sampled, trace-linked, one per data point per cycle, on trace-sampled requests (`otel_trace`) | Shipped |
| Error logs | template-coalesced error `LogRecord`s + companion rate metric (`otel_error_log`) | Shipped |
| **Selectable logs** | operator chooses *which* requests export, via an nginx `if=$cond` (status/latency/anything); nothing hardcoded | **Planned** |
| Tunable metric cardinality | `otel_metric_status_code_class on\|off` — rich per-status-class vs lean series | Shipped |
| TLS exporter transport | HTTPS / mTLS + OTLP-gRPC-over-TLS (ALPN `h2`) | Shipped |
| Collector & serving-cert metrics | expiry / validity gauges | Shipped |
| Status-aware delivery | retry / backoff honoring `Retry-After`/`RetryInfo`; stop-on-permanent; surface auth failures | Shipped |
| Sketch attributes (Theta) · OTAP transport · NGINX Plus signals | fleet-scale unique-counts/top-N; Arrow columnar transport; Plus metrics | Roadmap |

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

## Delivery semantics

The exporter provides **at-least-once delivery per signal per retry**. When a
send fails — network error, connection reset, or an HTTP 5xx / gRPC non-OK
response — the encoded batch is placed into a bounded per-signal retry queue
(`retry_queue` / `logs_retry_queue` / `spans_retry_queue`,
`src/export/mod.rs`) and retried in a later drain cycle. If the collector
received and processed the first attempt but the response was lost in transit,
the retry delivers the same batch a second time: there is no idempotency key
or dedup token in the OTLP payload. The practical consequence differs by
signal:

- **Metrics** — all instruments are exported as cumulative snapshots with a
  fixed `start_time_unix_nano` (`src/metric_source/instrumented.rs`,
  `src/metric_source/stub_status.rs`; `AggregationTemporality::Cumulative`
  throughout). A duplicate delivery is the same snapshot over the same
  `[start_time, time)` window. OTel-aware collectors and backends can detect
  and discard these by comparing the `{start_time_unix_nano, time_unix_nano}`
  pair, making metric re-sends effectively idempotent at the backend.
- **Logs and spans** — individual `LogRecord`s and spans carry no
  deduplication key. If a batch is retried after the collector already
  ingested it, the collector receives and stores duplicate records. Operators
  relying on exact-once log or trace counts should configure their collector
  pipeline with a deduplication processor or backend-native dedup on
  `trace_id`/`span_id`.

The exporter applies a **status-aware delivery policy** driven by a
protocol-neutral `DeliveryOutcome` verdict returned by each transport adapter
(`src/export/mod.rs`, `src/transport/hyper_http.rs`,
`src/transport/grpc/status_adapter.rs`):

- **`Accepted`** — the peer accepted the batch; released from the retry queue.
- **`PartialReject { rejected }`** — the peer accepted the batch but reported
  it dropped `rejected` individual records (OTLP `partial_success` body /
  gRPC partial-success response). The batch is released; the rejected count
  accumulates in `ngx_otel.delivery.partial_rejected`.
- **`Retryable { retry_after }`** — transient failure (HTTP exactly
  `429/502/503/504`; gRPC `UNAVAILABLE`/`DEADLINE_EXCEEDED`/`ABORTED`/
  `CANCELLED`/`OUT_OF_RANGE`/`DATA_LOSS`; `RESOURCE_EXHAUSTED` only when a
  recoverability hint is present). The batch is re-queued and the next drain
  of that signal is deferred: by the `Retry-After` / `RetryInfo` /
  `grpc-retry-pushback-ms` hint when present, else by exponential backoff
  (starting at the drain interval, doubling per consecutive retryable failure
  of that signal, capped — spec `SHOULD` for no-hint case). All other `4xx`
  and `5xx` responses that are not in the retryable set are treated as
  `Permanent` (spec: "MUST NOT retry").
- **`Permanent`** — non-retryable peer rejection (HTTP `400`, `404`, `413`,
  `501`, and any non-retryable `4xx`/`5xx` not listed above; gRPC
  `INVALID_ARGUMENT`/`INTERNAL`/`UNIMPLEMENTED`). The batch is dropped and
  counted in `ngx_otel.delivery.permanent_rejected`.
- **`Unauthorized`** — authentication or authorization failure (HTTP
  `401`/`403`; gRPC `UNAUTHENTICATED`/`PERMISSION_DENIED`). Same policy
  action as `Permanent` (drop, no retry, no backoff, no auto-pause), but kept
  in a distinct counter (`ngx_otel.delivery.unauthorized`) for observability.
  A rate-limited "check exporter credentials" log entry is emitted (at most
  once per 60 s) to surface the problem without flooding the error log.

The retry queue is bounded: when full, the oldest batch is evicted and
counted in `ngx_otel.dropped_records`. Producer-side ring drops —
`ngx_otel.logs.access.dropped_records`, `ngx_otel.logs.error.dropped_records`,
and `ngx_otel.traces.dropped_records` (see the self-observability table
below) — are a separate, upstream drop class that occurs before any batch
reaches the exporter retry buffer.

> **OTAP (Phase 5).** The `DeliveryOutcome` type and the gRPC-code→outcome
> mapping (`grpc_code_to_outcome`, `src/transport/grpc/status_adapter.rs`)
> are designed for reuse: OTAP's `BatchStatus.StatusCode` uses the same gRPC
> code space, so a future OTAP transport adapter maps into the existing policy
> engine with near-zero new code. No OTAP transport exists today.

---

## HTTP server request duration (exponential histogram, µs)

Derived per request in `LogPhaseHandler` (`src/metric_source/instrumented.rs`). The
request duration is an OTel **exponential histogram recorded in microseconds**, for
native sub-millisecond quantiles in the ~90–200µs operating regime.

The duration is emitted as **three decomposed series** (not a cross-product): a base
series carrying the bounded `{method × status-class × protocol}` dimensions, plus
independent per-route and per-upstream series. Each is its own `ExpHistogramSlot`
table in `WorkerSlots` (`src/shm.rs`).

| Metric | Instrument | Unit | Temporality | Attributes (data-point keys) |
|---|---|---|---|---|
| `http.server.request.duration` | ExponentialHistogram | `us` | Cumulative | `http.request.method`, `http.response.status_code`, `network.protocol.version` — **only when `otel_metric_status_code_class on`**; otherwise a single unattributed data point |
| `http.server.request.duration.by_route` | ExponentialHistogram | `us` | Cumulative | `http.route` (matched `location` name) |
| `http.server.request.duration.by_upstream` | ExponentialHistogram | `us` | Cumulative | `nginx.upstream.zone` (declared upstream `zone`) |

- The base series emits up to **160** data points (`N_HTTP_METHODS(8) ×
  N_STATUS_CLASSES(5) × N_PROTO_VERSIONS(4)`); empty combos are skipped.
  `http.response.status_code` carries the **status-class representative**
  (100/200/300/400/500), not the raw code — grouping into classes keeps the number
  of distinct values small (5, instead of hundreds of raw status codes).
- `by_route` / `by_upstream` are **always** emitted (independent of
  `otel_metric_status_code_class`). Route names are the matched `location`
  name (never the raw URI), bounded `ROUTE_CAP = 64` + an `"other"` slot;
  upstream zones are bounded `UPSTREAM_CAP = 32` + `"other"` / no-upstream.
- **SIGHUP reload behaviour:** `by_route` and `by_upstream` histogram
  slots are **zeroed on every reload** (`otel_shm_zone_init`, `shm.rs`).
  The slot→name mapping is rebuilt from the new config on each reload
  (new `ngx_http_core_loc_conf_t*` / `ngx_shm_zone_t*` values; any location
  add/remove/reorder shifts the slot index).  Preserving old counts would
  silently re-attribute them to the route/upstream that now owns that slot.
  The zero produces a valid OTLP cumulative reset at the reload boundary —
  `start_time_unix_nano` resets with the new exporter process, so consumers
  already baseline on restart.  The base-series (`by method × status × protocol`)
  and all global aggregate histograms carry over unchanged (their indices are
  config-independent).
- **Client-abort behaviour:** requests where nginx never sent response
  headers (`headers_out.status == 0`) are **excluded from the base series**
  (`http.server.request.duration`).  This covers port-scan SYN probes,
  TLS-to-plaintext probes, and client disconnects that arrive before the
  response status is set.  Per OTel HTTP semconv, `http.response.status_code`
  is CONDITIONALLY REQUIRED only when a response was actually sent — it is
  absent for aborted requests.  Counting status-0 as `5xx` (the prior
  `StatusClass::from_status` catch-all) inflated server-error rates on any
  environment exposed to port scans.  The `by_route` and `by_upstream`
  histograms **do** record these requests — the request still consumed real
  nginx resources regardless of the abort.
- **Exemplars:** the base series attaches uniformly-sampled exemplars
  (canonical `value` + `time_unix_nano` + `trace_id`/`span_id`, no
  `filtered_attributes`) — one small fixed-size reservoir per data point,
  reset every export cycle.  Exemplars are recorded only for trace-sampled
  requests (`otel_trace`; the OTel default `TraceBased` exemplar filter), so
  every exemplar carries a resolvable trace pointer.  The decomposed
  `by_route` / `by_upstream` series carry no exemplars.

### Exponential histogram parameters (`src/shm.rs`)

- **Scale:** `EXP_HISTOGRAM_SCALE = 3` → base = 2^(2^-3) ≈ 1.091 (8 buckets
  per power-of-two µs). 90µs → bucket 51; 150µs → bucket 57; 200µs → bucket 61
  — all distinct.
- **Buckets:** `N_EXP_BUCKETS = 192`, `positive_offset = 0`, covering
  ≈ [1µs, 2^24µs ≈ 16.7s); values above clamp to the last bucket; 0µs →
  `zero_count`.
- **Bucket computation is exact:** bucket index = `floor(log2(value_us) * 8)`,
  computed in O(1) using only integer shifts and 7 precomputed u64 thresholds —
  no float, no `log()` call, no syscall on the hot path. Verified exact for all
  values in [1, 2^14] and a random sample up to 2^24.
- **One-bucket difference from the spec, at exact powers of two (note):** our
  bucketing matches the OpenTelemetry exponential-histogram spec for every latency
  except one corner case, and the difference is only about which side of a bucket
  edge a value falls on. We treat each bucket as "from its lower edge up to, but not
  including, the next edge"; the spec treats it as "above the lower edge, up to and
  including the next edge." Those two rules disagree only when a value lands *exactly*
  on an edge — and for these buckets, the edges sit at exact powers of two
  microseconds (2µs, 4µs, 8µs, and so on). Such a value goes into the next bucket up
  under our rule versus the spec's. Every other integer-microsecond latency buckets
  identically. This is a deliberate, documented choice.
  (For reference: our index is `floor(log2(value_us) * 8)`, a lower-inclusive
  `[base^k, base^(k+1))` boundary; the spec uses the upper-inclusive
  `(base^k, base^(k+1)]`.)

---

## HTTP server size + upstream metrics (explicit-bucket histograms)

Explicit-bucket `Histogram<N>` (`src/shm.rs`), single unattributed data point each
(no method/route/zone decomposition). Recorded in `LogPhaseHandler`; upstream
metrics only when an upstream was used (from `ngx_http_upstream_state_t`).

| Metric | Instrument | Unit | Temporality |
|---|---|---|---|
| `http.server.request.body.size` | Histogram (explicit) | `By` | Cumulative |
| `http.server.response.body.size` | Histogram (explicit) | `By` | Cumulative |
| `http.server.upstream.response.duration` | Histogram (explicit) | `ms` | Cumulative |
| `http.server.upstream.header.duration` | Histogram (explicit) | `ms` | Cumulative |
| `http.server.upstream.connect.duration` | Histogram (explicit) | `ms` | Cumulative |
| `http.server.upstream.bytes.received` | Histogram (explicit) | `By` | Cumulative |
| `http.server.upstream.bytes.sent` | Histogram (explicit) | `By` | Cumulative |

> **Sentinel filtering — skipping upstream timings nginx never measured:** nginx initialises `response_time`,
> `connect_time`, and `header_time` in `ngx_http_upstream_state_t` to
> `(ngx_msec_t)-1` (`ngx_http_upstream.c:1580-1582`) to mark "timing not
> measured" (e.g., aborted upstream attempts, connection failures).  The
> nginx log module formats this sentinel as `"-"` (`:6074`).  The three
> upstream duration histograms skip recording when the sentinel is present;
> failed or aborted upstream attempts therefore contribute **zero
> observations** to those histograms.  `bytes_received` / `bytes_sent`
> (`off_t`, zero-initialised via `ngx_pcalloc`) are not affected.

## NGINX connection / request metrics

Read from nginx's `stub_status` globals each export interval
(`src/metric_source/stub_status.rs`). Connection state
(active/reading/writing/waiting) is emitted as OTLP **Gauge** metrics; the
cumulative counters (accepted/handled/requests) as monotonic **Sum** metrics.

> **Build-flag requirement.** These seven series exist **only** when nginx is
> built with `--with-http_stub_status_module` (which defines `NGX_STAT_STUB`,
> the source of the `ngx_stat_*` globals these metrics read). When the module is
> compiled against a nginx that lacks the flag, the source is not registered and
> these series are **absent** from the export (not present-as-zero); the exporter
> logs a one-shot `[warn]` at startup naming the missing flag. All other signals
> are unaffected.

| Name | Instrument | Unit (UCUM) | Temporality | Stability |
|---|---|---|---|---|
| `nginx.requests.total` | Counter (Sum, monotonic) | `{request}` | Cumulative | experimental |
| `nginx.connections.accepted` | Counter (Sum, monotonic) | `{connection}` | Cumulative | experimental |
| `nginx.connections.handled` | Counter (Sum, monotonic) | `{connection}` | Cumulative | experimental |
| `nginx.connections.active` | Gauge | `{connection}` | — | experimental |
| `nginx.connections.reading` | Gauge | `{connection}` | — | experimental |
| `nginx.connections.writing` | Gauge | `{connection}` | — | experimental |
| `nginx.connections.waiting` | Gauge | `{connection}` | — | experimental |

---

## Attributes

The duration series carry the attributes below. Each one is restricted to a small,
fixed set of possible values (at most 256), for the dictionary-encoding reason given
in Conventions at the top of this document — so a collector can store each as a small
integer index rather than a repeated string. Those fixed value sets are defined as
Rust enums in `src/shm.rs` (`HttpMethod`, `StatusClass`, `ProtoVersion`).

| Attribute | On series | Cardinality |
|---|---|---|
| `http.request.method` | base duration | 8 (`HttpMethod`, 7 + `_OTHER`) |
| `http.response.status_code` | base duration | 5 status classes (representative value) |
| `network.protocol.version` | base duration | 4 (`ProtoVersion`) |
| `http.route` | `…by_route` | ≤ 64 + `other` (location name) |
| `nginx.upstream.zone` | `…by_upstream` | ≤ 32 + `other`/none |

> **High-cardinality detail is NOT a metric dimension.** `url.path`,
> `user_agent.original`, and `client.address` are deliberately kept **off** the
> metrics. They ride on the **access-log exception tail** (and `url.path` is also a
> span attribute), reachable from a metric by following an exemplar's `trace_id`
> pointer into the trace — the exemplar itself carries only that pointer, not these
> values. They are never histogram attributes (that would blow the small
> fixed-value-set budget described in Conventions at the top).

## Histogram bucket boundaries (`src/shm.rs`)

- **Request duration** — exponential (see parameters above): scale 3, µs,
  192 buckets, offset 0. **Not** the explicit `ms` boundaries below.
- **Upstream durations (`ms`)** — explicit, `DURATION_BOUNDS_MS`, 14 + overflow:
  `5, 10, 25, 50, 75, 100, 250, 500, 750, 1000, 2500, 5000, 7500, 10000`
- **Byte sizes (`By`)** — explicit, `BYTES_BOUNDS`, 6 + overflow:
  `128, 512, 4096, 65536, 524288, 4194304`

---

## Error-rate metric (`ngx_otel.error_log.events`)

The companion error-rate metric emitted alongside the coalesced error `LogRecord`s.

| Metric | Instrument | Unit | Temporality | Attributes |
|---|---|---|---|---|
| `ngx_otel.error_log.events` | Counter (Sum, monotonic) | `{error}` | Cumulative | `severity_class` only |

Severity classes (5 values — a small fixed set):

| `severity_class` | nginx levels | level names |
|---|---|---|
| `"fatal"` | 1–3 | emerg, alert, crit |
| `"error"` | 4 | error |
| `"warn"` | 5 | warn |
| `"info"` | 6–7 | notice, info |
| `"debug"` | 8 | debug |

> **Why this metric has so few attributes.** It is broken down by severity only —
> there is no route, upstream, or `trace_id` dimension. The reason is structural.
> nginx invokes our error-log writer through a hook that is given its own logging
> handle, not the one attached to the connection that triggered the log line. So at
> the point where error logging happens, we have no way to tell which request or
> connection produced the message — that information is simply not reachable there.
> (The access-log path *does* have it, and is unaffected.) You can still see which
> upstream or route was involved: nginx writes that into the error message text
> itself, and we ship that text verbatim in the record body. The per-template
> occurrence count rides on the log record's `nginx.error.coalesced_count`
> attribute, not on this metric.

---

## Logs

OTel logs are **orthogonal to nginx's own `access_log`/`error_log`** (the module emits
via its own directives; core file logging is untouched and remains the on-box
transcript). The OTel stream carries "summary + samples", not a per-request firehose.

### Access log — thin exception tail (plus metric exemplars)

The bulk of access information is the **metrics** above. Per-event access output is two
distinct, orthogonal things, never a per-request log:

- **Metric exemplars** on the `http.server.request.duration` base series: representative
  trace pointers attached to the histogram, carrying the canonical OTel exemplar payload
  — measured `value` + `time_unix_nano` + `trace_id`/`span_id`, and **no
  `filtered_attributes`**. They are produced on the **trace-sampling** path (recorded
  only when the request is sampled — OTel's default `TraceBased` exemplar filter), so
  every exemplar carries a resolvable trace pointer. One small fixed-size reservoir
  (size 2) **per data point**, uniformly sampled
  (`SimpleFixedSizeExemplarReservoir`) and **reset every export cycle**. This is the
  metric → exemplar → trace drill-down pivot. (`src/metric_source/instrumented.rs`,
  `src/shm.rs` `ExemplarReservoir`, encoder `Exemplar`.)
- **Exception-tail `LogRecord`s**: emitted for the requests an operator selects with
  **`otel_log_export on | if=<expr>`** (absent ⇒ off, the privacy-safe default),
  carrying the high-cardinality attributes below + `trace_id`/`span_id` + request
  duration. Substrate is the per-worker SPSC ring.
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

A common (2xx, fast, unselected, unsampled) request produces **neither** — only the
histogram `fetch_add`.

**Exemplars vs exported log records** — both are "samples," but they are different
signals with different purposes:

| | Exemplars | Exported log records (exception tail) |
|---|---|---|
| Signal family | Metrics (attached to the duration histogram) | Logs |
| Carries | `value` + `time_unix_nano` + `trace_id`/`span_id` (no `filtered_attributes`) | full per-request `LogRecord` (attributes above + duration) |
| Selection | trace-sampled requests (`otel_trace`), uniform per data point, reset each cycle | operator condition `otel_log_export on \| if=<expr>` |
| Purpose | metric → trace drill-down pivot | the actual log line for the requests you care about |
| Authoritative? | best-effort hint (can be torn — see below) | yes |

> **Why exemplars dropped `url.path` / `user_agent`.** Per the OTel data model,
> `filtered_attributes` are attributes that were on the metric *measurement* but dropped
> from aggregation; `url.path` / `user_agent` are never measurement attributes here, so
> placing them there misuses the field (and the spec flags filtered attributes as a
> redaction hazard). The linked trace already carries `url.path`, and `user_agent` is
> addable via `otel_span_attr`, so no information is lost.
> <https://opentelemetry.io/docs/specs/otel/metrics/data-model/#exemplars>

> **Treat an exemplar as a hint, not as an exact record.** An individual exemplar
> can occasionally be internally inconsistent — for instance, a latency `value`
> paired with the wrong request's `trace_id`. This is a deliberate trade-off.
> Exemplars are written by the worker on the per-request hot path without any lock
> and without a step that commits all of an exemplar's fields together, so that
> recording one costs almost nothing. The cost of that speed is that a reader
> draining the data at the exact moment a worker is overwriting a slot can catch it
> half-updated (a "torn" read). The once-per-cycle reset of each reservoir's counter
> has the same property: a worker writing at that instant can lose that one update.
> None of this affects the totals — the aggregate histogram and the exception-tail
> log records are computed separately and remain authoritative. Use an exemplar only
> as a pointer for drilling from a metric into a trace, never as ground truth.

### Error log — coalesced `LogRecord`s

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

#### When the error buffer fills up: a count-only placeholder record

Recall how coalescing works, just above: for each repeated error the module keeps
one example message plus a running tally of how many times that error occurred this
interval. The example messages are stored in a fixed-size buffer (the "ring"). Under
a heavy flood of errors that buffer can fill up, so a new example message cannot be
stored — but the tally is just a counter, and it keeps counting regardless.

When that happens, the drain step is left holding a tally with no example message to
attach it to. Dropping the tally would under-report how many errors actually
happened, so instead the exporter sends a placeholder log record: it carries the
count, and its body says, in effect, "this many of these occurred; the example text
was dropped because the buffer was full." The fields:

| `LogRecord` field | Value |
|---|---|
| `severity_number` / `severity_text` | same mapping as normal error records |
| `event_name` | `nginx.error` |
| `body` | `"[nginx.error.coalesced_orphaned: N occurrences dropped (ring full)]"` where N = orphaned count |
| attr `nginx.error.template_hash` | same hash as the dropped verbatim sample |
| attr `nginx.error.coalesced_count` | total occurrence count for this template this interval |
| attr `nginx.error.coalesced_orphaned` | `true` — marks this as a synthetic (no real body) |

The companion metric `ngx_otel.logs.error.coalesced_orphaned_records` counts
these events (see [Metrics](#metrics)).  A high value means the error buffer is
saturated: example messages are being lost, though the occurrence counts are still
preserved.  Source: `src/export/mod.rs` (`drain_coalesce_table`).

## Traces

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
| `$otel_parent_sampled` | string `"1"` / empty | `"1"` when this request is sampled — including root spans with no inbound `traceparent`; empty only when tracing is disabled. (The name reads as a parent-only flag but reflects the sampling state of *this* request — see `span_start.rs`.) |

### Span shape

One OTel **server span** per sampled request.

| Field | Value | Source |
|---|---|---|
| `name` | `"METHOD route_name"` or `otel_span_name` override | `src/traces/mod.rs` |
| `start_time_unix_nano` | wall-clock anchor at REWRITE phase entry (`SystemTime::now()`) | `src/metric_source/span_start.rs` |
| `end_time_unix_nano` | `start_time_unix_nano + monotonic_duration_ns` (always ≥ start; NTP-immune; derived from `Instant::elapsed()` at LOG) | `src/metric_source/instrumented.rs` |
| `trace_id` | extracted from inbound `traceparent` (propagate/extract), or freshly generated | `src/traces/ctx.rs` |
| `span_id` | freshly generated per request | `src/traces/ctx.rs` |
| `parent_span_id` | from inbound `traceparent` (when `extract` or `propagate`), else **empty** (root span — OTLP `bytes` field empty = no parent, per proto semantics) | `src/metric_source/span_start.rs` |
| `flags` | W3C trace flags byte (propagated from inbound header, or `0x01` for root spans) | `src/metric_source/span_start.rs` |
| `kind` | `SERVER` | `src/traces/mod.rs` |
| `status` | `ERROR` (5xx), else `Unset` — semconv-correct (4xx is not a server-span error) | `src/metric_source/instrumented.rs` |
| ↳ parser note | `parse_span_record`'s `1 => Ok` branch (`traces/mod.rs`) is forward-compat only; dead for module-produced records (which are always 0 or 2). | — |

### Span attributes

Standard OTel HTTP semconv attributes recorded on every span:

| Attribute | Value | Source |
|---|---|---|
| `http.request.method` | HTTP method string | `r->method_name` |
| `url.path` | request URI path (≤ 64 bytes, `MAX_URL_PATH`) | `r->uri` |
| `http.response.status_code` | raw status code | `r->headers_out.status` |
| `http.server.request.duration` | request duration **in seconds** (derived from µs measurement; same field, same unit as the access-tail LogRecord — enables coherent metric→exemplar→log→trace drill-down) | `src/traces/mod.rs` |
| Custom attrs | from `otel_span_attr` directives | `src/metric_source/location_conf.rs` |

> **Not recorded as span attributes:** `http.route` (the matched location name
> appears in the span *name* `"METHOD route_name"`, and as `http.route` on the
> `by_route` *metric* — but it is not a span attribute), `network.protocol.version`,
> and `user_agent.original` / `client.address` (these ride on the access-tail
> `LogRecord`). Add any of them to the span per location with `otel_span_attr`.

### Sampling

**Worker-side only; no tail sampling.**

- **Parent-based:** when an inbound `traceparent` header is present (and `trace_context`
  is `extract` or `propagate`), the W3C `sampled` flag (`flags & 0x01`) is honoured.
  Sampled → emit span record. Unsampled → allocate `SpanCtx` (for `traceparent` propagation,
  if `inject`/`propagate`) but **no span record, no ring push**.
- **Ratio / head-sampling:** when no inbound `traceparent` is present, the `otel_trace`
  complex value is re-read at decision time. A `split_clients`-managed variable (e.g.
  `$otel_trace_sample`) returning `"1"` → sampled; `"0"` / `"off"` → unsampled.
  A truthy value → `sampled=true`.
- **Probe / health-check drop:** a configurable `probe_drop` pipeline `Processor`
  (`src/processor/mod.rs`) drops spans whose `url.path` matches the configured set
  (defaults: `/healthz`, `/readyz`, `/livez`, `/ping`, `/metrics`). Configured via the
  exporter `processor` block (independent of sampling).

### One span per request (internal redirects & subrequests)

Mirrors the C++ `nginx-otel` module's redirect-safe design:

- **Internal redirects** (`error_page`, `try_files`, named locations) re-run the
  REWRITE phase with `r->internal` set and the per-request module-ctx array
  zeroed by nginx. The span-start handler **early-returns on `r->internal`** (so
  it does not start a second span or re-decide sampling), and the original
  `SpanCtx` is **recovered at LOG** from a pool-cleanup anchor that survives the
  redirect. Result: **exactly one span per request**, carrying pass-1's parent
  linkage and timing — the span SURVIVES the redirect.
- **Subrequests** also set `r->internal`, so they do **not** get their own span
  (deliberate, upstream-mirrored semantic). A subrequest's work is attributed to
  the parent request's span.
- **Outbound `traceparent` injection** (`inject` / `propagate`) **updates an
  existing inbound `traceparent` in place** rather than appending — so the
  upstream receives **exactly one** `traceparent` (carrying our trace/span IDs),
  never a stale-plus-fresh duplicate.

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

- **Exemplars** on `http.server.request.duration` carry `trace_id`/`span_id` from the
  module's own spans (recorded on the trace-sampling path, so `otel_trace` must select
  the request). This is the metric→exemplar→**Tempo trace** drill-down pivot.
- **Access tail `LogRecord`s** carry the same `trace_id`/`span_id` as the span.
- **Error `LogRecord`s** do NOT carry trace context (the `ngx_log_writer_pt` seam can't
  reach request context — see the error-log scope note in [Logs](#logs)).

### Transport

OTLP via the same dedicated `nginx: otel exporter` process as metrics and logs.
Spans are sent to the derived traces path (`base/v1/traces` for OTLP/HTTP, or
overridden by `traces_endpoint` in `otel_exporter {}`; `otlp_grpc` uses the gRPC
TraceService method). All span encoding and I/O happen on the cold path.

---

## Transport security (TLS)

Both OTLP/HTTP and OTLP/gRPC support TLS when `endpoint` uses the `https://`
scheme. TLS is handled by the dedicated exporter process via a custom OpenSSL
async BIO bridge (`src/transport/tls.rs`). Workers never hold collector sockets
and are not involved in TLS.

### Directives

| Directive              | Default                    | Behaviour                                                                                                                                                        |
|------------------------|----------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `trusted_certificate`  | System trust store         | CA bundle (PEM) for validating the collector's server cert. When omitted, `SSL_CTX_set_default_verify_paths` loads the OS default store.                         |
| `ssl_certificate`      | (none — mTLS disabled)     | Client certificate chain (PEM) for mutual TLS. Must be set together with `ssl_certificate_key`.                                                                 |
| `ssl_certificate_key`  | (none — mTLS disabled)     | Client private key (PEM) for mutual TLS. Must be set together with `ssl_certificate`.                                                                           |
| `ssl_verify`           | `on`                       | `off` disables server certificate verification (INSECURE). Emits a config-time WARN. Useful for testing against a self-signed collector without a CA bundle.      |

### Verification model

- **Minimum TLS version**: 1.2 (`SSL_CTX_set_min_proto_version(TLS1_2_VERSION)`).
- **Certificate chain**: validated against `trusted_certificate` (or the OS
  trust store). An untrusted chain causes a TLS handshake failure — the exporter
  logs `send_failed` error alerts, activates retry backoff, and increments
  `ngx_otel.send_failures`. Zero data is delivered. Nginx continues serving.
- **Hostname verification (DNS endpoints)**: `X509_VERIFY_PARAM_set1_host` checks
  the cert's DNS SAN against the endpoint hostname. A mismatch fails closed.
- **IP-address verification (IP-literal endpoints)**: `X509_VERIFY_PARAM_set1_ip_asc`
  checks the cert's iPAddress SAN against the endpoint IP (RFC 5280). A mismatch
  fails closed. SNI is suppressed for IP literals per RFC 6066 §3.
- **mTLS**: when both `ssl_certificate` and `ssl_certificate_key` are set, the
  exporter presents the client cert during the TLS handshake. Without a client cert,
  a collector configured to require mutual TLS will reject the handshake (fails closed).
- **SIGHUP reload**: the new exporter generation reads the current cert/CA paths —
  rotating a cert or CA takes effect at reload, not at the next connection attempt.
- **gRPC over TLS**: `otel_export_protocol otlp_grpc` with an `https://` endpoint
  automatically negotiates ALPN `h2` for HTTP/2 — no extra configuration.

### Transport security notes for operators

- `ssl_verify off` should never be used in production. It disables all certificate
  chain and hostname checks, meaning any server can intercept the export stream.
  The config-time WARN is logged once per exporter generation to alert operators.
- The `trusted_certificate` path is read at config-parse time (existence-checked)
  but loaded into the `SSL_CTX` when the exporter process starts. A missing or
  unreadable CA file after config-parse causes an exporter startup error.
- For self-signed collector certs in test/dev environments, prefer `trusted_certificate
  /path/to/your-ca.pem` over `ssl_verify off`. This maintains chain validation while
  avoiding a commercial CA requirement.

---

## Exporter self-observability metrics (`SelfMetricsSource`)

The exporter process emits its own health metrics every export interval
(`src/export/mod.rs`, `SelfMetricsSource`). All Sums are monotonic cumulative.

| Metric | Instrument | Unit | Description |
|---|---|---|---|
| `ngx_otel.dropped_records` | Sum (monotonic) | `{record}` | Records from any signal (metrics, logs, spans) dropped because the per-signal retry buffer was full (oldest batch evicted) or a graceful-drain abort discarded queued batches (previously only the metrics lane was accounted) |
| `ngx_otel.send_failures` | Sum (monotonic) | `{failure}` | Cumulative export send failures since worker startup |
| `ngx_otel.bidi_backpressure_drops` | Sum (monotonic) | `{message}` | Bidi outbound messages dropped due to channel backpressure |
| `ngx_otel.logs.access.dropped_records` | Sum (monotonic) | `{record}` | Access log records dropped because the per-worker ring was full |
| `ngx_otel.logs.error.dropped_records` | Sum (monotonic) | `{record}` | Error log records dropped because the per-worker ring was full |
| `ngx_otel.logs.error.coalesced_orphaned_records` | Sum (monotonic) | `{record}` | Coalesced error-log occurrences whose verbatim ring sample was dropped (ring full); a synthetic record is emitted for each orphaned slot so the occurrence count is preserved. Accumulated additively across drain cycles. |
| `ngx_otel.logs.send_failures` | Sum (monotonic) | `{failure}` | Cumulative logs transport send failures since exporter startup |
| `ngx_otel.traces.dropped_records` | Sum (monotonic) | `{record}` | Span records dropped because the per-worker spans ring was full |
| `ngx_otel.export_interval` | Gauge | `ms` | Configured metric export interval |
| `ngx_otel.exporter.restarts` | Gauge | `crashes` | Prior exporter crashes observed in the current crash-loop window when this exporter process started (`0` = clean start; set once at exporter startup from the shared-memory crash counter). Not emitted after crash-loop give-up — no exporter process remains to emit it; the disable is announced by an ALERT in the error log. See `LIFECYCLE.md` |
| `ngx_otel.delivery.permanent_rejected` | Sum (monotonic) | `{batch}` | Batches the peer rejected as permanently unacceptable (e.g. HTTP `400`/`413`/`501`/non-retryable `4xx`/`5xx`; gRPC `INVALID_ARGUMENT`/`INTERNAL`/`UNIMPLEMENTED`); dropped and never retried. A sustained non-zero rate indicates a payload or endpoint configuration problem. |
| `ngx_otel.delivery.partial_rejected` | Sum (monotonic) | `{record}` | Individual records the peer reported it dropped on an otherwise-accepted batch (OTLP `partial_success.rejected_*` field / gRPC partial-success body). The batch is released; only the peer-reported rejected record count accumulates here. |
| `ngx_otel.delivery.unauthorized` | Sum (monotonic) | `{batch}` | Batches dropped because the peer reported an authentication or authorization failure (HTTP `401`/`403`; gRPC `UNAUTHENTICATED`/`PERMISSION_DENIED`). Same drop policy as `permanent_rejected` (no retry, no backoff, no auto-pause); a rate-limited "check exporter credentials" log entry is emitted alongside. A non-zero value indicates a credential or permission problem on the exporter endpoint. |

---

## Serving-certificate metrics (`ngx_otel.tls.certificate.*`)

Three int64 Gauges per TLS **serving** certificate
(`src/metric_source/tls_cert.rs`, `ServingCertSource`), emitted every export
interval by the exporter process. Requires nginx built with
`--with-http_ssl_module`; without it (or with no `ssl_certificate`
configured) the three series are **absent** from the export — not
present-as-zero — and a one-shot config-time NOTICE explains why.

| Metric | Instrument | Unit | Description |
|---|---|---|---|
| `ngx_otel.tls.certificate.not_after` | Gauge (int64) | `s` | Certificate `notAfter` as Unix epoch seconds |
| `ngx_otel.tls.certificate.not_before` | Gauge (int64) | `s` | Certificate `notBefore` as Unix epoch seconds |
| `ngx_otel.tls.certificate.time_to_expiration` | Gauge (int64) | `s` | `not_after − now` (wall clock), recomputed each export interval. **Negative once the certificate has expired** — the series does not disappear at expiry; alert on small or negative values, not on absence |

### Attributes

Each data point carries **exactly** this bounded attribute set (one data
point per certificate; the set is deliberately closed — no PEM, no key
material, no fingerprints, no full DNs, no SANs):

| Attribute | Value | Source |
|---|---|---|
| `file_path` | certificate file path as configured by `ssl_certificate` | `src/cert_table.rs` |
| `tls.server.subject` | subject CN only (empty string when the subject has no CN) | `src/cert_table.rs` |
| `tls.server.issuer` | issuer CN only (empty string when the issuer has no CN) | `src/cert_table.rs` |
| `serial_number` | serial as an uppercase hex string (no `0x` prefix) | `src/cert_table.rs` |
| `public_key_algorithm` | `"RSA"`, `"EC"`, `"ED25519"`, ... | `src/cert_table.rs` |
| `signature_algorithm` | signature algorithm short name (e.g. `"RSA-SHA256"`) | `src/cert_table.rs` |
| `server.address` | first non-wildcard `server_name` of the owning server block; `"_"` when the block has none | `src/cert_table.rs` |

A server block with multiple certificates (e.g. dual RSA + ECDSA) yields one
series per certificate per metric, distinguished by `file_path` /
`public_key_algorithm` / `serial_number`.

### Cadence: what nginx *serves*, not what is on disk

The certificate table is built **once per configuration cycle** — at startup
and on every reload — by walking the live `SSL_CTX` of each `server` block at
`postconfiguration` time (`src/cert_table.rs`). Between reloads the
values are constant except `time_to_expiration`, which is recomputed against
the wall clock each export interval.

This deliberately differs from file-watching tools (e.g. NGINX Agent, which
watches certificate *files*): a renewed certificate written to disk does
**not** change these metrics until nginx reloads, because nginx does not
*serve* the new certificate until reload. If `time_to_expiration` stays low
after your renewal automation ran, the renewed cert is on disk but nginx was
never reloaded — exactly the failure mode these metrics are designed to
expose.

### Limitations

- **Variable certificate paths** (`ssl_certificate $var`) are skipped with a
  config-time NOTICE — nginx defers loading such certificates to handshake
  time, so there is nothing to enumerate at config time.
- **Leaf certificates only**: intermediate/chain certificates in the
  configured bundle are not enumerated (deferred).

---

## Collector-certificate gauge (`ngx_otel.tls.collector_cert.not_after`)

One int64 Gauge for the TLS certificate the **collector** (OTLP endpoint)
presents during the handshake (`src/transport/tls.rs`). Emitted by the
exporter process every export interval once a successful TLS handshake has
been completed.

**Absent until first successful TLS handshake** (absent-not-zero):
- Plaintext (`http://`) endpoints: metric name does not appear.
- Pre-handshake (TLS configured but not yet connected): metric name does not appear.
- After a successful handshake: one data point, stable per exporter generation
  (the collector certificate does not change mid-connection).

| Metric | Instrument | Unit | Description |
|---|---|---|---|
| `ngx_otel.tls.collector_cert.not_after` | Gauge (int64) | `s` | Collector certificate `notAfter` as Unix epoch seconds |

### Attributes

| Attribute | Value | Source |
|---|---|---|
| `server.address` | collector hostname from the configured `otel_exporter` endpoint (e.g. `otel-collector.example.com`) | `src/export/mod.rs` |

### Implementation

- Captured in `TlsNgxConnIo::poll_handshake` via `SSL_get1_peer_certificate`
  (owned reference; freed after reading with `X509_free`).
- Epoch conversion reuses `cert_table::asn1_time_to_unix` — the same helper
  used by `ServingCertSource` — so there is no duplicated epoch math.
- Written to `COLLECTOR_CERT_NOT_AFTER: AtomicI64` (process-global, initial
  value 0 = absent); read by `collect_all_sources` at each export interval.
- Single-threaded exporter: `Relaxed` ordering is sound (no concurrent writers).

### Use case

Alert when the collector's own certificate is about to expire (e.g.
`time() - ngx_otel.tls.collector_cert.not_after < 30d`). Particularly useful
in mTLS deployments where the collector certificate is managed separately from
the nginx serving certificates.

---

## Dashboard

A reference Grafana dashboard is committed at
`test-harness/demo/grafana/dashboards/ngx-otel-rust-overview.json`. It covers the
emitted surface: request rate / latency by method · status-class · route
(`by_route`, topk) · upstream zone (`by_upstream`); body-size and upstream-timing
quantiles (explicit-bucket); nginx `stub_status`; the exporter self-metrics; an
error-rate panel (`ngx_otel.error_log.events`); a serving-certificate expiry table
(`ngx_otel.tls.certificate.time_to_expiration`, 30d/7d thresholds); a Loki panel
for 4xx/5xx access logs;
and the exemplar → Tempo trace pivot (`exemplarTraceIdDestinations` on the Tempo
datasource) for the metric → exemplar → trace → log drill-down.

## References

- [OpenTelemetry Semantic Conventions — HTTP metrics][semconv]
- Shared-memory layout + histograms: `src/shm.rs`
- Metrics emission + attributes: `src/metric_source/instrumented.rs`, `src/encoder/mod.rs`
- Logs: `src/logs/{access,ring,error_writer,coalesce,severity}.rs`; drain in `src/export/mod.rs`
- Traces: `src/metric_source/span_start.rs` (REWRITE), `src/metric_source/instrumented.rs` (LOG), `src/traces/mod.rs`, `src/metric_source/location_conf.rs`
- Configuration directives: see the project `README.md`

[semconv]: https://opentelemetry.io/docs/specs/semconv/http/http-metrics/
