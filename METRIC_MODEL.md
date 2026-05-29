# ngx-otel-rust — Metric Model

This document defines the metrics the module emits, in the style of the
[OpenTelemetry Semantic Conventions for metrics][semconv]. It is the
producer-side contract: metric names, instruments, units, temporality, and
the attribute set the OTAP collector dictionary-encodes downstream
(proposal §6.4, "Producer-side cardinality discipline").

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

> The duration defect fixed in `RALPH_METRICS_CORRECTNESS.md` was a *drift*
> from the avr model: `LogPhaseHandler` reimplemented request duration as
> `ngx_current_msec - r->start_msec` instead of avr's `get_request_time`.
> This doc exists so that lineage is not lost again.

## Resource and scope

| Field | Value | Source |
|---|---|---|
| Resource `service.name` | from `otel_service_name` directive | `src/config.rs` |
| Resource (extra) | from `otel_resource_attr` k/v pairs | `src/export/mod.rs` |
| Instrumentation scope name | `ngx-otel-rust` | `src/export/mod.rs:691` |
| Instrumentation scope version | crate version (`CARGO_PKG_VERSION`, currently `0.1.0`) | `src/export/mod.rs:692` |

## Aggregation temporality

All instrumented `http.*` metrics are aggregated per-worker in shared memory
as cumulative running totals (workers bump; the exporter snapshots without
resetting) and SHOULD be emitted **Cumulative** with a fixed
`start_time_unix_nano`, matching the `nginx.*` counters. The avr reference
aggregates into windowed time-slices (`trans_slice_bucket`); whether the
OTLP wire temporality should be Cumulative or Delta-windowed is tracked in
`RALPH_METRICS_CORRECTNESS.md` Sub-item 2.

> **Status (2026-05-29):** the `http.*` metrics currently emit `Delta`
> temporality with a zero `StartTimestamp` while carrying cumulative
> values — a mislabel under fix in `RALPH_METRICS_CORRECTNESS.md`. The
> tables below describe the *intended* model.

---

## HTTP server metrics

Derived per request in `LogPhaseHandler` (`src/metric_source/instrumented.rs`).
All are explicit-bucket **Histograms**.

### Metric: `http.server.request.duration`

Duration of HTTP server requests.

| Name | Instrument | Unit (UCUM) | Temporality | Stability | avr-module source |
|---|---|---|---|---|---|
| `http.server.request.duration` | Histogram | `ms` | Cumulative | experimental | `request_duration` ← `get_request_time` (`data_sources.c:10-13,99`) |

### Metric: `http.server.request.body.size`

Size of the HTTP request message body.

| Name | Instrument | Unit (UCUM) | Temporality | Stability | avr-module source |
|---|---|---|---|---|---|
| `http.server.request.body.size` | Histogram | `By` | Cumulative | experimental | `bytes_in` (`data_sources.h:78`) |

### Metric: `http.server.response.body.size`

Size of the HTTP response message body.

| Name | Instrument | Unit (UCUM) | Temporality | Stability | avr-module source |
|---|---|---|---|---|---|
| `http.server.response.body.size` | Histogram | `By` | Cumulative | experimental | `bytes_out` (`data_sources.h:79`) |

## HTTP upstream metrics

Recorded only when an upstream was used (`src/metric_source/instrumented.rs:101-115`),
from `ngx_http_upstream_state_t`.

### Metric: `http.server.upstream.response.duration`

Time from establishing the upstream connection to the last response byte.

| Name | Instrument | Unit (UCUM) | Temporality | Stability | avr-module source |
|---|---|---|---|---|---|
| `http.server.upstream.response.duration` | Histogram | `ms` | Cumulative | experimental | `uppstream_response_time` (`data_sources.h:88`) |

### Metric: `http.server.upstream.header.duration`

Time to first upstream response byte (TTFB).

| Name | Instrument | Unit (UCUM) | Temporality | Stability | avr-module source |
|---|---|---|---|---|---|
| `http.server.upstream.header.duration` | Histogram | `ms` | Cumulative | experimental | `uppstream_header_time` (`data_sources.h:86`) |

### Metric: `http.server.upstream.connect.duration`

Time to establish the upstream connection.

| Name | Instrument | Unit (UCUM) | Temporality | Stability | avr-module source |
|---|---|---|---|---|---|
| `http.server.upstream.connect.duration` | Histogram | `ms` | Cumulative | experimental | `uppstream_connect_time` (`data_sources.h:87`) |

### Metric: `http.server.upstream.bytes.received`

Bytes received from the upstream.

| Name | Instrument | Unit (UCUM) | Temporality | Stability | avr-module source |
|---|---|---|---|---|---|
| `http.server.upstream.bytes.received` | Histogram | `By` | Cumulative | experimental | `uppstream_bytes_received` (`data_sources.h:83`) |

### Metric: `http.server.upstream.bytes.sent`

Bytes sent to the upstream.

| Name | Instrument | Unit (UCUM) | Temporality | Stability | avr-module source |
|---|---|---|---|---|---|
| `http.server.upstream.bytes.sent` | Histogram | `By` | Cumulative | experimental | `uppstream_bytes_sent` (`data_sources.h:84`) |

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

## Attributes (planned — `fix3b` / proposal §6.4)

Data points are currently emitted with **no attributes**
(`src/metric_source/instrumented.rs:192-224`, `fix3b` TODO). The avr model
keys each transaction on the entity set below; the OTel port will attach
the bounded, semconv-aligned subset as data-point attributes once the
multi-dimensional histogram slots land. High-cardinality values stay
opt-in (`otel_metric_high_cardinality_attr`) so the collector-side
classifier can dictionary-encode at u8 key width.

| Attribute | Type | Requirement level | avr-module source (entity / lookup) |
|---|---|---|---|
| `http.request.method` | string (low-card) | Recommended | `method` → `avr_lookup_or_insert_method` (`output.c:144-148`) |
| `http.response.status_code` | int (or 5 status classes) | Recommended | `rcode`/`status` (`output.c:129-131`) |
| `network.protocol.version` | string (low-card) | Recommended | `http_version` (`output.c:132-134`) |
| `server.address` / host | string | Opt-in | `fqdn` → `avr_lookup_or_insert_id` (`output.c:150-154`) |
| `url.path` | string (high-card) | Opt-in | `url` → `avr_lookup_or_insert_url` (`output.c:138-142`) |
| `user_agent.original` | string (high-card) | Opt-in | `uagent` → `avr_lookup_or_insert_uagent` (`output.c:156-160`) |
| `client.address` | string (high-card) | Opt-in | `ip` → `avr_lookup_or_insert_ip` (`output.c:172-177`) |

## Histogram bucket boundaries

`src/shm.rs:32-42`.

- **Duration (`ms`)** — 14 boundaries + overflow:
  `5, 10, 25, 50, 75, 100, 250, 500, 750, 1000, 2500, 5000, 7500, 10000`
- **Byte sizes (`By`)** — 6 boundaries + overflow:
  `128, 512, 4096, 65536, 524288, 4194304`

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
| `uppstream_addr` | upstream peer address (dimension) |
| `is_ssl` | TLS yes/no (dimension) |

## References

- [OpenTelemetry Semantic Conventions — HTTP metrics][semconv]
- Reference model: `avr-module/src/ngx_http_avr_data_sources.{h,c}`,
  `ngx_http_avr_output.c`
- Producer-side cardinality discipline: proposal §6.4
- Open correctness items: `RALPH_METRICS_CORRECTNESS.md`

[semconv]: https://opentelemetry.io/docs/specs/semconv/http/http-metrics/
