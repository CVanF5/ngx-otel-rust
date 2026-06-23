# Configuration Reference — ngx-otel-rust

This is the complete directive reference for `ngx_http_otel_module`.

For the producer-side contract (every metric name, log record shape, span attribute,
and temporality), see **[`TELEMETRY_MODEL.md`](../TELEMETRY_MODEL.md)**.

---

## Table of contents

1. [Enabling the module](#1-enabling-the-module)
2. [otel_exporter block](#2-otel_exporter-block)
   - [endpoint](#endpoint)
   - [TLS sub-directives](#tls-sub-directives)
   - [Per-signal endpoint overrides](#per-signal-endpoint-overrides)
   - [Compatibility aliases](#compatibility-aliases)
3. [Top-level directives](#3-top-level-directives)
4. [Log export directives](#4-log-export-directives)
5. [Trace directives](#5-trace-directives)
6. [nginx variables](#6-nginx-variables)
7. [Span attributes](#7-span-attributes)

---

## 1. Enabling the module

```nginx
load_module modules/ngx_http_otel_module.so;
```

When `otel_exporter` is absent (or the block is present but empty) the module
is completely inert — no log-phase handler is registered, no exporter process
is spawned, and no per-request work runs.

---

## 2. `otel_exporter` block

```nginx
http {
    otel_exporter {
        endpoint http://127.0.0.1:4318;
    }
}
```

The block is valid in the `http` context only. One `otel_exporter` block per
config. `endpoint` is mandatory when the block is present.

### `endpoint`

| | |
|---|---|
| **Context** | `otel_exporter` |
| **Required** | Yes (the block is a no-op without it) |

Base URL for the OTLP collector.

- **OTLP/HTTP** (`otlp_http`, the default): any of `http://`, `https://`, or
  `unix:`. The module appends `/v1/metrics`, `/v1/logs`, `/v1/traces`
  automatically (matching the OTel spec `OTEL_EXPORTER_OTLP_ENDPOINT`
  semantics). Example: `http://127.0.0.1:4318`.
- **OTLP/gRPC** (`otlp_grpc`): `http://host:port` or `https://host:port`.
  Path is irrelevant; routing is by gRPC service method.
- **Unix socket** (OTLP/HTTP only): `unix:/run/otel-collector.sock`. The
  module appends `/v1/…` paths as with HTTP.

For DNS-name endpoints, a `resolver` directive must be present in the `http`
block; literal IPv4/IPv6 and `unix:` paths skip DNS and do not require one.

### TLS sub-directives

These sub-directives take effect when `endpoint` uses `https://`; they have no
effect for `http://` or `unix:` endpoints.

| Directive | Default | Description |
|---|---|---|
| `trusted_certificate <path>` | System trust store | PEM file (single CA or chain) to validate the collector's server certificate. When absent, `SSL_CTX_set_default_verify_paths` loads the OS default trust store. |
| `ssl_certificate <path>` | (none — mTLS disabled) | Client certificate chain for mTLS. PEM file. Must be set together with `ssl_certificate_key`. |
| `ssl_certificate_key <path>` | (none — mTLS disabled) | Client private key for mTLS. PEM file. Must be set together with `ssl_certificate`. |
| `ssl_verify on\|off` | `on` | `off` disables collector certificate verification. **INSECURE — for testing only.** A config-time WARN is emitted when `off`. |

Key behaviours:

- Server certificate verification is enforced by default. A TLS mismatch causes
  handshake failures, `send_failed` error-log alerts, and retry backoff — no data
  is delivered; nginx continues serving normally.
- Hostname verification: DNS-name endpoints use `X509_VERIFY_PARAM_set1_host`;
  IP-literal endpoints (e.g. `https://127.0.0.1:4317`) use
  `X509_VERIFY_PARAM_set1_ip_asc`.
- mTLS: set both `ssl_certificate` and `ssl_certificate_key` together. Setting
  only one is a config-time error.
- SIGHUP reload: the new exporter generation reads the current paths at reload
  time, so cert/CA rotation takes effect on reload.
- gRPC over TLS: when `endpoint` is `https://` and `otel_export_protocol
  otlp_grpc` is set, `h2` is negotiated via ALPN automatically.
- Minimum OpenSSL version: 1.1.1. See [`OPENSSL_SUPPORT.md`](../OPENSSL_SUPPORT.md).

### Per-signal endpoint overrides

Used as-is (no path appended), matching `OTEL_EXPORTER_OTLP_{SIGNAL}_ENDPOINT`.
Optional; the base `endpoint` with its auto-appended path applies when absent.

| Sub-directive | Default |
|---|---|
| `metrics_endpoint <url>` | (derived from `endpoint`) |
| `logs_endpoint <url>` | (derived from `endpoint`) |
| `traces_endpoint <url>` | (derived from `endpoint`) |

### Compatibility aliases

These sub-directives are accepted inside `otel_exporter {}` for config
compatibility with the C++ [`nginx/nginx-otel`](https://github.com/nginx/nginx-otel)
module. Equivalent top-level directives also exist.

| Sub-directive | Equivalent to | Notes |
|---|---|---|
| `header <name> <value>` | `otel_exporter_header <name> <value>` | Sets an HTTP request header on every export request. |
| `interval <time>` | `otel_metric_interval <time>` | nginx time string (`5s`, `500ms`, `1m`, …). Default `5s`. |
| `batch_size <n>` | (no effect) | Accepted for compatibility; logged as `[warn]`. This module uses a fixed-size ring. |
| `batch_count <n>` | (no effect) | Accepted for compatibility; logged as `[warn]`. |

---

## 3. Top-level directives

All of these are valid in the `http` context unless noted otherwise.

### `otel_export_protocol`

| | |
|---|---|
| **Context** | `http` |
| **Syntax** | `otel_export_protocol otlp_http \| otlp_grpc;` |
| **Default** | `otlp_http` |

Selects the OTLP wire transport.

- `otlp_http` (default): OTLP/HTTP over HTTP/1.1. `POST /v1/{signal}`.
- `otlp_grpc`: OTLP/gRPC unary over HTTP/2. Routing is by gRPC service method;
  `https://` endpoints negotiate `h2` via ALPN.

### `otel_service_name`

| | |
|---|---|
| **Context** | `http` |
| **Syntax** | `otel_service_name <name>;` |
| **Default** | `"unknown_service:nginx"` |

Sets the `service.name` OTel resource attribute. Matches the default used by
the C++ `nginx/nginx-otel` module.

### `otel_resource_attr`

| | |
|---|---|
| **Context** | `http` |
| **Syntax** | `otel_resource_attr <key> <value>;` |
| **Default** | (none) |

Adds a custom key/value pair to the OTel resource. Repeatable; each directive
appends one entry. Example: `otel_resource_attr deployment.environment production;`.

### `otel_exporter_header`

| | |
|---|---|
| **Context** | `http` |
| **Syntax** | `otel_exporter_header <name> <value>;` |
| **Default** | (none) |

Adds an HTTP request header to every outbound export request. Repeatable.
The `header` sub-directive inside `otel_exporter {}` is an alias for this.
Useful for authorization tokens: `otel_exporter_header authorization "Bearer …";`.

### `otel_metric_interval`

| | |
|---|---|
| **Context** | `http` |
| **Syntax** | `otel_metric_interval <time>;` |
| **Default** | `5s` |

How often the exporter drains and exports metrics. Accepts nginx time strings
(`5s`, `500ms`, `1m`, etc.). Matches the OTel SDK default and the `interval`
alias inside `otel_exporter {}`.

### `otel_metrics`

| | |
|---|---|
| **Context** | `http` |
| **Syntax** | `otel_metrics on \| off;` |
| **Default** | `on` |

Enables or disables all metric collection and export. Set `off` to suppress
metric emission entirely — for example, when migrating from the C++
`nginx/nginx-otel` module (which is traces-only). Does not affect traces or log
export.

When `off`, the per-worker metrics shared-memory zone is not allocated, worker
histogram increments are skipped, and the exporter's metrics drain loop does
not run.

### `otel_metric_status_code_class`

| | |
|---|---|
| **Context** | `http` |
| **Syntax** | `otel_metric_status_code_class on \| off;` |
| **Default** | `on` |

When `on` (the default), the `http.server.request.duration` histogram is
broken down by `http.request.method`, `http.response.status_class`, and
`network.protocol.version`. When `off`, a single unattributed data point is
emitted instead, reducing metric series count at the cost of less granularity.

### `otel_metric_zone`

| | |
|---|---|
| **Context** | `http` |
| **Syntax** | `otel_metric_zone <name> <size>;` |
| **Default** | (absent — auto-sized) |

**Optional tuning override.** Most deployments never need this directive.

When absent, the metrics shared-memory zone is auto-sized from `worker_processes`
and named `ngx_http_otel_zone`. The configured size is clamped to at least the
auto-computed minimum (`max(configured, required)`), so it can only enlarge the
zone, never shrink it. The name is the nginx shm-zone label and is not
referenced by any other directive.

Use this only if the auto-sized zone is too small for an unusually large
`worker_processes` count or a non-standard shm layout.

Example: `otel_metric_zone my_otel_zone 10m;`

---

## 4. Log export directives

### `otel_log_export`

| | |
|---|---|
| **Context** | `http`, `server`, `location` |
| **Syntax** | `otel_log_export on \| off \| if=<expr>;` |
| **Default** | absent (no records exported) |

Selects which requests produce an exception-tail `LogRecord`. Three forms:

- `on` (or bare `otel_log_export;`): export every request.
- `if=<expr>`: export when the complex value is truthy (non-empty and not `"0"`).
  The value may be any nginx variable expression, including one produced by a
  `map` block. Example for 4xx/5xx only:
  ```nginx
  map $status $otel_export_tail {
      default  "";   # 1xx/2xx/3xx — not exported
      ~^[45]   1;    # 4xx and 5xx — exported
  }
  otel_log_export if=$otel_export_tail;
  ```
- `off` or absent: no records are exported (the default, privacy-safe).

Innermost block wins on merge (`location` > `server` > `http`). Orthogonal to
nginx's own `access_log` directive — core `access_log on|off` has no effect on
this directive.

Note: metric exemplars (trace-linked `trace_id`/`span_id` pointers on the
duration histogram) are not controlled by `otel_log_export`; they ride on
`otel_trace` sampling.

### `otel_log_ring_size`

| | |
|---|---|
| **Context** | `http` |
| **Syntax** | `otel_log_ring_size <size>;` |
| **Default** | `512k` |

Per-worker ring capacity in bytes backing the exception-tail log record buffer.
Actual shared-memory cost is `size × 2 × N workers` (two rings per worker slot:
access + error). Raise for high-RPS deployments where per-worker loss is observed
(`ngx_otel.logs.access.dropped_records`). Must be a positive multiple of 8.

### `otel_error_log`

| | |
|---|---|
| **Context** | `http` |
| **Syntax** | `otel_error_log [<level>];` |
| **Default** | absent (error-log export disabled) |

Enables OTel error-log export. Inserts a writer node into nginx's `error_log`
chain and emits coalesced `LogRecord`s (one sample + count per distinct error
template) plus a companion `ngx_otel.error_log.events` rate counter.

- Bare (`otel_error_log;`): fixed severity floor `error` (NGX_LOG_ERR = 4).
  Intentionally decoupled from the core `error_log` level.
- With level argument: e.g. `otel_error_log warn;`. Accepted levels: `emerg`,
  `alert`, `crit`, `error`, `warn`, `notice`, `info`, `debug`.

### `otel_error_log_coalesce`

| | |
|---|---|
| **Context** | `http` |
| **Syntax** | `otel_error_log_coalesce on \| off;` |
| **Default** | `on` |

When `on` (the default), repeated error messages with the same template are
coalesced into a single `LogRecord` carrying a `coalesced_count` field — a
firehose of repeated errors becomes "count + representative sample".

When `off`, every level-passing error line is pushed verbatim to the bounded
ring. **This is best-effort, not guaranteed delivery**: the ring drops the newest
entries under load; dropped lines are counted in
`ngx_otel.logs.error.dropped_records` but are unrecoverable. The companion
error-rate metric counts the true total in both modes. The only guaranteed
full-fidelity transcript is nginx's own (untouched) `error_log` file.

---

## 5. Trace directives

All trace directives are valid in `http`, `server`, and `location` contexts.
The innermost block wins on merge.

### `otel_trace`

| | |
|---|---|
| **Context** | `http`, `server`, `location` |
| **Syntax** | `otel_trace <complex-value>;` |
| **Default** | absent (tracing disabled for this location, zero cost) |

Enables tracing. A complex value: `on`, `off`, a variable (`$var`), or the
output of a `split_clients` directive for ratio sampling.

When absent, the REWRITE-phase handler exits immediately with no allocation.

### `otel_trace_context`

| | |
|---|---|
| **Context** | `http`, `server`, `location` |
| **Syntax** | `otel_trace_context ignore \| extract \| inject \| propagate;` |
| **Default** | `extract` |

W3C `traceparent` propagation mode:

- `extract` (default): read the inbound `traceparent` header; do not write an
  outbound header.
- `inject`: write a fresh outbound `traceparent`; do not read inbound.
- `propagate`: read inbound and write outbound.
- `ignore`: neither read nor write.

### `otel_span_name`

| | |
|---|---|
| **Context** | `http`, `server`, `location` |
| **Syntax** | `otel_span_name <complex-value>;` |
| **Default** | `"METHOD location_name"` |

Per-location span name override. Evaluated as a complex value (nginx variables
are expanded). Example: `otel_span_name "API $request_method";`.

### `otel_span_attr`

| | |
|---|---|
| **Context** | `http`, `server`, `location` |
| **Syntax** | `otel_span_attr <key> <value>;` |
| **Default** | (none) |

Adds a custom attribute to every span from this location. Repeatable; multiple
directives accumulate. Inner location wins (attributes are not inherited from
outer blocks).

---

## 6. nginx variables

These variables are registered unconditionally in `preconfiguration` and usable
anywhere nginx accepts a complex value: `access_log` format strings, `if=`
conditions, `otel_span_name`, `map` blocks, etc.

| Variable | Value |
|---|---|
| `$otel_trace_id` | 32-char lowercase hex trace ID of the current span. Empty when tracing is not enabled for this request. |
| `$otel_span_id` | 16-char lowercase hex span ID of the current span. Empty when tracing is not enabled. |
| `$otel_parent_id` | 16-char lowercase hex parent span ID from the inbound `traceparent` header. `0000000000000000` (all-zero hex) for root spans (no inbound parent). Empty only when tracing is not enabled. |
| `$otel_parent_sampled` | `"1"` when this request is sampled; `"0"` when a span context exists but the W3C sampled bit is unset (traced-but-unsampled). Empty only when tracing is not enabled (no span context). |

`$otel_parent_sampled` reflects the sampling state of **this** request, not
just whether a parent was sampled. It is `"1"` for sampled spans (including
freshly-generated root spans), `"0"` for traced-but-unsampled requests, and
empty only when tracing is disabled (no span context for the request).

---

## 7. Span attributes

Standard [OTel HTTP semconv][http-spans-semconv] attributes recorded on every
span. All attribute keys are current semconv names (v1.21+).

For the full attribute table with notes on conditional attributes (e.g.
`network.peer.*` depending on the realip module), see
[`TELEMETRY_MODEL.md` — Span attributes](../TELEMETRY_MODEL.md#span-attributes).

In brief, every span carries:

| Attribute | Value |
|---|---|
| `http.request.method` | HTTP method (`GET`, `POST`, …) |
| `url.path` | request URI path (≤ 64 bytes; path only, no query string) |
| `url.query` | query string without the leading `?` (≤ 128 bytes; omitted when absent) |
| `http.response.status_code` | integer HTTP status code |
| `http.route` | matched `location` block name (≤ 128 bytes; omitted when absent) |
| `url.scheme` | `"http"` or `"https"` |
| `network.protocol.version` | `"1.0"`, `"1.1"`, `"2"`, or `"3"` |
| `user_agent.original` | `User-Agent` header (≤ 128 bytes; omitted when absent) |
| `http.request.body.size` | request body bytes (`Content-Length`; `0` when absent) |
| `http.response.body.size` | response body bytes sent (headers excluded) |
| `server.address` | server name from the matched virtual host (≤ 64 bytes) |
| `server.port` | local listening port (integer; omitted when absent) |
| `client.address` | logical client IP, realip-aware |
| `client.port` | logical client port (integer) |
| `network.peer.address` | true TCP socket peer address (absent when realip module not compiled in) |
| `network.peer.port` | true TCP socket peer port (absent when realip module not compiled in) |
| `error.type` | HTTP status as string (e.g. `"503"`; present only when status ≥ 500) |
| `http.server.request.duration` | request duration in seconds (enables metric→exemplar→span drill-down) |
| Custom attrs | from `otel_span_attr` directives, per-location |

[http-spans-semconv]: https://opentelemetry.io/docs/specs/semconv/http/http-spans/
