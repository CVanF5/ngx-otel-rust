# Migrating from nginx/nginx-otel to ngx-otel-rust

This guide covers the differences between the C++ [`nginx/nginx-otel`][cpp-module]
module and this module, and what — if anything — you need to change in your
nginx config, dashboards, and alerts.

**TL;DR.** For most users:

1. Replace the module binary.
2. Add `otel_metrics off;` inside `http {}` if you want traces only (this
   module also emits metrics by default).
3. Rename span attribute keys in your trace queries and dashboards
   (one-time 1:1 substitution — see the table below).

Config syntax is a config-level drop-in: your existing `otel_exporter {}` block,
`otel_trace`, `otel_span_name`, `otel_span_attr`, and `otel_trace_context`
directives load without modification.

[cpp-module]: https://github.com/nginx/nginx-otel

---

## Contents

1. [Span attribute renames](#1-span-attribute-renames)
2. [Additional span attributes](#2-additional-span-attributes)
3. [Span name default](#3-span-name-default)
4. [`otel_trace_context` default](#4-otel_trace_context-default)
5. [`otel_trace` truthiness](#5-otel_trace-truthiness)
6. [`tracestate` propagation](#6-tracestate-propagation)
7. [`batch_size` / `batch_count`](#7-batch_size--batch_count)
8. [Metrics — enabling or disabling](#8-metrics--enabling-or-disabling)
9. [Architecture differences](#9-architecture-differences)

---

## 1. Span attribute renames

The C++ module was written against OTel HTTP semconv **v1.16.0**, whose attribute
names were deprecated at v1.21 and replaced with new ones. This module uses the
**current semconv names** and does not emit the deprecated keys. The data is
equivalent; only the names changed.

This is a one-time, 1:1 rename in your trace queries and dashboards — no data is
lost or altered.

| C++ attribute (deprecated v1.16.0) | Current attribute | Notes |
|---|---|---|
| `http.method` | `http.request.method` | Same value |
| `http.target` | `url.path` + `url.query` | C++ concatenated path and query; this module emits them as two separate attributes (`url.path` = path only, `url.query` = query string without the leading `?`) |
| `http.status_code` | `http.response.status_code` | Same value (integer) |
| `http.route` | `http.route` | **Unchanged** — same key, same value |
| `http.scheme` | `url.scheme` | Same value (`"http"` or `"https"`) |
| `http.flavor` | `network.protocol.version` | Value format changed: `"1.0"`, `"1.1"`, `"2"`, `"3"` (C++ prefixed with `"HTTP/"`, e.g. `"HTTP/1.1"`) |
| `http.user_agent` | `user_agent.original` | Same value; capped at 128 bytes |
| `http.request_content_length` | `http.request.body.size` | Same value (integer bytes) |
| `http.response_content_length` | `http.response.body.size` | Same value (integer bytes; headers excluded, matching C++ semantics) |
| `net.host.name` | `server.address` | Same value |
| `net.host.port` | `server.port` | Same value (integer) |
| `net.sock.peer.addr` | `network.peer.address` | See note below |
| `net.sock.peer.port` | `network.peer.port` | See note below |

**`network.peer.address` / `network.peer.port` — realip interaction.** These
attributes represent the **true TCP socket peer** (the immediate machine the
connection arrived from), distinct from the logical client address.

- When nginx's `realip` module **is active** (compiled in *and* a
  `set_real_ip_from` rule matches), it rewrites the connection address in place
  to the real client, so `network.peer.address` is the proxy's address (read
  from the saved original via `$realip_remote_addr`) while `client.address`
  (see next section) is the real client IP — they differ.
- When `realip` is **inactive or not compiled in**
  (`--without-http_realip_module`), `network.peer.address` / `network.peer.port`
  are read directly from the connection socket peer and are **still present** —
  and, with no intermediary to distinguish, equal `client.address`. They are
  omitted only when the connection peer address is genuinely unavailable.

**OTel semconv reference:**
[HTTP spans — attributes](https://opentelemetry.io/docs/specs/semconv/http/http-spans/)

---

## 2. Additional span attributes

This module sets the following current-semconv attributes on every span
automatically (no configuration needed):

| Attribute | Value | Notes |
|---|---|---|
| `client.address` | Logical client IP (realip-aware; equivalent to nginx's `$remote_addr`) | Always present |
| `client.port` | Logical client port | Always present |
| `error.type` | HTTP status code as a string (e.g. `"503"`) | Present only when the response status is ≥ 500; absent on 2xx/3xx/4xx (per OTel HTTP semconv: server spans treat only 5xx as errors) |

These appear in your trace UI alongside the renamed attributes above; they
require no configuration to enable.

---

## 3. Span name default

The C++ module defaults the span name to the **bare location name** (e.g.
`"/api"`). This module defaults to `"METHOD route_name"` (e.g. `"GET /api"`).

If your dashboards or trace queries filter by span name, update them to the new
`"METHOD route"` format, **or** restore the C++ behaviour per location with:

```nginx
otel_span_name "$request_method $uri";
```

Or set an explicit name that matches your existing convention:

```nginx
otel_span_name "/api";
```

`otel_span_name` supports nginx complex values (variables are expanded at
request time).

---

## 4. `otel_trace_context` default

The C++ module defaults `otel_trace_context` to `ignore` (neither reads nor
writes `traceparent`). This module defaults to `extract` (reads an inbound
`traceparent` but does not inject one outbound).

For most deployments this makes no difference: if there is no inbound
`traceparent`, `extract` behaves the same as `ignore`. However, if you
explicitly relied on the `ignore` default — for example, to ensure no inbound
header can influence trace context — add this directive:

```nginx
otel_trace_context ignore;
```

---

## 5. `otel_trace` truthiness

The C++ module treats `otel_trace <expr>` as enabled only when the evaluated
value is exactly `"on"` or `"1"`. This module treats it as enabled for any
**non-empty** value that is not `"0"` or `"off"`.

In practice the common `split_clients` pattern is unaffected — `"on"` and `"off"`
are truthy/falsy on both. The edge case is a custom non-standard value like
`"yes"` or `"true"`: on this module that would enable tracing; on C++ it would
not.

If your `split_clients` map produces only `"on"` and `"off"` (or empty and
`"on"`, or `"1"` and `"0"`), there is no difference.

---

## 6. `tracestate` propagation

The C++ module extracts and re-injects the W3C `tracestate` header alongside
`traceparent`. **This module propagates `traceparent` only; `tracestate` is
not extracted or forwarded.** For most deployments running Jaeger, Zipkin, or a
standard OTLP-native collector, `tracestate` is not required and this is
harmless.

If your tracing infrastructure uses `tracestate` for vendor-specific data
(for example, Datadog's `_dd` propagation), those fields will not be carried
through nginx when using this module. Full `tracestate` support is on the
implementation roadmap.

---

## 7. `batch_size` / `batch_count`

Both sub-directives are accepted inside `otel_exporter {}` for config
compatibility, but they have no effect on this module:

```nginx
otel_exporter {
    endpoint http://collector:4318;
    batch_size  512;   # accepted, ignored — this module uses a fixed ring buffer
    batch_count 4;     # accepted, ignored — same reason
}
```

A `[warn]` log line is emitted at config-load time for each directive to
confirm it was parsed but not acted on. You can remove both directives safely;
there is no knob to replace them with.

---

## 8. Metrics — enabling or disabling

This module emits metrics and logs in addition to traces, with metrics on by
default whenever `otel_exporter` is configured.

To emit traces only, add:

```nginx
http {
    otel_metrics off;
    ...
}
```

`otel_metrics off` suppresses all metric emission (no shm zone allocation, no
worker-side histogram bumps, no exporter metrics drain loop) while leaving
traces and logs fully operational. Metrics remain on by default for users who
want the full observability picture.

---

## 9. Architecture differences

Both modules spawn a background process to handle OTel export so that worker
processes never hold a collector connection. The implementation differs:

| Aspect | C++ `nginx-otel` | This module |
|---|---|---|
| Export model | One background thread per worker process (`BatchSpanExporter` + `grpc++`) | One dedicated child process (`nginx: otel exporter`) shared by all workers via shared memory |
| Inter-process coupling | None — each worker exports independently | Per-worker shared-memory rings; exporter reads all workers |
| OS footprint | N extra threads (one per worker) | One extra process + shared memory zones |
| Signals | Traces only | Metrics + logs + traces |

The shared-memory architecture is invisible to the nginx config. All
`otel_exporter {}` sub-directives, `otel_service_name`, and `otel_resource_attr`
work identically.

The metrics shared-memory zone and the per-worker log rings are auto-sized
(from `worker_processes` and a fixed 512k default, respectively) with no
operator-facing tuning directive. Neither auto-sizing knob corresponds to any
C++ `nginx-otel` directive, so drop-in config compatibility is unaffected.

---

## Quick-reference: config diff for a traces-only C++ user

```nginx
# BEFORE (C++ nginx-otel)
load_module modules/ngx_http_otel_module.so;

http {
    otel_exporter {
        endpoint http://collector:4318;
        batch_size 512;
        batch_count 4;
        header authorization "Bearer ...";
    }
    otel_service_name my-nginx;

    server {
        otel_trace on;
        # otel_trace_context not set → defaults to "ignore" in C++

        location /api {
            otel_span_name "/api";
        }
    }
}

# AFTER (ngx-otel-rust, preserving identical behaviour)
load_module modules/ngx_http_otel_module.so;

http {
    otel_exporter {
        endpoint http://collector:4318;
        batch_size 512;   # still accepted; now logged as ignored
        batch_count 4;    # same
        header authorization "Bearer ...";
    }
    otel_service_name my-nginx;
    otel_metrics off;   # add this to suppress metric emission (C++ had no metrics)

    server {
        otel_trace on;
        otel_trace_context ignore;   # add this to match C++ default (our default is "extract")

        location /api {
            otel_span_name "/api";   # keep for span-name compatibility (our default is "GET /api")
        }
    }
}
```

And rename these keys in your Tempo queries / Grafana panels (one-time):

| Find | Replace with |
|---|---|
| `http.method` | `http.request.method` |
| `http.target` | `url.path` (and `url.query` for the query string) |
| `http.status_code` | `http.response.status_code` |
| `http.scheme` | `url.scheme` |
| `http.flavor` | `network.protocol.version` |
| `http.user_agent` | `user_agent.original` |
| `http.request_content_length` | `http.request.body.size` |
| `http.response_content_length` | `http.response.body.size` |
| `net.host.name` | `server.address` |
| `net.host.port` | `server.port` |
| `net.sock.peer.addr` | `network.peer.address` |
| `net.sock.peer.port` | `network.peer.port` |
