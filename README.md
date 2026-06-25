# ngx-otel-rust

A Rust dynamic [NGINX] module on the [`ngx-rust`] SDK that emits OpenTelemetry
signals — metrics, logs, and traces — to an OTel collector over OTLP/HTTP or
OTLP/gRPC. The hot path (worker processes) does only lock-free, syscall-free
shared-memory writes; a dedicated `nginx: otel exporter` child process owns all
collector I/O. Every signal it emits is defined in
**[`TELEMETRY_MODEL.md`](TELEMETRY_MODEL.md)**, the producer-side contract.

[NGINX]: https://nginx.org/
[`ngx-rust`]: https://github.com/nginx/ngx-rust

## Status

**Phases 1–3 shipped: metrics, logs, and traces from a dedicated exporter
process; pre-upstream-PR.**

- **Metrics** (Phase 1, on by default): lock-free per-worker counters; dedicated
  exporter aggregates and exports once per window.
- **Access logs + exemplars** (Phase 2, `otel_log_export on | if=<expr>`):
  operator-selected `LogRecord`s plus trace-linked exemplars on the
  trace-sampling path.
- **Error logs** (Phase 2, `otel_error_log`): coalesced error `LogRecord`s with
  a companion error-rate counter.
- **Traces** (Phase 3, `otel_trace <expr>`): OTel server spans; W3C `traceparent`
  propagation; parent/ratio sampling; per-location span name and attributes;
  `$otel_trace_id`, `$otel_span_id`, `$otel_parent_id`, `$otel_parent_sampled`.

**Performance:** zero-cost-when-disabled verified at ≤ 0.01% throughput delta
(isolated AWS EPYC and macOS arm64); 24-hour soak at ~523k req/s, bounded
memory, clean collector-downtime recovery.

**NGINX Plus (Phase 4)** and **OTAP (Phase 5)** remain roadmap.

## Getting Started

### Requirements

- NGINX sources, 1.22.0 or later, as a sibling checkout at `../nginx`
  (override with `NGINX_SOURCE_DIR`). Tested against nginx 1.31.1.
- The **patched `ngx-rust` fork** at `../ngx-rust`:
  ```sh
  git clone -b ngx-otel-rust-deadlock-fix git@github.com:CVanF5/ngx-rust.git
  ```
  `Cargo.toml` path-pins `../ngx-rust`. Stock `nginx/ngx-rust` will fail with
  missing symbols. (Tracking upstream via `ngx-rust` PR #295.)
- Regular NGINX build dependencies: C compiler, `make`, PCRE2, Zlib.
- OpenSSL 1.1.1 or later (system-wide).
- Rust 1.85.0 or later (MSRV set by `ngx-rust`).
- `pkg-config` or `pkgconf`, `libclang`, `protoc`.
- Optional: Docker, for the local OTel collector the integration tests use.

On Debian/Ubuntu:

```sh
sudo apt install -y \
    libclang-dev libssl-dev libpcre2-dev zlib1g-dev \
    pkg-config build-essential protobuf-compiler
```

On macOS (Homebrew):

```sh
xcode-select --install                          # clang, make, libclang
brew install openssl@3 pcre2 pkg-config protobuf
```

Install Rust via [rustup](https://rustup.rs/).

> [!TIP]
> The module built against unmodified NGINX Open Source with `--with-compat` is
> compatible with a corresponding NGINX Plus release. See F5's guide on
> [compiling dynamic modules for NGINX Plus][nginx-plus-modules].

[nginx-plus-modules]: https://www.f5.com/company/blog/nginx/compiling-dynamic-modules-nginx-plus

### Building

```sh
cd ngx-otel-rust
make build          # debug; produces objs-debug/ and ngx_http_otel_module.so
make build-release  # release
make build-sanitize # ASan
```

This invokes `auto/configure --add-dynamic-module=$(CURDIR) --with-compat
--with-http_ssl_module --with-http_stub_status_module` against
`$(NGINX_SOURCE_DIR)`. Key overrides: `NGINX_SOURCE_DIR`, `BUILD`, `NGX_CARGO`.

> **`--with-http_stub_status_module`:** The seven `nginx.connections.*` /
> `nginx.requests.total` series require this flag. Without it they are absent
> from the export and a one-shot `[warn]` names the missing flag. A stub-enabled
> module loaded into a no-flag nginx fails `nginx -t` with
> `undefined symbol: ngx_stat_<...>`.

> **`--with-http_ssl_module`:** The `ngx_otel.tls.certificate.*` gauges require
> this flag. Without it they are absent and a one-shot `[notice]` explains why.

A faster prototyping path skips NGINX's re-link step:

```sh
export NGINX_SOURCE_DIR=$(realpath ../nginx)
export NGINX_BUILD_DIR=$(realpath ../nginx/objs)
cargo build --release
```

On macOS also export `OPENSSL_DIR OPENSSL_STATIC OPENSSL_NO_VENDOR` to avoid
embedding a different OpenSSL than nginx's. See [`OPENSSL_SUPPORT.md`](OPENSSL_SUPPORT.md).

### Running tests

```sh
make check       # rustfmt + clippy (zero warnings required)
make unittest    # cargo test --lib
make test        # bash integration suite (needs collector; see below)
```

`make test` requires a running OTel collector on `127.0.0.1:4318/4317`:

```sh
make collector-up    # start Docker collector (idempotent)
make collector-down  # stop it
```

## How to Use

Add `load_module` and an `otel_exporter` block. When `otel_exporter` is absent
the module is completely inert — no log-phase handler, no exporter process,
zero per-request work.

### Example 1: basic tracing

```nginx
load_module modules/ngx_http_otel_module.so;

http {
    otel_exporter { endpoint http://127.0.0.1:4318; }
    otel_service_name my-nginx;
    otel_trace on;

    server {
        location / { proxy_pass http://backend; }
    }
}
```

### Example 2: ratio / parent-based sampling

```nginx
http {
    otel_exporter { endpoint http://127.0.0.1:4318; }

    split_clients $otel_trace_id $ratio_sampler { 10% on; * off; }

    server {
        location /api {
            otel_trace         $ratio_sampler;
            otel_trace_context propagate;   # follow parent's sampling decision
            proxy_pass         http://backend;
        }
        location /healthz {
            otel_trace off;   # zero cost
            return 200 "ok\n";
        }
    }
}
```

`otel_trace_context propagate` reads the inbound `traceparent` header and
forwards it upstream. `$otel_parent_sampled` exposes the parent's sampling bit.

For the complete directive reference, defaults, TLS options, variables, and span
attributes see **[`docs/CONFIGURATION.md`](docs/CONFIGURATION.md)**.

## Signals

The full producer-side contract — every metric, log record, and trace with
names, units, attributes, and temporality — lives in
**[`TELEMETRY_MODEL.md`](TELEMETRY_MODEL.md)**. Build dashboards, alerts, or
pipelines against that file; you do not need the design proposal to integrate.

In brief: HTTP request duration as an OTel exponential histogram (seconds);
body sizes; upstream timing and byte histograms; nginx `stub_status` series;
TLS certificate expiry gauges; access-log exception tail with exemplars;
coalesced error log records; distributed traces; 13 exporter self-metrics.

A runnable end-to-end demo (NGINX + OTel collector + Grafana, TLS optional) lives
in **[`test-harness/demo/`](test-harness/demo/README.md)**, including a ready-made
[Grafana dashboard](test-harness/demo/grafana/dashboards/ngx-otel-rust-overview.json).

## Architecture

Workers do only lock-free, syscall-free shared-memory writes on the request
path. A dedicated `nginx: otel exporter` child process (spawned and respawned by
the nginx master) reads shared memory, encodes OTLP protobuf, and drives all
collector I/O through NGINX's own event loop — workers never open a collector
socket. Metrics and summary-logs aggregate inside each window and scale for free;
traces are per-request and cap at ~10k spans/s/worker before the ring drops
gracefully (observable via `ngx_otel.traces.dropped_records`).

Full design detail, the pipeline diagram, invariants, and scaling measurements:
**[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)**.

## Limitations

- **At-least-once delivery on retry.** A send failure after the collector already
  ingested a batch causes a re-send. Metrics are idempotent (cumulative
  snapshots); log and span duplicates are possible and require collector-side
  dedup. See [`TELEMETRY_MODEL.md` — Delivery semantics](TELEMETRY_MODEL.md#delivery-semantics).
- **Gen-1 exporter is unsupervised under `daemon on`.** The gen-1 exporter is
  orphaned to init after the daemonize double-fork; nginx cannot respawn it. Run
  `nginx -s reload` once after startup (gen-2 onward is fully supervised). The
  module logs an `[alert]` at startup. See [`LIFECYCLE.md`](LIFECYCLE.md).
- **Hot path is single-process-per-worker;** per-histogram attribute populations
  require multi-dimensional shm (deferred).

## Contributing / Developing

See **[`docs/DEVELOPING.md`](docs/DEVELOPING.md)** for directory layout,
first-time setup, canonical test commands, the build-flavor guard, TSAN/ASan
gates, and the full project-layout tree.

## Related

- **[`MIGRATING_FROM_NGINX_OTEL.md`](MIGRATING_FROM_NGINX_OTEL.md)** — this module is a
  config drop-in replacement for the C++
  [`nginx/nginx-otel`](https://github.com/nginx/nginx-otel); the guide covers config
  compatibility and the behavioral differences to expect.
- ACME module precedent: [`nginx/nginx-acme`](https://github.com/nginx/nginx-acme).
  Build-system shape (Makefile + `config` + `auto/rust` + `build/*.mk`) mirrors
  nginx-acme's; see commits `6f3133b`, `fdd521c`, `4555185`.
- OTAP: [`open-telemetry/otel-arrow`](https://github.com/open-telemetry/otel-arrow).

## License

Apache-2.0. See [`LICENSE`](LICENSE).
