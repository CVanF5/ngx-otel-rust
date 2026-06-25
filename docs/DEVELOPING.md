# Developing

## Directory layout

```
../ngx-rust/   ← patched ngx-rust fork (branch ngx-otel-rust-deadlock-fix)
../nginx/      ← NGINX source checkout
ngx-otel-rust/ ← this repo
```

The Makefile defaults (`NGINX_SOURCE_DIR=../nginx`) and `.cargo/config.toml`
both expect sibling checkouts at these paths. Override via env vars if your
layout differs.

## First-time setup

```sh
# 1. Build nginx + debug module once (populates objs-debug/ and target/debug/).
make build

# 2. After that, rust-analyzer and bare `cargo check` / `cargo test` work
#    without going through make, because .cargo/config.toml supplies the
#    NGINX_SOURCE_DIR and NGINX_BUILD_DIR defaults automatically.
```

`.cargo/config.toml` contains `[env]` defaults pointing to the debug tree
(`NGINX_BUILD_DIR = "objs-debug"`). These defaults do NOT override variables
already set in the environment, so Makefile targets always win.

## Canonical test commands

```sh
make check             # rustfmt + clippy (zero warnings required)
make unittest          # cargo test --lib  (debug profile, objs-debug tree)
make unittest-release  # cargo test --release --lib  (release profile, objs-release tree)
make test              # bash integration suite (pins BUILD=release; see note below)
```

`make unittest-release` requires `make build-release` to have been run first
(to populate `objs-release/`).

`make test` always pins `BUILD=release` so the nginx binary, `NGINX_BUILD_DIR`,
and the cargo `--release` artifact are all from the same release pairing
(production-identical). For a debug-pairing integration run (e.g. to exercise
nginx debug assertions), use `BUILD=debug make test` — but note this writes a
release-profile `nginx-sys` artifact to `target/release` built against the
debug nginx tree, which poisons the cache for the next `make build-release`;
run `cargo clean` before `make build-release` afterward (the build-flavor guard
will flag the mismatch if you forget).

## Build-flavor guard

A build-time guard in `build.rs` enforces that the cargo profile and the nginx
tree flavor agree:

- **release profile + `--with-debug` nginx tree → hard error** (names the
  remedy). This is the hazard that `.cargo/config.toml`'s `objs-debug` default
  creates: bare `cargo test --release --lib` is blocked. Use
  `make unittest-release` instead.
- **debug profile + non-debug nginx tree → warning only** (unusual; tests still
  work, just without nginx's debug assertions).

Escape hatch (intentional cross-link): set `NGX_OTEL_ALLOW_FLAVOR_MISMATCH=1`.
Run `cargo clean` afterward to purge the stale release cache.

## Project layout

```
ngx-otel-rust/
├── auto/rust              # vendored ngx-rust shell library for autoconf integration
├── build/                 # per-flavor make includes (debug, release, sanitize, compat-*)
├── config                 # NGINX module config (sourced by auto/configure)
├── config.make            # NGINX module Makefile fragment
├── Makefile               # top-level entry: build / check / test / unittest
├── Cargo.toml
├── build.rs               # NGINX feature detection, prost-build for proto files
├── proto/                 # vendored OpenTelemetry proto sources: common, resource,
│                          # metrics, logs, trace + their collector service protos
│                          # (metrics/logs/trace _service); echo/ for the gRPC bidi smoke
├── src/
│   ├── lib.rs             # module declaration, init_process, exit_process, zero-cost-when-disabled invariant
│   ├── config.rs          # directives, MainConfig, old_config accessor for SIGHUP reload
│   ├── shm.rs             # per-worker shm slot setup, atomic increment helpers
│   ├── data_model/        # OTel-abstract types (Histogram / Sum / Gauge variants)
│   ├── metric_source/     # MetricSource trait + StubStatusSource + InstrumentedSource
│   ├── encoder/           # Encoder trait + OTLP/HTTP protobuf encoder
│   ├── transport/         # Transport trait; hyper_http.rs (OTLP/HTTP async),
│   │                      # grpc/ (OTLP/gRPC unary production transport + bidi
│   │                      # smoke harnesses on a runtime-less h2 executor)
│   ├── exporter/          # dedicated "nginx: otel exporter" process: control_shm
│   │                      # (flags + heartbeat), worker->exporter channel
│   ├── export/            # export loop, graceful drain, retry buffer,
│   │                      # SelfMetricsSource (13 self-metrics incl. exporter.restarts)
│   ├── traces/            # span instrumentation, W3C traceparent, sampling
│   ├── logs/              # access and error log record assembly
│   ├── processor/         # exporter-pipeline Processor (drain→process→encode; e.g. probe_drop span filter)
│   ├── shim/              # C shims for nginx struct fields (bindgen workarounds)
│   ├── cert_table.rs      # TLS certificate table (serving-cert + collector-cert gauges)
│   ├── liveness.rs        # liveness helpers for the exporter process
│   └── util.rs            # shared utilities
├── tests/
│   ├── transport_integration.rs  # async transport integration test (test-support feature)
│   ├── transport_errors.rs       # error-path coverage
│   ├── integration/              # end-to-end bash scripts (pending Test::Nginx port)
│   │   ├── nginx.conf
│   │   ├── run.sh                # baseline: metrics arrive end-to-end
│   │   ├── run_reload.sh         # SIGHUP reload, exit_process flush, counter-reset
│   │   ├── run_endpoint_change.sh # endpoint swap across reload
│   │   ├── run_grpc_*.sh         # gRPC smoke / bidi / overload + production export
│   │   └── run_exporter_*.sh     # exporter lifecycle, crash-respawn, reload-overlap, heartbeat
│   └── bench/
│       ├── nginx_c1.conf         # no module loaded
│       ├── nginx_c2.conf         # module loaded, no exporter (zero-cost case)
│       ├── nginx_c3.conf         # module loaded + exporter configured
│       ├── zero_cost.sh          # zero-cost wrk benchmark harness, randomised iteration order
│       ├── analyse.sh            # tolerance assertion against committed JSON results
│       └── RESULTS.md            # zero-cost + soak results (isolated AWS EPYC + macOS arm64)
└── ...
```

## Integration tests

Race and memory-safety detection run the integration scripts under
**ThreadSanitizer** and **AddressSanitizer** (Linux arm64, dockerized).
Results are committed as evidence (`tests/RESULTS-{tsan,asan}-*.txt`):

```sh
make tsan-test        # full TSAN suite (all integration scripts under TSAN)
make tsan-test-dns    # DNS / dual-stack resolver+connect path only
make tsan-test-error  # error-log path only (writer → ring → drain)
make asan-test        # ASan use-after-free gate (executor wake/teardown paths)
```

The path-scoped gates (`-dns`, `-error`) exist because some scripts are
timing-flaky inside the combined suite under TSAN's slowdown; running a
single path in isolation gives a clean race signal.

`make test` requires a running OTel collector on `127.0.0.1:4318`
(OTLP/HTTP) and `127.0.0.1:4317` (OTLP/gRPC). Start (and stop) the
project's collector with:

```sh
make collector-up      # start the local OTel collector container (idempotent)
make collector-status  # show its status
make collector-down    # stop it
```

The integration scripts assert against metrics that arrive at the collector,
so any OTLP receiver will work. In development the project uses an
`otel/opentelemetry-collector-contrib:0.152.0` Docker container with HTTP +
gRPC receivers and debug + file exporters.

Direct bash invocation (for debugging a specific test):

```sh
export NGINX_SOURCE_DIR=/path/to/nginx \
       NGINX_BUILD_DIR=/path/to/nginx/objs
bash tests/integration/run.sh                        # metrics arrive end-to-end (OTLP/HTTP)
bash tests/integration/run_reload.sh                 # SIGHUP reload + counter-reset
bash tests/integration/run_grpc_export.sh            # production OTLP/gRPC export path
bash tests/integration/run_access_log.sh             # access exception tail + exemplars
bash tests/integration/run_error_log.sh              # coalesced error log + rate metric
bash tests/bench/zero_cost.sh                        # zero-cost-when-disabled (~10 min)
bash tests/bench/analyse.sh                          # re-derive tolerance check from JSON
```

There are 36 `run_*.sh` scripts in `tests/integration/` covering reload,
endpoint changes, gRPC variants, exporter lifecycle, crash-respawn, DNS/IPv6,
TLS, signal handling, and more. Run any script directly with
`bash tests/integration/run_<name>.sh`.

The bash integration scripts are due to be ported to Perl [`Test::Nginx`]
(see [Project layout](#project-layout) above); after that `make test` will drive
`prove -I $(NGINX_TESTS_DIR)/lib t/`. The load-driver scripts
(`tests/bench/*.sh`) stay bash — Test::Nginx isn't a good fit for
`wrk`-driven benchmarks.

[`Test::Nginx`]: https://github.com/openresty/test-nginx
