# TLS and Certificate Metrics Research

*ngx-otel-rust — Design Research Report*
*Date: 2026-06-09 · Author: Claude (research agent)*

---

> **EMPIRICAL VERIFICATION — 2026-06-09 (debian-vm, Linux; clean rebuild with
> `--with-http_ssl_module`).** The "is `ngx_ssl_s` opaque?" question is RESOLVED:
> - ✅ `ngx_ssl_s.ctx: *mut SSL_CTX` **is exposed** with the flag (no `wrapper.h`
>   change, no C helper) — `ngx_core.h` pulls in `ngx_event_openssl.h` under
>   `NGX_OPENSSL`. `ngx_ssl_connection_s` and `ngx_http_ssl_module` are exposed too.
> - ❌ `ngx_http_ssl_srv_conf_t` is **still not emitted** (its header
>   `ngx_http_ssl_module.h` isn't in `wrapper.h`) — the *one* residual item for the
>   serving-cert feature. Fix is a **module-side C shim** (not a fork change).
> - The required nginx flag (`--with-http_ssl_module`) is a **Makefile/build-config
>   change, not a fork edit**. Net: HTTPS + exporter-side cert metrics are fully
>   unblocked; serving-cert enumeration is feasible with one small module C shim.
> See §2.4 item 2 for details/mechanism.

## Executive Summary

**Part 1 — HTTPS/TLS exporter transport.** The recommended approach is
`openssl-sys` direct (option b): wrap the existing `NgxConnIo` with an
`SSL` client session using `openssl-sys` functions, which are already a
direct dependency in `Cargo.toml:54`. The TLS layer sits between the raw
`NgxConnIo` bytes and hyper/tonic, yielding one `TlsNgxConnIo` type that
works for both transports. rustls is technically feasible (sync
`ClientConnection` + manual drive) but adds ~2 new crates and a
certificate-store question; nginx's own `ngx_ssl_*` API cannot be used
because `ngx_ssl_t` is an opaque ZST in the current generated bindings and
exposing its `SSL_CTX` field would require new nginx-sys bindings — a
frozen-fork blocker. The config surface already has a `trusted_certificate`
slot in `ExporterConfig` (`src/config.rs:92–93`). The https:// guard and
reject path exist in both `ParsedEndpoint::parse`
(`src/transport/hyper_http.rs:105–110`) and `MainConfig::postconfiguration`
(`src/config.rs:512–523`) — both are single-line removals when TLS is ready.
Effort: ~2–3 weeks solo.

**Part 2 — Certificate metrics.** OTel semconv has NOT standardized a
cert-expiry metric as of v1.41.1 (June 2026). The `tls.server.not_after`
attribute exists in the attribute registry but only as a span/log attribute —
not as a metric instrument. The recommended metric is a gauge
`ngx_otel.tls.certificate.not_after` (unit `s`, unix epoch int64) with
attributes drawn from the OTel `tls.*` namespace. **The more compelling
product feature is the serving-cert path** (the certs NGINX presents to
clients), not the exporter-connection cert. Serving-cert enumeration at
postconfiguration is feasible via `ngx_http_ssl_srv_conf_t.ssl.ctx` → OpenSSL
`SSL_CTX_get0_certificate` + `X509_getm_notAfter` — all available in
`openssl-sys-0.9.114`. The critical **frozen-fork blocker** is that
`ngx_http_ssl_srv_conf_t` is NOT in the current nginx-sys generated bindings
(the release build was configured with `--with-http_ssl_module` absent); it
would need `--with-http_ssl_module` added to the NGINX configure line AND the
bindings regenerated — which does not require changes to the ngx-rust Rust
source, only to the NGINX build config. This is not a code change to the
frozen fork; it is a build-environment change. Effort: ~2–3 weeks solo after
TLS transport lands.

**Phased plan summary:** Phase A (2–3 w): HTTPS exporter transport. Phase B
(1 w): exporter-side cert metric as a freebie (the cert the exporter's own
TLS session sees, zero new bindings). Phase C (2–3 w after A): serving-cert
expiry feature (needs `--with-http_ssl_module` in the NGINX build + bindings
regeneration).

---

## Part 1 — HTTPS/TLS Exporter Transport

### 1.1 Where TCP connections are established and bytes flow

The production TCP connection is established in `NgxConnector::connect`
(`src/transport/hyper_http.rs:964–1031`) via the nginx FFI
`ngx_event_connect_peer`. The resulting `Pin<Box<NgxConnIo>>` is the raw
async I/O handle handed to hyper or to h2.

`NgxConnIo` (`src/transport/hyper_http.rs:302–438`) implements
`hyper::rt::Read` and `hyper::rt::Write` by calling nginx's `c.recv` and
`c.send` function pointers on the underlying `ngx_connection_t`. Read
readiness is delivered by the C handler `ngx_otel_conn_read_handler`
(`hyper_http.rs:603`) via `Waker::wake()`; write readiness by
`ngx_otel_conn_write_handler` (`hyper_http.rs:626`). No threads, no Tokio.

For OTLP/HTTP, the byte path is:

```
NgxConnector::connect → Pin<Box<NgxConnIo>>
    → http_post (hyper_http.rs:1469)
        → hyper::client::conn::http1::handshake
        → hyper send → poll_write → c.send
```

For OTLP/gRPC, the path is:

```
NgxConnector::connect → Pin<Box<NgxConnIo>>
    → hyper::client::conn::http2::handshake (driven by NgxExecutor)
    → tonic MetricsServiceClient::export
```

Both paths consume a `Pin<Box<NgxConnIo>>` as the I/O type. TLS must be
inserted between `NgxConnIo` and the consumer (hyper/tonic). The strategy is
a `TlsNgxConnIo` wrapper that implements `hyper::rt::Read + hyper::rt::Write`
and owns both a `NgxConnIo` and an `openssl::ssl::Ssl` session, performing
the TLS record framing in the wrappers.

**DNS→connect entry point:** `NgxConnector::connect_dns`
(`src/transport/hyper_http.rs:1052–1135`) for name endpoints. Both IPv4 and
DNS paths call `future::poll_fn(|cx| io.as_mut().poll_connect(cx))` to drive
the connection, then return the `Pin<Box<NgxConnIo>>`. The TLS handshake
would follow immediately after the TCP connect resolves.

### 1.2 TLS approach evaluation

Three options were evaluated:

#### Option (a) — nginx's own `ngx_ssl_*` / `ngx_ssl_handshake`

nginx has a full SSL integration (`ngx_ssl_create`, `ngx_ssl_handshake`,
`ngx_ssl_certificate`, etc.) in `ngx_event_openssl.h`. However:

- `ngx_ssl_t` is declared as `pub struct ngx_ssl_s { _unused: [u8; 0] }` in
  the generated bindings (`target/release/build/nginx-sys-*/out/bindings.rs:13002–13005`).
  It is an **opaque zero-size struct** — its fields (`SSL_CTX *ctx`) are
  inaccessible from Rust.
- `ngx_ssl_connection_t` is similarly opaque (`bindings.rs:13021–13024`).
- Using nginx's handshake API would require either (i) adding a shim C
  function to the module (possible, avoiding fork changes) or (ii) new
  nginx-sys bindings exposing `ngx_ssl_t` fields — which is a change to the
  frozen ngx-rust fork.
- **Verdict: blocked by frozen fork unless a C shim is added. Not
  recommended.** The added complexity of a C shim for one API outweighs the
  benefit.

#### Option (b) — `openssl-sys` directly, wrapping NgxConnIo

`openssl-sys = "0.9.110"` is already a direct dependency (`Cargo.toml:54`).
The functions needed are all present in the `0.9.114` version in the registry:

| Function | File in openssl-sys |
|---|---|
| `SSL_CTX_new`, `TLS_client_method` | `src/handwritten/ssl.rs:301,531` |
| `SSL_CTX_load_verify_locations` | `src/handwritten/ssl.rs:550` |
| `SSL_CTX_set_default_verify_paths` | `src/handwritten/ssl.rs:549` |
| `SSL_CTX_set_verify` | `src/handwritten/ssl.rs:403` |
| `SSL_CTX_use_certificate_file`, `_chain_file` | `src/handwritten/ssl.rs:346,351` |
| `SSL_CTX_use_PrivateKey_file` | `src/handwritten/ssl.rs:341` |
| `SSL_new`, `SSL_connect`, `SSL_read`, `SSL_write` | `src/handwritten/ssl.rs:421,471,472,499` |
| `SSL_set_tlsext_host_name` (SNI) | `src/tls1.rs:22` |
| `SSL_CTX_set_tlsext_servername_callback` | `src/tls1.rs:64` |
| `SSL_pending` | `src/handwritten/ssl.rs:322` |

The implementation pattern is a `TlsNgxConnIo` struct that wraps
`Pin<Box<NgxConnIo>>` and an `*mut SSL`. In `poll_read` it calls
`SSL_read` (which internally calls the `BIO_read` callback that polls
`NgxConnIo`), and in `poll_write` calls `SSL_write`. A custom `BIO` with
`BIO_METHOD` read/write callbacks dispatches to the `NgxConnIo` poll_read /
poll_write. This is the standard pattern for wrapping arbitrary async I/O
with raw OpenSSL.

The TLS handshake is async-driven: in `poll_connect`, call `SSL_connect`;
on `SSL_ERROR_WANT_READ` store the waker and return `Pending`; the
`NgxConnIo` C handlers fire `wake()` when the fd is ready; recheck
`SSL_ERROR_WANT_WRITE` symmetrically.

One `TlsNgxConnIo` type serves both transports because hyper's
`http_post` and `hyper::client::conn::http2::handshake` accept anything that
implements `hyper::rt::Read + hyper::rt::Write + Unpin + 'static` — the
`Connector` trait returns an associated `type Io` that could be
`TlsNgxConnIo` when TLS is enabled.

- **Verdict: RECOMMENDED.** No new dependencies, uses the pre-planned dep,
  one TLS layer serves both transports.

#### Option (c) — rustls manual drive

rustls `ClientConnection` is explicitly runtime-agnostic: it does not do
network I/O; the caller supplies `read_tls()` bytes from the transport and
drains `write_tls()` back to it. This can work without tokio.

However:

- Adds `rustls` (~80k LOC) and `rustls-webpki` as new crates. `rustls` 0.23
  is already in the registry (`~/.cargo/registry/.../rustls-0.23.36`) but is
  not a project dependency today.
- Certificate store: rustls requires a `RootCertStore` populated at startup.
  On Linux this means bundling `webpki-roots` or reading the system cert
  store via `rustls-native-certs`. Both add more crates. On macOS the system
  store is accessible, but the module targets Linux production.
- `hyper` 1.x does not have a built-in rustls connector (unlike hyper 0.14).
  The `hyper-rustls` crate exists but brings its own tokio integration path;
  using rustls directly requires implementing the same `TlsNgxConnIo` wrapper
  with `ClientConnection::process_new_packets()` in the poll_read/write
  methods — similar work to option (b) but with a bigger dep surface.
- tonic 0.14 has a `tls` feature flag but it pulls `tonic-tls` → tokio.
- **Verdict: feasible but 2–3 extra crates, no concrete advantage over
  openssl-sys which is already present. Not recommended for this project.**

### 1.3 Concrete implementation plan

#### ParsedEndpoint extension

Add an `Https` variant to `ParsedEndpoint` (`src/transport/hyper_http.rs:91`):

```rust
pub(crate) enum ParsedEndpoint {
    Http { host: String, port: u16, path: String },
    Https { host: String, port: u16, path: String },  // new
    Unix { socket_path: String, http_path: String },
}
```

Remove the `https://` error arms at `hyper_http.rs:105–110` and
`config.rs:512–523` (the explicit guards that today return errors). The
`config.rs:524` scheme validator would add `b"https://"` to the accepted
set.

#### TlsConfig struct (new, in `src/transport/tls.rs`)

```rust
pub struct TlsConfig {
    /// Path to CA bundle (from `trusted_certificate` directive).
    /// None = use system default (SSL_CTX_set_default_verify_paths).
    pub ca_file: Option<String>,
    /// mTLS client cert path (from `ssl_certificate` directive).
    pub client_cert: Option<String>,
    /// mTLS client key path (from `ssl_certificate_key` directive).
    pub client_key: Option<String>,
    /// Skip server cert verification (insecure; from `ssl_verify off`).
    pub insecure: bool,
}
```

This would be stored on `ExporterConfig` and initialized from new directives
(see §1.4).

#### TlsNgxConnIo wrapper

```rust
pub struct TlsNgxConnIo {
    inner: Pin<Box<NgxConnIo>>,   // the raw TCP connection
    ssl: *mut openssl_sys::SSL,   // the SSL session (owns connection state)
    // A small BIO pair wires SSL_{read,write} back to NgxConnIo polls.
}
```

The `BIO_METHOD` read callback checks whether `NgxConnIo::poll_read` would
block (NGX_AGAIN) and signals `BIO_RW_RETRY`; the write callback mirrors
this. Both cases store the waker from the calling poll context so the C
handlers fire `wake()` on readiness — matching the existing `NgxConnIo`
contract exactly.

`TlsNgxConnIo` then implements `hyper::rt::Read + hyper::rt::Write`, and
`NgxConnector::connect` returns `Pin<Box<TlsNgxConnIo>>` instead of
`Pin<Box<NgxConnIo>>` when the endpoint scheme is `Https`.

gRPC: the origin URI in `GrpcTransport::with_connector`
(`src/transport/grpc/transport.rs:129–132`) builds `http://host:port` today;
for HTTPS it would build `https://host:port`. tonic does not care about the
origin scheme for routing (gRPC framing is independent of scheme), but the
`MetricsServiceClient::with_origin` call should use `https://` so that any
scheme-aware middleware has the right context.

#### Connection lifecycle

TLS adds one async step before the first hyper send:

1. `NgxConnector::connect` → TCP connect (`poll_connect`) → `Ok(raw_io)`
2. TLS handshake: `poll_fn(|cx| tls_io.poll_handshake(cx))` drives
   `SSL_connect` with waker round-trips through the BIO callbacks
3. Return `Pin<Box<TlsNgxConnIo>>` to the caller

For SIGHUP reload: the NGINX master creates a new exporter process with a
new `MainConfig`. The TLS `SSL_CTX` is constructed fresh in the new process
from the configured cert paths. No state transfer is needed.

### 1.4 Config surface and directive specification

The C++ `nginx-otel` module exposes exactly one TLS directive:
`trusted_certificate path` in the `otel_exporter` block (since v0.1.2;
confirmed from `nginx.org/en/docs/ngx_otel_module.html`).

The OTel environment variable conventions are:
`OTEL_EXPORTER_OTLP_CERTIFICATE`, `OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE`,
`OTEL_EXPORTER_OTLP_CLIENT_KEY`, `OTEL_EXPORTER_OTLP_INSECURE`.

The nginx directive precedent is `proxy_ssl_trusted_certificate`,
`proxy_ssl_certificate`, `proxy_ssl_certificate_key`, `proxy_ssl_verify`.

**Proposed directives** (all valid inside `otel_exporter { }`, mirroring
`trusted_certificate` which already exists in `ExporterConfig` at
`src/config.rs:90–93`):

```nginx
otel_exporter {
    endpoint https://collector.example.com:4317;

    # CA bundle for verifying the collector's certificate.
    # Default: system CA bundle (SSL_CTX_set_default_verify_paths).
    # Mirrors nginx proxy_ssl_trusted_certificate and OTEL_EXPORTER_OTLP_CERTIFICATE.
    trusted_certificate /etc/ssl/certs/ca-bundle.crt;   # already parsed; inert until TLS lands

    # mTLS: present a client certificate to the collector.
    # Mirrors OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE.
    ssl_certificate /etc/nginx/certs/exporter-client.pem;     # new directive

    # mTLS: private key for ssl_certificate.
    # Mirrors OTEL_EXPORTER_OTLP_CLIENT_KEY.
    ssl_certificate_key /etc/nginx/certs/exporter-client-key.pem;  # new directive

    # Skip collector certificate verification (INSECURE; for dev/testing only).
    # Mirrors OTEL_EXPORTER_OTLP_INSECURE.
    ssl_verify off;     # new directive; default: on
}
```

SNI: use the `host` from the parsed `https://` URL as the SNI server name
(passed to `SSL_set_tlsext_host_name`, `openssl-sys/src/tls1.rs:22`).
No separate directive needed.

**Landing points:**

| What | Where | Action |
|---|---|---|
| `ssl_certificate` directive | `src/config.rs` — `ExporterConfig` struct + command table (~1280–1337) | Add field + cmd handler |
| `ssl_certificate_key` directive | same | Add field + cmd handler |
| `ssl_verify` directive | same | Add field + cmd handler |
| `https://` parsing | `src/transport/hyper_http.rs:105–110` and `src/config.rs:512–523` | Remove error guard, add `Https` variant |
| TLS wrapper | New file `src/transport/tls.rs` | New `TlsNgxConnIo`, `TlsConfig`, `TlsConnector` |
| `NgxConnector::connect` | `src/transport/hyper_http.rs:964` | Dispatch to TLS wrapper when endpoint is `Https` |
| gRPC origin URI | `src/transport/grpc/transport.rs:129–132` | Use `https://` scheme when TLS |

### 1.5 Effort estimate and risks

**Effort: ~2–3 weeks solo.**

Breakdown:
- TlsNgxConnIo + BIO wiring: ~5 days. The BIO callback pattern is well
  documented in OpenSSL; the waker round-trip mirrors the existing
  `NgxConnIo` pattern precisely.
- Config plumbing (3 new directives, ParsedEndpoint Https variant): ~2 days.
- gRPC path + origin URI fix: ~1 day.
- Tests (a new `TlsSpinConnector` for unit tests + integration test against a
  collector with TLS): ~3–4 days. A TLS test connector for unit tests needs a
  test certificate.
- Integration test wiring: ~1–2 days.

**Risks:**

1. **BIO callback re-entrancy:** The custom BIO read/write callbacks run from
   within `SSL_connect`, `SSL_read`, `SSL_write` — which are called from
   within `poll_read`/`poll_write`. The waker storage must not deadlock.
   Pattern: only store the waker; never poll recursively. Identical to the
   existing design.

2. **`openssl-sys` version alignment:** The project uses `openssl-sys 0.9.110`
   (`Cargo.toml:54`); the registry has `0.9.114`. If the NGINX system OpenSSL
   version (1.1.1 / 3.x) does not match, `openssl-sys` will fail to link.
   The README requires system OpenSSL 1.1.1 or later (`README.md:258`).
   `SSL_CTX_get0_certificate` was added in OpenSSL 1.1.0 — confirmed present
   in `openssl-sys:581`.

3. **NGINX build does not currently include `--with-http_ssl_module`**: The
   `objs-release/ngx_auto_config.h` configure line is:
   `--with-compat --with-http_stub_status_module`. Adding TLS for the
   exporter does NOT require `--with-http_ssl_module` — the exporter uses
   `openssl-sys` directly, not nginx's SSL integration. No Makefile change
   needed for Part 1.

4. **No tokio:** `SSL_connect` is blocking in raw OpenSSL. The BIO callback
   pattern makes it non-blocking by returning `BIO_RW_RETRY` (analogous to
   EAGAIN). This is the standard approach for integrating OpenSSL with async
   event loops without a dedicated thread.

---

## Part 2 — TLS / Certificate Metrics

### 2.1 OTel semantic conventions status (as of v1.41.1, June 2026)

The OTel semconv registry defines the `tls.*` attribute namespace at:
https://opentelemetry.io/docs/specs/semconv/registry/attributes/tls/

The relevant attributes for certificates are (status: Development):

| Attribute | Type | Description |
|---|---|---|
| `tls.server.certificate` | string | PEM-encoded leaf cert |
| `tls.server.certificate_chain` | string[] | PEM-encoded chain |
| `tls.server.hash.md5` / `.sha1` / `.sha256` | string | Fingerprints |
| `tls.server.issuer` | string | Distinguished name of issuer |
| `tls.server.subject` | string | Distinguished name of subject |
| `tls.server.not_before` | string | Validity start (date-time string) |
| `tls.server.not_after` | string | Expiration date-time string |
| `tls.server.ja3s` | string | Server handshake hash |

**Key finding:** `tls.server.not_after` and `tls.server.not_before` exist as
**span/log record attributes** in the OTel registry. They are NOT defined as
metric instrument attributes in any OTel semconv metric specification. There
is NO standardized OTel metric for certificate expiry as of v1.41.1.

The OTel Collector contrib project does have a `tlscheckreceiver` (Development
status) that emits `tlscheck.time_left` (gauge, seconds, signed) per
certificate, with attributes `tlscheck.x509.issuer`, `tlscheck.x509.cn`, and
`tlscheck.x509.san` — but this is a receiver for *external* TLS endpoints,
not a module that reads serving certs from nginx internals. See:
https://pkg.go.dev/github.com/open-telemetry/opentelemetry-collector-contrib/receiver/tlscheckreceiver

Because OTel has not standardized a cert-expiry metric, this project must
define its own name. The recommended convention follows:
- The project's `ngx_otel.*` prefix for module self-metrics
- The OTel `tls.*` attribute namespace for attributes
- The Prometheus de-facto convention of emitting the **absolute notAfter Unix
  timestamp** (seconds since epoch) rather than "seconds remaining"

### 2.2 Prior art: timestamp vs. time-remaining debate

| Source | Metric | Shape |
|---|---|---|
| prometheus/blackbox_exporter | `probe_ssl_earliest_cert_expiry` | Gauge, Unix timestamp (seconds) |
| ribbybibby/ssl_exporter | `ssl_cert_not_after` | Gauge, Unix timestamp (seconds) |
| OTel tlscheckreceiver | `tlscheck.time_left` | Gauge, signed seconds until expiry |

The **absolute Unix timestamp** shape (`ssl_cert_not_after`,
`probe_ssl_earliest_cert_expiry`) is the de-facto Prometheus standard and is
strongly preferable for the following reasons:

1. **Stable value**: the gauge reading does not drift minute-by-minute while
   the cert is valid. An operator querying historic data sees the same
   timestamp on every collection cycle — no false "alert resolved" events.
2. **Flexible alerting**: `(ngx_otel.tls.certificate.not_after - time()) <
   86400 * 30` computes "less than 30 days remaining" in any query language.
   The offset to "now" is done at query time, not at collection time.
3. **Multiple certs**: with multiple server blocks / SNI certs, operators can
   compute `min(ngx_otel.tls.certificate.not_after)` as the earliest expiry.
4. **Signed time-remaining goes negative** post-expiry, which is valid but
   requires alerting rules to check for negative values — less intuitive than
   checking `not_after < (time() + window)`.

**Recommendation: emit `ngx_otel.tls.certificate.not_after` as a Gauge with
value = `X509_getm_notAfter` converted to Unix epoch int64 (seconds).**

Also emit `ngx_otel.tls.certificate.not_before` for completeness (allows
computing cert lifetime).

### 2.3 Two certificate sources — analysis

#### Source 1: The collector's certificate (exporter TLS session)

When TLS is implemented (Part 1), the `SSL` session after handshake has
`SSL_get_peer_certificate()` — the cert the collector presented. This can be
read in `TlsNgxConnIo::post_handshake()` and emitted as a one-time gauge.

- **Value**: minor. Operators generally know what cert their own collector
  runs. Useful only to confirm the cert the exporter actually sees.
- **Implementation**: zero new bindings needed once Part 1 is done. Call
  `SSL_get_peer_certificate(ssl)` (available in `openssl-sys/src/handwritten/ssl.rs`)
  and `X509_getm_notAfter(cert)` on the result.
- **Verdict**: implement as a freebie in Phase B (one extra gauge point added
  to `SelfMetricsSource` after TLS lands).

#### Source 2: The certificates NGINX SERVES to clients (the compelling feature)

This is the observability operators actually want: "are any of my serving
certs about to expire?" The certificates are configured via `ssl_certificate`
in `server {}` blocks and loaded into `ngx_http_ssl_srv_conf_t.ssl` at
config time.

**Data access path (nginx internals):**

```
nginx http main conf
  → servers array (ngx_http_core_main_conf_t.servers)
  → each server's ctx (ngx_http_core_srv_conf_t.ctx)
  → loc_conf[ngx_http_ssl_module.ctx_index] → ngx_http_ssl_srv_conf_t *
  → .ssl (ngx_ssl_t, embedded by value)
  → .ssl.ctx (SSL_CTX*, first field — see nginx/src/event/ngx_event_openssl.h:104–105)
  → SSL_CTX_get0_certificate(ctx) → X509 * (the leaf cert)
  → X509_getm_notAfter(x509) → ASN1_TIME *
```

The walk is nearly identical to `build_route_table`
(`src/config.rs:978–1035`), which already walks the exact same
`ngx_http_core_main_conf_t.servers` array → `ngx_http_core_srv_conf_t.ctx`
chain. The serving-cert walk adds one additional module conf lookup and the
OpenSSL calls.

**Multi-cert / SNI:** nginx supports multiple `ssl_certificate` directives
per server block (since 1.11.0) stored in `ngx_http_ssl_srv_conf_t.certificates`
(an `ngx_array_t` of paths). However, `SSL_CTX_get0_certificate` returns only
the leaf cert that OpenSSL has cached for the context — for multi-cert server
blocks, nginx creates one `SSL_CTX` per certificate and selects at handshake
time via SNI callback. The enumeration approach should iterate over all server
blocks and, where possible, over multiple `SSL_CTX`s. The simplest correct
approach: collect one data point per `(server_name, SSL_CTX)` pair; the SNI
name is `ngx_http_ssl_srv_conf_t`'s associated server's `server_name`.

**ASN1_TIME → Unix epoch:** `openssl-sys` provides `ASN1_TIME_diff`
(`src/handwritten/asn1.rs:76–82`) which computes the signed delta between two
`ASN1_TIME` values. To get the Unix epoch: `ASN1_TIME_set(NULL, 0)` gives the
epoch (1970-01-01T00:00:00Z) as an `ASN1_TIME`; then
`ASN1_TIME_diff(days, secs, epoch, notAfter)` gives days+seconds from epoch
to notAfter. Unix timestamp = `days * 86400 + secs`. Alternatively, parse the
ASN1_TIME string directly (it is YYMMDDhhmmssZ for UTCTime or
YYYYMMDDhhmmssZ for GeneralizedTime — both are valid in X.509). **Note:**
`ASN1_TIME_to_tm` is available in OpenSSL 1.1.1d+; it was NOT found in
`openssl-sys-0.9.114` (not in any `.rs` under `src/handwritten/`). The
`ASN1_TIME_diff` approach is safer and portable.

### 2.4 Frozen-fork binding analysis for serving-cert enumeration

| Needed | Available in nginx-sys bindings? | Status |
|---|---|---|
| Walk `ngx_http_core_main_conf_t.servers` | YES — same walk used in `build_route_table` (`config.rs:978`) | Available |
| `ngx_http_core_srv_conf_t.ctx` field | YES — field is in the generated bindings | Available |
| `ngx_http_ssl_module.ctx_index` | **AVAILABLE w/ `--with-http_ssl_module`** — verified 2026-06-09 (debian-vm): `pub static mut ngx_http_ssl_module: ngx_module_t` is emitted | Resolved by build flag |
| `ngx_http_ssl_srv_conf_t` struct | **NOT emitted even WITH the flag** — verified 2026-06-09 (grep count 0). `wrapper.h` includes `ngx_http.h` but never `ngx_http_ssl_module.h`, so bindgen never sees this struct. Needs a small **module-side** C shim to navigate `srv_conf → .ssl` (the module compiles against nginx headers, so this is NOT a fork change) | Module C shim |
| `ngx_ssl_s.ctx` field (SSL_CTX*) | **AVAILABLE w/ `--with-http_ssl_module`** — verified 2026-06-09: bindgen emits `ngx_ssl_s { ctx: *mut SSL_CTX, … }` (see the dated note at the top) | Resolved by build flag |
| `SSL_CTX_get0_certificate` | YES — `openssl-sys/src/handwritten/ssl.rs:581` | Available |
| `X509_getm_notAfter` | YES — `openssl-sys/src/handwritten/x509.rs:297` | Available |
| `X509_getm_notBefore` | YES — `openssl-sys/src/handwritten/x509.rs:296` | Available |
| `X509_get_issuer_name` | YES — `openssl-sys/src/handwritten/x509.rs:236` | Available |
| `X509_get_subject_name` | YES — `openssl-sys/src/handwritten/x509.rs:238` | Available |
| `X509_get_signature_nid` | YES — `openssl-sys/src/handwritten/x509.rs:186` | Available |
| `OBJ_nid2sn` | YES — `openssl-sys/src/handwritten/object.rs:7` | Available |
| `X509_get_pubkey` + `EVP_PKEY_bits` | YES — `x509.rs:216`, `evp.rs:455` | Available |
| `X509_get_serialNumber` | YES — `openssl-sys/src/handwritten/x509.rs:222` | Available |
| `NID_subject_alt_name` | YES — `openssl-sys/src/obj_mac.rs:566` | Available |
| `X509_get_ext_by_NID`, `X509_get_ext` | YES — `openssl-sys/src/handwritten/x509.rs:479,482` | Available |
| `GENERAL_NAME`, `stack_st_GENERAL_NAME` | YES — `openssl-sys/src/x509v3.rs:6,12` | Available |
| `X509_NAME_oneline` | **MISSING** — not in `openssl-sys-0.9.114` | Must use `X509_NAME_get_entry` + `ASN1_STRING_get0_data` instead, or add a bindgen entry |
| `ASN1_TIME_to_tm` | **MISSING** — not in `openssl-sys-0.9.114` | Use `ASN1_TIME_diff` from epoch instead |
| `ASN1_TIME_diff` | YES — `openssl-sys/src/handwritten/asn1.rs:76` | Available |
| `ASN1_STRING_get0_data` | YES — `openssl-sys/src/handwritten/asn1.rs:51` | Available |
| `ASN1_STRING_to_UTF8` | YES (gated cfg) — `asn1.rs:114` | Available |

**Summary of blockers:**

1. **Build-config blocker (not a code change to the frozen fork):** The
   current nginx release build was configured as:
   `--with-compat --with-http_stub_status_module`
   (`objs-release/ngx_auto_config.h:1`).
   To access `ngx_http_ssl_module.ctx_index` and `ngx_http_ssl_srv_conf_t`,
   the build needs `--with-http_ssl_module` added to
   `NGINX_CONFIGURE_BASE` in the `Makefile`. This causes `nginx-sys` to
   regenerate its bindings to include these types. This is a **build
   environment change, not a fork code change**, and is explicitly
   mentioned in `Makefile:21` as a planned Phase 1.2 addition:
   *"Phase 1.2 will add --with-http_ssl_module + --with-pcre etc."*

2. **`ngx_ssl_s.ctx` field — RESOLVED, empirically verified 2026-06-09 (debian-vm, Linux):**
   The worry that it might stay opaque is laid to rest. After a clean rebuild
   with `--with-http_ssl_module`, the regenerated `bindings.rs` expands the
   struct fully:
   ```rust
   pub struct ngx_ssl_s { pub ctx: *mut SSL_CTX, pub log: *mut ngx_log_t,
       pub buffer_size: usize, pub certs: ngx_array_t, /* … */ }
   ```
   Mechanism: `wrapper.h` includes `ngx_core.h`, which under `NGX_OPENSSL`
   (set by `--with-http_ssl_module`) `#include`s `<ngx_event_openssl.h>`
   (`ngx_core.h:85-86`), so bindgen sees the full definition. **No `wrapper.h`
   change and no C helper are needed for `ngx_ssl_s.ctx`.** (Caveat: bindgen
   emits its own `SSL_CTX` type; cast the `*mut SSL_CTX` to
   `openssl_sys::SSL_CTX` — same C type — before calling `SSL_CTX_get0_certificate`.)
   `ngx_ssl_connection_s` (`connection: *mut SSL`, `session_ctx: *mut SSL_CTX`)
   is likewise emitted.

   **The one residual gap (verified same run):** `ngx_http_ssl_srv_conf_t` is
   *not* emitted even with the flag (`wrapper.h` includes `ngx_http.h` but not
   `ngx_http_ssl_module.h`, where that struct lives). It is the container that
   holds the per-server `ngx_ssl_t`, so the navigation
   `cscf->ctx->srv_conf[ngx_http_ssl_module.ctx_index] → .ssl` needs it. The
   fix WITHOUT touching the frozen fork: a tiny C shim compiled INTO the module
   (a `.c` file via a `cc` build step, which can `#include <ngx_http_ssl_module.h>`),
   e.g. `ngx_ssl_t *ngx_otel_srv_ssl(void *ssc){ return &((ngx_http_ssl_srv_conf_t*)ssc)->ssl; }`.
   From there `->ctx` is the now-directly-bound `SSL_CTX*`. So serving-cert
   enumeration is FEASIBLE within the frozen fork; the only fork-external
   additions are the `--with-http_ssl_module` Makefile flag + this one module-side shim.

3. **`X509_NAME_oneline` missing from openssl-sys:** This function formats
   the X509_NAME as a single string. Alternative: iterate name entries via
   `X509_NAME_entry_count` + `X509_NAME_get_entry` + `X509_NAME_ENTRY_get_data`
   + `ASN1_STRING_get0_data` — tedious but all available in `openssl-sys`.
   Or: just emit the issuer CN only (most useful for alerting) via
   `X509_NAME_get_text_by_NID` which IS available... checking:

   ```
   grep -r "X509_NAME_get_text_by_NID" openssl-sys-0.9.114/
   ```
   
   (verification TODO — not confirmed in the files I searched; mark as
   unknown until confirmed against the installed version).

### 2.5 Recommended metric specification

#### Metric 1: Serving certificate expiry

```
Metric name:  ngx_otel.tls.certificate.not_after
Instrument:   Gauge
Value type:   int64
Unit:         s  (Unix epoch seconds, i.e. the raw notAfter timestamp)
Description:  "Unix epoch timestamp (seconds) of the X.509 certificate's
               notAfter field for each certificate loaded by NGINX's SSL
               server contexts. Alert when (value - time()) < 30*86400."
Temporality:  N/A (Gauge; point-in-time; recollected on every export tick)
```

Attributes (names from OTel `tls.*` semconv where standardized):

| Attribute key | OTel semconv | Value | Example |
|---|---|---|---|
| `tls.server.subject` | `tls.server.subject` (Development) | Subject DN or CN | `"CN=example.com"` |
| `tls.server.issuer` | `tls.server.issuer` (Development) | Issuer DN or CN | `"CN=Let's Encrypt R3"` |
| `tls.server.hash.sha256` | `tls.server.hash.sha256` (Development) | Hex SHA-256 fingerprint | unique dedup key |
| `server.address` | OTel semconv | Hostname from nginx server_name | `"example.com"` |
| `tls.server.not_before` | (emit as second gauge — see below) | — | — |
| `ngx_otel.tls.key_bits` | Project-specific | Key size in bits | `2048`, `256` |
| `ngx_otel.tls.sig_alg` | Project-specific | OBJ_nid2sn of sig nid | `"RSA"`, `"ecdsa-with-SHA256"` |

**Note on `tls.server.not_after` as a span attribute:** the OTel semconv
defines `tls.server.not_after` as a string (date-time), not an int64. We
deliberately deviate: the gauge value IS the unix timestamp (int64), and
`tls.server.subject`/`tls.server.issuer` are the identifying attributes.
We do NOT put `not_after` as an attribute on its own gauge — that would be
redundant (the gauge value IS the not_after).

#### Metric 2: Serving certificate validity start

```
Metric name:  ngx_otel.tls.certificate.not_before
Instrument:   Gauge
Value type:   int64
Unit:         s
Description:  "Unix epoch timestamp (seconds) of the X.509 certificate's
               notBefore field. Combined with not_after, allows computing
               total certificate lifetime and fraction remaining."
```

Same attribute set as `not_after`.

#### Metric 3: Exporter-side collector cert (Phase B freebie)

```
Metric name:  ngx_otel.tls.collector_cert.not_after
Instrument:   Gauge
Value type:   int64
Unit:         s
Description:  "Unix epoch timestamp of the notAfter field of the TLS
               certificate presented by the OTLP collector endpoint.
               Populated after the exporter establishes its first TLS
               connection. Zero until connected."
```

No complex attributes needed — just `server.address` (the collector host).

### 2.6 Where the CertMetricSource hooks in

The existing `MetricSource` pattern (defined at `src/metric_source/mod.rs:27`)
is the correct hook:

```rust
// New file: src/metric_source/tls_cert.rs
pub struct ServingCertSource {
    // Populated once at postconfiguration from the server block walk.
    // Immutable after that; safe to read from the exporter (fork-shared memory).
    pub certs: Vec<CertInfo>,
}

pub struct CertInfo {
    pub server_name: String,        // from ngx_http_core_srv_conf_t
    pub not_after_unix:  i64,       // computed from X509_getm_notAfter
    pub not_before_unix: i64,       // computed from X509_getm_notBefore
    pub subject_cn:      String,    // from X509_get_subject_name
    pub issuer_cn:       String,    // from X509_get_issuer_name
    pub sha256_hex:      String,    // from X509_digest (SHA-256)
    pub sig_alg:         String,    // from OBJ_nid2sn(X509_get_signature_nid)
    pub key_bits:        i32,       // from EVP_PKEY_bits(X509_get_pubkey)
}

impl MetricSource for ServingCertSource {
    fn collect(&self) -> Vec<Metric> { ... }  // emit not_after + not_before gauges
}
```

The `ServingCertSource` is constructed at `postconfiguration` time (same call
site as `build_route_table` and `build_upstream_table` in `src/config.rs`),
stored on `MainConfig`, and registered in the `collect_all_sources` closure
inside `export_loop` (`src/export/mod.rs:~1340–1440`).

**Landing points for Part 2:**

| What | Where |
|---|---|
| `ServingCertSource`, `CertInfo` structs | New `src/metric_source/tls_cert.rs` |
| `MainConfig::serving_certs: Vec<CertInfo>` field | `src/config.rs` — `MainConfig` struct |
| Cert walk at postconfiguration | `src/config.rs` — `MainConfig::postconfiguration` or a new `build_cert_table` method |
| `ServingCertSource` registration in export loop | `src/export/mod.rs` — `collect_all_sources` |
| TELEMETRY_MODEL.md update | Add `ngx_otel.tls.certificate.*` section |
| README update | Add to "Exporter self-metrics" table |

### 2.7 Effort estimate and risks

**Effort: ~2–3 weeks, after Part 1 is done (requires openssl-sys working in the module).**

Breakdown:
- Build-config change (`--with-http_ssl_module`) and bindings verification: ~0.5 days.
- `ngx_ssl_s.ctx` access (either verify opaque or write C helper shim): ~1 day.
  If wrapper.h change is needed: flag as a frozen-fork issue; use C shim in
  the module instead (~0.5 days extra).
- Cert walk (parallel to `build_route_table`): ~2 days.
- `CertInfo` population from X509 (notAfter/before, CN, sig alg, key bits): ~2 days.
- `ASN1_TIME` → Unix epoch via `ASN1_TIME_diff`: ~1 day (needs a careful
  epoch baseline construction).
- MetricSource + data model + encoder: ~1–2 days.
- Tests (unit: mock `CertInfo`, integration: nginx with `ssl_certificate`): ~3 days.

**Risks:**

1. **`ngx_ssl_s.ctx` field access.** If `ngx_ssl_s` remains opaque after
   adding `--with-http_ssl_module`, a C shim function (not touching the
   frozen fork) is the mitigation:
   ```c
   // src/tls_helpers.c (new file in the module)
   #include <ngx_event_openssl.h>
   SSL_CTX *ngx_otel_get_ssl_ctx(ngx_ssl_t *ssl) { return ssl->ctx; }
   ```
   This is declared as `extern "C"` in Rust and called without any
   ngx-rust/nginx-sys changes. **This is the recommended fallback.**

2. **`--with-http_ssl_module` must match the deployed nginx binary.** The
   module would only emit cert metrics when nginx is built with SSL. When
   nginx is built without `--with-http_ssl_module`, the `ngx_http_ssl_module`
   is absent and there are no serving certs — the module must
   `#[cfg(ngx_feature = "http_ssl")]`-gate the cert walk. The
   `ngx_feature = "http_ssl"` cfg is already recognized by the nginx-sys
   build script (`ngx-rust/nginx-sys/build/main.rs:47`).

3. **Dynamic cert load (ssl_certificate with $variables).** nginx supports
   `ssl_certificate` with nginx variables (e.g. `$ssl_server_name`) for SNI-
   driven multi-cert. These certs are not loaded at config time; they are
   loaded on-demand. `SSL_CTX_get0_certificate` on the base context returns
   only the static cert. The module should enumerate only statically-
   configured certs; variable-expanded certs are explicitly out of scope for
   the initial implementation and should be documented as a known limitation.

4. **SIGHUP reload:** On reload, nginx creates a new `MainConfig` with a new
   cert walk. The `ServingCertSource` on the new config reflects the new certs.
   The old exporter exits, the new one starts. No cross-cycle cert state is
   needed.

---

## Phased Plan

### Phase A — HTTPS exporter transport (~2–3 weeks)
- Add `TlsNgxConnIo` with openssl-sys BIO wiring
- Add `ParsedEndpoint::Https` variant
- Remove https:// error guards in hyper_http.rs and config.rs
- Add `ssl_certificate`, `ssl_certificate_key`, `ssl_verify` directives
- Enable `trusted_certificate` to actually take effect
- Tests: SpinTlsConnector mock for unit tests + integration test

### Phase B — Exporter-side cert metric (freebie, ~3 days, after Phase A)
- In `TlsNgxConnIo::post_handshake`: call `SSL_get_peer_certificate`
- Add one `CertInfo` point for the collector cert to `SelfMetricsSource`
- New gauge: `ngx_otel.tls.collector_cert.not_after`
- No new bindings needed

### Phase C — NGINX serving-cert expiry metrics (~2–3 weeks, after Phase A)
- Add `--with-http_ssl_module` to `NGINX_CONFIGURE_BASE` in Makefile
- Regenerate and verify bindings expand `ngx_ssl_s`; if still opaque, write
  `ngx_otel_get_ssl_ctx()` C shim
- Implement `build_cert_table` cert walk at postconfiguration
- Implement `src/metric_source/tls_cert.rs`: `ServingCertSource`, `CertInfo`
- Wire into `collect_all_sources` in `src/export/mod.rs`
- Update TELEMETRY_MODEL.md + README
- Tests: unit + integration with a self-signed `ssl_certificate`

---

## Explicit Frozen-Fork Binding Risks

| Risk | Severity | Mitigation |
|---|---|---|
| `ngx_ssl_s` is opaque in bindings (ZST, no `ctx` field) | MEDIUM — blocks direct field access | C helper shim in the module (not fork); no fork change required |
| `ngx_http_ssl_module` not in bindings (no `--with-http_ssl_module`) | HIGH — blocks `ctx_index` lookup | Makefile build-config change (not fork code); cf. `Makefile:21` plan |
| `X509_NAME_oneline` missing from openssl-sys | LOW — workaround via entry iteration | Use `X509_NAME_get_entry` chain; or emit only CN |
| `ASN1_TIME_to_tm` missing from openssl-sys | LOW | Use `ASN1_TIME_diff` from epoch (available) |
| New TLS directive lands in ExporterConfig | NONE — ExporterConfig is in the module, not the fork | Normal module code change |
| TlsNgxConnIo requires ngx-rust Executor changes | NONE — uses existing NgxExecutor and NgxConnIo unchanged | Normal module code |

---

## Open Questions for the Maintainer

1. **`ngx_ssl_s.ctx` field visibility after adding `--with-http_ssl_module`:**
   After rebuilding with the SSL module enabled, does the regenerated
   `bindings.rs` expose `ngx_ssl_s.ctx`? If not, is a one-line addition to
   `nginx-sys/build/wrapper.h` acceptable (frozen-fork boundary call), or
   should the module use a C shim instead?

2. **mTLS for the exporter:** Is client-certificate authentication
   (`ssl_certificate` / `ssl_certificate_key` inside `otel_exporter {}`)
   in scope for Phase A, or should Phase A cover CA cert + insecure-skip
   only, deferring mTLS to Phase A+1?

3. **SNI handling for multi-cert nginx server blocks:** nginx can select
   different `SSL_CTX`s at handshake time based on SNI, which means one server
   block may have multiple `SSL_CTX`s. The proposed implementation enumerates
   one `SSL_CTX` per server block (the "default" context before SNI
   selection). Should the module attempt to enumerate all per-SNI contexts, or
   is the default context sufficient? (The SNI-selection callback is
   configurable; its implementation varies.)

4. **`server.address` attribute for serving certs:** For a server block with
   multiple `server_name` values, which should be used as the `server.address`
   attribute? The first? All of them (multiple data points)? Or just the
   `_` (catch-all)?

5. **Cert metrics cadence:** Should `ngx_otel.tls.certificate.not_after` be
   re-collected every export tick from the live `SSL_CTX`? Or collected once
   at startup and held in `MainConfig::serving_certs`? The certificate does
   not change without a reload — once-at-startup + reload-reset is cleaner
   and has zero per-tick cost.

6. **Certificate chain enumeration:** `SSL_CTX_get0_certificate` returns only
   the leaf cert. Should intermediate/chain certs also be enumerated (for
   early detection of intermediate CA expiry)? nginx does load the chain via
   `ssl_certificate` (which calls `SSL_CTX_use_certificate_chain_file`), but
   the chain is not easily retrievable from a live `SSL_CTX` without
   iterating the internal chain store. Flag as deferred for initial
   implementation.

7. **`ngx_feature = "http_ssl"` cfg gate:** When the module is loaded into
   a nginx binary built without `--with-http_ssl_module`, should the cert
   walk silently skip (emit no cert metrics) or log a one-time NOTICE? The
   nginx idiom is to log at config time if a feature is unavailable; silently
   skipping at metric collection time is less noisy but harder to diagnose.

---

## References and Sources

- OTel TLS attribute namespace (v1.41.1, Development):
  https://opentelemetry.io/docs/specs/semconv/registry/attributes/tls/
- OTel Collector contrib `tlscheckreceiver` metric `tlscheck.time_left`:
  https://pkg.go.dev/github.com/open-telemetry/opentelemetry-collector-contrib/receiver/tlscheckreceiver
- `tlscheckreceiver` metadata.yaml (metric name, attrs, units):
  https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/tlscheckreceiver/metadata.yaml
- nginx-otel C++ module `trusted_certificate` directive (TLS since v0.1.2):
  https://nginx.org/en/docs/ngx_otel_module.html
- prometheus/blackbox_exporter `probe_ssl_earliest_cert_expiry` (Unix timestamp):
  https://promlabs.com/blog/2024/02/06/monitoring-tls-endpoint-certificate-expiration-with-prometheus/
- openssl-sys 0.9.114 source:
  `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/openssl-sys-0.9.114/`
- rustls `ClientConnection` runtime-agnostic design (no network I/O):
  https://docs.rs/rustls/latest/rustls/
- Confirmed code locations in this repo:
  - `NgxConnIo` implementation: `src/transport/hyper_http.rs:302–438`
  - `NgxConnector::connect` (TCP establishment): `src/transport/hyper_http.rs:964–1031`
  - `ParsedEndpoint::parse` (https:// error guard): `src/transport/hyper_http.rs:105–110`
  - `MainConfig::postconfiguration` (https:// error guard): `src/config.rs:512–523`
  - `ExporterConfig.trusted_cert` field (already exists): `src/config.rs:90–93`
  - `trusted_certificate` directive + cmd handler: `src/config.rs:1305–1379`
  - nginx configure line (no ssl module): `objs-release/ngx_auto_config.h:1`
  - `ngx_ssl_s` as opaque ZST: generated `bindings.rs:13002–13005`
  - `ngx_ssl_s.ctx` field in nginx source: `nginx/src/event/ngx_event_openssl.h:105`
  - `ngx_http_ssl_srv_conf_t` in nginx source: `nginx/src/http/modules/ngx_http_ssl_module.h:17–69`
  - `build_route_table` (model for cert walk): `src/config.rs:978–1035`
  - `MetricSource` trait: `src/metric_source/mod.rs:27`
  - `SelfMetricsSource` (model for self-metrics): `src/export/mod.rs:237–326`
  - `openssl-sys` dep: `Cargo.toml:54`
  - Makefile Phase 1.2 note about `--with-http_ssl_module`: `Makefile:21`
