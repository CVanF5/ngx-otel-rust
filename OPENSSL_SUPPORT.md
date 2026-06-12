# OpenSSL support matrix — ngx-otel-rust

## THE RULE (binding)

> **`openssl-sys` must link the SAME OpenSSL that nginx links, dynamically.**

Mixing OpenSSL runtimes causes silent corruption on SSL context access:

- The nginx process carries ONE OpenSSL in memory (dynamically linked at
  nginx build time, e.g. `openssl@3` on Homebrew macOS or
  `/usr/lib/x86_64-linux-gnu/libssl.so.3` on Debian).
- If the Rust module is compiled against a different OpenSSL (e.g. `openssl@4`
  vendored or statically embedded by `openssl-sys`), it writes to `SSL_CTX`
  objects using the WRONG struct layout.  The corruption is silent at startup;
  it manifests as empty results, wrong values, or crashes — in our case the
  C2 cert walk silently enumerated **ZERO** certs from nginx's `SSL_CTX`
  objects (the macOS demo `f2d8455` find).

**Consequence**: NEVER allow `openssl-sys` to vendor or statically link its
own OpenSSL when the module is loaded into a running nginx process.  Always
resolve to the exact same shared library nginx resolved at its own link time.

---

## Minimum OpenSSL version

**Minimum: OpenSSL 1.1.1** (released September 2018).

The TLS client in `src/transport/tls.rs` uses the following API calls, all of
which are present in OpenSSL 1.1.1:

| API call                              | Introduced | Purpose                                    |
|---------------------------------------|------------|--------------------------------------------|
| `TLS_client_method`                   | 1.1.0      | Flexible TLS method (replaces `TLSv1_2_method`) |
| `SSL_CTX_set_min_proto_version`       | 1.1.0      | Enforce minimum TLS 1.2                    |
| `SSL_CTX_load_verify_locations`       | 0.9.x      | Load trusted CA bundle                     |
| `SSL_CTX_set_default_verify_paths`    | 0.9.x      | Load system default trust store            |
| `SSL_CTX_use_certificate_chain_file`  | 0.9.x      | Load mTLS client certificate               |
| `SSL_CTX_use_PrivateKey_file`         | 0.9.x      | Load mTLS client private key               |
| `SSL_CTX_check_private_key`           | 0.9.x      | Verify cert/key match                      |
| `X509_VERIFY_PARAM_set1_host`         | 1.0.2      | DNS-name hostname verification             |
| `X509_VERIFY_PARAM_set1_ip_asc`       | 1.0.2      | IP-address SAN verification (A2)           |
| `SSL_get0_param`                      | 1.0.2      | Retrieve verify params from SSL            |
| `BIO_meth_new` / `BIO_meth_set_*`     | 1.1.0      | Custom BIO method (async bridge)           |
| `BIO_get_new_index`                   | 1.1.0      | Per-process BIO type index                 |
| `SSL_set_tlsext_host_name`            | 1.0.0      | SNI hostname extension                     |

`X509_VERIFY_PARAM_set1_host` and `set1_ip_asc` (1.0.2) are the binding lower
bound. In practice, **OpenSSL 1.1.1 or later is strongly recommended** because
1.0.2 reached end-of-life in December 2019 and many distributions no longer
ship it. OpenSSL 3.x (3.0, 3.1, 3.2, 3.3, 3.4, 3.5) is fully supported and
is the version shipped by current Debian/Ubuntu/Fedora/RHEL releases.

**Verified on**: OpenSSL 3.5.6 (Debian arm64, debian-vm, 2026-06-12, A3 full
E2E test — all scenarios a-g including mTLS and IP-SAN verification).

---

## Darwin (macOS) Makefile pin

The `Makefile` enforces this with a dual `:=`/`!=` assignment (the
`MAKE_FLAVOR` pattern) so it works on both GNU make 3.81 (macOS system make,
which silently ignores `!=`) and POSIX-2024/GNU ≥ 3.82 makes (which take
`!=` and ignore the `:=`/`$(shell)` form):

```makefile
# macOS: openssl-sys MUST link the SAME OpenSSL that nginx links (dynamic
# openssl@3), or the module carries its own incompatible OpenSSL and the
# Phase C cert walk silently enumerates ZERO certs from nginx's SSL_CTX
# objects (found via the demo 2026-06-12; the C2 review flagged the skew).
# Linux has one system OpenSSL, so this expands to nothing there.
OPENSSL_BUILD_ENV := $(shell if [ "`uname -s`" = "Darwin" ] && [ -e /opt/homebrew/opt/openssl@3/lib/libssl.dylib ]; then echo "OPENSSL_DIR=/opt/homebrew/opt/openssl@3 OPENSSL_STATIC=0 OPENSSL_NO_VENDOR=1"; fi)
OPENSSL_BUILD_ENV != if [ "`uname -s`" = "Darwin" ] && [ -e /opt/homebrew/opt/openssl@3/lib/libssl.dylib ]; then echo "OPENSSL_DIR=/opt/homebrew/opt/openssl@3 OPENSSL_STATIC=0 OPENSSL_NO_VENDOR=1"; fi
```

This injects three `openssl-sys` env vars into every `cargo build`:
- `OPENSSL_DIR=/opt/homebrew/opt/openssl@3` — point at the same OpenSSL
  installed by Homebrew that nginx links.
- `OPENSSL_STATIC=0` — force dynamic linking; do NOT embed a private copy.
- `OPENSSL_NO_VENDOR=1` — disable the `openssl-sys` vendored fallback.

On Linux there is a single system OpenSSL; no override is needed because
`openssl-sys` resolves to the same library nginx uses by default.

---

## Platform support matrix

| Platform            | nginx OpenSSL             | Required env vars                                             | Tested | Notes                                    |
|---------------------|---------------------------|---------------------------------------------------------------|--------|------------------------------------------|
| macOS (Homebrew)    | openssl@3 (dynamic)       | `OPENSSL_DIR=openssl@3 OPENSSL_STATIC=0 OPENSSL_NO_VENDOR=1` | Yes    | See Makefile pin; A0/C2/C3 verified      |
| Debian/Ubuntu arm64 | libssl3 (system)          | _(none — default resolution is correct)_                     | Yes    | debian-vm; A3 full E2E 2026-06-12        |
| Debian/Ubuntu amd64 | libssl3 (system)          | _(none — default resolution is correct)_                     | Yes    | TSAN/ASan dockerized gate                |
| Other Linux (glibc) | libssl3 or libssl1.1      | _(none — default resolution correct if single OpenSSL)_      | No     | Expected to work; min version 1.1.1      |
| Alpine Linux (musl) | system libssl             | May need `OPENSSL_DIR` if pkg name differs from nginx build   | No     | Not tested                               |
| CI (Docker/GitHub)  | libssl3 (Debian-based)    | _(none)_                                                      | Partial| TSAN/ASan images use debian:bookworm     |

---

## TLS feature set (what is exercised E2E)

Verified by `tests/integration/run_a3_tls_e2e.sh` on debian-vm, 2026-06-12:

- **Server cert verification** (`trusted_certificate`): OTLP/HTTP and gRPC
  both validate the collector's certificate against the configured CA (scenarios
  a + b). A wrong CA causes fail-closed with no data delivery (scenario c).
- **Insecure mode** (`ssl_verify off`): delivers despite mismatched CA;
  config-time WARN is emitted (scenario d).
- **mTLS** (`ssl_certificate` + `ssl_certificate_key`): client cert presented
  to a collector requiring mutual TLS (scenario e1); missing client cert
  fails closed (scenario e2).
- **DNS hostname verification** (`X509_VERIFY_PARAM_set1_host`): cert SAN
  mismatch for DNS names fails (scenario f1).
- **IP-literal hostname verification** (`X509_VERIFY_PARAM_set1_ip_asc`):
  cert IP SAN mismatch for IP-literal endpoints fails (scenario f2). This
  exercises the A2 IP-literal branch distinctly from the DNS branch.
- **TLS 1.2 minimum**: enforced via `SSL_CTX_set_min_proto_version(TLS1_2_VERSION)`.
- **SIGHUP reload**: new exporter generation reads updated cert/CA paths after
  reload (scenario g).
- **ALPN h2** (gRPC over TLS): negotiated automatically by the gRPC transport
  when the endpoint is `https://`.
- **SNI** (DNS names): set via `SSL_set_tlsext_host_name`; suppressed for
  IP-literal endpoints per RFC 6066 §3.

---

## Why STATIC=0 matters

`openssl-sys` by default tries to find a system OpenSSL; if it cannot, it
falls back to vendoring (building from source and statically linking).  A
statically linked OpenSSL:

1. Uses a **different address space** for global state (`OPENSSL_init_ssl`,
   engine lists, BIO method tables) than the copy nginx loaded.
2. Is a **different version** from what nginx was tested against, so TLS
   behaviour may differ (cipher selection, defaults, etc.).
3. Causes `SSL_CTX` pointer arithmetic to use the **wrong struct offsets**
   when accessed from the shared-library copy, causing silent data corruption.

Setting `OPENSSL_STATIC=0` + `OPENSSL_NO_VENDOR=1` prevents the fallback
and causes a hard build error if the correct shared OpenSSL cannot be found
— which is the correct failure mode.
