# OpenSSL support matrix — ngx-otel-rust

**STATUS: STUB** — filled fully by Phase A item A3 once the TLS layer pins
actual version requirements. The rule below is verified and binding now
(discovered via demo 2026-06-12, `f2d8455`).

---

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

## Summary table (to be completed in A3)

| Platform         | nginx OpenSSL         | Required env vars                                             | Notes                        |
|------------------|-----------------------|---------------------------------------------------------------|------------------------------|
| macOS (Homebrew) | openssl@3 (dynamic)   | `OPENSSL_DIR=openssl@3 OPENSSL_STATIC=0 OPENSSL_NO_VENDOR=1` | See Makefile pin above       |
| Debian/Ubuntu    | system libssl3        | _(none — default resolution is correct)_                     | Verified on debian-vm        |
| Other Linux      | system libssl         | _(none — default resolution is correct)_                     | To be confirmed in A3        |
| CI (Docker)      | TBD in A3             | TBD in A3                                                     |                              |

**Minimum OpenSSL version**: TBD in A3 (driven by `SSL_set1_host` /
`X509_VERIFY_PARAM` API availability — will be pinned once A1 lands).

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

---

*This file is a stub. A3 will add: minimum version requirements, CI matrix,
TLS 1.2/1.3 feature flags, mTLS cert/key format constraints, and tested
platform matrix.*
