#!/usr/bin/env bash
# build/tsan-run.sh — executed inside the TSAN Docker container by `make tsan-test`.
#
# Runs inside build/Dockerfile.tsan.  Mount layout (all writable):
#   /work/ngx-otel-rust  ← project root
#   /work/nginx          ← sibling nginx source checkout
#   /work/ngx-rust       ← sibling ngx-rust checkout
#
# Design
# ──────
#   Step 1 – Compile sanity: `make build BUILD=tsan` builds nginx + the
#             module (staticlib via auto/rust) with all TSAN flags.  The
#             resulting nginx binary has the module statically linked
#             (--add-module) and is NOT used for integration tests because
#             nginx's ngx_load_module guard would reject a second load_module
#             of the same symbol table.  This step only verifies that all
#             TSAN flags are accepted by clang + rustc inside the container.
#
#   Step 2 – Plain TSAN nginx (no --add-module): configure + build a second
#             nginx binary WITHOUT --add-module.  This binary can load the
#             module dynamically via `load_module` in the integration scripts'
#             nginx.conf without hitting the "already loaded" guard.
#
#   Step 3 – TSAN RUSTFLAGS: export -Zsanitizer=thread (+ RUSTC_BOOTSTRAP=1,
#             -Zexternal-clangrt) so the integration scripts' own
#             `cargo build --release` produces a TSAN-instrumented cdylib at
#             target/release/ — the hardcoded MODULE_PATH both scripts use.
#             No -Zbuild-std / --target here because the scripts' cargo
#             invocation does not pass --target; the host std is unmodified
#             (acceptable — we instrument the module's own code).
#
#   Step 4 – Run both smoke scripts with NGINX_BINARY and NGINX_BUILD_DIR
#             pointing at the plain TSAN nginx.
#
#   Step 5 – Belt-and-suspenders scan: grep error.logs for any
#             "WARNING: ThreadSanitizer" lines.  With halt_on_error=1 a
#             real race would already have aborted the worker; this scan
#             catches any that slipped through.
#
# TSAN_OPTIONS must be set by the caller (done by `make tsan-test`):
#   halt_on_error=1:second_deadlock_stack=1:detect_deadlocks=1

set -euo pipefail

cd /work/ngx-otel-rust

TSAN_OBJS=/work/ngx-otel-rust/objs-tsan
PLAIN_OBJS=/work/ngx-otel-rust/objs-tsan-plain

# ── Step 1: Compile sanity check ─────────────────────────────────────────────

echo "[tsan-run] Step 1: Compile sanity check (make build BUILD=tsan)..."
NGINX_SOURCE_DIR=/work/nginx \
NGINX_BUILD_DIR="${TSAN_OBJS}" \
make build BUILD=tsan
echo "[tsan-run] Step 1: OK — TSAN flags accepted by clang + rustc."

# ── Step 2: Plain TSAN nginx (no --add-module) for integration tests ──────────

echo "[tsan-run] Step 2: Building plain TSAN nginx (no --add-module)..."
mkdir -p "${PLAIN_OBJS}"

# auto/configure unconditionally writes /work/nginx/Makefile even for out-of-
# tree builds.  Preserve the original and restore it afterwards.
cd /work/nginx
if [[ -f Makefile ]]; then
    cp -f Makefile Makefile.tsan-bak
fi

auto/configure \
    --with-compat \
    --with-http_stub_status_module \
    --with-cc=clang \
    --with-cc-opt="-O1 -fsanitize=thread -fno-omit-frame-pointer" \
    --with-ld-opt="-fsanitize=thread" \
    --with-debug \
    --builddir="${PLAIN_OBJS}"

# auto/configure regenerated /work/nginx/Makefile; remove it and restore backup.
rm -f /work/nginx/Makefile
if [[ -f /work/nginx/Makefile.tsan-bak ]]; then
    mv -f /work/nginx/Makefile.tsan-bak /work/nginx/Makefile
fi

# Build the plain TSAN nginx binary (must be run from nginx source dir).
make -f "${PLAIN_OBJS}/Makefile" binary

cd /work/ngx-otel-rust
echo "[tsan-run] Step 2: OK — plain TSAN nginx at ${PLAIN_OBJS}/nginx"

# ── Step 3: Export TSAN RUSTFLAGS for integration scripts ────────────────────

echo "[tsan-run] Step 3: Exporting TSAN RUSTFLAGS for integration scripts..."
# The scripts hardcode MODULE_PATH to target/release/libngx_http_otel_module.so
# and run `cargo build --release --features test-support` themselves.  Exporting
# RUSTFLAGS here causes that cargo invocation to produce a TSAN-instrumented
# cdylib at the expected path without any modification to the scripts.
#
# -Zexternal-clangrt: use the clang TSAN runtime already linked into the nginx
# binary rather than a Rust-bundled copy.  Avoids duplicate runtime init.
# -Zbuild-std is omitted: the scripts do not pass --target, so cargo builds for
# the host triple and outputs to target/release/.  The standard library is not
# re-compiled under TSAN; only the module's own code is instrumented.
export RUSTFLAGS="-Cforce-frame-pointers=yes -Zsanitizer=thread -Zexternal-clangrt"
export RUSTC_BOOTSTRAP=1

# Point integration scripts at the plain TSAN nginx.
export NGINX_BINARY="${PLAIN_OBJS}/nginx"
export NGINX_SOURCE_DIR=/work/nginx
export NGINX_BUILD_DIR="${PLAIN_OBJS}"

echo "[tsan-run] TSAN nginx:  ${NGINX_BINARY}"
echo "[tsan-run] RUSTFLAGS:   ${RUSTFLAGS}"

# ── Step 4: Run integration scripts ──────────────────────────────────────────

echo ""
echo "[tsan-run] === Running run_grpc_smoke.sh under TSAN ==="
bash tests/integration/run_grpc_smoke.sh

echo ""
echo "[tsan-run] === Running run_grpc_bidi_smoke.sh under TSAN ==="
bash tests/integration/run_grpc_bidi_smoke.sh

# ── Step 5: Belt-and-suspenders ThreadSanitizer warning scan ─────────────────

echo ""
echo "[tsan-run] Checking for ThreadSanitizer warnings in error logs..."
TSAN_WARNINGS=0
for log in /tmp/ngx-otel-grpc-smoke.*/logs/error.log \
           /tmp/ngx-otel-grpc-bidi-smoke.*/logs/error.log; do
    if [[ -f "${log}" ]]; then
        count=$(grep -c "WARNING: ThreadSanitizer" "${log}" 2>/dev/null || true)
        if [[ "${count}" -gt 0 ]]; then
            echo "[tsan-run] TSAN WARNING found in ${log}:" >&2
            grep "WARNING: ThreadSanitizer" "${log}" >&2
            TSAN_WARNINGS=$(( TSAN_WARNINGS + count ))
        fi
    fi
done

if [[ "${TSAN_WARNINGS}" -gt 0 ]]; then
    echo "[tsan-run] FAIL: ${TSAN_WARNINGS} ThreadSanitizer warning(s) detected." >&2
    echo "[tsan-run] STOP-AND-ASK: surface the full TSAN report for review." >&2
    exit 1
fi

echo "[tsan-run] Zero ThreadSanitizer warnings.  TSAN gate: PASS."
