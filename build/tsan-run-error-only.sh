#!/usr/bin/env bash
# build/tsan-run-error-only.sh — error-log-only TSAN gate.
#
# Runs Steps 1-3 of tsan-run.sh (compile sanity + plain TSAN nginx + TSAN env),
# then exercises ONLY run_error_log.sh, then scans the error-log test's nginx
# prefixes for ThreadSanitizer warnings.
#
# Why a dedicated target: run_error_log.sh is timing-flaky inside the *combined*
# tsan-run.sh suite (many fresh nginx instances + a signal/flood path under
# TSAN's slowdown — see commit f169a77, which added the analogous DNS-only
# target). Running it in isolation gives the race signal for the error-log path
# (writer -> error ring -> drain) without the combined-suite flakiness. Used to
# re-verify the Phase 2.3 path after the wall-clock timestamp fix (ngx_cached_time).
#
# Usage (inside the TSAN Docker container, same mounts as tsan-run.sh):
#   bash build/tsan-run-error-only.sh 2>&1 | tee /tmp/tsan-error-only.txt
#
# Called by: `make tsan-test-error` target (see Makefile)

set -euo pipefail

cd /work/ngx-otel-rust

TSAN_OBJS=/work/ngx-otel-rust/objs-tsan
PLAIN_OBJS=/work/ngx-otel-rust/objs-tsan-plain

# ── Step 1: Compile sanity check ─────────────────────────────────────────────

echo "[tsan-err] Step 1: Compile sanity check (make build BUILD=tsan)..."
NGINX_SOURCE_DIR=/work/nginx \
NGINX_BUILD_DIR="${TSAN_OBJS}" \
make build BUILD=tsan
echo "[tsan-err] Step 1: OK — TSAN flags accepted."

# ── Step 2: Plain TSAN nginx ──────────────────────────────────────────────────

echo "[tsan-err] Step 2: Building plain TSAN nginx (no --add-module)..."
mkdir -p "${PLAIN_OBJS}"

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

rm -f /work/nginx/Makefile
if [[ -f /work/nginx/Makefile.tsan-bak ]]; then
    mv -f /work/nginx/Makefile.tsan-bak /work/nginx/Makefile
fi

make -f "${PLAIN_OBJS}/Makefile" binary

cd /work/ngx-otel-rust
echo "[tsan-err] Step 2: OK — plain TSAN nginx at ${PLAIN_OBJS}/nginx"

# ── Step 3: Export TSAN env ───────────────────────────────────────────────────

echo "[tsan-err] Step 3: Exporting TSAN env..."
export RUSTFLAGS="-Cforce-frame-pointers=yes -Zsanitizer=thread -Zexternal-clangrt"
export RUSTC_BOOTSTRAP=1
export CARGO_BUILD_TARGET="$(rustc -vV | awk '/^host: / { print $2 }')"
export CARGO_UNSTABLE_BUILD_STD="std,panic_abort"

export NGINX_BINARY="${PLAIN_OBJS}/nginx"
export NGINX_SOURCE_DIR=/work/nginx
export NGINX_BUILD_DIR="${PLAIN_OBJS}"

echo "[tsan-err] TSAN nginx:  ${NGINX_BINARY}"
echo "[tsan-err] RUSTFLAGS:   ${RUSTFLAGS}"

# ── Step 4: Error-log integration test ───────────────────────────────────────

echo ""
echo "[tsan-err] === Running run_error_log.sh under TSAN (Phase 2.3 §6.6.2 error-log path) ==="
bash tests/integration/run_error_log.sh

# ── Step 5: ThreadSanitizer warning scan (error-log prefixes only) ───────────

echo ""
echo "[tsan-err] Checking error-log test prefixes for ThreadSanitizer warnings..."
TSAN_WARNINGS=0
for log in /tmp/ngx-otel-error-log.*/logs/error.log \
           /tmp/ngx-otel-error-log-stage-e.*/logs/error.log \
           /tmp/ngx-otel-dp-c.*/logs/error.log; do
    if [[ -f "${log}" ]]; then
        count=$(grep -c "WARNING: ThreadSanitizer" "${log}" 2>/dev/null || true)
        if [[ "${count}" -gt 0 ]]; then
            echo "[tsan-err] TSAN WARNING found in ${log}:" >&2
            grep "WARNING: ThreadSanitizer" "${log}" >&2
            TSAN_WARNINGS=$(( TSAN_WARNINGS + count ))
        fi
    fi
done

if [[ "${TSAN_WARNINGS}" -gt 0 ]]; then
    echo "[tsan-err] FAIL: ${TSAN_WARNINGS} ThreadSanitizer warning(s) detected." >&2
    echo "[tsan-err] STOP-AND-ASK: surface the full TSAN report for review." >&2
    exit 1
fi

echo "[tsan-err] Zero ThreadSanitizer warnings.  Error-log TSAN gate: PASS."
echo "TSAN_EXIT:0"
