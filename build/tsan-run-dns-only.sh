#!/usr/bin/env bash
# build/tsan-run-dns-only.sh — DNS-only TSAN gate (option-a follow-up to full run).
#
# Runs Steps 1-3 of tsan-run.sh (compile sanity + plain TSAN nginx + TSAN env),
# then exercises ONLY run_dns_dualstack.sh, then scans DNS error logs for
# ThreadSanitizer warnings.
#
# Usage (inside the TSAN Docker container, same mounts as tsan-run.sh):
#   bash build/tsan-run-dns-only.sh 2>&1 | tee /tmp/tsan-dns-only.txt
#
# Called by: `make tsan-test-dns` target (see Makefile)

set -euo pipefail

cd /work/ngx-otel-rust

TSAN_OBJS=/work/ngx-otel-rust/objs-tsan
PLAIN_OBJS=/work/ngx-otel-rust/objs-tsan-plain

# ── Step 1: Compile sanity check ─────────────────────────────────────────────

echo "[tsan-dns] Step 1: Compile sanity check (make build BUILD=tsan)..."
NGINX_SOURCE_DIR=/work/nginx \
NGINX_BUILD_DIR="${TSAN_OBJS}" \
make build BUILD=tsan
echo "[tsan-dns] Step 1: OK — TSAN flags accepted."

# ── Step 2: Plain TSAN nginx ──────────────────────────────────────────────────

echo "[tsan-dns] Step 2: Building plain TSAN nginx (no --add-module)..."
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
echo "[tsan-dns] Step 2: OK — plain TSAN nginx at ${PLAIN_OBJS}/nginx"

# ── Step 3: Export TSAN env ───────────────────────────────────────────────────

echo "[tsan-dns] Step 3: Exporting TSAN env..."
export RUSTFLAGS="-Cforce-frame-pointers=yes -Zsanitizer=thread -Zexternal-clangrt"
export RUSTC_BOOTSTRAP=1
export CARGO_BUILD_TARGET="$(rustc -vV | awk '/^host: / { print $2 }')"
export CARGO_UNSTABLE_BUILD_STD="std,panic_abort"

export NGINX_BINARY="${PLAIN_OBJS}/nginx"
export NGINX_SOURCE_DIR=/work/nginx
export NGINX_BUILD_DIR="${PLAIN_OBJS}"

echo "[tsan-dns] TSAN nginx:  ${NGINX_BINARY}"
echo "[tsan-dns] RUSTFLAGS:   ${RUSTFLAGS}"

# ── Step 4: DNS + IPv6 dual-stack test ───────────────────────────────────────

echo ""
echo "[tsan-dns] === Running run_dns_dualstack.sh under TSAN ==="
bash tests/integration/run_dns_dualstack.sh

# ── Step 5: ThreadSanitizer warning scan (DNS logs only) ─────────────────────

echo ""
echo "[tsan-dns] Checking DNS error logs for ThreadSanitizer warnings..."
TSAN_WARNINGS=0
for log in /tmp/ngx-otel-dns-a.*/logs/error.log \
           /tmp/ngx-otel-dns-b.*/logs/error.log \
           /tmp/ngx-otel-dns-c.*/logs/error.log \
           /tmp/ngx-otel-dns-d.*/logs/error.log; do
    if [[ -f "${log}" ]]; then
        count=$(grep -c "WARNING: ThreadSanitizer" "${log}" 2>/dev/null || true)
        if [[ "${count}" -gt 0 ]]; then
            echo "[tsan-dns] TSAN WARNING found in ${log}:" >&2
            grep "WARNING: ThreadSanitizer" "${log}" >&2
            TSAN_WARNINGS=$(( TSAN_WARNINGS + count ))
        fi
    fi
done

if [[ "${TSAN_WARNINGS}" -gt 0 ]]; then
    echo "[tsan-dns] FAIL: ${TSAN_WARNINGS} ThreadSanitizer warning(s) detected." >&2
    echo "[tsan-dns] Review the full TSAN report in the error.log files listed above." >&2
    exit 1
fi

echo "[tsan-dns] Zero ThreadSanitizer warnings.  DNS TSAN gate: PASS."
echo "TSAN_EXIT:0"
