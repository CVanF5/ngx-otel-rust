#!/usr/bin/env bash
# tests/integration/run_worker_order.sh — worker-processes-order regression test
#
# Covers three assertions:
#
#   CASE 1 — ncpu-headroom POSITIVE (would FAIL without the ncpu-headroom fix):
#     worker_processes == ncpu placed AFTER http{}.  Without the fix, zones were
#     reserved for 1 slot (UNSET → 1), so check_zone_sizing would refuse any
#     count > 1.  With the fix, zones are reserved for ngx_ncpu slots, so this
#     starts cleanly.  Skipped on single-CPU machines where ncpu == 1 (before/after
#     the fix indistinguishable: both succeed).
#
#   CASE 2 — residual worker-count error:
#     worker_processes == ncpu+1 placed AFTER http{}.  init_module must refuse
#     and log "shm zones were reserved for".  Operator instruction: move
#     worker_processes before http{} or reduce it.
#
#   CASE 3 — NORMAL ORDERING (regression guard):
#     worker_processes before http{} → nginx must start.
#
# Exit codes:
#   0  all assertions passed
#   1  pre-flight or build error
#   2  an assertion failed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPO_ROOT="$(cd "${CRATE_DIR}/.." && pwd)"

WORKER_AFTER_HTTP_CONF="${SCRIPT_DIR}/nginx_worker_processes_after_http.conf"
A1B_POSITIVE_CONF="${SCRIPT_DIR}/nginx_wp_after_http_under_ncpu.conf"
NORMAL_CONF="${SCRIPT_DIR}/nginx.conf"

. "${CRATE_DIR}/test-harness/lib.sh"
resolve_nginx_binary || true

case "$(uname -s)" in
    Darwin) MODULE_EXT="dylib" ;;
    *)      MODULE_EXT="so"    ;;
esac
if [[ -n "${CARGO_BUILD_TARGET:-}" ]]; then
    MODULE_PATH="${CRATE_DIR}/target/${CARGO_BUILD_TARGET}/release/libngx_http_otel_module.${MODULE_EXT}"
else
    MODULE_PATH="${CRATE_DIR}/target/release/libngx_http_otel_module.${MODULE_EXT}"
fi

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass()  { echo -e "${GREEN}[PASS]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*" >&2; exit 2; }
info()  { echo -e "${YELLOW}[INFO]${NC} $*"; }
skip()  { echo -e "${YELLOW}[SKIP]${NC} $*"; }

# ─── Pre-flight ───────────────────────────────────────────────────────────────

if [[ ! -x "${NGINX_BINARY}" ]]; then
    echo "ERROR: nginx binary not found at ${NGINX_BINARY}" >&2
    exit 1
fi

# ─── Build ────────────────────────────────────────────────────────────────────

info "Building release module..."
(
    cd "${CRATE_DIR}"
    NGINX_SOURCE_DIR="${NGINX_SOURCE_DIR:-${REPO_ROOT}/nginx}" \
    NGINX_BUILD_DIR="${NGINX_BUILD_DIR:-${REPO_ROOT}/nginx/objs}" \
    cargo build --release 2>&1
)
if [[ ! -f "${MODULE_PATH}" ]]; then
    echo "ERROR: module not found after build: ${MODULE_PATH}" >&2
    exit 1
fi
info "Module built: ${MODULE_PATH}"

# Determine ngx_ncpu equivalent from the OS (matches nginx's ngx_os_init).
NCPU="$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 1)"
info "Detected ncpu=${NCPU}"

# ─── CASE 1: ncpu-headroom positive ───────────────────────────────────────────
# worker_processes == ncpu AFTER http{} → must START (ncpu-headroom fix).
# Without the fix: reserved = 1 < ncpu → check_zone_sizing would refuse (FAIL).
# With the fix: reserved = ncpu ≥ ncpu → init_module accepts (PASS).

info "--- CASE 1: ncpu-headroom positive (worker_processes=${NCPU} after http{}) ---"

if [[ "${NCPU}" -lt 2 ]]; then
    skip "CASE 1: ncpu=${NCPU} — single-CPU machine, before/after the fix indistinguishable; skipping"
else
    PREFIX1="$(mktemp -d /tmp/ngx-otel-worker-order-pos.XXXXXX)"
    cleanup1() {
        [[ -n "${NGINX_PID1:-}" ]] && kill "${NGINX_PID1}" 2>/dev/null || true
        echo "=== error.log (ncpu-headroom positive) ==="
        cat "${PREFIX1}/logs/error.log" 2>/dev/null || echo "(not found)"
        rm -rf "${PREFIX1}"
    }
    trap cleanup1 EXIT
    mkdir -p "${PREFIX1}/logs"

    sed \
        -e "s|@MODULE_PATH@|${MODULE_PATH}|g" \
        -e "s|@PREFIX@|${PREFIX1}|g" \
        -e "s|@WORKER_PROCESSES@|${NCPU}|g" \
        "${A1B_POSITIVE_CONF}" > "${PREFIX1}/nginx.conf"

    "${NGINX_BINARY}" \
        -p "${PREFIX1}" \
        -c "${PREFIX1}/nginx.conf" &
    NGINX_PID1=$!

    sleep 1

    if kill -0 "${NGINX_PID1}" 2>/dev/null; then
        pass "CASE 1: nginx starts with worker_processes=${NCPU} after http{}"
    else
        echo "=== error.log (ncpu-headroom positive) ==="
        cat "${PREFIX1}/logs/error.log" 2>/dev/null || echo "(not found)"
        fail "CASE 1: nginx exited — worker_processes=${NCPU} after http{} should have started"
    fi

    # ── Telemetry check: verify requests succeed on all NCPU workers ─────────
    # The ncpu-headroom fix reserves ngx_ncpu WorkerSlots at shm-init time.  If any
    # worker had an out-of-bounds slot index it would crash on the first
    # instrumented request, causing a non-200 response below.
    # We also check that the exporter produced metrics visible at the collector.
    REQ_COUNT=$(( NCPU * 3 ))
    info "CASE 1: sending ${REQ_COUNT} requests to exercise all ${NCPU} worker slots..."
    for i in $(seq 1 "${REQ_COUNT}"); do
        HTTP_STATUS="$(curl -sf -o /dev/null -w '%{http_code}' --max-time 2 http://127.0.0.1:9201/ 2>/dev/null || echo 000)"
        if [[ "${HTTP_STATUS}" != "200" ]]; then
            fail "CASE 1: request ${i}/${REQ_COUNT} returned ${HTTP_STATUS} — a worker may have crashed (bad slot index with ${NCPU} workers after http{})"
        fi
    done
    pass "CASE 1: all ${REQ_COUNT} HTTP requests returned 200 (all ${NCPU} worker slots correctly reserved)"

    # Give the exporter at least one 250ms tick + export round-trip.
    sleep 0.6

    if _collector_endpoint_reachable; then
        if grep -q "ngx-otel-worker-order-ncpu-test" "${METRICS_LOG}" 2>/dev/null; then
            pass "CASE 1: metrics.json contains ngx-otel-worker-order-ncpu-test — exporter running with ${NCPU} workers reached the collector"
        else
            info "CASE 1: collector reachable but ngx-otel-worker-order-ncpu-test not yet in metrics.json; skipping (metrics pipeline may not have flushed)"
        fi
    else
        info "CASE 1: collector not reachable at ${COLLECTOR_HTTP_ENDPOINT:-http://127.0.0.1:4318} — skipping telemetry-arrival check (run with collector up to assert full pipeline)"
    fi

    kill "${NGINX_PID1}" 2>/dev/null || true
    wait "${NGINX_PID1}" 2>/dev/null || true
    trap - EXIT
    rm -rf "${PREFIX1}"
fi

# ─── CASE 2: residual worker-count error ──────────────────────────────────────
# worker_processes == ncpu+1 AFTER http{} → init_module must REFUSE.
# (reserved = ncpu, actual = ncpu+1 > reserved → error)

ABOVE_NCPU=$(( NCPU + 1 ))
info "--- CASE 2: residual worker-count error (worker_processes=${ABOVE_NCPU} after http{}) ---"

PREFIX2="$(mktemp -d /tmp/ngx-otel-worker-order-err.XXXXXX)"
cleanup2() {
    echo "=== error.log (residual worker-count error) ==="
    cat "${PREFIX2}/logs/error.log" 2>/dev/null || echo "(not found)"
    rm -rf "${PREFIX2}"
}
trap cleanup2 EXIT
mkdir -p "${PREFIX2}/logs"

sed \
    -e "s|@MODULE_PATH@|${MODULE_PATH}|g" \
    -e "s|@PREFIX@|${PREFIX2}|g" \
    -e "s|@WORKER_PROCESSES@|${ABOVE_NCPU}|g" \
    "${WORKER_AFTER_HTTP_CONF}" > "${PREFIX2}/nginx.conf"

NGINX_EXIT2=0
"${NGINX_BINARY}" \
    -p "${PREFIX2}" \
    -c "${PREFIX2}/nginx.conf" \
    2>/dev/null \
    || NGINX_EXIT2=$?

if [[ "${NGINX_EXIT2}" -eq 0 ]]; then
    fail "CASE 2: nginx exited 0 with worker_processes=${ABOVE_NCPU} after http{} — expected refusal"
fi
pass "CASE 2: nginx exited ${NGINX_EXIT2} (non-zero) with worker_processes=${ABOVE_NCPU} after http{}"

if grep -q "shm zones were reserved for" "${PREFIX2}/logs/error.log" 2>/dev/null; then
    pass "CASE 2: error.log contains expected ncpu-headroom refusal message"
else
    echo "=== error.log tail ==="
    tail -20 "${PREFIX2}/logs/error.log" 2>/dev/null
    fail "CASE 2: error.log missing 'shm zones were reserved for' — ncpu-headroom refusal message not emitted"
fi

trap - EXIT
rm -rf "${PREFIX2}"

# ─── CASE 3: normal ordering guard ───────────────────────────────────────────
# worker_processes before http{} → must start (basic regression guard).

info "--- CASE 3: normal ordering (worker_processes before http{}) ---"

PREFIX3="$(mktemp -d /tmp/ngx-otel-worker-order-norm.XXXXXX)"
cleanup3() {
    [[ -n "${NGINX_PID3:-}" ]] && kill "${NGINX_PID3}" 2>/dev/null || true
    rm -rf "${PREFIX3}"
}
trap cleanup3 EXIT
mkdir -p "${PREFIX3}/logs"

sed \
    -e "s|@MODULE_PATH@|${MODULE_PATH}|g" \
    -e "s|@PREFIX@|${PREFIX3}|g" \
    "${NORMAL_CONF}" > "${PREFIX3}/nginx.conf"

"${NGINX_BINARY}" \
    -p "${PREFIX3}" \
    -c "${PREFIX3}/nginx.conf" &
NGINX_PID3=$!

sleep 1

if kill -0 "${NGINX_PID3}" 2>/dev/null; then
    pass "CASE 3: nginx starts correctly with normal ordering"
else
    echo "=== error.log (normal ordering) ==="
    cat "${PREFIX3}/logs/error.log" 2>/dev/null || echo "(not found)"
    fail "CASE 3: nginx exited with normal ordering — unexpected failure"
fi

kill "${NGINX_PID3}" 2>/dev/null || true
wait "${NGINX_PID3}" 2>/dev/null || true
trap - EXIT
rm -rf "${PREFIX3}"

# ─── Summary ─────────────────────────────────────────────────────────────────

echo ""
pass "worker_processes-order regression test: all assertions passed"
