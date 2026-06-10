#!/usr/bin/env bash
# tests/integration/run_a1_worker_order.sh — A1 regression test
#
# Verifies that nginx refuses to start (exits non-zero) when the module's shm
# zones are undersized because `worker_processes` appears after the `http {}`
# block.  Before the A1 fix, nginx would start silently and workers 1-3 would
# write past the zone end into adjacent memory.  After the fix, init_module
# detects the mismatch and returns NGX_ERROR.
#
# Also verifies the NORMAL ordering (worker_processes before http{}) still
# works, as a regression guard.
#
# Exit codes:
#   0  all assertions passed
#   1  pre-flight or build error
#   2  an assertion failed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPO_ROOT="$(cd "${CRATE_DIR}/.." && pwd)"

CONF_TEMPLATE="${SCRIPT_DIR}/nginx_worker_processes_after_http.conf"
NORMAL_CONF_TEMPLATE="${SCRIPT_DIR}/nginx.conf"

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

# ─── Pre-flight ──────────────────────────────────────────────────────────────

if [[ ! -x "${NGINX_BINARY}" ]]; then
    echo "ERROR: nginx binary not found at ${NGINX_BINARY}" >&2
    exit 1
fi

# ─── Build ───────────────────────────────────────────────────────────────────

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

# ─── Assertion 1: hostile ordering → nginx refuses to start ─────────────────

info "--- A1 assertion 1: hostile ordering (worker_processes after http{}) ---"

PREFIX="$(mktemp -d /tmp/ngx-otel-a1.XXXXXX)"
cleanup_hostile() {
    echo "=== error.log (hostile ordering) ==="
    cat "${PREFIX}/logs/error.log" 2>/dev/null || echo "(not found)"
    rm -rf "${PREFIX}"
}
trap cleanup_hostile EXIT

mkdir -p "${PREFIX}/logs"

sed \
    -e "s|@MODULE_PATH@|${MODULE_PATH}|g" \
    -e "s|@PREFIX@|${PREFIX}|g" \
    "${CONF_TEMPLATE}" > "${PREFIX}/nginx.conf"

# Run nginx; it must exit with a non-zero status (init_module returns NGX_ERROR).
NGINX_EXIT=0
"${NGINX_BINARY}" \
    -p "${PREFIX}" \
    -c "${PREFIX}/nginx.conf" \
    2>/dev/null \
    || NGINX_EXIT=$?

if [[ "${NGINX_EXIT}" -eq 0 ]]; then
    fail "A1: nginx exited 0 with hostile ordering — expected non-zero (init_module did not fail)"
fi
pass "A1: nginx exited ${NGINX_EXIT} (non-zero) with hostile ordering"

# Assert the error log contains our A1 message.
if grep -q "shm zones were sized for 1 worker" "${PREFIX}/logs/error.log" 2>/dev/null; then
    pass "A1: error.log contains the expected sizing mismatch message"
else
    echo "=== error.log tail (looking for A1 message) ==="
    tail -20 "${PREFIX}/logs/error.log" 2>/dev/null
    fail "A1: error.log does NOT contain the expected sizing mismatch message"
fi

trap - EXIT
rm -rf "${PREFIX}"

# ─── Assertion 2: normal ordering → nginx starts correctly ──────────────────

info "--- A1 assertion 2: normal ordering (worker_processes before http{}) ---"

PREFIX2="$(mktemp -d /tmp/ngx-otel-a1-normal.XXXXXX)"
cleanup_normal() {
    [[ -n "${NGINX_PID2:-}" ]] && kill "${NGINX_PID2}" 2>/dev/null || true
    rm -rf "${PREFIX2}"
}
trap cleanup_normal EXIT

mkdir -p "${PREFIX2}/logs"

sed \
    -e "s|@MODULE_PATH@|${MODULE_PATH}|g" \
    -e "s|@PREFIX@|${PREFIX2}|g" \
    "${NORMAL_CONF_TEMPLATE}" > "${PREFIX2}/nginx.conf"

"${NGINX_BINARY}" \
    -p "${PREFIX2}" \
    -c "${PREFIX2}/nginx.conf" &
NGINX_PID2=$!

sleep 1

if kill -0 "${NGINX_PID2}" 2>/dev/null; then
    pass "A1: nginx starts correctly with normal ordering"
else
    echo "=== error.log (normal ordering) ==="
    cat "${PREFIX2}/logs/error.log" 2>/dev/null || echo "(not found)"
    fail "A1: nginx exited unexpectedly with normal ordering"
fi

kill "${NGINX_PID2}" 2>/dev/null || true
wait "${NGINX_PID2}" 2>/dev/null || true
trap - EXIT
rm -rf "${PREFIX2}"

# ─── Summary ─────────────────────────────────────────────────────────────────

echo ""
pass "A1 worker_processes-after-http{} regression test: all assertions passed"
