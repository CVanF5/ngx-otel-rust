#!/usr/bin/env bash
# tests/integration/run_exporter_heartbeat.sh — Phase 1.3.3 Sub-item 3 gate
#
# Verifies that the exporter liveness heartbeat (control_shm.version) increments
# on schedule by reading it via the test-support `otel_status_endpoint` directive.
#
# Protocol:
#   1. Build module with --features test-support (otel_status_endpoint present).
#   2. Start nginx with otel_metric_interval 1s and location /otel_status.
#   3. Curl /otel_status → V_INITIAL.
#   4. Sleep 5s.
#   5. Curl /otel_status → V_AFTER.
#   6. Assert V_AFTER >= V_INITIAL + 1 (heartbeat fired at least once).
#
# Exit codes: 0 = PASS, 1 = preflight failed, 2 = assertion failed.

set -euo pipefail

# ─── Resolve paths ────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CONF_TEMPLATE="${SCRIPT_DIR}/nginx_heartbeat.conf"

. "${CRATE_DIR}/test-harness/lib.sh" 2>/dev/null || true

# Resolve nginx binary.
NGINX_BINARY="${NGINX_BINARY:-${CRATE_DIR}/objs-release/nginx}"
if [[ ! -x "${NGINX_BINARY}" ]]; then
    NGINX_BINARY="${CRATE_DIR}/objs-debug/nginx"
fi
if [[ ! -x "${NGINX_BINARY}" ]]; then
    echo "ERROR: nginx binary not found. Set NGINX_BINARY or run 'make build-release'." >&2
    exit 1
fi

# Use cargo's release output (built with test-support below).
case "$(uname -s)" in
    Darwin) MODULE_EXT="dylib" ;;
    *)      MODULE_EXT="so"    ;;
esac
# When CARGO_BUILD_TARGET is set (e.g., the TSAN gate uses --target so cargo
# can also -Zbuild-std), cargo writes its output to target/<triple>/release/
# rather than target/release/.  Backwards-compatible: unset -> original path.
if [[ -n "${CARGO_BUILD_TARGET:-}" ]]; then
    MODULE_PATH="${CRATE_DIR}/target/${CARGO_BUILD_TARGET}/release/libngx_http_otel_module.${MODULE_EXT}"
else
    MODULE_PATH="${CRATE_DIR}/target/release/libngx_http_otel_module.${MODULE_EXT}"
fi

# ─── Colour helpers ───────────────────────────────────────────────────────────

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
pass()  { echo -e "${GREEN}[PASS]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*" >&2; exit 2; }
info()  { echo -e "${YELLOW}[INFO]${NC} $*"; }

# ─── Pre-flight checks ────────────────────────────────────────────────────────

if [[ ! -x "${NGINX_BINARY}" ]]; then
    echo "ERROR: nginx binary not found at ${NGINX_BINARY}." >&2
    exit 1
fi
info "nginx binary: ${NGINX_BINARY}"

# ─── Build module with test-support feature ───────────────────────────────────
#
# otel_status_endpoint is gated #[cfg(any(test, feature = "test-support"))].
# Without this feature flag the directive is absent and nginx -t will fail.

info "Building release module with --features test-support..."
(
    cd "${CRATE_DIR}"
    NGINX_SOURCE_DIR="${NGINX_SOURCE_DIR:-${CRATE_DIR}/../nginx}" \
    NGINX_BUILD_DIR="${NGINX_BUILD_DIR:-${CRATE_DIR}/objs-release}" \
    cargo build --release --features test-support 2>&1
)
if [[ ! -f "${MODULE_PATH}" ]]; then
    echo "ERROR: test-support module not found: ${MODULE_PATH}" >&2
    exit 1
fi
info "Module built: ${MODULE_PATH}"

# ─── Sandbox setup ────────────────────────────────────────────────────────────

PREFIX="$(mktemp -d /tmp/ngx-otel-heartbeat.XXXXXX)"
NGINX_PID=""

cleanup() {
    if [[ -n "${NGINX_PID:-}" ]]; then
        kill -QUIT "${NGINX_PID}" 2>/dev/null || kill "${NGINX_PID}" 2>/dev/null || true
        sleep 1
    fi
    [[ "${KEEP_SANDBOX:-0}" == "1" ]] || rm -rf "${PREFIX}"
}
trap cleanup EXIT

mkdir -p "${PREFIX}/logs" "${PREFIX}/client_body_temp"

sed \
    -e "s|@MODULE_PATH@|${MODULE_PATH}|g" \
    -e "s|@PREFIX@|${PREFIX}|g" \
    "${CONF_TEMPLATE}" > "${PREFIX}/nginx.conf"

# ─── Start nginx and wait for it to be ready ──────────────────────────────────

"${NGINX_BINARY}" -p "${PREFIX}" -c "${PREFIX}/nginx.conf" &
NGINX_PID=$!
info "nginx started (PID ${NGINX_PID})"
sleep 2

if ! kill -0 "${NGINX_PID}" 2>/dev/null; then
    echo "=== error.log ===" >&2
    cat "${PREFIX}/logs/error.log" >&2
    fail "nginx exited immediately — config error?"
fi

# ─── Heartbeat check ─────────────────────────────────────────────────────────

STATUS_URL="http://127.0.0.1:9201/otel_status"

info "Reading V_INITIAL from ${STATUS_URL}..."
V_INITIAL="$(curl -sf --max-time 3 "${STATUS_URL}" | tr -d '[:space:]')"
if [[ -z "${V_INITIAL}" ]]; then
    echo "=== error.log ===" >&2
    grep -i "otel\|status\|error" "${PREFIX}/logs/error.log" | head -20 >&2
    fail "Failed to read /otel_status — check error.log"
fi
if ! [[ "${V_INITIAL}" =~ ^[0-9]+$ ]]; then
    fail "V_INITIAL is not a non-negative integer: '${V_INITIAL}'"
fi
info "V_INITIAL = ${V_INITIAL}"

info "Sleeping 5s (metric_interval=1s, expect ≥4 heartbeats)..."
sleep 5

info "Reading V_AFTER from ${STATUS_URL}..."
V_AFTER="$(curl -sf --max-time 3 "${STATUS_URL}" | tr -d '[:space:]')"
if [[ -z "${V_AFTER}" ]]; then
    fail "Failed to read /otel_status on second curl"
fi
if ! [[ "${V_AFTER}" =~ ^[0-9]+$ ]]; then
    fail "V_AFTER is not a non-negative integer: '${V_AFTER}'"
fi
info "V_AFTER  = ${V_AFTER}"

# Assert V_AFTER > V_INITIAL (heartbeat incremented at least once).
if (( V_AFTER <= V_INITIAL )); then
    fail "Heartbeat did not increment: V_AFTER=${V_AFTER} ≤ V_INITIAL=${V_INITIAL}"
fi

DELTA=$(( V_AFTER - V_INITIAL ))
pass "Heartbeat incremented: V_INITIAL=${V_INITIAL} → V_AFTER=${V_AFTER} (delta=${DELTA})"

# ─── Verify otel_status_endpoint absent from production build ─────────────────

PROD_MODULE="${CRATE_DIR}/objs-release/ngx_http_otel_module.so"
if [[ -f "${PROD_MODULE}" ]]; then
    if strings "${PROD_MODULE}" | grep -q "otel_status_endpoint"; then
        fail "Production .so contains 'otel_status_endpoint' — cfg gate broken!"
    fi
    pass "Production .so does NOT contain 'otel_status_endpoint' (cfg gate holds)"
fi

echo ""
pass "=== Heartbeat integration test passed ==="
