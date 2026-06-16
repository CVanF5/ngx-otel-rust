#!/usr/bin/env bash
# tests/integration/run.sh — end-to-end integration test
#
# Builds the NGINX otel module, starts NGINX with worker_processes 4,
# sends HTTP traffic, waits for a metrics flush, then checks that:
#   1. metrics.json contains entries with service.name = ngx-otel-step9-integration
#   2. At least one histogram data point for http.server.request.duration arrived
#   3. error.log contains exactly one "export loop started" line (exporter process only)
#      The export task runs in the otel exporter process, not Worker 0.
#
# Prerequisites
# ─────────────
# 1. Docker available on PATH.  The OTel collector container is
#    auto-started if not already running (see test-harness/lib.sh).
#    Set OTEL_COLLECTOR_AUTOSTART=0 to skip auto-start (e.g., CI
#    environments managing the collector externally).
#
# 2. Required environment variables (or sensible defaults will be used):
#      NGINX_BINARY   — path to the nginx binary (default: auto-detected)
#      NGINX_SOURCE_DIR — nginx source tree (for cargo build)
#      NGINX_BUILD_DIR  — nginx build dir   (for cargo build)
#
# Running
# ───────
#   # From the ngx-otel-rust directory:
#   NGINX_SOURCE_DIR=../nginx \
#   NGINX_BUILD_DIR=../nginx/objs \
#   bash tests/integration/run.sh
#
# Exit codes
# ──────────
#   0  all assertions passed
#   1  a pre-flight or build check failed
#   2  a test assertion failed

set -euo pipefail

# ─── Resolve paths ───────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPO_ROOT="$(cd "${CRATE_DIR}/.." && pwd)"

CONF_TEMPLATE="${SCRIPT_DIR}/nginx.conf"

# Source the shared harness library.  Sets HARNESS_DIR, METRICS_LOG,
# COLLECTOR_HTTP_ENDPOINT, and exposes ensure_collector_running and
# resolve_nginx_binary.
. "${CRATE_DIR}/test-harness/lib.sh"
resolve_nginx_binary || true   # missing-binary error is produced by the preflight below

# Detect module extension (macOS = .dylib, Linux = .so)
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

SERVICE_NAME="ngx-otel-step9-integration"
METRIC_INTERVAL_S=2          # must match nginx.conf otel_metric_interval
FLUSH_WAIT_S=$(( METRIC_INTERVAL_S + 2 ))
N_REQUESTS=20

# ─── Colour helpers ──────────────────────────────────────────────────────────

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass()  { echo -e "${GREEN}[PASS]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*" >&2; exit 2; }
info()  { echo -e "${YELLOW}[INFO]${NC} $*"; }

# ─── Pre-flight checks ───────────────────────────────────────────────────────

info "Pre-flight checks..."

if [[ ! -x "${NGINX_BINARY}" ]]; then
    echo "ERROR: nginx binary not found at ${NGINX_BINARY}" >&2
    echo "       Set NGINX_BINARY to the correct path." >&2
    exit 1
fi

ensure_collector_running || exit 1

# ─── Build the module ────────────────────────────────────────────────────────

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

# ─── Sandbox prefix directory ────────────────────────────────────────────────

PREFIX="$(mktemp -d /tmp/ngx-otel-step9.XXXXXX)"
cleanup() {
    [[ -n "${NGINX_PID:-}" ]] && kill "${NGINX_PID}" 2>/dev/null || true
    echo ""
    echo "=== error.log (first 40 lines) ==="
    head -40 "${PREFIX}/logs/error.log" 2>/dev/null || echo "(not found)"
    echo "..."
    echo "=== error.log (last 30 lines) ==="
    tail -30 "${PREFIX}/logs/error.log" 2>/dev/null
    info "Tearing down ${PREFIX}"
    rm -rf "${PREFIX}"
}
trap cleanup EXIT

mkdir -p "${PREFIX}/logs"
mkdir -p "${PREFIX}/client_body_temp"

# Substitute placeholders and write nginx.conf into the sandbox.
sed \
    -e "s|@MODULE_PATH@|${MODULE_PATH}|g" \
    -e "s|@PREFIX@|${PREFIX}|g" \
    "${CONF_TEMPLATE}" > "${PREFIX}/nginx.conf"

info "Sandbox: ${PREFIX}"

# ─── Snapshot metrics.json BEFORE starting nginx ─────────────────────────────

PRE_SIZE=0
if [[ -f "${METRICS_LOG}" ]]; then
    PRE_SIZE=$(wc -c < "${METRICS_LOG}")
fi
info "metrics.json pre-size: ${PRE_SIZE} bytes"

# ─── Start NGINX ─────────────────────────────────────────────────────────────

info "Starting nginx (worker_processes 4)..."
# Note: error_log is already set in nginx.conf; do NOT pass -g "error_log ..."
# here as that would create a second log target and double every line, causing
# the "exactly 1 export loop started" assertion to fail.
"${NGINX_BINARY}" \
    -p "${PREFIX}" \
    -c "${PREFIX}/nginx.conf" &
NGINX_PID=$!

# Give nginx time to fork workers and run init_process.
sleep 1

# Verify nginx is still running.
if ! kill -0 "${NGINX_PID}" 2>/dev/null; then
    echo "ERROR: nginx exited immediately. Check ${PREFIX}/logs/error.log" >&2
    cat "${PREFIX}/logs/error.log" >&2
    exit 1
fi
info "nginx running (PID ${NGINX_PID})"

# ─── Send HTTP traffic ───────────────────────────────────────────────────────

info "Sending ${N_REQUESTS} requests to http://127.0.0.1:9100/..."
for i in $(seq 1 "${N_REQUESTS}"); do
    curl -sf http://127.0.0.1:9100/ >/dev/null
done
info "Traffic sent."

# ─── Wait for flush ──────────────────────────────────────────────────────────

info "Waiting ${FLUSH_WAIT_S}s for metrics flush (interval=${METRIC_INTERVAL_S}s)..."
sleep "${FLUSH_WAIT_S}"

# ─── Graceful shutdown ───────────────────────────────────────────────────────

info "Sending nginx -s quit (graceful drain)..."
"${NGINX_BINARY}" \
    -p "${PREFIX}" \
    -c "${PREFIX}/nginx.conf" \
    -s quit 2>/dev/null || true

# Wait for nginx to exit (up to 10s).
for i in $(seq 1 10); do
    if ! kill -0 "${NGINX_PID}" 2>/dev/null; then
        break
    fi
    sleep 1
done
# Ensure the PID is gone before we inspect logs.
NGINX_PID=""

# ─── Assertions ──────────────────────────────────────────────────────────────

info "Running assertions..."
FAILED=0

# Read new content appended since the pre-flight snapshot.
NEW_CONTENT=""
if [[ -f "${METRICS_LOG}" ]]; then
    POST_SIZE=$(wc -c < "${METRICS_LOG}")
    if (( POST_SIZE > PRE_SIZE )); then
        NEW_CONTENT=$(tail -c "+$(( PRE_SIZE + 1 ))" "${METRICS_LOG}")
    fi
fi

# 1. service.name in new metrics
if echo "${NEW_CONTENT}" | grep -q "${SERVICE_NAME}"; then
    pass "metrics.json contains service.name = ${SERVICE_NAME}"
else
    fail "metrics.json does NOT contain '${SERVICE_NAME}' in newly appended content.
       New content:
$(echo "${NEW_CONTENT}" | head -5)"
    FAILED=1
fi

# 2. histogram metric name present
if echo "${NEW_CONTENT}" | grep -q "http.server.request.duration"; then
    pass "metrics.json contains http.server.request.duration"
else
    fail "metrics.json does NOT contain 'http.server.request.duration' in new content."
    FAILED=1
fi

# 3. Exactly one "export loop started" in error.log (otel exporter process only)
# The export task is spawned inside the otel exporter process, not Worker 0.
# The "otel export: export loop started" line is logged once per exporter cycle,
# confirming the async task is running in the correct process.
# (Previously this checked for "spawning export task" on Worker 0.)
SPAWN_COUNT=$(grep -c "export loop started" "${PREFIX}/logs/error.log" 2>/dev/null) || SPAWN_COUNT=0
if [[ "${SPAWN_COUNT}" -eq 1 ]]; then
    pass "error.log contains exactly 1 'export loop started' line (otel exporter process)"
else
    fail "error.log contains ${SPAWN_COUNT} 'export loop started' lines (expected 1).
       Relevant lines:
$(grep "export loop started\|otel exporter\|otel export" "${PREFIX}/logs/error.log" | head -20)"
    FAILED=1
fi

# 4. Graceful-drain integrity check.
#
# The SIGQUIT-during-sleep race is resolved. The exporter is not a worker
# and is not subject to ngx_event_no_timers_left. The drain fires reliably when
# ngx_quit is set. The exporter cycle waits for EXPORT_LOOP_DONE before calling
# process::exit, so the drain always completes.
#
# We assert the drain must complete if it started. A regression where the drain
# begins but hangs would leave a "graceful drain starting" line with no matching
# "graceful drain complete" line — that we want to catch.
DRAIN_START=$(grep -c "graceful drain starting" "${PREFIX}/logs/error.log" 2>/dev/null) || DRAIN_START=0
DRAIN_END=$(grep -c "graceful drain complete" "${PREFIX}/logs/error.log" 2>/dev/null) || DRAIN_END=0
if [[ "${DRAIN_START}" -eq 0 ]]; then
    info "Note: graceful drain did not fire this run (exporter may have been SIGTERM'd)."
elif [[ "${DRAIN_START}" -eq "${DRAIN_END}" ]]; then
    pass "graceful drain integrity: ${DRAIN_START} start(s), ${DRAIN_END} complete(s)"
else
    fail "graceful drain started ${DRAIN_START} time(s) but completed ${DRAIN_END} time(s) — drain hung.
       Relevant lines:
$(grep "graceful drain" "${PREFIX}/logs/error.log" | head -20)"
    FAILED=1
fi

# ─── Summary ─────────────────────────────────────────────────────────────────

echo ""
if [[ "${FAILED}" -eq 0 ]]; then
    pass "All assertions passed. End-to-end test COMPLETE."
    echo ""
    echo "  New metrics.json tail:"
    echo "${NEW_CONTENT}" | tail -3
    exit 0
else
    echo -e "${RED}One or more assertions FAILED.${NC}" >&2
    echo ""
    echo "Diagnostics:"
    echo "  nginx error.log:"
    tail -30 "${PREFIX}/logs/error.log" 2>/dev/null || echo "  (not found)"
    exit 2
fi
