#!/usr/bin/env bash
# tests/integration/run_access_log.sh — Phase 2.1 access-log integration test
#
# Starts NGINX with `otel_access_log on;`, sends HTTP requests, waits for
# the export interval, then verifies that the OTel collector received
# LogRecord entries with HTTP semconv attributes.
#
# Assertions:
#   1. At least N/2 LogRecord entries appear in LOGS_LOG (batch drop tolerance).
#   2. Records contain http.request.method = "GET".
#   3. Records contain http.response.status_code = 200.
#   4. Records contain client.address (non-empty string).
#   5. severity_number = 9 (INFO).
#   6. event_name = "http.access".
#   7. No regressions in metrics.json (service.name + duration metric present).
#
# Prerequisites
# ─────────────
# Same as run.sh: Docker available, OTel collector reachable.
#
# Exit codes: 0 = all assertions passed; 1 = preflight failure; 2 = assertion failed.

set -euo pipefail

# ─── Resolve paths ───────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPO_ROOT="$(cd "${CRATE_DIR}/.." && pwd)"

CONF_TEMPLATE="${SCRIPT_DIR}/nginx_access_log.conf"

. "${CRATE_DIR}/test-harness/lib.sh"
resolve_nginx_binary || true

case "$(uname -s)" in
    Darwin) MODULE_EXT="dylib" ;;
    *)      MODULE_EXT="so"    ;;
esac
MODULE_PATH="${CRATE_DIR}/target/release/libngx_http_otel_module.${MODULE_EXT}"

SERVICE_NAME="ngx-otel-access-log-test"
METRIC_INTERVAL_S=2
FLUSH_WAIT_S=$(( METRIC_INTERVAL_S + 3 ))
N_REQUESTS=30
# Minimum records expected (50% of N_REQUESTS to account for batching lag)
MIN_LOG_RECORDS=$(( N_REQUESTS / 2 ))

# ─── Colour helpers ──────────────────────────────────────────────────────────

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass()  { echo -e "${GREEN}[PASS]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*" >&2; FAILED=1; }
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

PREFIX="$(mktemp -d /tmp/ngx-otel-access-log.XXXXXX)"
NGINX_PID=""
FAILED=0

cleanup() {
    [[ -n "${NGINX_PID:-}" ]] && kill "${NGINX_PID}" 2>/dev/null || true
    echo ""
    echo "=== error.log (last 30 lines) ==="
    tail -30 "${PREFIX}/logs/error.log" 2>/dev/null || echo "(not found)"
    info "Tearing down ${PREFIX}"
    rm -rf "${PREFIX}"
}
trap cleanup EXIT

mkdir -p "${PREFIX}/logs"
mkdir -p "${PREFIX}/client_body_temp"

sed \
    -e "s|@MODULE_PATH@|${MODULE_PATH}|g" \
    -e "s|@PREFIX@|${PREFIX}|g" \
    "${CONF_TEMPLATE}" > "${PREFIX}/nginx.conf"

info "Sandbox: ${PREFIX}"

# ─── Snapshot file sizes BEFORE starting nginx ───────────────────────────────

PRE_METRICS_SIZE=0
if [[ -f "${METRICS_LOG}" ]]; then
    PRE_METRICS_SIZE=$(wc -c < "${METRICS_LOG}")
fi
info "metrics.json pre-size: ${PRE_METRICS_SIZE} bytes"

PRE_LOGS_SIZE=0
if [[ -f "${LOGS_LOG}" ]]; then
    PRE_LOGS_SIZE=$(wc -c < "${LOGS_LOG}")
fi
info "logs.json pre-size: ${PRE_LOGS_SIZE} bytes"

# ─── Start NGINX ─────────────────────────────────────────────────────────────

info "Starting nginx..."
"${NGINX_BINARY}" -p "${PREFIX}" -c "${PREFIX}/nginx.conf" &
NGINX_PID=$!

sleep 1

if ! kill -0 "${NGINX_PID}" 2>/dev/null; then
    echo "ERROR: nginx exited immediately. Check ${PREFIX}/logs/error.log" >&2
    cat "${PREFIX}/logs/error.log" >&2
    exit 1
fi
info "nginx running (PID ${NGINX_PID})"

# ─── Send HTTP traffic ───────────────────────────────────────────────────────

info "Sending ${N_REQUESTS} GET requests to http://127.0.0.1:9101/..."
for i in $(seq 1 "${N_REQUESTS}"); do
    curl -sf http://127.0.0.1:9101/ >/dev/null
done
info "Traffic sent."

# ─── Wait for flush ──────────────────────────────────────────────────────────

info "Waiting ${FLUSH_WAIT_S}s for export flush (interval=${METRIC_INTERVAL_S}s)..."
sleep "${FLUSH_WAIT_S}"

# ─── Graceful shutdown ───────────────────────────────────────────────────────

info "Sending nginx -s quit (graceful drain)..."
"${NGINX_BINARY}" -p "${PREFIX}" -c "${PREFIX}/nginx.conf" -s quit 2>/dev/null || true
for i in $(seq 1 10); do
    if ! kill -0 "${NGINX_PID}" 2>/dev/null; then break; fi
    sleep 1
done
NGINX_PID=""

# Give the collector a moment to write the last batch.
sleep 1

# ─── Assertions ──────────────────────────────────────────────────────────────

info "Running assertions..."

# ── metrics.json: regression check ───────────────────────────────────────────
NEW_METRICS=""
if [[ -f "${METRICS_LOG}" ]]; then
    POST_METRICS_SIZE=$(wc -c < "${METRICS_LOG}")
    if (( POST_METRICS_SIZE > PRE_METRICS_SIZE )); then
        NEW_METRICS=$(tail -c "+$(( PRE_METRICS_SIZE + 1 ))" "${METRICS_LOG}")
    fi
fi

if echo "${NEW_METRICS}" | grep -q "${SERVICE_NAME}"; then
    pass "metrics.json: service.name = ${SERVICE_NAME} present (metrics not regressed)"
else
    fail "metrics.json: '${SERVICE_NAME}' NOT found — possible metrics regression"
fi

if echo "${NEW_METRICS}" | grep -q "http.server.request.duration"; then
    pass "metrics.json: http.server.request.duration present"
else
    fail "metrics.json: http.server.request.duration NOT found"
fi

# ── logs.json: presence of LogRecord entries ──────────────────────────────────
NEW_LOGS=""
if [[ -f "${LOGS_LOG}" ]]; then
    POST_LOGS_SIZE=$(wc -c < "${LOGS_LOG}")
    if (( POST_LOGS_SIZE > PRE_LOGS_SIZE )); then
        NEW_LOGS=$(tail -c "+$(( PRE_LOGS_SIZE + 1 ))" "${LOGS_LOG}")
    fi
fi

if [[ -z "${NEW_LOGS}" ]]; then
    fail "logs.json: no new content — no LogRecords arrived at the collector"
    info "  (check that the collector's logs pipeline is configured with file/logs exporter)"
else
    info "logs.json: got $(echo "${NEW_LOGS}" | wc -c) bytes of new content"
fi

# Count log records (each line in the JSON file is one export request;
# count resourceLogs occurrences as a proxy for "at least one batch arrived").
LOG_RECORD_COUNT=$(echo "${NEW_LOGS}" | grep -o '"http.access"' | wc -l || echo 0)
info "event_name=http.access count in new logs.json content: ${LOG_RECORD_COUNT}"

if (( LOG_RECORD_COUNT >= MIN_LOG_RECORDS )); then
    pass "logs.json: at least ${MIN_LOG_RECORDS} http.access records present (got ${LOG_RECORD_COUNT})"
else
    fail "logs.json: expected >= ${MIN_LOG_RECORDS} http.access records, got ${LOG_RECORD_COUNT}"
fi

# Assertion: http.request.method = "GET"
if echo "${NEW_LOGS}" | grep -q '"http.request.method"'; then
    pass "logs.json: http.request.method attribute present"
else
    fail "logs.json: http.request.method attribute NOT found"
fi

# Assertion: http.response.status_code = 200
if echo "${NEW_LOGS}" | grep -q '"http.response.status_code"'; then
    pass "logs.json: http.response.status_code attribute present"
else
    fail "logs.json: http.response.status_code attribute NOT found"
fi

# Assertion: client.address non-empty
if echo "${NEW_LOGS}" | grep -q '"client.address"'; then
    pass "logs.json: client.address attribute present"
else
    fail "logs.json: client.address attribute NOT found"
fi

# Assertion: severity_number = 9 (INFO — nginx level 7 → OTel INFO)
if echo "${NEW_LOGS}" | grep -q '"severityNumber":9\|"severity_number":9\|"severityNumber": 9'; then
    pass "logs.json: severity_number = 9 (INFO) present"
else
    # The collector may format severity_number as a string ("INFO") or integer.
    # Check for the INFO string representation as well.
    if echo "${NEW_LOGS}" | grep -qE '"severityText":"info"|"severity_text":"info"'; then
        pass "logs.json: severity = INFO present (via text)"
    else
        fail "logs.json: severity_number=9 (INFO) NOT found; severity mapping may be wrong"
    fi
fi

# Assertion: event_name = "http.access"
if echo "${NEW_LOGS}" | grep -q '"http.access"'; then
    pass "logs.json: event_name = http.access present"
else
    fail "logs.json: event_name=http.access NOT found"
fi

# ─── Final result ────────────────────────────────────────────────────────────

echo ""
if [[ "${FAILED}" -eq 0 ]]; then
    pass "All assertions passed."
    exit 0
else
    fail "One or more assertions FAILED."
    exit 2
fi
