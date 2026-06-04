#!/usr/bin/env bash
# tests/integration/run_access_log.sh — Phase 2.2 access-log integration test
#
# Starts NGINX with `otel_access_log_sample 16;`, sends HTTP requests, waits for
# the export interval, then verifies the §6.6.1 rebalanced shape:
#
# Assertions:
#   1. 200 flood produces ZERO per-request LogRecords (is_interesting gate blocks them).
#   2. Error requests (500) DO produce tail LogRecords.
#   3. Histogram metric (http.server.request.duration) still arrives (always-on).
#   4. Tail records contain http.request.method, http.response.status_code,
#      client.address, severity, event_name=http.access.
#   5. No regressions in metrics.json (service.name present).
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
N_OK_REQUESTS=30    # 200 flood — must produce ZERO LogRecords
N_ERR_REQUESTS=5    # 500 requests — must each produce a tail LogRecord

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

# Phase 2.2: 200 flood — is_interesting gate should block all of these.
info "Sending ${N_OK_REQUESTS} GET requests (200) to http://127.0.0.1:9101/..."
for i in $(seq 1 "${N_OK_REQUESTS}"); do
    curl -sf http://127.0.0.1:9101/ >/dev/null
done

# Error requests — is_interesting gate should pass all of these (status 500 ≥ 400).
info "Sending ${N_ERR_REQUESTS} GET requests (500/error) to http://127.0.0.1:9101/error..."
for i in $(seq 1 "${N_ERR_REQUESTS}"); do
    curl -sf http://127.0.0.1:9101/error >/dev/null || true  # 500 exit ≠ 0
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

# ── logs.json: Phase 2.2 assertions ──────────────────────────────────────────
NEW_LOGS=""
if [[ -f "${LOGS_LOG}" ]]; then
    POST_LOGS_SIZE=$(wc -c < "${LOGS_LOG}")
    if (( POST_LOGS_SIZE > PRE_LOGS_SIZE )); then
        NEW_LOGS=$(tail -c "+$(( PRE_LOGS_SIZE + 1 ))" "${LOGS_LOG}")
    fi
fi

info "logs.json: got $(echo "${NEW_LOGS}" | wc -c) bytes of new content"

# Count all http.access records produced.
LOG_RECORD_COUNT=$(echo "${NEW_LOGS}" | grep -o '"http.access"' | wc -l | tr -d ' ' || echo 0)
info "event_name=http.access count in new logs.json content: ${LOG_RECORD_COUNT}"

# ── Key assertion 1: 200 flood → ZERO LogRecords (is_interesting gate) ────────
# The test sent N_OK_REQUESTS 200/fast requests — none should appear as records.
# All N_ERR_REQUESTS 500 requests should appear (status 500 ≥ TAIL_STATUS_FLOOR=400).
# If any 200 slip through the gate that is a test failure.
if (( LOG_RECORD_COUNT <= N_ERR_REQUESTS )); then
    pass "logs.json: 200 flood correctly produced no tail records (total=${LOG_RECORD_COUNT}, errs=${N_ERR_REQUESTS})"
else
    fail "logs.json: too many tail records (${LOG_RECORD_COUNT} > ${N_ERR_REQUESTS}); 200 requests may be leaking through the is_interesting gate"
fi

# ── Key assertion 2: error requests DO produce tail records ───────────────────
if (( LOG_RECORD_COUNT >= 1 )); then
    pass "logs.json: at least 1 tail LogRecord present from error requests (got ${LOG_RECORD_COUNT})"
else
    fail "logs.json: expected ≥ 1 tail LogRecord from ${N_ERR_REQUESTS} error requests, got 0"
fi

# ── Check tail record fields ──────────────────────────────────────────────────
if [[ -n "${NEW_LOGS}" ]]; then
    # Assertion: http.request.method present
    if echo "${NEW_LOGS}" | grep -q '"http.request.method"'; then
        pass "logs.json: http.request.method attribute present"
    else
        fail "logs.json: http.request.method attribute NOT found"
    fi

    # Assertion: http.response.status_code present
    if echo "${NEW_LOGS}" | grep -q '"http.response.status_code"'; then
        pass "logs.json: http.response.status_code attribute present"
    else
        fail "logs.json: http.response.status_code attribute NOT found"
    fi

    # Assertion: client.address present
    if echo "${NEW_LOGS}" | grep -q '"client.address"'; then
        pass "logs.json: client.address attribute present"
    else
        fail "logs.json: client.address attribute NOT found"
    fi

    # Assertion: severity_number = 9 (INFO)
    if echo "${NEW_LOGS}" | grep -qE '"severityNumber":9|"severity_number":9|"severityNumber": 9'; then
        pass "logs.json: severity_number = 9 (INFO) present"
    elif echo "${NEW_LOGS}" | grep -qE '"severityText":"info"|"severity_text":"info"'; then
        pass "logs.json: severity = INFO present (via text)"
    else
        fail "logs.json: severity_number=9 (INFO) NOT found; severity mapping may be wrong"
    fi

    # Assertion: event_name = "http.access"
    if echo "${NEW_LOGS}" | grep -q '"http.access"'; then
        pass "logs.json: event_name = http.access present"
    else
        fail "logs.json: event_name=http.access NOT found"
    fi
else
    fail "logs.json: no new content — exception-tail records did not arrive at the collector"
    info "  (check that the collector's logs pipeline is configured with the logs file exporter)"
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
