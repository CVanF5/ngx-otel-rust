#!/usr/bin/env bash
# tests/integration/run_metrics_off_traces.sh
#
# Verifies that `otel_metrics off` suppresses metrics while leaving traces and
# access-log tails fully operational.  This is a direct behavioral test of the
# C++ drop-in requirement that disabling metrics must not affect traces or logs.
#
# Assertions:
#   1. A span arrives in traces.json — traces are NOT suppressed by otel_metrics off.
#   2. Span traceId matches the inbound traceparent — W3C extraction works.
#   3. Span parentSpanId matches — parent context propagated.
#   4. A tail LogRecord arrives in logs.json — access-log tail NOT suppressed.
#   5. Tail LogRecord carries the expected traceId — cross-signal correlation works.
#   6. metrics.json contains NO per-request series — metrics ARE suppressed.
#      (Only self-metrics from the exporter process may appear, which do not
#       require the worker shm zone.)
#
# Exit codes: 0 = all assertions passed; 1 = preflight failure; 2 = assertion failed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPO_ROOT="$(cd "${CRATE_DIR}/.." && pwd)"

CONF_TEMPLATE="${SCRIPT_DIR}/nginx_metrics_off_traces.conf"

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

SERVICE_NAME="ngx-otel-metrics-off-traces-test"
METRIC_INTERVAL_S=2
FLUSH_WAIT_S=$(( METRIC_INTERVAL_S + 4 ))

TRACEPARENT="00-b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6-a1b2c3d4e5f6a7b8-01"
TRACE_ID="b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6"
PARENT_SPAN_ID="a1b2c3d4e5f6a7b8"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass()  { echo -e "${GREEN}[PASS]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*" >&2; FAILED=1; }
info()  { echo -e "${YELLOW}[INFO]${NC} $*"; }

info "Pre-flight checks..."
if [[ ! -x "${NGINX_BINARY}" ]]; then
    echo "ERROR: nginx binary not found at ${NGINX_BINARY}" >&2
    echo "       Set NGINX_BINARY to the correct path." >&2
    exit 1
fi
ensure_collector_running || exit 1

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

PREFIX="$(mktemp -d /tmp/ngx-otel-metrics-off-traces.XXXXXX)"
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

PRE_TRACES_SIZE=0
if [[ -f "${TRACES_LOG}" ]]; then
    PRE_TRACES_SIZE=$(wc -c < "${TRACES_LOG}")
fi
PRE_LOGS_SIZE=0
if [[ -f "${LOGS_LOG}" ]]; then
    PRE_LOGS_SIZE=$(wc -c < "${LOGS_LOG}")
fi
PRE_METRICS_SIZE=0
if [[ -f "${METRICS_LOG}" ]]; then
    PRE_METRICS_SIZE=$(wc -c < "${METRICS_LOG}")
fi
info "Pre-sizes: traces=${PRE_TRACES_SIZE} logs=${PRE_LOGS_SIZE} metrics=${PRE_METRICS_SIZE}"

info "Starting nginx with otel_metrics off..."
"${NGINX_BINARY}" -p "${PREFIX}" -c "${PREFIX}/nginx.conf" &
NGINX_PID=$!

sleep 1

if ! kill -0 "${NGINX_PID}" 2>/dev/null; then
    echo "ERROR: nginx exited immediately. Check ${PREFIX}/logs/error.log" >&2
    cat "${PREFIX}/logs/error.log" >&2
    exit 1
fi
info "nginx running (PID ${NGINX_PID})"

info "Sending 5 GET / requests (baseline)..."
for i in $(seq 1 5); do
    curl -sf http://127.0.0.1:9105/ >/dev/null
done

info "Sending 1 GET /error with traceparent (known trace_id=${TRACE_ID})..."
curl -sf -H "traceparent: ${TRACEPARENT}" http://127.0.0.1:9105/error >/dev/null || true

info "Waiting ${FLUSH_WAIT_S}s for the exporter to flush..."
sleep "${FLUSH_WAIT_S}"

info "Stopping nginx (SIGQUIT)..."
kill -QUIT "${NGINX_PID}" 2>/dev/null || true
sleep 3
NGINX_PID=""

NEW_TRACES=""
if [[ -f "${TRACES_LOG}" ]]; then
    POST_TRACES_SIZE=$(wc -c < "${TRACES_LOG}")
    if (( POST_TRACES_SIZE > PRE_TRACES_SIZE )); then
        NEW_TRACES=$(tail -c "+$(( PRE_TRACES_SIZE + 1 ))" "${TRACES_LOG}")
    fi
fi

NEW_LOGS=""
if [[ -f "${LOGS_LOG}" ]]; then
    POST_LOGS_SIZE=$(wc -c < "${LOGS_LOG}")
    if (( POST_LOGS_SIZE > PRE_LOGS_SIZE )); then
        NEW_LOGS=$(tail -c "+$(( PRE_LOGS_SIZE + 1 ))" "${LOGS_LOG}")
    fi
fi

NEW_METRICS=""
if [[ -f "${METRICS_LOG}" ]]; then
    POST_METRICS_SIZE=$(wc -c < "${METRICS_LOG}")
    if (( POST_METRICS_SIZE > PRE_METRICS_SIZE )); then
        NEW_METRICS=$(tail -c "+$(( PRE_METRICS_SIZE + 1 ))" "${METRICS_LOG}")
    fi
fi

echo ""
echo "=== Assertions (otel_metrics off — traces + logs must still work) ==="

# ─── 1. A span arrives ───────────────────────────────────────────────────────
# HARD: otel_metrics off must NOT suppress spans.

if [[ -z "${NEW_TRACES}" ]]; then
    fail "traces.json: NO new data — otel_metrics off incorrectly suppressed spans"
    echo "    Pre-fix: LogPhaseHandler returned early at the metrics-shm null check,"
    echo "    which blocked the span block entirely."
    exit 2
fi

if echo "${NEW_TRACES}" | grep -q '"resourceSpans"'; then
    pass "traces.json: spans present — otel_metrics off does not suppress traces"
else
    fail "traces.json: new data arrived but contains no resourceSpans"
fi

# ─── 2. Span traceId matches inbound traceparent ─────────────────────────────

if echo "${NEW_TRACES}" | grep -q "\"${TRACE_ID}\""; then
    pass "traces.json: traceId=${TRACE_ID} present — W3C extraction works with otel_metrics off"
else
    fail "traces.json: traceId ${TRACE_ID} NOT found"
fi

# ─── 3. Span parentSpanId matches ────────────────────────────────────────────

if echo "${NEW_TRACES}" | grep -q "\"${PARENT_SPAN_ID}\""; then
    pass "traces.json: parentSpanId=${PARENT_SPAN_ID} present"
else
    fail "traces.json: parentSpanId ${PARENT_SPAN_ID} NOT found"
fi

# ─── 4. Access-log tail arrives in logs.json ─────────────────────────────────
# HARD: otel_metrics off must NOT suppress the access-log tail.

if [[ -z "${NEW_LOGS}" ]]; then
    fail "logs.json: NO new data — otel_metrics off incorrectly suppressed access-log tails"
    echo "    Pre-fix: same early return also blocked the logs-tail block."
else
    pass "logs.json: access-log tail data present — otel_metrics off does not suppress logs"
fi

# ─── 5. Cross-signal: traceId on tail LogRecord ──────────────────────────────

if [[ -n "${NEW_LOGS}" ]] && echo "${NEW_LOGS}" | grep -q "${TRACE_ID}"; then
    pass "logs.json: trace_id ${TRACE_ID} on tail LogRecord — cross-signal correlation works"
elif [[ -n "${NEW_LOGS}" ]]; then
    fail "logs.json: trace_id ${TRACE_ID} NOT on any LogRecord — cross-signal correlation broken"
fi

# ─── 6. No per-request metrics in metrics.json ───────────────────────────────
# HARD: otel_metrics off must suppress per-request http.server.* series.
# Self-metrics from the exporter (ngx_otel.*) may still appear.

if echo "${NEW_METRICS}" | grep -q '"http.server.request'; then
    fail "metrics.json: http.server.request.* series present — otel_metrics off did NOT suppress metrics"
else
    pass "metrics.json: no http.server.request.* series — metrics correctly suppressed by otel_metrics off"
fi

echo ""
if [[ "${FAILED}" -eq 0 ]]; then
    echo -e "${GREEN}[PASS]${NC} All assertions passed (otel_metrics off: traces + logs operational, metrics suppressed)."
else
    echo -e "${RED}[FAIL]${NC} ${FAILED} assertion(s) failed." >&2
    exit 2
fi
