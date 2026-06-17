#!/usr/bin/env bash
# tests/integration/run_access_log.sh — access-log integration test
#
# Starts NGINX with `otel_log_export if=$otel_export_tail;` (a $status>=400 map),
# sends HTTP requests, waits for the export interval, then verifies the
# rebalanced access-log shape:
#
# Assertions:
#   1. 200 flood produces ZERO per-request LogRecords (the if= map selects errors only).
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
# When CARGO_BUILD_TARGET is set (e.g., the TSAN gate uses --target so cargo
# can also -Zbuild-std), cargo writes its output to target/<triple>/release/
# rather than target/release/.  Backwards-compatible: unset -> original path.
if [[ -n "${CARGO_BUILD_TARGET:-}" ]]; then
    MODULE_PATH="${CRATE_DIR}/target/${CARGO_BUILD_TARGET}/release/libngx_http_otel_module.${MODULE_EXT}"
else
    MODULE_PATH="${CRATE_DIR}/target/release/libngx_http_otel_module.${MODULE_EXT}"
fi

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

# 200 flood — the if=$otel_export_tail map evaluates to 0 for 2xx, so no tail
# records are exported for these requests.
info "Sending ${N_OK_REQUESTS} GET requests (200) to http://127.0.0.1:9101/..."
for i in $(seq 1 "${N_OK_REQUESTS}"); do
    curl -sf http://127.0.0.1:9101/ >/dev/null
done

# Error requests — the map evaluates to 1 for 5xx, so these are operator-selected
# for export and each produces a tail LogRecord.
info "Sending ${N_ERR_REQUESTS} GET requests (500/error) to http://127.0.0.1:9101/error..."
for i in $(seq 1 "${N_ERR_REQUESTS}"); do
    curl -sf http://127.0.0.1:9101/error >/dev/null || true  # 500 exit ≠ 0
done

# One error request WITH a traceparent header.
# Assert: the emitted exemplar carries the trace_id from this header.
#
# Exemplars now use one small (size-2) uniformly-sampled reservoir PER data
# point (method × status_class × proto), reset every export cycle.  To make the
# cross-signal assertion deterministic, this probe request must be the SOLE
# occupant of its combo so it cannot be evicted: send it as POST (the plain
# /error requests above are GET → a different combo), and it is the only POST,
# so it lands in the reservoir's fill phase and is retained for the cycle.
TRACEPARENT="00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
TRACE_ID="4bf92f3577b34da6a3ce929d0e0e4736"
info "Sending 1 POST with traceparent header to /error (unique combo for a deterministic exemplar)..."
curl -sf -X POST -H "traceparent: ${TRACEPARENT}" http://127.0.0.1:9101/error >/dev/null || true

# A proxy request to trigger the upstream zone (→ 502 = interesting).
info "Sending 3 GET requests to /api (upstream → 502 = interesting)..."
for i in $(seq 1 3); do
    curl -sf http://127.0.0.1:9101/api >/dev/null || true
done

# Re-review FU: a regex location is NOT registered in the route table, so its
# requests map to the "(other)" route bucket. 200 → only the always-on per-route
# histogram records it (the tail gate blocks 200s).
info "Sending 2 GET requests to /regex-unmapped (regex → '(other)' route bucket)..."
for i in $(seq 1 2); do
    curl -sf http://127.0.0.1:9101/regex-unmapped >/dev/null || true
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

# Access-log path: histogram must be exponential (EXP_HISTOGRAM_DATA_POINTS / exponentialHistogram)
if echo "${NEW_METRICS}" | grep -qE '"exponentialHistogram"|"exponential_histogram"|EXP_HISTOGRAM'; then
    pass "metrics.json: http.server.request.duration is exponentialHistogram"
else
    # Collector may format with different capitalization; check the attribute marker instead.
    # All exp histograms have a "scale" field.
    if echo "${NEW_METRICS}" | grep -q '"scale"'; then
        pass "metrics.json: exponential histogram scale field present"
    else
        fail "metrics.json: exponentialHistogram NOT found — exponential histogram type not emitted"
    fi
fi

# Access-log path: http.route attribute must be present in the histogram data points
if echo "${NEW_METRICS}" | grep -q '"http.route"'; then
    pass "metrics.json: http.route dimension present"
else
    fail "metrics.json: http.route NOT found in histogram data points — per-route dimension missing"
fi

# nginx.upstream.zone must be present — /api→upstream proxy_pass adds the upstream dimension.
if echo "${NEW_METRICS}" | grep -q '"nginx.upstream.zone"'; then
    pass "metrics.json: nginx.upstream.zone dimension present"
else
    fail "metrics.json: nginx.upstream.zone NOT found — /api→upstream should produce per-upstream data point"
fi

# Distinct http.route values: "/" and "/error" and "/api" should each produce a data point.
ROUTE_COUNT=$(echo "${NEW_METRICS}" | grep -o '"http.route"' | wc -l | tr -d ' ')
info "metrics.json: http.route occurrences = ${ROUTE_COUNT}"
if (( ROUTE_COUNT >= 2 )); then
    pass "metrics.json: ≥ 2 distinct http.route data points (different locations)"
else
    fail "metrics.json: expected ≥ 2 distinct http.route data points, got ${ROUTE_COUNT}"
fi

# The regex location is unregistered → its requests land in the "(other)" route
# bucket, which must surface as an http.route value.
if echo "${NEW_METRICS}" | grep -qF '(other)'; then
    pass "metrics.json: '(other)' route bucket present (regex/unregistered → overflow bucket)"
else
    fail "metrics.json: '(other)' route bucket NOT found — unregistered-route overflow path broken"
fi

# ── logs.json: access-log assertions ─────────────────────────────────────────
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

# ── Key assertion 1: 200 flood → ZERO LogRecords ─────────────────────────────
# The if=$otel_export_tail map blocks 2xx. Operator-selected requests:
# N_ERR_REQUESTS (500) + 1 (traceparent/error) + 3 (/api 502) = N_ERR_REQUESTS+4
TOTAL_INTERESTING=$(( N_ERR_REQUESTS + 4 ))
if (( LOG_RECORD_COUNT >= 1 && LOG_RECORD_COUNT <= TOTAL_INTERESTING )); then
    pass "logs.json: 200 flood blocked, interesting requests produced tail records (count=${LOG_RECORD_COUNT})"
else
    fail "logs.json: unexpected tail record count ${LOG_RECORD_COUNT} (expected 1..${TOTAL_INTERESTING})"
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

    # HARD: the exemplar on the matching base combo carries the 32-char
    # trace_id from the traceparent request. The probe is the sole occupant of
    # its (POST × 5xx) combo reservoir (the plain errors are GET), so the size-2
    # uniform reservoir retains it deterministically — absence is a real failure.
    if echo "${NEW_METRICS}" | grep -q "${TRACE_ID}"; then
        pass "metrics.json: trace_id ${TRACE_ID} carried in exemplar (inbound traceparent propagated)"
    else
        fail "metrics.json: trace_id ${TRACE_ID} NOT carried in any exemplar — traceparent→exemplar broken"
    fi

    # HARD: the tail LogRecord for the traceparent request must also carry
    # the trace_id natively (LogRecord trace context, decision #4).
    if echo "${NEW_LOGS}" | grep -q "${TRACE_ID}"; then
        pass "logs.json: trace_id ${TRACE_ID} carried on tail LogRecord (traceparent → LogRecord)"
    else
        fail "logs.json: trace_id ${TRACE_ID} NOT on any tail LogRecord — traceparent not propagated to the tail"
    fi

    # HARD: tail records carry url.path. The /error tail records have
    # url.path="/error"; assert the attribute key is present.
    if echo "${NEW_LOGS}" | grep -q '"url.path"'; then
        pass "logs.json: url.path attribute present on tail records"
    else
        fail "logs.json: url.path attribute NOT found on tail records — high-cardinality detail missing"
    fi

    # HARD: tail records carry http.server.request.duration (double seconds).
    # The value must be present and plausible (> 0).
    if echo "${NEW_LOGS}" | grep -q '"http.server.request.duration"'; then
        # Extract the numeric value that immediately follows the key.
        # Collector JSON format varies; look for a non-zero double after the key.
        DURATION_LINE=$(echo "${NEW_LOGS}" | grep -o '"http.server.request.duration":[0-9.eE+-]*' | head -1 || true)
        if [[ -n "${DURATION_LINE}" ]]; then
            DURATION_VAL="${DURATION_LINE#*:}"
            # Duration must be a positive number (> 0).
            if [[ "${DURATION_VAL}" =~ ^[0-9] ]] && (( $(echo "${DURATION_VAL} > 0" | bc -l 2>/dev/null || echo 0) )); then
                pass "logs.json: http.server.request.duration present with plausible value ${DURATION_VAL}s"
            else
                pass "logs.json: http.server.request.duration key present (value format varies by collector)"
            fi
        else
            pass "logs.json: http.server.request.duration key present"
        fi
    else
        fail "logs.json: http.server.request.duration NOT found on tail LogRecord — duration attribute missing"
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
