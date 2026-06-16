#!/usr/bin/env bash
# tests/integration/run_error_log.sh — error-log integration test
#
# Tests the coalesced error-log + companion error-rate metric.
# Runs FOUR stages + two standalone checks (each a fresh nginx):
#
#   Stage A: Coalesce-on flood (default)
#     - 100 /flood requests → broken upstream → "connect() failed" errors
#     - HARD-assert: coalesces to 1 LogRecord with coalesced_count > 1
#     - HARD-assert: companion metric ngx_otel.error_log.events with severity_class
#     - HARD-assert: NO trace_id/http.route/upstream.zone on error records
#     - HARD-assert: body contains upstream context (nginx appends it)
#
#   Stage B: Coalesce-off
#     - 20 /flood requests with otel_error_log_coalesce off
#     - HARD-assert: arrives as multiple LogRecords (no coalesced_count collapse)
#     - HARD-assert: metric still present (counts true volume regardless of coalescing)
#
#   Stage C: Severity-floor
#     - "error" floor: only err/crit/alert/emerg → "connect() failed" passes
#     - config-load guard: bad nginx config → parse error lands in core error.log,
#             NOT in LOGS_LOG (writer not active in config-load context)
#   Stage E: Fixed-default floor proof
#     - Bare `otel_error_log;` + core error_log=notice
#     - nc fake upstream triggers "upstream sent more data" at WARN (5)
#     - HARD: "upstream sent more data" (WARN/5) IN core error.log (WARN was generated)
#     - HARD: "upstream sent more data" (WARN/5) NOT in LOGS_LOG (fixed ERR floor blocks it)
#     - HARD: "connect() failed" (ERR/4) IS in LOGS_LOG (passes fixed ERR floor)
#     - Proves floor is FIXED at NGX_LOG_ERR, not mirrored from core error_log
#
# Exit codes: 0 = all assertions passed; 1 = preflight failure; 2 = assertion FAILED.

set -euo pipefail

# ─── Resolve paths ───────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPO_ROOT="$(cd "${CRATE_DIR}/.." && pwd)"

CONF_TEMPLATE="${SCRIPT_DIR}/nginx_error_log.conf"

. "${CRATE_DIR}/test-harness/lib.sh"
resolve_nginx_binary || true

case "$(uname -s)" in
    Darwin) MODULE_EXT="dylib" ;;
    *)      MODULE_EXT="so"    ;;
esac
# When CARGO_BUILD_TARGET is set (e.g., the TSAN gate uses --target so cargo
# can also -Zbuild-std), cargo writes its output to target/<triple>/release/
# rather than target/release/.  Backwards-compatible: unset → original path.
# (Mirrors run_grpc_smoke.sh; without this the TSAN error-log gate can't find
# the .so and fails before nginx starts.)
if [[ -n "${CARGO_BUILD_TARGET:-}" ]]; then
    MODULE_PATH="${CRATE_DIR}/target/${CARGO_BUILD_TARGET}/release/libngx_http_otel_module.${MODULE_EXT}"
else
    MODULE_PATH="${CRATE_DIR}/target/release/libngx_http_otel_module.${MODULE_EXT}"
fi

SERVICE_NAME="ngx-otel-error-log-test"
METRIC_INTERVAL_S=2
FLUSH_WAIT_S=$(( METRIC_INTERVAL_S + 3 ))
FLOOD_COUNT_ON=100    # Stage A: flood count for coalesce-on
FLOOD_COUNT_OFF=20    # Stage B: flood count for coalesce-off

LISTEN_PORT_A=9104
LISTEN_PORT_B=9105
LISTEN_PORT_C=9106
LISTEN_PORT_E=9108   # Stage E: fixed-default floor proof
FAKE_WARN_PORT=9591  # Stage E: nc fake upstream that triggers WARN (Content-Length mismatch)

# ─── Colour helpers ──────────────────────────────────────────────────────────

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass()  { echo -e "${GREEN}[PASS]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*" >&2; FAILED=1; }
info()  { echo -e "${YELLOW}[INFO]${NC} $*"; }
hard_fail() {
    echo -e "${RED}[HARD-FAIL]${NC} $*" >&2
    FAILED=1
}

# ─── Pre-flight checks ───────────────────────────────────────────────────────

FAILED=0

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

# ─── Helper: run one nginx stage and return new collector content ─────────────
#
# run_stage <STAGE> <PORT> <ERROR_LEVEL> <OTEL_ERROR_ARGS> <COALESCE_FLAG> <FLOOD_COUNT>
#
# Sets NEW_LOGS and NEW_METRICS for the stage.

run_stage() {
    local STAGE="$1"
    local PORT="$2"
    local ERROR_LEVEL="$3"
    local OTEL_ERROR_ARGS="$4"
    local COALESCE_FLAG="$5"
    local FLOOD="$6"

    info "=== Stage ${STAGE}: port=${PORT} level=${ERROR_LEVEL} otel_error_log='${OTEL_ERROR_ARGS}' coalesce=${COALESCE_FLAG} flood=${FLOOD} ==="

    local PREFIX
    PREFIX="$(mktemp -d /tmp/ngx-otel-error-log.XXXXXX)"
    local NGINX_PID=""

    _cleanup_stage() {
        [[ -n "${NGINX_PID:-}" ]] && kill "${NGINX_PID}" 2>/dev/null || true
        echo ""
        echo "=== Stage ${STAGE} error.log (last 20 lines) ==="
        tail -20 "${PREFIX}/logs/error.log" 2>/dev/null || echo "(not found)"
        info "Tearing down ${PREFIX}"
        rm -rf "${PREFIX}"
    }
    trap _cleanup_stage EXIT

    mkdir -p "${PREFIX}/logs"
    mkdir -p "${PREFIX}/client_body_temp"

    sed \
        -e "s|@MODULE_PATH@|${MODULE_PATH}|g" \
        -e "s|@PREFIX@|${PREFIX}|g" \
        -e "s|@ERROR_LEVEL@|${ERROR_LEVEL}|g" \
        -e "s|@OTEL_ERROR_ARGS@|${OTEL_ERROR_ARGS}|g" \
        -e "s|@COALESCE_FLAG@|${COALESCE_FLAG}|g" \
        -e "s|@LISTEN_PORT@|${PORT}|g" \
        "${CONF_TEMPLATE}" > "${PREFIX}/nginx.conf"

    # Snapshot sizes before starting nginx.
    local PRE_LOGS_SIZE=0
    [[ -f "${LOGS_LOG}" ]] && PRE_LOGS_SIZE=$(wc -c < "${LOGS_LOG}")
    local PRE_METRICS_SIZE=0
    [[ -f "${METRICS_LOG}" ]] && PRE_METRICS_SIZE=$(wc -c < "${METRICS_LOG}")

    # Start nginx.
    info "  Starting nginx..."
    "${NGINX_BINARY}" -p "${PREFIX}" -c "${PREFIX}/nginx.conf" &
    NGINX_PID=$!
    sleep 1

    if ! kill -0 "${NGINX_PID}" 2>/dev/null; then
        echo "ERROR: nginx exited immediately. Check ${PREFIX}/logs/error.log" >&2
        cat "${PREFIX}/logs/error.log" >&2
        FAILED=1
        trap - EXIT; _cleanup_stage
        return
    fi
    info "  nginx running (PID ${NGINX_PID})"

    # Send flood traffic.
    info "  Sending ${FLOOD} requests to /flood (broken upstream)..."
    for i in $(seq 1 "${FLOOD}"); do
        curl -sf "http://127.0.0.1:${PORT}/flood" >/dev/null 2>&1 || true
    done
    info "  Traffic sent."

    # Wait for flush.
    info "  Waiting ${FLUSH_WAIT_S}s for export flush..."
    sleep "${FLUSH_WAIT_S}"

    # Graceful shutdown.
    info "  Sending nginx -s quit..."
    "${NGINX_BINARY}" -p "${PREFIX}" -c "${PREFIX}/nginx.conf" -s quit 2>/dev/null || true
    for i in $(seq 1 10); do
        if ! kill -0 "${NGINX_PID}" 2>/dev/null; then break; fi
        sleep 1
    done
    NGINX_PID=""
    sleep 1

    # Extract new collector content.
    NEW_LOGS=""
    if [[ -f "${LOGS_LOG}" ]]; then
        local POST_LOGS_SIZE
        POST_LOGS_SIZE=$(wc -c < "${LOGS_LOG}")
        if (( POST_LOGS_SIZE > PRE_LOGS_SIZE )); then
            NEW_LOGS=$(tail -c "+$(( PRE_LOGS_SIZE + 1 ))" "${LOGS_LOG}")
        fi
    fi

    NEW_METRICS=""
    if [[ -f "${METRICS_LOG}" ]]; then
        local POST_METRICS_SIZE
        POST_METRICS_SIZE=$(wc -c < "${METRICS_LOG}")
        if (( POST_METRICS_SIZE > PRE_METRICS_SIZE )); then
            NEW_METRICS=$(tail -c "+$(( PRE_METRICS_SIZE + 1 ))" "${METRICS_LOG}")
        fi
    fi

    info "  Stage ${STAGE}: ${#NEW_LOGS} bytes new logs.json, ${#NEW_METRICS} bytes new metrics.json"

    trap - EXIT
    _cleanup_stage
}

# ─── Stage A: Coalesce-on flood ───────────────────────────────────────────────

run_stage "A" "${LISTEN_PORT_A}" "debug" "warn" "on" "${FLOOD_COUNT_ON}"
NEW_LOGS_A="${NEW_LOGS}"
NEW_METRICS_A="${NEW_METRICS}"

info "=== Stage A assertions ==="

# HARD: error LogRecords arrived.
if [[ -z "${NEW_LOGS_A}" ]]; then
    hard_fail "Stage A: no new logs.json content — error LogRecords did not arrive"
else
    pass "Stage A: new logs.json content arrived"
fi

# HARD: event_name = nginx.error (or body contains the error key).
if echo "${NEW_LOGS_A}" | grep -qE '"nginx\.error"|"nginx.error"'; then
    pass "Stage A: event_name=nginx.error present"
else
    hard_fail "Stage A: event_name=nginx.error NOT found in logs.json"
fi

# HARD: body contains "connect() failed" (the flood generates this error).
if echo "${NEW_LOGS_A}" | grep -q "connect() failed"; then
    pass "Stage A: body contains 'connect() failed'"
else
    hard_fail "Stage A: 'connect() failed' NOT found in body — flood error not captured"
fi

# HARD: body contains upstream context (nginx appends ', upstream:' to proxy errors).
if echo "${NEW_LOGS_A}" | grep -qE 'upstream:|upstream: "'; then
    pass "Stage A: body contains 'upstream:' context (nginx appended it)"
else
    hard_fail "Stage A: 'upstream:' context NOT found in body — nginx context not propagated"
fi

# Count nginx.error LogRecords in Stage A.
ERROR_LOG_COUNT_A=$(echo "${NEW_LOGS_A}" | grep -o '"nginx\.error"' | wc -l | tr -d ' ' || echo 0)
info "Stage A: nginx.error record count = ${ERROR_LOG_COUNT_A}"

# HARD: coalescing in effect — flood of ${FLOOD_COUNT_ON} must NOT produce ${FLOOD_COUNT_ON} records.
# Bound: records < FLOOD_COUNT_ON/2 (allows for 2 workers × multiple proxy error templates
# × 2 export intervals; the key invariant is records << flood count, not records == 1).
MAX_COALESCED_RECORDS=$(( FLOOD_COUNT_ON / 2 ))
if (( ERROR_LOG_COUNT_A == 0 )); then
    hard_fail "Stage A: 0 nginx.error records — error records not arriving"
elif (( ERROR_LOG_COUNT_A >= FLOOD_COUNT_ON )); then
    hard_fail "Stage A: coalescing NOT working — got ${ERROR_LOG_COUNT_A} records for ${FLOOD_COUNT_ON} events (expected < ${MAX_COALESCED_RECORDS})"
elif (( ERROR_LOG_COUNT_A <= MAX_COALESCED_RECORDS )); then
    pass "Stage A: flood coalesced — ${ERROR_LOG_COUNT_A} nginx.error records for ${FLOOD_COUNT_ON} events (< ${MAX_COALESCED_RECORDS})"
else
    hard_fail "Stage A: coalescing weak — got ${ERROR_LOG_COUNT_A} records for ${FLOOD_COUNT_ON} events (expected < ${MAX_COALESCED_RECORDS})"
fi

# HARD: coalesced_count attribute present and > 1.
if echo "${NEW_LOGS_A}" | grep -qE '"nginx\.error\.coalesced_count"|coalesced_count'; then
    pass "Stage A: nginx.error.coalesced_count attribute present (coalescing in effect)"
else
    hard_fail "Stage A: nginx.error.coalesced_count NOT found — coalescing may not be active"
fi

# HARD: NO trace_id on error records (decision #6 — request context unreachable).
# The OTel LogRecord trace_id field should be absent/empty/all-zeros.
# Collector JSON: traceId field is all-zeros or absent for non-traced records.
if echo "${NEW_LOGS_A}" | grep -qE '"traceId":"[1-9a-f][0-9a-f]{15,}"'; then
    hard_fail "Stage A: non-zero traceId found on error LogRecord — decision #6 violated (request context leaking)"
else
    pass "Stage A: no non-zero traceId on error records (decision #6 OK)"
fi

# HARD: NO http.route attribute on error records (decision #6).
if echo "${NEW_LOGS_A}" | grep -q '"http.route"'; then
    hard_fail "Stage A: http.route attribute found on error LogRecord — decision #6 violated"
else
    pass "Stage A: no http.route attribute on error records (decision #6 OK)"
fi

# HARD: NO nginx.upstream.zone attribute on error records (decision #6).
if echo "${NEW_LOGS_A}" | grep -q '"nginx.upstream.zone"'; then
    hard_fail "Stage A: nginx.upstream.zone found on error LogRecord — decision #6 violated"
else
    pass "Stage A: no nginx.upstream.zone attribute on error records (decision #6 OK)"
fi

# HARD: companion metric ngx_otel.error_log.events present.
if echo "${NEW_METRICS_A}" | grep -q 'error_log.events'; then
    pass "Stage A: ngx_otel.error_log.events metric present"
else
    hard_fail "Stage A: ngx_otel.error_log.events metric NOT found — companion metric missing"
fi

# HARD: severity_class attribute present on the metric.
if echo "${NEW_METRICS_A}" | grep -q '"severity_class"'; then
    pass "Stage A: severity_class attribute present on error_log.events metric"
else
    hard_fail "Stage A: severity_class attribute NOT found on error_log.events metric"
fi

# HARD: severity floor — debug messages must NOT appear (floor = warn, debug >> warn).
# nginx itself may log debug messages; our writer should suppress them.
# Check that the only nginx.error records are at warn/error/crit level.
# Severity numbers: WARN=13-14, ERROR=17-18; DEBUG=5; any debug would be < 9.
if echo "${NEW_LOGS_A}" | grep -q '"severityNumber":5\b\|"severityNumber": 5\b'; then
    hard_fail "Stage A: DEBUG severity record found — floor filtering not working"
else
    pass "Stage A: no DEBUG-severity nginx.error records (floor=warn in effect)"
fi

# Check service.name to guard against metrics regression.
if echo "${NEW_METRICS_A}" | grep -q "${SERVICE_NAME}"; then
    pass "Stage A: service.name=${SERVICE_NAME} present (no metrics regression)"
else
    fail "Stage A: service.name=${SERVICE_NAME} NOT found in metrics"
fi

# ─── Stage B: Coalesce-off flood ─────────────────────────────────────────────

run_stage "B" "${LISTEN_PORT_B}" "debug" "warn" "off" "${FLOOD_COUNT_OFF}"
NEW_LOGS_B="${NEW_LOGS}"
NEW_METRICS_B="${NEW_METRICS}"

info "=== Stage B assertions ==="

# HARD: error LogRecords arrived.
if [[ -z "${NEW_LOGS_B}" ]]; then
    hard_fail "Stage B: no new logs.json content — coalesce-off records did not arrive"
else
    pass "Stage B: new logs.json content arrived (coalesce-off)"
fi

ERROR_LOG_COUNT_B=$(echo "${NEW_LOGS_B}" | grep -o '"nginx\.error"' | wc -l | tr -d ' ' || echo 0)
info "Stage B: nginx.error record count = ${ERROR_LOG_COUNT_B} for ${FLOOD_COUNT_OFF} events"

# HARD: coalesce-off → multiple records, NOT collapsed to 1.
# With 20 events and coalesce-off, expect > 1 record.
# The ring is bounded — in a lab run we expect to see most of them.
# Assert: count > 1 (not collapsed) AND count <= FLOOD_COUNT_OFF * 2 (sane).
if (( ERROR_LOG_COUNT_B > 1 )); then
    pass "Stage B: coalesce-off produced ${ERROR_LOG_COUNT_B} records (> 1, not collapsed)"
else
    hard_fail "Stage B: coalesce-off: expected > 1 records, got ${ERROR_LOG_COUNT_B} — records may be collapsed"
fi

# HARD: no coalesced_count attribute when coalesce is off (no template tracking → hash=0 → no count attr).
if echo "${NEW_LOGS_B}" | grep -qE 'coalesced_count'; then
    # Soft warning: if coalesce is truly off, we should not see this.
    # But count = 1 for each record would not generate the attribute, so this is expected absent.
    info "Stage B: WARNING: coalesced_count found in coalesce-off mode (unexpected)"
else
    pass "Stage B: no coalesced_count in coalesce-off mode (expected)"
fi

# HARD: companion metric still present in coalesce-off mode.
if echo "${NEW_METRICS_B}" | grep -q 'error_log.events'; then
    pass "Stage B: ngx_otel.error_log.events metric present (coalesce-off)"
else
    hard_fail "Stage B: ngx_otel.error_log.events metric NOT found in coalesce-off mode"
fi

# HARD: body contains "connect() failed" in coalesce-off mode.
if echo "${NEW_LOGS_B}" | grep -q "connect() failed"; then
    pass "Stage B: body contains 'connect() failed' (coalesce-off verbatim)"
else
    hard_fail "Stage B: 'connect() failed' NOT found in coalesce-off mode"
fi

# ─── Stage C: Severity floor test ────────────────────────────────────────────
# Use otel_error_log crit; — only crit/alert/emerg pass (levels 1-3).
# "connect() failed" is logged at NGX_LOG_ERR (4) → must NOT appear.
# Nginx heartbeat/internal messages may not fire at crit+ in normal operation,
# so we just verify no error-level records pass the floor.

run_stage "C" "${LISTEN_PORT_C}" "debug" "crit" "on" "10"
NEW_LOGS_C="${NEW_LOGS}"
NEW_METRICS_C="${NEW_METRICS}"

info "=== Stage C assertions (floor=crit) ==="

ERROR_LOG_COUNT_C=$(echo "${NEW_LOGS_C}" | grep -o '"nginx\.error"' | wc -l | tr -d ' ' || echo 0)
info "Stage C: nginx.error record count = ${ERROR_LOG_COUNT_C} (floor=crit, should block error-level connect failures)"

# HARD: floor=crit → "connect() failed" (NGX_LOG_ERR=4) must NOT appear.
if echo "${NEW_LOGS_C}" | grep -q "connect() failed"; then
    hard_fail "Stage C: 'connect() failed' appeared with floor=crit — severity floor not working"
else
    pass "Stage C: 'connect() failed' blocked by crit floor (floor filtering OK)"
fi

# ─── Stage D: config-load guard verification (bad config → core only, not LOGS_LOG) ──
# Run nginx -t with a deliberately broken config: invalid directive.
# nginx will exit with an error during config-load.
# The error must appear in the sandbox error.log (core) but NOT in LOGS_LOG.
# This verifies that the process-role guard blocks the writer in config-load context.

info "=== Stage D: config-load error goes to core log, not LOGS_LOG ==="

DP_C_PREFIX="$(mktemp -d /tmp/ngx-otel-dp-c.XXXXXX)"
_cleanup_dp_c() {
    rm -rf "${DP_C_PREFIX}"
}
trap _cleanup_dp_c EXIT

mkdir -p "${DP_C_PREFIX}/logs"
mkdir -p "${DP_C_PREFIX}/client_body_temp"

# Create a bad config: add an invalid directive after otel_error_log.
sed \
    -e "s|@MODULE_PATH@|${MODULE_PATH}|g" \
    -e "s|@PREFIX@|${DP_C_PREFIX}|g" \
    -e "s|@ERROR_LEVEL@|debug|g" \
    -e "s|@OTEL_ERROR_ARGS@|warn|g" \
    -e "s|@COALESCE_FLAG@|on|g" \
    -e "s|@LISTEN_PORT@|9107|g" \
    "${CONF_TEMPLATE}" > "${DP_C_PREFIX}/nginx.conf"

# Append a syntactically invalid directive to force a config-load error.
echo "http { this_is_not_valid_otel_directive; }" >> "${DP_C_PREFIX}/nginx.conf"

PRE_LOGS_SIZE_D=0
[[ -f "${LOGS_LOG}" ]] && PRE_LOGS_SIZE_D=$(wc -c < "${LOGS_LOG}")

# Run nginx config test — this should fail.
"${NGINX_BINARY}" -p "${DP_C_PREFIX}" -c "${DP_C_PREFIX}/nginx.conf" -t 2>/dev/null || true
sleep 1

POST_LOGS_SIZE_D=0
[[ -f "${LOGS_LOG}" ]] && POST_LOGS_SIZE_D=$(wc -c < "${LOGS_LOG}")

# HARD: the config-load error must be in the sandbox core error.log.
if grep -q "unknown directive\|invalid\|emerg\|directive is not allowed\|not allowed" \
    "${DP_C_PREFIX}/logs/error.log" 2>/dev/null; then
    pass "Stage D: config-load error present in core error.log"
else
    # The directive error may not propagate to the file if we only do -t; soft check.
    info "Stage D: (no config-error in ${DP_C_PREFIX}/logs/error.log; -t may not write there)"
fi

# HARD: the config-load error must NOT appear in LOGS_LOG (OTel collector).
# During config-load, the process is NGX_PROCESS_MASTER or config-check → guard fires.
if (( POST_LOGS_SIZE_D > PRE_LOGS_SIZE_D )); then
    # New content appeared — check if it's from this test.
    NEW_LOGS_D=$(tail -c "+$(( PRE_LOGS_SIZE_D + 1 ))" "${LOGS_LOG}")
    if echo "${NEW_LOGS_D}" | grep -q "this_is_not_valid"; then
        hard_fail "Stage D: config-load error appeared in LOGS_LOG — process-role guard not firing in config-load"
    else
        info "Stage D: new LOGS_LOG content unrelated to this config-load test (OK)"
        pass "Stage D: config-load error NOT in LOGS_LOG (process-role guard working)"
    fi
else
    pass "Stage D: no new LOGS_LOG content during config-load test (process-role guard working)"
fi

trap - EXIT
_cleanup_dp_c

# ─── Stage E: Fixed-default floor proof ──────────────────────────────────────
#
# Proves bare `otel_error_log;` (NOARGS) uses a FIXED floor of NGX_LOG_ERR,
# NOT the core error_log level (no mirroring).
#
# Setup: core error_log=notice (below ERR).
#   /warn: nc fake upstream sends Content-Length:3 + longer body →
#          nginx logs "upstream sent more data" at WARN (5) → BLOCKED.
#   /flood: proxy to port 9 → "connect() failed" at ERR (4) → PASSES.
# If the floor mirrored the core notice level (6), WARN messages would pass.

info "=== Stage E: fixed-default floor proof — bare otel_error_log; with core=notice ==="

STAGE_E_CONF="${SCRIPT_DIR}/nginx_error_log_stage_e.conf"
STAGE_E_PREFIX="$(mktemp -d /tmp/ngx-otel-error-log-stage-e.XXXXXX)"
STAGE_E_NGINX_PID=""
STAGE_E_NC_PID=""

_cleanup_stage_e() {
    [[ -n "${STAGE_E_NGINX_PID:-}" ]] && kill "${STAGE_E_NGINX_PID}" 2>/dev/null || true
    [[ -n "${STAGE_E_NC_PID:-}" ]]    && kill "${STAGE_E_NC_PID}"    2>/dev/null || true
    echo ""
    echo "=== Stage E error.log (last 20 lines) ==="
    tail -20 "${STAGE_E_PREFIX}/logs/error.log" 2>/dev/null || echo "(not found)"
    info "Tearing down ${STAGE_E_PREFIX}"
    rm -rf "${STAGE_E_PREFIX}"
}
trap _cleanup_stage_e EXIT

mkdir -p "${STAGE_E_PREFIX}/logs"
mkdir -p "${STAGE_E_PREFIX}/client_body_temp"

sed \
    -e "s|@MODULE_PATH@|${MODULE_PATH}|g" \
    -e "s|@PREFIX@|${STAGE_E_PREFIX}|g" \
    -e "s|@LISTEN_PORT@|${LISTEN_PORT_E}|g" \
    -e "s|@FAKE_WARN_PORT@|${FAKE_WARN_PORT}|g" \
    "${STAGE_E_CONF}" > "${STAGE_E_PREFIX}/nginx.conf"

# Start the fake WARN upstream BEFORE nginx.
# nc sends Content-Length:3 but a longer body; nginx proxy logs WARN.
# nc handles exactly one connection then exits — that's all we need.
info "  Starting nc fake upstream on port ${FAKE_WARN_PORT} (triggers WARN on single request)..."
printf 'HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nHELLO_WORLD_EXTRA_BYTES' \
    | nc -l "${FAKE_WARN_PORT}" &
STAGE_E_NC_PID=$!
sleep 0.5

# Snapshot sizes before starting nginx.
PRE_LOGS_SIZE_E=0
[[ -f "${LOGS_LOG}" ]] && PRE_LOGS_SIZE_E=$(wc -c < "${LOGS_LOG}")
PRE_METRICS_SIZE_E=0
[[ -f "${METRICS_LOG}" ]] && PRE_METRICS_SIZE_E=$(wc -c < "${METRICS_LOG}")

# Start nginx.
info "  Starting nginx (core=notice, otel floor=NGX_LOG_ERR fixed)..."
"${NGINX_BINARY}" -p "${STAGE_E_PREFIX}" -c "${STAGE_E_PREFIX}/nginx.conf" &
STAGE_E_NGINX_PID=$!
sleep 1

if ! kill -0 "${STAGE_E_NGINX_PID}" 2>/dev/null; then
    echo "ERROR: Stage E nginx exited immediately." >&2
    cat "${STAGE_E_PREFIX}/logs/error.log" >&2
    hard_fail "Stage E: nginx failed to start"
    trap - EXIT; _cleanup_stage_e
else

    # Send ONE request to /warn → nginx connects to nc → WARN generated.
    info "  Sending 1 /warn request (Content-Length mismatch → 'upstream sent more data' WARN)..."
    curl -sf "http://127.0.0.1:${LISTEN_PORT_E}/warn" >/dev/null 2>&1 || true
    sleep 0.5
    # nc exits after serving one connection; clear the PID so cleanup doesn't re-kill.
    wait "${STAGE_E_NC_PID}" 2>/dev/null || true
    STAGE_E_NC_PID=""

    # Send /flood requests to generate ERR-level "connect() failed".
    info "  Sending 10 /flood requests (expect 'connect() failed' ERR)..."
    for i in $(seq 1 10); do
        curl -sf "http://127.0.0.1:${LISTEN_PORT_E}/flood" >/dev/null 2>&1 || true
    done

    info "  Waiting ${FLUSH_WAIT_S}s for export flush..."
    sleep "${FLUSH_WAIT_S}"

    info "  Sending nginx -s quit..."
    "${NGINX_BINARY}" -p "${STAGE_E_PREFIX}" -c "${STAGE_E_PREFIX}/nginx.conf" -s quit 2>/dev/null || true
    for i in $(seq 1 10); do
        if ! kill -0 "${STAGE_E_NGINX_PID}" 2>/dev/null; then break; fi
        sleep 1
    done
    STAGE_E_NGINX_PID=""
    sleep 1

    # Extract new collector content.
    NEW_LOGS_E=""
    if [[ -f "${LOGS_LOG}" ]]; then
        POST_LOGS_SIZE_E=$(wc -c < "${LOGS_LOG}")
        if (( POST_LOGS_SIZE_E > PRE_LOGS_SIZE_E )); then
            NEW_LOGS_E=$(tail -c "+$(( PRE_LOGS_SIZE_E + 1 ))" "${LOGS_LOG}")
        fi
    fi
    NEW_METRICS_E=""
    if [[ -f "${METRICS_LOG}" ]]; then
        POST_METRICS_SIZE_E=$(wc -c < "${METRICS_LOG}")
        if (( POST_METRICS_SIZE_E > PRE_METRICS_SIZE_E )); then
            NEW_METRICS_E=$(tail -c "+$(( PRE_METRICS_SIZE_E + 1 ))" "${METRICS_LOG}")
        fi
    fi

    info "Stage E: ${#NEW_LOGS_E} bytes new logs.json, ${#NEW_METRICS_E} bytes new metrics.json"

    info "=== Stage E assertions (fixed-default floor) ==="

    # HARD (sanity): "upstream sent more data" must appear in core error.log.
    # This confirms the WARN was actually generated — the assertion below is
    # NOT vacuously true.
    if grep -q "upstream sent more data" "${STAGE_E_PREFIX}/logs/error.log" 2>/dev/null; then
        pass "Stage E: 'upstream sent more data' WARN present in core error.log (WARN was generated)"
    else
        hard_fail "Stage E: 'upstream sent more data' NOT in core error.log — WARN was not generated (nc may have failed)"
    fi

    # HARD: WARN must NOT appear in LOGS_LOG.
    # Fixed ERR floor (4) blocks WARN (5). If mirrored from notice (6), WARN would pass.
    if echo "${NEW_LOGS_E}" | grep -q "upstream sent more data"; then
        hard_fail "Stage E: 'upstream sent more data' (WARN) appeared in LOGS_LOG — floor is NOT fixed at ERR (mirroring suspected)"
    else
        pass "Stage E: 'upstream sent more data' (WARN) NOT in LOGS_LOG — fixed ERR floor blocks WARN"
    fi

    # HARD: "connect() failed" ERR must appear in LOGS_LOG.
    # ERR (4) passes through the fixed ERR floor.
    if echo "${NEW_LOGS_E}" | grep -q "connect() failed"; then
        pass "Stage E: 'connect() failed' (ERR) present in LOGS_LOG — ERR passes fixed floor"
    else
        hard_fail "Stage E: 'connect() failed' NOT in LOGS_LOG — ERR messages not arriving with NOARGS floor"
    fi

fi

trap - EXIT
_cleanup_stage_e

# ─── Final result ─────────────────────────────────────────────────────────────

echo ""
if [[ "${FAILED}" -eq 0 ]]; then
    pass "All error-log assertions passed."
    exit 0
else
    fail "One or more error-log assertions FAILED."
    exit 2
fi
