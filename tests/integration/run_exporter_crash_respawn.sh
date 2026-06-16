#!/usr/bin/env bash
# tests/integration/run_exporter_crash_respawn.sh — exporter crash-respawn gate
#
# Verifies that master auto-respawns the `nginx: otel exporter` child after a
# SIGKILL (crash).  Gate: "exporter restart on crash works with bounded telemetry loss".
#
# Assertions:
#   1. nginx starts with one exporter child (PID #1).
#   2. SIGKILL the exporter; within 5s a new exporter PID (#2) appears.
#   3. PID #2 != PID #1.
#   4. error.log contains "otel exporter: cycle entered" at least twice
#      (once for original spawn, once for respawn).
#   5. ngx_otel.dropped_records > 0 in metrics.json (bounded-loss gate):
#      nginx is started BEFORE the collector so Worker 0's export loop
#      immediately gets ECONNREFUSED and fills its retry buffer (retry_depth=4).
#      After 5+ failed intervals (5s) DROPPED_RECORDS accumulates; the
#      collector is then started so the SAME Worker 0 exports the drops.
#   6. After SIGQUIT shutdown, no exporter remains.
#   7. Script is idempotent — running it twice in a row both pass.
#
# Known constraint: if the exporter ever exits with status 2, nginx disables
# respawn (ngx_process.c:551-557).  The exporter cycle must never call
# exit(2) on a recoverable error.
#
# Collector requirement: the test ensures the OTel collector is running
# AFTER the drop-accumulation window, not before.  nginx connects to
# 127.0.0.1:4318 from the start; ECONNREFUSED (instant) fills the retry
# queue quickly.  Once the collector starts, the same Worker 0 process
# retries and exports with dropped_records > 0.
#
# Prerequisites: NGINX_BINARY set or auto-detected from objs-release/nginx.
#
# Exit codes: 0 = all assertions passed, 1 = preflight failed, 2 = assertion failed.

set -euo pipefail

# ─── Resolve paths ───────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

CONF_TEMPLATE="${SCRIPT_DIR}/nginx_exporter.conf"

. "${CRATE_DIR}/test-harness/lib.sh"
resolve_nginx_binary || true

case "$(uname -s)" in
    Darwin) MODULE_EXT="dylib" ;;
    *)      MODULE_EXT="so"    ;;
esac

RELEASE_MODULE="${CRATE_DIR}/objs-release/ngx_http_otel_module.so"
# CARGO_BUILD_TARGET set (TSAN gate uses --target) -> cargo writes to
# target/<triple>/release/ rather than target/release/.
if [[ -n "${CARGO_BUILD_TARGET:-}" ]]; then
    CARGO_MODULE="${CRATE_DIR}/target/${CARGO_BUILD_TARGET}/release/libngx_http_otel_module.${MODULE_EXT}"
else
    CARGO_MODULE="${CRATE_DIR}/target/release/libngx_http_otel_module.${MODULE_EXT}"
fi
if [[ -f "${RELEASE_MODULE}" ]]; then
    MODULE_PATH="${RELEASE_MODULE}"
elif [[ -f "${CARGO_MODULE}" ]]; then
    MODULE_PATH="${CARGO_MODULE}"
else
    echo "ERROR: module not found. Run 'make build-release' first." >&2
    exit 1
fi

# ─── Colour helpers ──────────────────────────────────────────────────────────

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass()  { echo -e "${GREEN}[PASS]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*" >&2; exit 2; }
info()  { echo -e "${YELLOW}[INFO]${NC} $*"; }

# ─── Pre-flight ───────────────────────────────────────────────────────────────

if [[ ! -x "${NGINX_BINARY}" ]]; then
    echo "ERROR: nginx binary not found at ${NGINX_BINARY}." >&2
    exit 1
fi
info "nginx binary: ${NGINX_BINARY}"
info "Module:       ${MODULE_PATH}"

# ─── Helpers ─────────────────────────────────────────────────────────────────

wait_for() {
    local timeout=$1 desc=$2 expr=$3
    local deadline=$(( $(date +%s) + timeout ))
    while (( $(date +%s) < deadline )); do
        if eval "${expr}" 2>/dev/null; then
            return 0
        fi
        sleep 0.5
    done
    fail "Timed out waiting for: ${desc}"
}

# Return the PID of the otel exporter child (first match).
#
# WHY ps -eo pid,args (not pid,comm):
#   Linux `comm` reads /proc/PID/comm, which holds the 15-byte TASK_COMM_LEN
#   kernel name set by exec or prctl(PR_SET_NAME) — NOT by argv[0] rewrites.
#   nginx's ngx_setproctitle() rewrites argv[0] in-place; it never calls
#   prctl(PR_SET_NAME), so /proc/PID/comm always shows the original exec name
#   ("nginx"), losing the "nginx: otel exporter" title entirely on Linux.
#   macOS ps(1) happens to surface argv[0] via its own comm column, which is
#   why the old `comm` pattern worked there but silently failed on Linux.
#   `args` (POSIX) returns the full argv joined, so it captures argv[0]
#   rewrites on both platforms.
#
# WHY field-anchored awk ($2=="nginx:" && $3=="otel" && $4=="exporter"):
#   The regex /nginx: otel exporter/ self-matches: the awk process appears in
#   ps -eo args with its own script containing "nginx: otel exporter", causing
#   exporter_pid() to return the awk PID even when no nginx exporter is running.
#   Field-anchored equality only matches lines where $2 is exactly "nginx:" —
#   the awk process has $2="awk", not "nginx:". Prevents false positives that
#   would cause wait_for "[[ -z $(exporter_pid) ]]" to time out on SIGQUIT even
#   after the exporter has already exited.
exporter_pid() {
    ps -eo pid,args 2>/dev/null \
        | awk '$2 == "nginx:" && $3 == "otel" && $4 == "exporter" {print $1}' \
        | head -1
}

# ─── Test body ───────────────────────────────────────────────────────────────

PREFIX="$(mktemp -d /tmp/ngx-otel-crash.XXXXXX)"
NGINX_PID=""

cleanup() {
    [[ -n "${NGINX_PID:-}" ]] && kill "${NGINX_PID}" 2>/dev/null || true
    sleep 1
    echo ""
    echo "=== error.log (last 30 lines) ==="
    tail -30 "${PREFIX}/logs/error.log" 2>/dev/null || echo "(not found)"
    rm -rf "${PREFIX}"
}
trap cleanup EXIT

mkdir -p "${PREFIX}/logs" "${PREFIX}/client_body_temp"
sed \
    -e "s|@MODULE_PATH@|${MODULE_PATH}|g" \
    -e "s|@PREFIX@|${PREFIX}|g" \
    "${CONF_TEMPLATE}" > "${PREFIX}/nginx.conf"

# Stop the collector so port 4318 is unreachable when nginx starts.
# This guarantees Worker 0's export loop gets ECONNREFUSED immediately.
# The collector is restarted after the failure window (below).
if command -v docker >/dev/null 2>&1; then
    info "Stopping collector to create export-failure window..."
    ( cd "${CRATE_DIR}/test-harness" && docker compose stop 2>/dev/null ) || true
    # Brief wait for port to release.
    sleep 1
fi

# Record nginx start time so we can measure from it.
NGINX_START_S="$(date +%s)"

info "Starting nginx (collector stopped — drop window begins)..."
"${NGINX_BINARY}" -p "${PREFIX}" -c "${PREFIX}/nginx.conf" &
NGINX_PID=$!
sleep 1

if ! kill -0 "${NGINX_PID}" 2>/dev/null; then
    fail "nginx exited immediately"
fi

# Assertion 1: exporter appears.
EXP_PID_1="$(exporter_pid)"
if [[ -z "${EXP_PID_1}" ]]; then
    fail "No 'otel exporter' process found after nginx start"
fi
pass "Initial exporter PID = ${EXP_PID_1}"

# Drive a brief HTTP load while we kill the exporter (verifies nginx keeps
# serving requests during the respawn window, and generates metric data points
# in the producer's ring buffer — "bump-and-defer" records in flight).
# NOTE: track CURL_PIDS so we can wait on them specifically (not nginx).
CURL_PIDS=()
for _ in $(seq 1 20); do
    curl -s --max-time 3 http://127.0.0.1:9200/ >/dev/null 2>&1 &
    CURL_PIDS+=($!)
done

# Assertion 2+3: SIGKILL the exporter; a NEW pid appears within 5s.
info "Sending SIGKILL to exporter PID ${EXP_PID_1}..."
kill -SIGKILL "${EXP_PID_1}" 2>/dev/null || fail "kill -SIGKILL failed (exporter already gone?)"

EXP_PID_2=""
for _ in $(seq 1 10); do
    sleep 0.5
    CUR="$(exporter_pid)"
    if [[ -n "${CUR}" && "${CUR}" != "${EXP_PID_1}" ]]; then
        EXP_PID_2="${CUR}"
        break
    fi
done

if [[ -z "${EXP_PID_2}" ]]; then
    fail "Master did not respawn exporter within 5s after SIGKILL"
fi
pass "Respawned exporter PID = ${EXP_PID_2} (was ${EXP_PID_1})"

# Wait only for curl jobs (not nginx).
for cpid in "${CURL_PIDS[@]}"; do
    wait "${cpid}" 2>/dev/null || true
done

# ── Wait for the drop-accumulation window ─────────────────────────────────────
#
# Worker 0 attempts to export every otel_metric_interval=1s.  Each attempt gets
# ECONNREFUSED immediately (nothing listening on 4318).  With retry_depth=4,
# the retry buffer fills after 4 intervals and starts evicting oldest entries
# at interval 5+.  We need at least 5s from nginx start for the first drop;
# wait until T+7s (= 6-7 drop events, ~2-3 batches evicted).
NOW_S="$(date +%s)"
ELAPSED=$(( NOW_S - NGINX_START_S ))
DROP_WINDOW_END=$(( NGINX_START_S + 7 ))
REMAINING=$(( DROP_WINDOW_END - NOW_S ))
if (( REMAINING > 0 )); then
    info "Waiting ${REMAINING}s more for retry buffer overflow (${ELAPSED}s elapsed from nginx start)..."
    sleep "${REMAINING}"
fi

# ── Now start the collector so Worker 0 can export the accumulated drops ──────
info "Starting collector so Worker 0 can export dropped_records..."

# Snapshot metrics.json before we start collecting — ensures we only look at
# payloads emitted during this test.
PRE_SIZE=0
if [[ -f "${METRICS_LOG}" ]]; then
    PRE_SIZE=$(wc -c < "${METRICS_LOG}")
fi
info "metrics.json pre-size: ${PRE_SIZE} bytes"

ensure_collector_running

# Give Worker 0 time to retry (2 export intervals = 2s) and send the payload.
info "Waiting for Worker 0 to export to collector..."
sleep 3

# Assertion 4: error.log contains "cycle entered" at least twice.
CYCLE_ENTERED_COUNT="$(grep -c "otel exporter: cycle entered" "${PREFIX}/logs/error.log" 2>/dev/null || true)"
if (( CYCLE_ENTERED_COUNT < 2 )); then
    fail "error.log contains 'otel exporter: cycle entered' only ${CYCLE_ENTERED_COUNT} time(s); expected >= 2"
fi
pass "error.log contains 'otel exporter: cycle entered' ${CYCLE_ENTERED_COUNT} time(s) (>= 2)"

# Assertion 5: dropped_records > 0 in metrics.json delta (bounded-loss gate).
#
# The retry buffer overflow increments DROPPED_RECORDS in Worker 0's process.
# Once the collector is available, the next successful export includes
# ngx_otel.dropped_records = N > 0 in the self-metrics payload.
#
# The load-bearing claim: "exporter restart on crash works with bounded telemetry loss"
# — measured by the dropped_records metric reaching the collector, not just by log lines.
NEW_CONTENT=""
if [[ -f "${METRICS_LOG}" ]]; then
    POST_SIZE=$(wc -c < "${METRICS_LOG}")
    if (( POST_SIZE > PRE_SIZE )); then
        NEW_CONTENT=$(tail -c "+$(( PRE_SIZE + 1 ))" "${METRICS_LOG}")
    fi
fi

DROPPED_VALUE=0
if [[ -n "${NEW_CONTENT}" ]]; then
    DROPPED_VALUE="$(echo "${NEW_CONTENT}" \
        | python3 -c "
import sys, json
max_dropped = 0
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        d = json.loads(line)
    except Exception:
        continue
    for rm in d.get('resourceMetrics', []):
        for sm in rm.get('scopeMetrics', []):
            for m in sm.get('metrics', []):
                if m.get('name') == 'ngx_otel.dropped_records':
                    for pt in m.get('sum', {}).get('dataPoints', []):
                        v = int(pt.get('asInt', 0))
                        if v > max_dropped:
                            max_dropped = v
print(max_dropped)
" 2>/dev/null || echo "0")"
fi

if (( DROPPED_VALUE > 0 )); then
    pass "ngx_otel.dropped_records = ${DROPPED_VALUE} > 0 (bounded-loss gate)"
else
    fail "ngx_otel.dropped_records not > 0 in metrics.json delta (got ${DROPPED_VALUE:-0}).
       Expected retry buffer (depth=4) to overflow after 5+ failed 1s-interval exports.
       New metrics.json content (first 3 lines):
$(echo "${NEW_CONTENT}" | head -3 || echo "(no new content)")
       send_failures in error.log:
$(grep -aE 'send failed|retry buffer full|retry send failed' "${PREFIX}/logs/error.log" | head -5 || echo "(none)")"
fi

# Assertion 6: clean shutdown leaves no exporter.
info "Sending SIGQUIT to master PID ${NGINX_PID}..."
kill -SIGQUIT "${NGINX_PID}"
wait_for 10 "exporter to exit after SIGQUIT" \
    "[[ -z \"\$(exporter_pid)\" ]]"
wait_for 10 "nginx master to exit" \
    "! kill -0 ${NGINX_PID} 2>/dev/null"
pass "No exporter or master process remains after SIGQUIT"
NGINX_PID=""
trap - EXIT
rm -rf "${PREFIX}"

echo ""
pass "=== All crash-respawn assertions passed ==="
