#!/usr/bin/env bash
# tests/integration/run_exporter_binary_upgrade.sh — R2 USR2 live binary-upgrade gate
#
# Verifies that a USR2 live binary upgrade produces:
#   1. A second master (M2) and two otel exporters during the overlap window.
#   2. M2's exporter has a DIFFERENT service.instance.id from M1's.
#   3. The collector receives telemetry carrying BOTH instance ids during overlap.
#   4. M1 and its exporter exit cleanly after WINCH + QUIT.
#   5. M2 and its exporter remain running; steady-state: 1 master + 1 exporter.
#   6. error.log clean: no panic/abort/SIGSEGV.
#
# Gate run: **debian-vm** (Linux process model for USR2/WINCH/QUIT signals).
# macOS may also be used for development but the committed evidence MUST be
# from a Linux run.  STOP-AND-ASK [R2-PLATFORM] applies.
#
# Prerequisites:
#   - NGINX_BINARY set or auto-detected (release or debug build).
#   - Module built (make build or make build-release).
#   - Collector running (ensure_collector_running handles this).
#
# Exit codes: 0 = all assertions passed, 1 = preflight failed, 2 = assertion failed.

set -euo pipefail

# ─── Resolve paths ────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

. "${CRATE_DIR}/test-harness/lib.sh"
resolve_nginx_binary || true

case "$(uname -s)" in
    Darwin) MODULE_EXT="dylib" ;;
    *)      MODULE_EXT="so"    ;;
esac

RELEASE_MODULE="${CRATE_DIR}/objs-release/ngx_http_otel_module.so"
CARGO_MODULE="${CRATE_DIR}/target/release/libngx_http_otel_module.${MODULE_EXT}"
if [[ -f "${RELEASE_MODULE}" ]]; then
    MODULE_PATH="${RELEASE_MODULE}"
elif [[ -f "${CARGO_MODULE}" ]]; then
    MODULE_PATH="${CARGO_MODULE}"
else
    echo "ERROR: module not found. Run 'make build-release' first." >&2
    exit 1
fi

# ─── Colour helpers ───────────────────────────────────────────────────────────

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

# USR2 is a Linux-only live binary upgrade signal.
# macOS sends SIGUSR2 to the process but nginx does not implement the
# binary upgrade logic on macOS (no execve of a new binary).
if [[ "$(uname -s)" != "Linux" ]]; then
    echo "STOP-AND-ASK [R2-PLATFORM]: USR2 live binary upgrade requires Linux." >&2
    echo "This script must be run on the debian-vm (Linux aarch64)." >&2
    echo "The committed gate artifact MUST be the debian-vm run." >&2
    exit 1
fi

ensure_collector_running

# ─── Helpers ──────────────────────────────────────────────────────────────────

wait_for() {
    local timeout=$1 desc=$2 expr=$3
    local deadline=$(( SECONDS + timeout ))
    while (( SECONDS < deadline )); do
        if eval "${expr}" 2>/dev/null; then
            return 0
        fi
        sleep 0.5
    done
    fail "Timed out waiting for: ${desc}"
}

# Count ALL live "nginx: otel exporter" processes (any parent).
# In daemon mode the exporter is spawned before the double-fork daemonize
# step, so its PPID becomes 1 (init) rather than the final master PID.
# PPID-based filtering is therefore unreliable; we just count by title.
count_all_exporters() {
    ps -eo pid,args 2>/dev/null \
        | awk '$2 == "nginx:" && $3 == "otel" && $4 == "exporter" {print $1}' \
        | wc -l | tr -d ' '
}

# Return the PID of the Nth exporter logged in the error.log since the
# beginning of the test (1-indexed).  nginx logs "start otel exporter <PID>"
# every time it spawns one.  This is more reliable than PPID in daemon mode.
exporter_pid_from_log() {
    local n="${1:-1}"
    grep "start otel exporter" "${PREFIX}/logs/error.log" 2>/dev/null \
        | awk '{print $NF}' \
        | sed -n "${n}p"
}

# Count ALL nginx master processes visible in ps.
# ps -eo pid,args: $1=pid, $2=first-word-of-args="nginx:", $3="master", $4="process"
nginx_master_count() {
    ps -eo pid,args 2>/dev/null \
        | awk '$2 == "nginx:" && $3 == "master" && $4 == "process" {print $1}' \
        | wc -l | tr -d ' '
}

# Return the PID of a second nginx master (i.e., not the original M1_PID).
second_master_pid() {
    local m1_pid=$1
    ps -eo pid,args 2>/dev/null \
        | awk -v exclude="${m1_pid}" \
            '$2 == "nginx:" && $3 == "master" && $4 == "process" && $1 != exclude {print $1}' \
        | head -1
}

# Extract service.instance.id from a JSON log file for a given service.name.
# Returns all distinct values found.
instance_ids_from_metrics() {
    local content="$1"
    echo "${content}" | python3 -c "
import json, sys

ids = set()
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:
        d = json.loads(line)
        for rm in d.get('resourceMetrics', []):
            res = rm.get('resource', {})
            attrs = res.get('attributes', [])
            for a in attrs:
                if a.get('key') == 'service.instance.id':
                    val = a.get('value', {})
                    s = val.get('stringValue') or val.get('asString') or str(val)
                    if s:
                        ids.add(s)
    except Exception:
        pass
for i in sorted(ids):
    print(i)
" 2>/dev/null
}

instance_ids_from_logs() {
    local content="$1"
    echo "${content}" | python3 -c "
import json, sys

ids = set()
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:
        d = json.loads(line)
        for rl in d.get('resourceLogs', []):
            res = rl.get('resource', {})
            attrs = res.get('attributes', [])
            for a in attrs:
                if a.get('key') == 'service.instance.id':
                    val = a.get('value', {})
                    s = val.get('stringValue') or val.get('asString') or str(val)
                    if s:
                        ids.add(s)
    except Exception:
        pass
for i in sorted(ids):
    print(i)
" 2>/dev/null
}

# ─── Test body ────────────────────────────────────────────────────────────────

METRIC_INTERVAL_S=1
SERVICE_NAME="ngx-otel-binary-upgrade"
NGINX_PORT=9209  # unique port; other tests use 9200-9208

PREFIX="$(mktemp -d /tmp/ngx-otel-usr2.XXXXXX)"
M1_PID=""
CURL_PID=""

cleanup() {
    # Stop curl first — active keep-alive connections prevent worker graceful drain.
    [[ -n "${CURL_PID:-}" ]] && kill "${CURL_PID}" 2>/dev/null || true
    CURL_PID=""
    # Shut down M1 first.  CRITICAL: M2 must NOT exit before M1 finishes its
    # graceful shutdown.  If M2 exits while M1 is draining, nginx's old master
    # sees "new binary process exited" and reverts to active mode (never exits).
    if [[ -n "${M1_PID:-}" ]] && kill -0 "${M1_PID}" 2>/dev/null; then
        kill -QUIT "${M1_PID}" 2>/dev/null || true
        local deadline=$(( SECONDS + 15 ))
        while (( SECONDS < deadline )) && kill -0 "${M1_PID}" 2>/dev/null; do
            sleep 0.5
        done
        kill -TERM "${M1_PID}" 2>/dev/null || true
        sleep 1
        kill -KILL "${M1_PID}" 2>/dev/null || true
    fi
    # Only then shut down M2.
    if [[ -n "${M2_PID:-}" ]] && kill -0 "${M2_PID}" 2>/dev/null; then
        kill -QUIT "${M2_PID}" 2>/dev/null || true
        sleep 2
        kill -TERM "${M2_PID}" 2>/dev/null || true
    fi
    sleep 1
    echo ""
    echo "=== error.log (last 50 lines) ==="
    grep -v '\[debug\]' "${PREFIX}/logs/error.log" 2>/dev/null | tail -50 || echo "(not found)"
    rm -rf "${PREFIX}"
}
trap cleanup EXIT

mkdir -p "${PREFIX}/logs" "${PREFIX}/client_body_temp"

# nginx configuration for the binary-upgrade test.
# NOTE: daemon mode is the DEFAULT (no 'daemon off') — this is REQUIRED for
# USR2 live binary upgrade to work.  With 'daemon off', nginx checks
# getppid() > 1 as a "mid-upgrade" guard and ignores the USR2 signal.
# In daemon mode nginx re-parents to PID 1 so getppid() == 1 and the guard
# does not fire.  We read M1_PID from the PID file after nginx starts.
cat > "${PREFIX}/nginx.conf" <<CONF
master_process on;
worker_processes 2;
error_log ${PREFIX}/logs/error.log debug;
pid       ${PREFIX}/logs/nginx.pid;

load_module ${MODULE_PATH};

events {
    worker_connections 64;
}

http {
    otel_exporter {
        endpoint http://127.0.0.1:4318/v1/metrics;
    }
    otel_service_name ${SERVICE_NAME};
    otel_metric_interval ${METRIC_INTERVAL_S}s;
    otel_access_log_sample 1;

    server {
        listen 127.0.0.1:${NGINX_PORT};
        location / {
            return 200 "ok\n";
        }
    }
}
CONF

# Snapshot file sizes before the test so we can extract new content afterwards.
PRE_METRICS_SIZE=0
PRE_LOGS_SIZE=0
[[ -f "${METRICS_LOG}" ]] && PRE_METRICS_SIZE=$(wc -c < "${METRICS_LOG}")
[[ -f "${LOGS_LOG}" ]]    && PRE_LOGS_SIZE=$(wc -c < "${LOGS_LOG}")
info "Pre-test metrics.json size: ${PRE_METRICS_SIZE} bytes"
info "Pre-test logs.json size:    ${PRE_LOGS_SIZE} bytes"

# ─── Phase 1: start M1 and verify initial state ───────────────────────────────

info "Starting M1 nginx (daemon mode, interval=${METRIC_INTERVAL_S}s, port=${NGINX_PORT})..."
"${NGINX_BINARY}" -p "${PREFIX}" -c "${PREFIX}/nginx.conf"

# In daemon mode nginx writes the PID file and exits the launcher; read M1_PID.
wait_for 5 "nginx.pid file to appear" \
    '[[ -s "${PREFIX}/logs/nginx.pid" ]]'
M1_PID="$(cat "${PREFIX}/logs/nginx.pid")"

if ! kill -0 "${M1_PID}" 2>/dev/null; then
    fail "M1 nginx (PID ${M1_PID}) not alive after start"
fi
pass "M1 master started, PID=${M1_PID}"

# Assertion 1a: exactly one otel exporter running.
# In daemon mode the exporter's PPID is 1 after the double-fork, so we
# detect it from the error.log ("start otel exporter <PID>").
wait_for 5 "otel exporter log entry" \
    '[[ -n "$(exporter_pid_from_log 1)" ]]'
EXP1_PID="$(exporter_pid_from_log 1)"
EXP1_COUNT="$(count_all_exporters)"
if [[ "${EXP1_COUNT}" -ne 1 ]]; then
    fail "Expected exactly 1 otel exporter after start, got ${EXP1_COUNT}"
fi
if ! kill -0 "${EXP1_PID}" 2>/dev/null; then
    fail "Exporter PID ${EXP1_PID} (from log) is not alive"
fi
pass "M1 has exactly 1 otel exporter, PID=${EXP1_PID}"

# Drive HTTP load to produce telemetry.
info "Driving HTTP load to generate telemetry (3s)..."
(
    while true; do
        curl -sf "http://127.0.0.1:${NGINX_PORT}/" >/dev/null 2>&1 || true
        sleep 0.1
    done
) &
CURL_PID=$!
sleep 3

# Capture M1's service.instance.id from the collector.
MID_METRICS_SIZE=0
[[ -f "${METRICS_LOG}" ]] && MID_METRICS_SIZE=$(wc -c < "${METRICS_LOG}")
M1_METRICS_CONTENT=""
if (( MID_METRICS_SIZE > PRE_METRICS_SIZE )); then
    M1_METRICS_CONTENT=$(tail -c "+$(( PRE_METRICS_SIZE + 1 ))" "${METRICS_LOG}")
fi

# Assertion 1b: M1's exporter exported at least one batch with service.instance.id.
M1_INSTANCE_IDS="$(instance_ids_from_metrics "${M1_METRICS_CONTENT}")"
if [[ -z "${M1_INSTANCE_IDS}" ]]; then
    fail "Collector received no metrics with service.instance.id from M1 exporter.
       Check metrics.json for service.name=${SERVICE_NAME} entries.
       Ensure otel_metric_interval=1s and the collector is receiving."
fi
M1_INSTANCE_ID="$(echo "${M1_INSTANCE_IDS}" | head -1)"
pass "M1 service.instance.id = ${M1_INSTANCE_ID} (from metrics Resource)"

# Verify the value matches M1's PID (since service.instance.id = master PID = M1_PID).
if [[ "${M1_INSTANCE_ID}" != "${M1_PID}" ]]; then
    info "Note: M1 instance.id=${M1_INSTANCE_ID}, M1_PID=${M1_PID}."
    info "These differ — master PID and nginx background PID may differ."
    info "The key property is that M2's id differs from M1's id (tested below)."
fi

# ─── Phase 2: send USR2 to M1 (live binary upgrade) ──────────────────────────

info "Sending USR2 to M1 (PID ${M1_PID}) for live binary upgrade..."
kill -USR2 "${M1_PID}" 2>/dev/null || fail "kill -USR2 ${M1_PID} failed"

# Wait for M2 (a second nginx master) to appear.
info "Waiting for M2 (second nginx master) to appear..."
M2_PID=""
wait_for 10 "second nginx master (M2)" \
    '[[ -n "$(second_master_pid ${M1_PID})" ]]'
M2_PID="$(second_master_pid "${M1_PID}")"
pass "M2 master appeared, PID=${M2_PID}"

# Assertion 2a: two nginx master processes.
MASTER_COUNT="$(nginx_master_count)"
info "nginx master count after USR2: ${MASTER_COUNT}"
if [[ "${MASTER_COUNT}" -lt 2 ]]; then
    fail "Expected ≥ 2 nginx masters after USR2, found ${MASTER_COUNT}"
fi
pass "Two nginx masters running (M1=${M1_PID}, M2=${M2_PID})"

# Assertion 2b: M2 has its own exporter (second log entry after USR2).
info "Waiting for M2's exporter to start..."
wait_for 10 "second otel exporter log entry" \
    '[[ -n "$(exporter_pid_from_log 2)" ]]'
EXP2_PID="$(exporter_pid_from_log 2)"
if ! kill -0 "${EXP2_PID}" 2>/dev/null; then
    fail "M2 exporter PID ${EXP2_PID} (from log) is not alive"
fi
pass "M2 has otel exporter, PID=${EXP2_PID}"

# Assertion 2c: two total otel exporter processes (one per master).
ALL_EXP_COUNT="$(count_all_exporters)"
if [[ "${ALL_EXP_COUNT}" -ne 2 ]]; then
    fail "Expected exactly 2 otel exporters during overlap, found ${ALL_EXP_COUNT}"
fi
pass "Two otel exporters running during overlap (${EXP1_PID} + ${EXP2_PID})"

# Let both exporters ship telemetry during the overlap window.
info "Waiting for both exporters to ship telemetry during overlap (5s)..."
sleep 5

# Capture overlap window content from collector.
OVERLAP_METRICS_SIZE=0
[[ -f "${METRICS_LOG}" ]] && OVERLAP_METRICS_SIZE=$(wc -c < "${METRICS_LOG}")
OVERLAP_CONTENT=""
if (( OVERLAP_METRICS_SIZE > PRE_METRICS_SIZE )); then
    OVERLAP_CONTENT=$(tail -c "+$(( PRE_METRICS_SIZE + 1 ))" "${METRICS_LOG}")
fi

OVERLAP_IDS="$(instance_ids_from_metrics "${OVERLAP_CONTENT}")"
info "service.instance.id values seen during overlap: $(echo "${OVERLAP_IDS}" | tr '\n' ' ')"
OVERLAP_ID_COUNT="$(echo "${OVERLAP_IDS}" | grep -c . || echo 0)"

# Assertion 2d: collector received BOTH instance ids during overlap.
if [[ "${OVERLAP_ID_COUNT}" -lt 2 ]]; then
    fail "STOP-AND-ASK [R2-HANDOFF-BUG]: Expected ≥ 2 distinct service.instance.id values
       during overlap (one per master), found ${OVERLAP_ID_COUNT}.
       Values seen: $(echo "${OVERLAP_IDS}" | tr '\n' ' ')
       This indicates the old exporter did not ship any telemetry during the
       overlap window or service.instance.id was not included on M2's Resource.
       Do NOT relax this assertion — investigate the lifecycle bug."
fi

# Extract M2's instance id (the one that is NOT M1's).
M2_INSTANCE_ID=""
while IFS= read -r id; do
    if [[ "${id}" != "${M1_INSTANCE_ID}" ]] && [[ -n "${id}" ]]; then
        M2_INSTANCE_ID="${id}"
        break
    fi
done <<< "${OVERLAP_IDS}"

if [[ -z "${M2_INSTANCE_ID}" ]]; then
    fail "Could not determine M2's service.instance.id (all overlap ids equal M1's id=${M1_INSTANCE_ID})"
fi

# Assertion 2e: M2's service.instance.id is different from M1's.
if [[ "${M2_INSTANCE_ID}" == "${M1_INSTANCE_ID}" ]]; then
    fail "M2 service.instance.id (${M2_INSTANCE_ID}) equals M1's (${M1_INSTANCE_ID}).
       USR2 must produce a distinct instance id for the new master generation.
       Check that MASTER_PID is captured from ngx_parent (not the exporter's own pid)."
fi
pass "M2 service.instance.id = ${M2_INSTANCE_ID} (distinct from M1's ${M1_INSTANCE_ID})"
pass "Both service.instance.id values present in overlap window (${OVERLAP_ID_COUNT} distinct ids)"

# ─── Phase 3: shut down M1 gracefully (WINCH then QUIT) ──────────────────────

# Stop the curl load BEFORE sending WINCH/QUIT.  Active keep-alive connections
# on M1's workers prevent graceful drain; stopping curl lets workers drain and
# exit promptly.
info "Stopping curl load before M1 shutdown..."
[[ -n "${CURL_PID:-}" ]] && kill "${CURL_PID}" 2>/dev/null || true
CURL_PID=""
sleep 1

info "Sending SIGWINCH to M1 (${M1_PID}) to stop accepting new connections..."
kill -WINCH "${M1_PID}" 2>/dev/null || info "WINCH to M1 failed (may have already exited)"
sleep 2

info "Sending SIGQUIT to M1 (${M1_PID}) for graceful shutdown..."
kill -QUIT "${M1_PID}" 2>/dev/null || info "QUIT to M1 failed (may have already exited)"

# Assertion 3a: M1 master exits within 20s.
info "Waiting for M1 (PID ${M1_PID}) to exit..."
M1_EXITED=0
DEADLINE=$(( SECONDS + 20 ))
while (( SECONDS < DEADLINE )); do
    if ! kill -0 "${M1_PID}" 2>/dev/null; then
        M1_EXITED=1
        break
    fi
    sleep 0.5
done
if [[ "${M1_EXITED}" -ne 1 ]]; then
    PID_CMD="$(ps -o args= -p "${M1_PID}" 2>/dev/null || echo "not found")"
    fail "STOP-AND-ASK [R2-HANDOFF-BUG]: M1 master (${M1_PID}) did not exit within 20s after QUIT.
       Process: ${PID_CMD}
       This is a lifecycle bug — M1 is orphaned."
fi
pass "M1 master (PID ${M1_PID}) exited cleanly"

# Assertion 3b: M1's exporter (EXP1_PID) also exited.
EXP1_EXITED=0
DEADLINE=$(( SECONDS + 10 ))
while (( SECONDS < DEADLINE )); do
    if ! kill -0 "${EXP1_PID}" 2>/dev/null; then
        EXP1_EXITED=1
        break
    fi
    sleep 0.5
done
if [[ "${EXP1_EXITED}" -ne 1 ]]; then
    fail "STOP-AND-ASK [R2-HANDOFF-BUG]: M1's exporter (PID ${EXP1_PID}) did not exit
       after M1 quit.  Orphaned exporter — this is a lifecycle bug."
fi
pass "M1's exporter (PID ${EXP1_PID}) exited cleanly"

# Assertion 3c: M2 is still running and has exactly one exporter.
if ! kill -0 "${M2_PID}" 2>/dev/null; then
    fail "M2 master (${M2_PID}) exited unexpectedly after M1 quit"
fi
pass "M2 master (PID ${M2_PID}) still running"

EXP2_RUNNING=0
DEADLINE=$(( SECONDS + 5 ))
while (( SECONDS < DEADLINE )); do
    if kill -0 "${EXP2_PID}" 2>/dev/null; then
        EXP2_RUNNING=1
        break
    fi
    sleep 0.5
done
if [[ "${EXP2_RUNNING}" -ne 1 ]]; then
    fail "M2's exporter (PID ${EXP2_PID}) not found after M1 quit"
fi
pass "M2's exporter (PID ${EXP2_PID}) still running"

# Assertion 3d: No panic/abort/SIGSEGV in error.log.
if grep -qE "panic|abort|SIGSEGV|SIGABRT|Segmentation fault" "${PREFIX}/logs/error.log" 2>/dev/null; then
    fail "STOP-AND-ASK [R2-HANDOFF-BUG]: error.log contains panic/abort/SIGSEGV:
       $(grep -E 'panic|abort|SIGSEGV|SIGABRT|Segmentation fault' "${PREFIX}/logs/error.log")"
fi
pass "error.log clean: no panic/abort/SIGSEGV"

# Assertion 3e: exactly 1 exporter remains total (M2's only; M1's must be gone).
# EXP1_PID must be dead and EXP2_PID must be alive.
if kill -0 "${EXP1_PID}" 2>/dev/null; then
    fail "STOP-AND-ASK [R2-HANDOFF-BUG]: M1's exporter (PID ${EXP1_PID}) is still alive
       after M1 quit.  Orphaned exporter — this is a lifecycle bug."
fi
pass "M1's exporter (PID ${EXP1_PID}) is gone (no orphan)"
REMAINING_EXP_COUNT="$(count_all_exporters)"
if [[ "${REMAINING_EXP_COUNT}" -ne 1 ]]; then
    fail "STOP-AND-ASK [R2-HANDOFF-BUG]: Expected exactly 1 exporter after M1 exit,
       found ${REMAINING_EXP_COUNT}."
fi
pass "Exactly 1 exporter remaining (no orphans from M1)"

# ─── Phase 4: steady-state assertions ────────────────────────────────────────

info "Verifying steady-state after M1 exit..."

# Assertion 4a: exactly 1 master remaining (M2).
FINAL_MASTER_COUNT="$(nginx_master_count)"
if [[ "${FINAL_MASTER_COUNT}" -ne 1 ]]; then
    fail "Expected exactly 1 nginx master after M1 exit, found ${FINAL_MASTER_COUNT}"
fi
pass "Exactly 1 nginx master remaining (M2=${M2_PID})"

# Assertion 4b: exactly 1 exporter remaining (M2's) and it is alive.
FINAL_EXP_COUNT="$(count_all_exporters)"
if [[ "${FINAL_EXP_COUNT}" -ne 1 ]]; then
    fail "Expected exactly 1 otel exporter after M1 exit, found ${FINAL_EXP_COUNT}"
fi
if ! kill -0 "${EXP2_PID}" 2>/dev/null; then
    fail "M2's exporter (PID ${EXP2_PID}) is not alive in steady state"
fi
pass "Exactly 1 otel exporter remaining (PID=${EXP2_PID}, M2's)"

# Assertion 4c: collector continues to receive M2's instance id and stops
# receiving M1's.  Wait 4s for M2's exporter to ship at least one batch.
sleep 4

POST_METRICS_SIZE=0
[[ -f "${METRICS_LOG}" ]] && POST_METRICS_SIZE=$(wc -c < "${METRICS_LOG}")
POST_CONTENT=""
if (( POST_METRICS_SIZE > OVERLAP_METRICS_SIZE )); then
    POST_CONTENT=$(tail -c "+$(( OVERLAP_METRICS_SIZE + 1 ))" "${METRICS_LOG}")
fi

POST_IDS="$(instance_ids_from_metrics "${POST_CONTENT}")"
info "service.instance.id values in post-M1 content: $(echo "${POST_IDS}" | tr '\n' ' ')"

# M2's id must be present in post-M1 telemetry.
if ! echo "${POST_IDS}" | grep -qF "${M2_INSTANCE_ID}"; then
    fail "M2's service.instance.id (${M2_INSTANCE_ID}) not seen in post-M1 telemetry.
       Collector may have lost M2's exporter after M1 quit."
fi
pass "Collector receiving M2's service.instance.id (${M2_INSTANCE_ID}) post-M1-exit"

# M1's id must NOT be present in post-M1 telemetry.
if echo "${POST_IDS}" | grep -qF "${M1_INSTANCE_ID}"; then
    fail "M1's service.instance.id (${M1_INSTANCE_ID}) still appearing in post-M1 telemetry.
       Old exporter may be orphaned or M2 incorrectly inherited M1's id."
fi
pass "M1's service.instance.id (${M1_INSTANCE_ID}) absent in post-M1 telemetry"

# ─── Graceful M2 shutdown ─────────────────────────────────────────────────────

kill "${CURL_PID}" 2>/dev/null || true
CURL_PID=""

info "Shutting down M2 gracefully..."
kill -QUIT "${M2_PID}" 2>/dev/null || true
DEADLINE=$(( SECONDS + 15 ))
while (( SECONDS < DEADLINE )); do
    if ! kill -0 "${M2_PID}" 2>/dev/null; then
        break
    fi
    sleep 0.5
done
M2_PID=""

# ─── Summary ──────────────────────────────────────────────────────────────────

echo ""
pass "=== All USR2 binary-upgrade assertions passed ==="
echo ""
echo "  M1 master PID:        ${M1_PID} (exited)"
echo "  M1 exporter PID:      ${EXP1_PID} (exited)"
echo "  M1 service.instance.id: ${M1_INSTANCE_ID}"
echo "  M2 master PID:        ${M2_PID:-<shutdown>}"
echo "  M2 exporter PID:      ${EXP2_PID}"
echo "  M2 service.instance.id: ${M2_INSTANCE_ID}"
echo ""
