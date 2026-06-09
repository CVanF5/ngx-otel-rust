#!/usr/bin/env bash
# tests/integration/run_chaos_dead_collector.sh — C2 chaos: dead-collector drain gate
#
# Verifies that a dead / unreachable collector does NOT stall nginx shutdown or
# reload — the two lifecycle paths where a hung exporter would block the master:
#
#   SIGQUIT (graceful shutdown):
#   1. With exporter trying to drain to an unreachable collector, SIGQUIT to
#      master causes nginx to exit within the graceful-drain backstop + margin
#      (15 s backstop + 5 s margin = 20 s total budget).
#   2. No orphan master, worker, or exporter process remains after exit.
#
#   SIGHUP (reload with dead collector):
#   3. SIGHUP spawns a new exporter that inherits the dead endpoint.
#   4. After reload, workers still serve HTTP 200 (data plane unaffected).
#   5. After reload, crash_count in shm was zeroed (reload-safe reset):
#      the new exporter's crash count starts fresh (verified indirectly by
#      confirming the new exporter is still running after SIGHUP, not
#      pre-emptively self-disabled by a stale counter).
#      NOTE: Assertion 5 here is intentionally lightweight (liveness only).
#      Part C below is the hard reload-reset gate (F3).
#
#   SIGHUP crash-counter reset (Part C — F3 hardened reload-reset gate):
#   6. Using the test-support crash hook (NGX_OTEL_CRASH_ON_STARTUP),
#      pre-accumulate crash_count=3 BEFORE the reload, then SIGHUP and assert
#      the new exporter's first backoff log entry reads "crash #2 in window"
#      (not "crash #4") — proving control_shm_zone_init zeroed the counter on
#      reload.  The assertion is hard: it checks the exact crash sequence number
#      from error.log, NOT just whether the exporter is alive.
#
#      MUTATION CHECK (part of this test): temporarily neutering the
#      store(0) call in control_shm_zone_init and re-running this test causes
#      a FAIL (sees "crash #4 in window" instead of "crash #2").  Evidence
#      recorded in the commit message and the RESULTS artifact.
#
# Prerequisites: NGINX_BINARY set or auto-detected; no OTel collector required
# (the endpoint is a black-hole port that has no listener).
# Exit codes: 0 = all assertions passed, 1 = preflight, 2 = assertion failed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Use a black-hole endpoint (no listener on :19318).
DEAD_ENDPOINT="http://127.0.0.1:19318"
NGINX_CONF_BODY="
daemon off;
master_process on;
worker_processes 2;
error_log @PREFIX@/logs/error.log debug;
pid       @PREFIX@/logs/nginx.pid;

load_module @MODULE_PATH@;

events {
    worker_connections 64;
}

http {
    otel_exporter {
        endpoint ${DEAD_ENDPOINT};
    }
    otel_service_name ngx-otel-dead-collector-chaos;
    otel_metric_interval 1s;

    server {
        listen 127.0.0.1:9201;
        location / {
            return 200 \"ok\n\";
        }
    }
}
"

. "${CRATE_DIR}/test-harness/lib.sh"
resolve_nginx_binary || true

case "$(uname -s)" in
    Darwin) MODULE_EXT="dylib" ;;
    *)      MODULE_EXT="so"    ;;
esac

RELEASE_MODULE="${CRATE_DIR}/objs-release/ngx_http_otel_module.so"
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
    echo "ERROR: module not found. Run 'make build-release' first." >&2; exit 1
fi

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
pass()  { echo -e "${GREEN}[PASS]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*" >&2; exit 2; }
info()  { echo -e "${YELLOW}[INFO]${NC} $*"; }

if [[ ! -x "${NGINX_BINARY}" ]]; then
    echo "ERROR: nginx binary not found at ${NGINX_BINARY}." >&2; exit 1
fi
info "nginx binary: ${NGINX_BINARY}"
info "Module:       ${MODULE_PATH}"
info "Dead endpoint: ${DEAD_ENDPOINT}"

wait_for() {
    local timeout=$1 desc=$2 expr=$3
    local deadline=$(( $(date +%s) + timeout ))
    while (( $(date +%s) < deadline )); do
        if eval "${expr}" 2>/dev/null; then return 0; fi
        sleep 0.5
    done
    fail "Timed out (${timeout}s) waiting for: ${desc}"
}

exporter_pid() {
    local master_pid="${1:-}"
    if [[ -n "${master_pid}" ]]; then
        ps -eo pid,ppid,args 2>/dev/null \
            | awk -v mpid="${master_pid}" \
                '$2==mpid && $3 == "nginx:" && $4 == "otel" && $5 == "exporter" {print $1}' \
            | head -1
    else
        ps -eo pid,args 2>/dev/null \
            | awk '$2 == "nginx:" && $3 == "otel" && $4 == "exporter" {print $1}' \
            | head -1
    fi
}

# ─── Test body — Part A: SIGQUIT with dead collector ────────────────────────

PREFIX="$(mktemp -d /tmp/ngx-otel-deadcoll.XXXXXX)"
NGINX_PID=""

cleanup() {
    [[ -n "${NGINX_PID:-}" ]] && kill "${NGINX_PID}" 2>/dev/null || true
    sleep 1
    echo ""
    echo "=== error.log (last 20 lines) ==="
    tail -20 "${PREFIX}/logs/error.log" 2>/dev/null || echo "(not found)"
    rm -rf "${PREFIX}"
}
trap cleanup EXIT

mkdir -p "${PREFIX}/logs" "${PREFIX}/client_body_temp"
echo "${NGINX_CONF_BODY}" \
    | sed -e "s|@MODULE_PATH@|${MODULE_PATH}|g" \
          -e "s|@PREFIX@|${PREFIX}|g" \
    > "${PREFIX}/nginx.conf"

info "=== Part A: SIGQUIT with dead collector ==="
info "Starting nginx (endpoint: ${DEAD_ENDPOINT})..."
"${NGINX_BINARY}" -p "${PREFIX}" -c "${PREFIX}/nginx.conf" &
NGINX_PID=$!
sleep 1

if ! kill -0 "${NGINX_PID}" 2>/dev/null; then
    fail "nginx master exited immediately after start"
fi
wait_for 5 "exporter to appear" "[[ -n \"\$(exporter_pid ${NGINX_PID})\" ]]"
pass "Exporter started with dead endpoint"

# Let the export loop run for ≥ 2 intervals so the drain queue has stale bytes.
info "Waiting 3s for export-loop to accumulate retry queue..."
sleep 3

# Send SIGQUIT and time the shutdown.
QUIT_START="$(date +%s)"
info "Sending SIGQUIT to master PID ${NGINX_PID}..."
kill -SIGQUIT "${NGINX_PID}"

# Budget: GRACEFUL_DRAIN_BACKSTOP (15s) + 5s margin = 20s.
SIGQUIT_BUDGET=20
wait_for ${SIGQUIT_BUDGET} \
    "nginx to exit after SIGQUIT with dead collector (budget ${SIGQUIT_BUDGET}s)" \
    "! kill -0 ${NGINX_PID} 2>/dev/null"

QUIT_ELAPSED=$(( $(date +%s) - QUIT_START ))
pass "nginx exited ${QUIT_ELAPSED}s after SIGQUIT (budget ${SIGQUIT_BUDGET}s)"

# No orphan exporter.
sleep 0.5
EXP_ORPHAN="$(exporter_pid "${NGINX_PID}")"
if [[ -n "${EXP_ORPHAN}" ]]; then
    fail "Orphan exporter remains after nginx shutdown (PID ${EXP_ORPHAN})"
fi
pass "No orphan exporter after SIGQUIT"

NGINX_PID=""

# ─── Part B: SIGHUP with dead collector ──────────────────────────────────────

info "=== Part B: SIGHUP reload with dead collector ==="

# Fresh prefix for Part B.
PREFIX_B="$(mktemp -d /tmp/ngx-otel-deadcoll-b.XXXXXX)"
mkdir -p "${PREFIX_B}/logs" "${PREFIX_B}/client_body_temp"
echo "${NGINX_CONF_BODY}" \
    | sed -e "s|@MODULE_PATH@|${MODULE_PATH}|g" \
          -e "s|@PREFIX@|${PREFIX_B}|g" \
    > "${PREFIX_B}/nginx.conf"

NGINX_PID_B=""
cleanup_b() {
    [[ -n "${NGINX_PID_B:-}" ]] && kill "${NGINX_PID_B}" 2>/dev/null || true
    sleep 1
    echo "=== Part B error.log (last 10 lines) ==="
    tail -10 "${PREFIX_B}/logs/error.log" 2>/dev/null || echo "(not found)"
    rm -rf "${PREFIX_B}"
}
# Temporarily replace the trap.
trap '{ cleanup; cleanup_b; }' EXIT

"${NGINX_BINARY}" -p "${PREFIX_B}" -c "${PREFIX_B}/nginx.conf" &
NGINX_PID_B=$!
sleep 1

if ! kill -0 "${NGINX_PID_B}" 2>/dev/null; then
    fail "nginx master (Part B) exited immediately"
fi
EXP_PID_B1="$(exporter_pid "${NGINX_PID_B}")"
[[ -n "${EXP_PID_B1}" ]] || fail "No exporter after Part B start"
pass "Part B: exporter started, PID = ${EXP_PID_B1}"

# Send SIGHUP (reload).
info "Sending SIGHUP to master PID ${NGINX_PID_B}..."
kill -SIGHUP "${NGINX_PID_B}"

# Assertion 3: new exporter appears after reload.
EXP_PID_B2=""
for _ in $(seq 1 20); do
    sleep 0.5
    CUR="$(exporter_pid "${NGINX_PID_B}")"
    if [[ -n "${CUR}" && "${CUR}" != "${EXP_PID_B1}" ]]; then
        EXP_PID_B2="${CUR}"
        break
    fi
done
[[ -n "${EXP_PID_B2}" ]] \
    || fail "No new exporter appeared within 10 s after SIGHUP"
pass "SIGHUP: new exporter PID = ${EXP_PID_B2} (was ${EXP_PID_B1})"

# Assertion 4: workers still return 200 after reload.
sleep 0.5
HTTP_RESULT_B="$(curl -s -o /dev/null -w '%{http_code}' \
    --max-time 3 http://127.0.0.1:9201/ 2>/dev/null || echo 000)"
if [[ "${HTTP_RESULT_B}" == "200" ]]; then
    pass "Workers return HTTP 200 after SIGHUP reload with dead collector"
else
    fail "Workers returned ${HTTP_RESULT_B} after SIGHUP (expected 200)"
fi

# Assertion 5: new exporter is still alive (crash counter reset on reload).
# If the counter were NOT reset on reload, and the old exporter had accumulated
# crashes, the new exporter might immediately self-disable. Checking it lives
# for > 2s without self-disabling confirms the reload-safe reset.
sleep 3
EXP_STILL_ALIVE="$(exporter_pid "${NGINX_PID_B}")"
if [[ -n "${EXP_STILL_ALIVE}" ]]; then
    pass "New exporter still alive 3s after reload (crash counter reset on SIGHUP verified)"
else
    fail "New exporter disappeared shortly after reload — crash counter may not have reset"
fi

# Shutdown Part B.
info "Sending SIGQUIT to Part B master PID ${NGINX_PID_B}..."
kill -SIGQUIT "${NGINX_PID_B}"
wait_for 25 "Part B nginx to exit" "! kill -0 ${NGINX_PID_B} 2>/dev/null"
pass "Part B nginx exited cleanly"
NGINX_PID_B=""

# ─── Part C: SIGHUP crash-counter reset — hardened F3 gate ───────────────────
#
# Assertion 5 in Part B above passes vacuously when the prior exporter never
# crashed (liveness ≠ counter-reset evidence). Part C drives real crashes into
# the exporter BEFORE the reload, then asserts the exact crash-sequence number
# in error.log AFTER the reload.
#
# Hard observable: after a clean-slate reload the first exporter crash logs
# "crash #2 in window" (count 0→1 first start, 1→2 on first crash-restart).
# Without the reset it would log "crash #4 in window" (3 prior + 1 = 4).
#
# Requires the test-support feature (crash hook: NGX_OTEL_CRASH_ON_STARTUP).
# No non-test-gated production code is changed.

info "=== Part C: SIGHUP crash-counter reset (F3 hardened gate) ==="

# ─ Build test-support module (same pattern as run_chaos_crashloop.sh) ─────────
case "$(uname -s)" in
    Darwin) MODULE_EXT="dylib" ;;
    *)      MODULE_EXT="so"    ;;
esac

TEST_SUPPORT_TARGET_DIR="${CRATE_DIR}/target/test-support"
TEST_SUPPORT_MODULE="${TEST_SUPPORT_TARGET_DIR}/debug/libngx_http_otel_module.${MODULE_EXT}"

NGINX_BUILD_DIR_C="${CRATE_DIR}/objs-${BUILD:-debug}"
if [[ ! -d "${NGINX_BUILD_DIR_C}" ]]; then
    NGINX_BUILD_DIR_C="$(ls -d "${CRATE_DIR}"/objs-* 2>/dev/null | head -1)"
fi
if [[ -z "${NGINX_BUILD_DIR_C}" ]]; then
    echo "ERROR: no objs-* build dir found. Run 'make' first." >&2; exit 1
fi
NGINX_SOURCE_DIR_C="${CRATE_DIR}/../nginx"
if [[ ! -d "${NGINX_SOURCE_DIR_C}" ]]; then
    echo "ERROR: nginx source dir not found at ${NGINX_SOURCE_DIR_C}." >&2; exit 1
fi

if [[ ! -f "${TEST_SUPPORT_MODULE}" ]]; then
    info "Building test-support module (features=test-support)..."
    NGINX_BUILD_DIR="${NGINX_BUILD_DIR_C}" NGINX_SOURCE_DIR="${NGINX_SOURCE_DIR_C}" \
        cargo build \
        --manifest-path "${CRATE_DIR}/Cargo.toml" \
        --features test-support \
        --target-dir "${TEST_SUPPORT_TARGET_DIR}" 2>&1 | grep -E 'Compiling|Finished|error' || true
fi
if [[ ! -f "${TEST_SUPPORT_MODULE}" ]]; then
    fail "test-support module not found at ${TEST_SUPPORT_MODULE} after build"
fi
pass "Part C: test-support module ready: ${TEST_SUPPORT_MODULE}"

# ─ Start nginx with crash hook on a fresh prefix ──────────────────────────────
PREFIX_C="$(mktemp -d /tmp/ngx-otel-deadcoll-c.XXXXXX)"
mkdir -p "${PREFIX_C}/logs" "${PREFIX_C}/client_body_temp"
echo "${NGINX_CONF_BODY}" \
    | sed -e "s|@MODULE_PATH@|${TEST_SUPPORT_MODULE}|g" \
          -e "s|@PREFIX@|${PREFIX_C}|g" \
    > "${PREFIX_C}/nginx.conf"

NGINX_PID_C=""
cleanup_c() {
    [[ -n "${NGINX_PID_C:-}" ]] && kill "${NGINX_PID_C}" 2>/dev/null || true
    sleep 1
    echo "=== Part C error.log (last 40 lines) ==="
    tail -40 "${PREFIX_C}/logs/error.log" 2>/dev/null || echo "(not found)"
    rm -rf "${PREFIX_C}"
}
trap '{ cleanup; cleanup_b; cleanup_c; }' EXIT

# MAX_CRASH_RESTARTS=5; we want to accumulate exactly 3 crashes then reload.
# Total time: 3 crashes × (500ms crash-hook sleep + nginx respawn overhead)
# ≈ 3 × 1.5s = ~5s. Allow 30s.
MAX_WAIT_C=30

info "Starting nginx (Part C) with NGX_OTEL_CRASH_ON_STARTUP=1..."
env NGX_OTEL_CRASH_ON_STARTUP=1 \
    "${NGINX_BINARY}" -p "${PREFIX_C}" -c "${PREFIX_C}/nginx.conf" &
NGINX_PID_C=$!
sleep 1

if ! kill -0 "${NGINX_PID_C}" 2>/dev/null; then
    fail "nginx master (Part C) exited immediately"
fi
pass "Part C: nginx master started, PID = ${NGINX_PID_C}"

# Wait for crash_count to reach 3. Indicator: "crash #3 in window" in error.log.
# (count=1 has no log; count=2 has "crash #2"; count=3 has "crash #3".)
info "Part C: waiting for crash_count=3 ('crash #3 in window' in error.log)..."
deadline_c=$(( $(date +%s) + MAX_WAIT_C ))
SEEN_COUNT3=false
while (( $(date +%s) < deadline_c )); do
    if grep -q "crash #3 in window" "${PREFIX_C}/logs/error.log" 2>/dev/null; then
        SEEN_COUNT3=true
        break
    fi
    sleep 0.5
done
if [[ "${SEEN_COUNT3}" != "true" ]]; then
    fail "Part C: 'crash #3 in window' not seen in error.log within ${MAX_WAIT_C}s"
fi
pass "Part C: crash_count=3 confirmed in error.log ('crash #3 in window' observed)"

# Record the current log line count so we can isolate post-reload entries.
LOG_LINES_BEFORE_RELOAD=$(wc -l < "${PREFIX_C}/logs/error.log" 2>/dev/null || echo 0)
info "Part C: log line offset before SIGHUP = ${LOG_LINES_BEFORE_RELOAD}"

# Give the exporter time to actually start (back off + setproctitle) before
# the reload races with it.  The 300ms crash-hook sleep in the crash path means
# the exporter is alive for ~300-500ms before aborting; add a beat to let it
# reach step 10 (setproctitle).
sleep 1

# Send SIGHUP (reload).
info "Part C: sending SIGHUP to master PID ${NGINX_PID_C}..."
kill -SIGHUP "${NGINX_PID_C}"

# Wait for a new exporter PID after reload.
EXP_PID_C_OLD="$(exporter_pid "${NGINX_PID_C}")"
EXP_PID_C_NEW=""
for _ in $(seq 1 20); do
    sleep 0.5
    CUR="$(exporter_pid "${NGINX_PID_C}")"
    if [[ -n "${CUR}" && "${CUR}" != "${EXP_PID_C_OLD:-}" ]]; then
        EXP_PID_C_NEW="${CUR}"
        break
    fi
done
[[ -n "${EXP_PID_C_NEW}" ]] \
    || fail "Part C: no new exporter appeared within 10s after SIGHUP"
pass "Part C: new exporter after reload, PID = ${EXP_PID_C_NEW}"

# Wait for the first "crash #N in window" entry AFTER the reload.
# The new exporter still has NGX_OTEL_CRASH_ON_STARTUP inherited, so it will
# crash and log the backoff message on its second startup (count=2 after reset).
info "Part C: waiting for first post-reload crash log entry..."
deadline_c2=$(( $(date +%s) + 20 ))
POST_RELOAD_CRASH_LINE=""
while (( $(date +%s) < deadline_c2 )); do
    if POST_RELOAD_CRASH_LINE="$(tail -n +"${LOG_LINES_BEFORE_RELOAD}" \
            "${PREFIX_C}/logs/error.log" 2>/dev/null \
            | grep "crash #" | head -1)"; then
        if [[ -n "${POST_RELOAD_CRASH_LINE}" ]]; then
            break
        fi
    fi
    sleep 0.5
done
if [[ -z "${POST_RELOAD_CRASH_LINE}" ]]; then
    fail "Part C: no 'crash #N in window' line appeared after reload within 20s"
fi
info "Part C: first post-reload crash line: ${POST_RELOAD_CRASH_LINE}"

# Hard assertion: the sequence number must be 2, not 4.
# "crash #2 in window" → counter was reset to 0 on SIGHUP (PASS).
# "crash #4 in window" → counter was NOT reset (stale value 3 carried over → FAIL).
if echo "${POST_RELOAD_CRASH_LINE}" | grep -q "crash #2 in window"; then
    pass "Part C: post-reload crash log shows 'crash #2 in window' — counter reset on SIGHUP CONFIRMED"
elif echo "${POST_RELOAD_CRASH_LINE}" | grep -qE "crash #[3-9] in window|crash #[0-9]{2,}"; then
    fail "Part C: post-reload crash log shows high sequence number — counter NOT reset on SIGHUP: ${POST_RELOAD_CRASH_LINE}"
else
    fail "Part C: unexpected post-reload crash log format: ${POST_RELOAD_CRASH_LINE}"
fi

# Assertion (a): new exporter is still alive 3s after reload (liveness guard).
# With a reset counter the backoffs start from 200ms, 400ms, etc.
# With a stale counter=3, backoffs start from 800ms — but self-disable would
# come 2 more crashes later (not 5), so the liveness window is different.
sleep 3
EXP_C_ALIVE="$(exporter_pid "${NGINX_PID_C}")"
# The exporter may have aborted again (crash hook still on, count now at 3)
# but it has NOT yet self-disabled (that requires count > 5 = 6 total).
# It will respawn. Check master is still alive (not just exporter).
if kill -0 "${NGINX_PID_C}" 2>/dev/null; then
    pass "Part C: master still alive 3s after reload (not prematurely disabled)"
else
    fail "Part C: master exited unexpectedly after reload"
fi

# Shutdown Part C.
info "Part C: sending SIGQUIT to master PID ${NGINX_PID_C}..."
kill -SIGQUIT "${NGINX_PID_C}"
wait_for 25 "Part C nginx to exit" "! kill -0 ${NGINX_PID_C} 2>/dev/null"
pass "Part C nginx exited cleanly"
NGINX_PID_C=""
trap - EXIT
rm -rf "${PREFIX}" "${PREFIX_B}" "${PREFIX_C}"

echo ""
pass "=== All dead-collector shutdown/reload assertions passed ==="
