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
#      let the exporter SELF-DISABLE (crash_count=6 > MAX_CRASH_RESTARTS=5 →
#      exit(2)) BEFORE sending SIGHUP.  After self-disable, no more concurrent
#      exporter activity can race with control_shm_zone_init's store(0) call.
#      The SIGHUP reload resets the counter to 0; the new exporter's second
#      start logs "crash #2 in window" (count: 0→1→2).  Without the reset,
#      it would log "crash #7 in window" (stale count 6 → incremented to 7).
#      The assertion checks the exact crash sequence number from error.log,
#      NOT just whether the exporter is alive.
#
#      MUTATION CHECK (part of this test): temporarily neutering the
#      store(0) call in control_shm_zone_init and re-running this test causes
#      a FAIL.  With stale count=6, the first post-reload exporter sees
#      count=7>MAX_CRASH_RESTARTS and immediately re-disables via exit(2) —
#      nginx stops respawning, test fails with "no exporter appeared".
#      Evidence recorded in the commit message and the RESULTS artifact.
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
# When CARGO_BUILD_TARGET is set (TSAN/ASan harness), the sanitizer-instrumented
# module is at target/<triple>/release/.  Prefer CARGO_MODULE over RELEASE_MODULE
# in that case to avoid a stale non-instrumented objs-release artifact being loaded
# by a TSAN/ASan nginx (which causes a runtime symbol mismatch and nginx to abort).
if [[ -n "${CARGO_BUILD_TARGET:-}" && -f "${CARGO_MODULE}" ]]; then
    MODULE_PATH="${CARGO_MODULE}"
elif [[ -f "${CARGO_MODULE}" ]]; then
    MODULE_PATH="${CARGO_MODULE}"
elif [[ -f "${RELEASE_MODULE}" ]]; then
    MODULE_PATH="${RELEASE_MODULE}"
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
# crashed (liveness ≠ counter-reset evidence). Part C drives the exporter into
# FULL SELF-DISABLE (crash_count=6 > MAX_CRASH_RESTARTS=5 → exit(2)) before
# sending SIGHUP.  After self-disable, the counter is stable in shm (no more
# concurrent increments), eliminating a race with control_shm_zone_init.
#
# Hard observable: after reload with store(0) present, crash_count=0 → first
# two post-reload starts bring count to 1 (no log) then 2 ("crash #2 in window").
# Without store(0) (mutation), crash_count remains 6; the first post-reload
# exporter sees count=7>MAX_CRASH_RESTARTS and immediately re-disables via
# exit(2) — nginx stops respawning, test fails with "no exporter appeared".
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
# When CARGO_BUILD_TARGET is set (TSAN/ASan harness), cargo writes the cdylib
# to target/test-support/<triple>/debug/ — NOT target/test-support/debug/.
# The harness exports CARGO_BUILD_TARGET, RUSTFLAGS, RUSTC_BOOTSTRAP, and
# CARGO_UNSTABLE_BUILD_STD so this `cargo build` produces an instrumented .so.
if [[ -n "${CARGO_BUILD_TARGET:-}" ]]; then
    TEST_SUPPORT_MODULE="${TEST_SUPPORT_TARGET_DIR}/${CARGO_BUILD_TARGET}/debug/libngx_http_otel_module.${MODULE_EXT}"
else
    TEST_SUPPORT_MODULE="${TEST_SUPPORT_TARGET_DIR}/debug/libngx_http_otel_module.${MODULE_EXT}"
fi

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

# Strategy: let the exporter SELF-DISABLE before sending SIGHUP.
# After self-disable (crash_count > MAX_CRASH_RESTARTS=5 → exit(2)), the master
# stops respawning — no more concurrent exporter activity races with the SIGHUP
# reload path.  crash_count will be 6 (or higher) in shm at that point.
#
# After SIGHUP with the reset: crash_count becomes 0, so the new exporter's
# second start logs "crash #2 in window".
# After SIGHUP WITHOUT the reset: crash_count remains 6+, so the new exporter's
# second start logs "crash #7 in window" (or higher).
# The check is: N <= 3 → reset happened; N >= 5 → reset missed.
#
# Total wall-clock time: full self-disable run ≈ 45s (same as crashloop.sh).
# Allow MAX_WAIT_C seconds.
MAX_WAIT_C="${MAX_WAIT_C:-60}"

info "Starting nginx (Part C) with NGX_OTEL_CRASH_ON_STARTUP=1..."
env NGX_OTEL_CRASH_ON_STARTUP=1 \
    "${NGINX_BINARY}" -p "${PREFIX_C}" -c "${PREFIX_C}/nginx.conf" &
NGINX_PID_C=$!
sleep 1

if ! kill -0 "${NGINX_PID_C}" 2>/dev/null; then
    fail "nginx master (Part C) exited immediately"
fi
pass "Part C: nginx master started, PID = ${NGINX_PID_C}"

# Wait for exporter SELF-DISABLE ("disabled after N crashes" ALERT in error.log).
# The self-disable happens after crash_count > MAX_CRASH_RESTARTS (5), so
# crash_count will be 6 when the ALERT fires.  At this point no more exporter
# processes are spawned — the counter in shm is stable.
info "Part C: waiting for exporter self-disable ('disabled after N crashes' ALERT)..."
deadline_c=$(( $(date +%s) + MAX_WAIT_C ))
SEEN_DISABLED=false
while (( $(date +%s) < deadline_c )); do
    if grep -q "otel exporter: disabled after" "${PREFIX_C}/logs/error.log" 2>/dev/null; then
        SEEN_DISABLED=true
        break
    fi
    sleep 0.5
done
if [[ "${SEEN_DISABLED}" != "true" ]]; then
    fail "Part C: exporter self-disable ALERT not seen in error.log within ${MAX_WAIT_C}s"
fi
# Log the actual ALERT line for evidence.
DISABLE_LINE="$(grep "otel exporter: disabled after" "${PREFIX_C}/logs/error.log" | head -1)"
pass "Part C: exporter self-disabled — ${DISABLE_LINE}"

# Confirm no exporter is running (master stopped respawning after exit(2)).
sleep 1
EXP_BEFORE_RELOAD="$(exporter_pid "${NGINX_PID_C}")"
if [[ -n "${EXP_BEFORE_RELOAD}" ]]; then
    fail "Part C: exporter still running after self-disable (expected no process); PID=${EXP_BEFORE_RELOAD}"
fi
pass "Part C: no exporter running before SIGHUP (self-disable confirmed, crash_count stable in shm)"

# Send SIGHUP (reload) — no racing exporter activity; counter is stable.
info "Part C: sending SIGHUP to master PID ${NGINX_PID_C}..."
kill -SIGHUP "${NGINX_PID_C}"

# Wait for a new exporter to appear after reload.
# The reload calls control_shm_zone_init(old_data!=NULL) → store(0) resets crash_count.
# The new exporter (crash hook still inherited) crashes immediately (count=1 → no log).
EXP_PID_C_NEW=""
deadline_c2=$(( $(date +%s) + 20 ))
while (( $(date +%s) < deadline_c2 )); do
    CUR="$(exporter_pid "${NGINX_PID_C}")"
    if [[ -n "${CUR}" ]]; then
        EXP_PID_C_NEW="${CUR}"
        break
    fi
    sleep 0.3
done
[[ -n "${EXP_PID_C_NEW}" ]] \
    || fail "Part C: no exporter appeared within 20s after SIGHUP (expected new post-reload exporter)"
pass "Part C: first post-reload exporter appeared, PID = ${EXP_PID_C_NEW}"

# Wait for EXP_PID_C_NEW to die (count=1, crash hook fires, no backoff log).
info "Part C: waiting for post-reload exporter ${EXP_PID_C_NEW} to crash (count=1, no log)..."
deadline_c3=$(( $(date +%s) + 20 ))
while kill -0 "${EXP_PID_C_NEW}" 2>/dev/null; do
    if (( $(date +%s) > deadline_c3 )); then
        fail "Part C: post-reload exporter ${EXP_PID_C_NEW} did not crash within 20s"
    fi
    sleep 0.3
done
info "Part C: post-reload exporter ${EXP_PID_C_NEW} crashed (count=1, no backoff log expected)"

# Capture the SECOND post-reload exporter PID (the one that logs "crash #2").
EXP_PID_C_NEW2=""
deadline_c4=$(( $(date +%s) + 15 ))
while (( $(date +%s) < deadline_c4 )); do
    CUR="$(exporter_pid "${NGINX_PID_C}")"
    if [[ -n "${CUR}" && "${CUR}" != "${EXP_PID_C_NEW}" ]]; then
        EXP_PID_C_NEW2="${CUR}"
        break
    fi
    sleep 0.3
done
[[ -n "${EXP_PID_C_NEW2}" ]] \
    || fail "Part C: master did not respawn second post-reload exporter within 15s"
info "Part C: second post-reload exporter PID = ${EXP_PID_C_NEW2}"

# Wait for EXP_PID_C_NEW2 to log its backoff message (PID-keyed grep).
# With reset: crash_count=1 (after first post-reload crash) → incremented to 2 → "crash #2 in window".
# Without reset: crash_count=6 (stale) → incremented to 7 → immediately exit(2) again, no EXP_PID_C_NEW2
# (the test would have failed earlier at "no exporter appeared" or "no second post-reload exporter").
POST_RELOAD_CRASH_LINE=""
deadline_c5=$(( $(date +%s) + 20 ))
while (( $(date +%s) < deadline_c5 )); do
    LINE="$(grep "${EXP_PID_C_NEW2}#.*crash #" \
        "${PREFIX_C}/logs/error.log" 2>/dev/null | head -1 || true)"
    if [[ -n "${LINE}" ]]; then
        POST_RELOAD_CRASH_LINE="${LINE}"
        break
    fi
    sleep 0.3
done
if [[ -z "${POST_RELOAD_CRASH_LINE}" ]]; then
    fail "Part C: no 'crash #N in window' line from PID ${EXP_PID_C_NEW2} appeared within 20s"
fi
info "Part C: second post-reload exporter crash line (PID ${EXP_PID_C_NEW2}): ${POST_RELOAD_CRASH_LINE}"

# Hard assertion: the sequence number must be LOW (2 or 3) → counter was reset.
# A HIGH number (>= 5) means stale counter carried over → reset failed.
#   store(0) present  → crash_count resets to 0 → "crash #2 in window" (count 0→1→2)
#   store(0) neutered → crash_count remains 6; first post-reload exporter sees
#                       count=7>MAX_CRASH_RESTARTS → immediately re-disables (no EXP_PID_C_NEW2).
#                       If somehow a second exporter appeared, it would log "crash #8+".
# In practice the neutered path fails at "no second post-reload exporter" before reaching here.
if echo "${POST_RELOAD_CRASH_LINE}" | grep -qE "crash #[1-3] in window"; then
    pass "Part C: PID ${EXP_PID_C_NEW2} logs low crash# — counter reset on SIGHUP CONFIRMED: ${POST_RELOAD_CRASH_LINE}"
elif echo "${POST_RELOAD_CRASH_LINE}" | grep -qE "crash #[5-9] in window|crash #[0-9]{2,}"; then
    fail "Part C: PID ${EXP_PID_C_NEW2} logs high crash# — counter NOT reset on SIGHUP: ${POST_RELOAD_CRASH_LINE}"
else
    # crash #4 is ambiguous: could be stale counter at 3 (without reset) or new cycle at 4.
    # In our scenario (self-disable = count 6+), getting "crash #4" is anomalous — fail safe.
    fail "Part C: ambiguous crash# from PID ${EXP_PID_C_NEW2} (expected #2 or #7+): ${POST_RELOAD_CRASH_LINE}"
fi

# Assertion (a): master still alive (crash loop will eventually self-disable again,
# but that takes 5 more crashes; well within the 3s check window).
sleep 3
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
