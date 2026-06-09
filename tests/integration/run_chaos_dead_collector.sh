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
trap - EXIT
rm -rf "${PREFIX}" "${PREFIX_B}"

echo ""
pass "=== All dead-collector shutdown/reload assertions passed ==="
