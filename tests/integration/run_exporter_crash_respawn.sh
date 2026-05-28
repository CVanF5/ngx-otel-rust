#!/usr/bin/env bash
# tests/integration/run_exporter_crash_respawn.sh — Phase 1.3.1 crash-respawn gate
#
# Verifies that master auto-respawns the `nginx: otel exporter` child after a
# SIGKILL (crash).  Gate from proposal §3: "exporter restart on crash works
# with bounded telemetry loss".
#
# Assertions:
#   1. nginx starts with one exporter child (PID #1).
#   2. SIGKILL the exporter; within 5s a new exporter PID (#2) appears.
#   3. PID #2 != PID #1.
#   4. error.log contains "otel exporter: cycle entered" at least twice
#      (once for original spawn, once for respawn).
#   5. After SIGQUIT shutdown, no exporter remains.
#   6. Script is idempotent — running it twice in a row both pass.
#
# Known constraint (documented inline): if the exporter ever exits with
# status 2, nginx disables respawn (ngx_process.c:551-557). The exporter
# cycle must never call exit(2) on a recoverable error.
#
# Prerequisites: NGINX_BINARY set or auto-detected from objs-release/nginx.
# No collector required (export failures during the crash window are accepted).
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
CARGO_MODULE="${CRATE_DIR}/target/release/libngx_http_otel_module.${MODULE_EXT}"
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
exporter_pid() {
    ps -eo pid,args 2>/dev/null \
        | awk '/nginx: otel exporter/{print $1}' \
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

info "Starting nginx..."
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

# Drive a brief HTTP load while we kill the exporter (optional — verifies
# nginx keeps serving requests during the respawn window).
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

# Wait only for curl jobs (not nginx) — with a short deadline so the test
# doesn't hang if any curl is slow.
for cpid in "${CURL_PIDS[@]}"; do
    wait "${cpid}" 2>/dev/null || true
done

# Assertion 4: error.log contains "cycle entered" at least twice.
sleep 1  # Give the new exporter time to log its startup line.
CYCLE_ENTERED_COUNT="$(grep -c "otel exporter: cycle entered" "${PREFIX}/logs/error.log" 2>/dev/null || true)"
if (( CYCLE_ENTERED_COUNT < 2 )); then
    fail "error.log contains 'otel exporter: cycle entered' only ${CYCLE_ENTERED_COUNT} time(s); expected >= 2"
fi
pass "error.log contains 'otel exporter: cycle entered' ${CYCLE_ENTERED_COUNT} time(s) (>= 2)"

# Assertion 5: clean shutdown leaves no exporter.
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
