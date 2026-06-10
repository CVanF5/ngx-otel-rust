#!/usr/bin/env bash
# tests/integration/run_b2_orphan.sh — B2 regression: kill-9 master → exporter exits
#
# B2 finding: on `kill -9` of the nginx master the master's channel socket end
# is closed → the exporter's channel fd sees EOF on the next event loop tick.
# Pre-fix: the NGX_ERROR branch returned WITHOUT closing the channel connection
# or setting ngx_terminate.  The level-triggered EOF kept re-firing every
# `ngx_process_events_and_timers` call → exporter at 100% CPU forever (orphan).
#
# Post-fix (B2): the NGX_ERROR branch:
#   1. Calls ngx_close_connection(c) — deregisters the fd from epoll/kqueue
#      and closes the socket (mirrors ngx_channel_handler at
#      ngx_process_cycle.c:1022-1029 in nginx source).
#   2. Sets ngx_terminate = 1 — the cycle loop exits cleanly; the exporter
#      does not outlive its master.
#
# This test FAILS on pre-fix code: the exporter never exits after kill -9
# master (it orphans forever), so the "wait for exporter to exit" assertion
# times out and exits 2.
#
# Assertions:
#   1. nginx starts with an otel exporter child.
#   2. kill -9 the master → master is gone within 2 s.
#   3. exporter exits within ORPHAN_EXIT_TIMEOUT (10 s) after master dies.
#      Pre-fix: this assertion fails (exporter spins forever).
#   4. No exporter process remains after the timeout.
#
# Prerequisites: NGINX_BINARY set or auto-detected; no collector required.
# Exit codes: 0 = all assertions passed, 1 = preflight, 2 = assertion failed.

set -euo pipefail

ORPHAN_EXIT_TIMEOUT=10   # seconds the exporter gets to exit after master dies

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
if [[ -n "${CARGO_BUILD_TARGET:-}" ]]; then
    CARGO_MODULE="${CRATE_DIR}/target/${CARGO_BUILD_TARGET}/release/libngx_http_otel_module.${MODULE_EXT}"
else
    CARGO_MODULE="${CRATE_DIR}/target/release/libngx_http_otel_module.${MODULE_EXT}"
fi
if [[ -n "${CARGO_BUILD_TARGET:-}" && -f "${CARGO_MODULE}" ]]; then
    MODULE_PATH="${CARGO_MODULE}"
elif [[ -f "${RELEASE_MODULE}" ]]; then
    MODULE_PATH="${RELEASE_MODULE}"
elif [[ -f "${CARGO_MODULE}" ]]; then
    MODULE_PATH="${CARGO_MODULE}"
else
    echo "ERROR: module not found. Run 'make build-release' first." >&2
    exit 1
fi

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
pass()  { echo -e "${GREEN}[PASS]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*" >&2; exit 2; }
info()  { echo -e "${YELLOW}[INFO]${NC} $*"; }

if [[ ! -x "${NGINX_BINARY}" ]]; then
    echo "ERROR: nginx binary not found at ${NGINX_BINARY}." >&2; exit 1
fi
info "nginx binary:   ${NGINX_BINARY}"
info "Module:         ${MODULE_PATH}"

wait_for() {
    local timeout=$1 desc=$2 expr=$3
    local deadline=$(( $(date +%s) + timeout ))
    while (( $(date +%s) < deadline )); do
        if eval "${expr}" 2>/dev/null; then return 0; fi
        sleep 0.5
    done
    fail "Timed out (${timeout}s) waiting for: ${desc}"
}

# Return the PID of the otel exporter child of the given master PID,
# or empty string if none found.
exporter_pid() {
    local master_pid="${1:-}"
    if [[ -n "${master_pid}" ]]; then
        ps -eo pid,ppid,args 2>/dev/null \
            | awk -v ppid="${master_pid}" '$2==ppid && /otel exporter/ {print $1; exit}'
    else
        ps -eo pid,args 2>/dev/null \
            | awk '/nginx: otel exporter/ {print $1; exit}'
    fi
}

# ── Setup ─────────────────────────────────────────────────────────────────────

PREFIX="$(mktemp -d /tmp/ngx-b2-orphan.XXXXXX)"
NGINX_PID=""

cleanup() {
    echo "=== error.log ==="
    cat "${PREFIX}/logs/error.log" 2>/dev/null || echo "(not found)"
    if [[ -n "${NGINX_PID:-}" ]]; then
        kill "${NGINX_PID}" 2>/dev/null || true
    fi
    rm -rf "${PREFIX}"
}
trap cleanup EXIT

mkdir -p "${PREFIX}/logs"

sed \
    -e "s|@MODULE_PATH@|${MODULE_PATH}|g" \
    -e "s|@PREFIX@|${PREFIX}|g" \
    "${CONF_TEMPLATE}" > "${PREFIX}/nginx.conf"

# ── Start nginx ────────────────────────────────────────────────────────────────

"${NGINX_BINARY}" -p "${PREFIX}" -c "${PREFIX}/nginx.conf" &
NGINX_PID=$!
sleep 1

if ! kill -0 "${NGINX_PID}" 2>/dev/null; then
    echo "=== error.log ==="
    cat "${PREFIX}/logs/error.log" 2>/dev/null || echo "(not found)"
    fail "nginx exited immediately after start"
fi

# Assertion 1: exporter is running.
EXP_PID="$(exporter_pid "${NGINX_PID}")"
[[ -n "${EXP_PID}" ]] \
    || fail "No 'otel exporter' process found after nginx start"
pass "Assertion 1: exporter started (PID=${EXP_PID}, master=${NGINX_PID})"

# ── kill -9 the master ────────────────────────────────────────────────────────

info "Sending SIGKILL to master PID ${NGINX_PID}..."
kill -SIGKILL "${NGINX_PID}"

# Assertion 2: master is gone within 2 s.
wait_for 2 "master to die after SIGKILL" "! kill -0 ${NGINX_PID} 2>/dev/null"
pass "Assertion 2: master (PID=${NGINX_PID}) died after SIGKILL"
NGINX_PID=""   # prevent cleanup from trying to kill a recycled PID

# ── Verify exporter exits ─────────────────────────────────────────────────────
#
# B2 regression gate: pre-fix the exporter never exits (100% CPU orphan);
# post-fix ngx_terminate=1 causes the cycle loop to call exit(0) within
# one event-loop tick (typically < 100 ms after the channel EOF fires).

info "Waiting up to ${ORPHAN_EXIT_TIMEOUT}s for exporter (PID=${EXP_PID}) to exit..."
wait_for "${ORPHAN_EXIT_TIMEOUT}" \
    "exporter to exit after master SIGKILL (B2)" \
    "! kill -0 ${EXP_PID} 2>/dev/null"

pass "Assertion 3: exporter (PID=${EXP_PID}) exited within ${ORPHAN_EXIT_TIMEOUT}s of master SIGKILL"

# Assertion 4: no exporter process remains under any nginx master.
STRAY="$(ps -eo pid,args 2>/dev/null | awk '/nginx: otel exporter/ {print $1}')"
if [[ -n "${STRAY}" ]]; then
    fail "Stray 'otel exporter' process(es) still running: ${STRAY}"
fi
pass "Assertion 4: no stray otel exporter processes"

trap - EXIT
rm -rf "${PREFIX}"

echo ""
pass "=== B2 orphan regression test: all assertions passed ==="
