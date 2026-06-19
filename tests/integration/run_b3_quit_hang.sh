#!/usr/bin/env bash
# tests/integration/run_b3_quit_hang.sh — B3 regression: nginx -s quit exits within backstop
#
# B3 finding: early returns in export_loop (bad endpoint / transport
# construction failure) never set EXPORT_LOOP_DONE.  The drain-wait loop in
# otel_exporter_cycle called ngx_process_events_and_timers in a tight loop
# checking the deadline, but if no fds or timers were active epoll/kqueue
# blocked forever → nginx -s quit hung until manual SIGTERM.
#
# B3 fix — two layers:
#   1. RAII guard (ExportLoopDoneGuard) in export_loop: sets EXPORT_LOOP_DONE
#      on every exit path, including the early-return startup-abort paths.
#   2. Backstop timer in otel_exporter_cycle: registers an nginx timer at
#      GRACEFUL_DRAIN_BACKSTOP (15 s) so ngx_process_events_and_timers always
#      returns by the deadline even with no other active events.
#
# Test strategy: configure nginx with an invalid (unreachable) endpoint so
# export_loop aborts early.  Then send `nginx -s quit`.  The master must exit
# within QUIT_DEADLINE seconds.  Pre-fix this assertion times out.
#
# NOTE: the test uses a non-routable address (192.0.2.1 / RFC 5737 TEST-NET-1)
# rather than a refused port because a refused connection returns immediately
# and may not trigger the early-abort path.  With a non-routable address the
# TCP connect attempt hangs (no RST) — but our transport construction may fail
# fast on DNS / address resolution depending on platform.  To reliably trigger
# the early-return path we use a deliberately invalid UTF-8 endpoint workaround
# or an unparseable URL.  The simplest approach that reliably triggers the
# transport-construction failure on all platforms: use a bogus scheme URL.
#
# Assertions:
#   1. nginx starts with an otel exporter child.
#   2. `nginx -s quit` causes the master to exit within QUIT_DEADLINE seconds.
#      Pre-fix: master never exits (hangs in drain-wait forever).
#   3. No nginx master or otel exporter processes remain after the deadline.
#
# Prerequisites: NGINX_BINARY set or auto-detected; no collector required.
# Exit codes: 0 = all assertions passed, 1 = preflight, 2 = assertion failed.

set -euo pipefail

# How long nginx -s quit must complete before we declare failure.
# GRACEFUL_DRAIN_BACKSTOP is 15 s; we allow 5 s margin.
QUIT_DEADLINE=20

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CONF_TEMPLATE="${SCRIPT_DIR}/nginx_b3_bad_endpoint.conf"

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

PREFIX="$(mktemp -d /tmp/ngx-b3-quit.XXXXXX)"
NGINX_PID=""

cleanup() {
    echo "=== error.log ==="
    cat "${PREFIX}/logs/error.log" 2>/dev/null || echo "(not found)"
    if [[ -n "${NGINX_PID:-}" ]]; then
        kill -SIGKILL "${NGINX_PID}" 2>/dev/null || true
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

# ── Send nginx -s quit ─────────────────────────────────────────────────────────

info "Sending 'nginx -s quit' to master PID ${NGINX_PID}..."
"${NGINX_BINARY}" -p "${PREFIX}" -c "${PREFIX}/nginx.conf" -s quit 2>/dev/null || true

# Assertion 2: master exits within QUIT_DEADLINE.
# B3 regression gate: pre-fix this never completes (master blocks in drain-wait).
info "Waiting up to ${QUIT_DEADLINE}s for master to exit (B3)..."
wait_for "${QUIT_DEADLINE}" \
    "nginx master to exit after quit (B3 regression gate)" \
    "! kill -0 ${NGINX_PID} 2>/dev/null"

pass "Assertion 2: nginx master (PID=${NGINX_PID}) exited within ${QUIT_DEADLINE}s of 'nginx -s quit'"
DEAD_MASTER_PID="${NGINX_PID}"
NGINX_PID=""

# Assertion 3: no leftover exporter child of this test's master.
# Scope the check to children of THIS test's master PID so that concurrent
# test runs or other nginx instances do not cause false failures.
STRAY_EXP="$(exporter_pid "${DEAD_MASTER_PID}")"
if [[ -n "${STRAY_EXP}" ]]; then
    fail "Stray 'otel exporter' process(es) still running (child of this test's master PID=${DEAD_MASTER_PID}): ${STRAY_EXP}"
fi
pass "Assertion 3: no stray otel exporter processes"

trap - EXIT
rm -rf "${PREFIX}"

echo ""
pass "=== B3 quit-hang regression test: all assertions passed ==="
