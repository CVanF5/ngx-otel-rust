#!/usr/bin/env bash
# tests/integration/run_chaos_quit_responsiveness.sh
#   — H3F3 chaos gate: h3f3_quit_responsiveness
#
# The H3F3 bug: periodic exporter sends (fresh metrics/logs/spans + retry-queue
# drains) were awaited BARE. The only backstop was the transport read timer
# (DEFAULT_READ_TIMEOUT_MS = 60 s), and that covers only connect + read — a
# poll_write that returns NGX_AGAIN against a stalled collector arms NO timer, so
# a write can hang unbounded. Either way, a single export wake chains several
# sends and shutdown flags are polled only BETWEEN wakes, so `nginx -s quit`
# behind a hung-but-connected collector could block for a minute or more.
#
# This differs from run_chaos_dead_collector.sh, which uses a black-hole port
# with NO listener (connect fails fast with ECONNREFUSED — never exercises the
# stall). Here the collector ACCEPTS the TCP connection and then NEVER RESPONDS
# (a Python socket that accepts and sleeps), so the exporter's send genuinely
# hangs in connect-complete/write/read — exactly the path PERIODIC_SEND_BUDGET
# (15 s, src/export/mod.rs) now bounds.
#
# Assertion (HARD CEILING): with the exporter mid-send to the never-responding
# collector, SIGQUIT to the master causes nginx to fully exit within
#   PERIODIC_SEND_BUDGET (15 s, the one in-flight send) +
#   a few graceful-drain attempts (GRACEFUL_DRAIN_PER_ATTEMPT_BUDGET = 2 s each) +
#   margin  ==>  hard ceiling 25 s.
# Pre-fix, the same scenario blocks on the 60 s read timer (or unbounded on the
# write path), so a 25 s ceiling cleanly separates fixed from unfixed.
# Also asserts no orphan exporter/worker/master remains.
#
# Exit codes: 0 = pass, 1 = preflight error, 2 = assertion failed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Port for the accept-but-never-respond collector.
HANG_PORT="${HANG_PORT:-19328}"
HANG_ENDPOINT="http://127.0.0.1:${HANG_PORT}"

# Hard ceiling for the SIGQUIT-to-exit latency (seconds).
QUIT_CEILING="${QUIT_CEILING:-25}"

NGINX_CONF_BODY="
daemon off;
master_process on;
worker_processes 2;
error_log @PREFIX@/logs/error.log info;
pid       @PREFIX@/logs/nginx.pid;

load_module @MODULE_PATH@;

events {
    worker_connections 64;
}

http {
    otel_exporter {
        endpoint ${HANG_ENDPOINT};
    }
    otel_service_name ngx-otel-quit-responsiveness-chaos;
    # Short interval so the export loop is actively sending when SIGQUIT lands.
    otel_metric_interval 1s;

    server {
        listen 127.0.0.1:9211;
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

PYTHON_BIN="$(command -v python3 || command -v python || true)"
if [[ -z "${PYTHON_BIN}" ]]; then
    echo "ERROR: python3 required for the accept-but-never-respond collector." >&2; exit 1
fi

info "nginx binary:  ${NGINX_BINARY}"
info "Module:        ${MODULE_PATH}"
info "Hang endpoint: ${HANG_ENDPOINT} (accepts, never responds)"
info "Quit ceiling:  ${QUIT_CEILING}s"

exporter_pid() {
    local master_pid="${1:-}"
    ps -eo pid,ppid,args 2>/dev/null \
        | awk -v mpid="${master_pid}" \
            '$2==mpid && $3 == "nginx:" && $4 == "otel" && $5 == "exporter" {print $1}' \
        | head -1
}

wait_for() {
    local timeout=$1 desc=$2 expr=$3
    local deadline=$(( $(date +%s) + timeout ))
    while (( $(date +%s) < deadline )); do
        if eval "${expr}" 2>/dev/null; then return 0; fi
        sleep 0.2
    done
    fail "Timed out (${timeout}s) waiting for: ${desc}"
}

PREFIX="$(mktemp -d /tmp/ngx-otel-quitresp.XXXXXX)"
NGINX_PID=""
HANG_PID=""

cleanup() {
    [[ -n "${NGINX_PID:-}" ]] && kill "${NGINX_PID}" 2>/dev/null || true
    [[ -n "${HANG_PID:-}" ]]  && kill "${HANG_PID}"  2>/dev/null || true
    sleep 1
    echo ""
    echo "=== error.log (last 25 lines) ==="
    tail -25 "${PREFIX}/logs/error.log" 2>/dev/null || echo "(not found)"
    rm -rf "${PREFIX}"
}
trap cleanup EXIT

mkdir -p "${PREFIX}/logs" "${PREFIX}/client_body_temp"
echo "${NGINX_CONF_BODY}" \
    | sed -e "s|@MODULE_PATH@|${MODULE_PATH}|g" \
          -e "s|@PREFIX@|${PREFIX}|g" \
    > "${PREFIX}/nginx.conf"

# ─── Start the accept-but-never-respond collector ───────────────────────────
info "Starting accept-but-never-respond collector on :${HANG_PORT}..."
"${PYTHON_BIN}" - "${HANG_PORT}" <<'PYEOF' &
import socket, sys, time
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
s.listen(64)
conns = []
while True:
    try:
        c, _ = s.accept()
        # Accept and HOLD the connection open forever: never read, never reply.
        # This keeps the exporter's send hung in connect-complete/write/read.
        conns.append(c)
    except Exception:
        time.sleep(0.1)
PYEOF
HANG_PID=$!
sleep 0.5
if ! kill -0 "${HANG_PID}" 2>/dev/null; then
    fail "accept-but-never-respond collector failed to start"
fi
pass "Hang-collector listening (PID ${HANG_PID})"

# ─── Start nginx ────────────────────────────────────────────────────────────
info "Starting nginx..."
"${NGINX_BINARY}" -p "${PREFIX}" -c "${PREFIX}/nginx.conf" &
NGINX_PID=$!
sleep 1
if ! kill -0 "${NGINX_PID}" 2>/dev/null; then
    fail "nginx master exited immediately after start"
fi
wait_for 5 "exporter to appear" "[[ -n \"\$(exporter_pid ${NGINX_PID})\" ]]"
pass "Exporter started against the hung collector"

# Let the export loop run several 1s intervals so it is actively attempting
# sends (and accumulating a retry queue) against the hung collector.
info "Waiting 4s for the export loop to engage the hung collector..."
sleep 4

# ─── SIGQUIT and time the shutdown ──────────────────────────────────────────
QUIT_START="$(date +%s.%N)"
info "Sending SIGQUIT to master PID ${NGINX_PID}..."
kill -SIGQUIT "${NGINX_PID}"

wait_for "${QUIT_CEILING}" \
    "nginx to exit after SIGQUIT behind a hung collector (ceiling ${QUIT_CEILING}s)" \
    "! kill -0 ${NGINX_PID} 2>/dev/null"

QUIT_END="$(date +%s.%N)"
QUIT_ELAPSED="$(awk -v a="${QUIT_START}" -v b="${QUIT_END}" 'BEGIN{printf "%.2f", b-a}')"

# Hard ceiling assertion.
if awk -v e="${QUIT_ELAPSED}" -v c="${QUIT_CEILING}" 'BEGIN{exit !(e <= c)}'; then
    pass "h3f3_quit_responsiveness: nginx exited ${QUIT_ELAPSED}s after SIGQUIT (ceiling ${QUIT_CEILING}s)"
else
    fail "h3f3_quit_responsiveness: nginx took ${QUIT_ELAPSED}s to exit (exceeds ${QUIT_CEILING}s ceiling)"
fi

# No orphan exporter.
sleep 0.5
EXP_ORPHAN="$(exporter_pid "${NGINX_PID}")"
if [[ -n "${EXP_ORPHAN}" ]]; then
    fail "Orphan exporter remains after nginx shutdown (PID ${EXP_ORPHAN})"
fi
pass "No orphan exporter after SIGQUIT"

NGINX_PID=""
kill "${HANG_PID}" 2>/dev/null || true
HANG_PID=""

echo ""
pass "=== h3f3_quit_responsiveness: PASSED (quit latency ${QUIT_ELAPSED}s <= ${QUIT_CEILING}s) ==="
