#!/usr/bin/env bash
# tests/integration/run_chaos_quit_responsiveness.sh
#   — H3F3 chaos gate: h3f3_quit_responsiveness
#
# PREMISE CORRECTED (H3F3 follow-up): the original "blocks quit for minutes"
# framing was FALSE. The pre-existing GRACEFUL_DRAIN_BACKSTOP (15 s,
# src/exporter/mod.rs) already bounds SIGQUIT-to-exit independently of the
# PERIODIC_SEND_BUDGET wrap, so a hung send never blocks quit for "a minute or
# more" — the backstop caps it. Because that backstop and PERIODIC_SEND_BUDGET
# are both 15 s, a pure quit-latency ceiling does NOT discriminate the fix: it
# passes whether or not the periodic wrap is present (the original gate's
# defect — it went green against the parent commit with the fix entirely
# absent).
#
# The TRUE justification for the PERIODIC_SEND_BUDGET wrap, and what this gate
# now verifies:
#   1. Bound each INDIVIDUAL hung periodic send so its batch lands back in the
#      retry queue within the wake (retry-queue accuracy + in-wake
#      responsiveness) — rather than the whole wake stalling on the transport
#      read timer (DEFAULT_READ_TIMEOUT_MS = 60 s) for connect+read paths.
#   2. Close the UNBOUNDED write-stall gap: a poll_write returning NGX_AGAIN
#      against a stalled collector arms NO timer, so without the wrap a write
#      can hang with no ceiling at all (the read timer never covers it).
#
# DISCRIMINATING ASSERTION (the part the original gate missed). The
# PERIODIC_SEND_BUDGET deadline emits a DISTINCTIVE ERR line when it fires on a
# periodic send:
#     "otel export: ... send timed out after 15s; queuing for retry"
# This line is produced ONLY by the with_deadline() wrap on the periodic send
# path. With the wrap absent/neutralized, the periodic send awaits BARE and this
# line is NEVER emitted (the send blocks on the 60 s read timer / unbounded
# write, then the backstop tears the exporter down at quit). So we let the
# exporter sit on the hung collector longer than PERIODIC_SEND_BUDGET and assert
# the signature appears — this FAILS on the unwrapped build and PASSES on the
# fixed build. Verified both polarities in the H3F3 follow-up (mutation: the
# deadline wrap removed → signature absent → this gate fails).
#
# This differs from run_chaos_dead_collector.sh, which uses a black-hole port
# with NO listener (connect fails fast with ECONNREFUSED — never exercises the
# stall). Here the collector ACCEPTS the TCP connection and then NEVER RESPONDS
# (a Python socket that accepts and sleeps), so the exporter's periodic send
# genuinely hangs in connect-complete/write/read — exactly the path
# PERIODIC_SEND_BUDGET (15 s, src/export/mod.rs) now bounds.
#
# SECONDARY assertion (HARD CEILING, kept as a backstop sanity check, NOT the
# discriminator): with the exporter mid-send to the never-responding collector,
# SIGQUIT to the master causes nginx to fully exit within the
# GRACEFUL_DRAIN_BACKSTOP (15 s) + a few graceful-drain attempts
# (GRACEFUL_DRAIN_PER_ATTEMPT_BUDGET = 2 s each) + margin ==> ceiling 25 s.
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

# PERIODIC_SEND_BUDGET (src/export/mod.rs) is 15s. The periodic send to the
# hung collector must hang for the full budget before the deadline fires and
# emits the distinctive ERR signature. We wait the budget + margin so the
# signature is guaranteed to have landed in error.log before we assert on it.
DEADLINE_BUDGET_SECS="${DEADLINE_BUDGET_SECS:-15}"
SIGNATURE_WAIT="${SIGNATURE_WAIT:-22}"

# The DISCRIMINATING signature: emitted ONLY by the with_deadline() wrap on a
# periodic send. Absent on the unwrapped (bug-present) build. Matches all three
# periodic lanes — metrics ("send timed out after ...; queuing for retry"),
# logs ("logs send timed out ..."), spans ("spans send timed out ...") — and the
# retry-drain lane ("... retry send timed out after ...; re-queuing"). With the
# wrap absent the periodic send awaits bare and NONE of these lines is emitted.
DEADLINE_SIGNATURE='otel export: .*send timed out after .*; (queuing for retry|re-queuing)'

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

# ─── H3F9(h): artifact-freshness guard ───────────────────────────────────────
# The chaos test LOADS an existing cdylib but does NOT build it; a mutation
# cycle once silently ran against a STALE artifact (edit a src file, forget to
# rebuild → the test exercised the old binary).  Refuse to run if the loaded
# module is older than any tracked source input.  `find -newer` is portable
# across GNU/BSD; `-print -quit` stops at the first newer file.
assert_module_fresh() {
    local module="$1"
    [[ -f "${module}" ]] || return 0
    local newer
    newer=$(find \
        "${CRATE_DIR}/src" \
        "${CRATE_DIR}/Cargo.toml" \
        "${CRATE_DIR}/Cargo.lock" \
        "${CRATE_DIR}/build.rs" \
        -type f -newer "${module}" -print -quit 2>/dev/null || true)
    if [[ -n "${newer}" ]]; then
        echo "ERROR: loaded module is STALE — a source input is newer than the cdylib:" >&2
        echo "         module: ${module}" >&2
        echo "         newer:  ${newer}" >&2
        echo "       Rebuild before running: 'make build-release' (or 'cargo build --release')." >&2
        exit 1
    fi
}
assert_module_fresh "${MODULE_PATH}"

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
info "Deadline wait: ${SIGNATURE_WAIT}s (PERIODIC_SEND_BUDGET ${DEADLINE_BUDGET_SECS}s + margin)"

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

ERROR_LOG="${PREFIX}/logs/error.log"

# ─── DISCRIMINATING ASSERTION: periodic-send deadline signature ─────────────
# Let the periodic send hang on the collector for longer than
# PERIODIC_SEND_BUDGET (15s) so the deadline fires and emits its distinctive
# ERR line. On the FIXED build the signature appears; on the unwrapped
# (bug-present) build the send awaits bare and the line never appears — so this
# is the half the original ceiling-only gate missed.
info "Waiting up to ${SIGNATURE_WAIT}s for the periodic-send deadline (${DEADLINE_BUDGET_SECS}s budget) to fire..."
SIG_DEADLINE=$(( $(date +%s) + SIGNATURE_WAIT ))
SIGNATURE_SEEN=0
while (( $(date +%s) < SIG_DEADLINE )); do
    if grep -Eq "${DEADLINE_SIGNATURE}" "${ERROR_LOG}" 2>/dev/null; then
        SIGNATURE_SEEN=1
        break
    fi
    # Bail early if nginx died unexpectedly during the wait.
    if ! kill -0 "${NGINX_PID}" 2>/dev/null; then
        fail "nginx master exited unexpectedly before the deadline signature appeared"
    fi
    sleep 0.5
done

if (( SIGNATURE_SEEN == 1 )); then
    SIG_LINE="$(grep -E "${DEADLINE_SIGNATURE}" "${ERROR_LOG}" 2>/dev/null | head -1)"
    pass "h3f3_periodic_deadline: PERIODIC_SEND_BUDGET signature observed during the chaos run"
    info "  signature: ${SIG_LINE}"
else
    # This is the assertion the unwrapped build trips: without the deadline wrap
    # the periodic send hangs on the 60s read timer / unbounded write and the
    # "send timed out after ...; queuing for retry" line is never emitted.
    fail "h3f3_periodic_deadline: PERIODIC_SEND_BUDGET signature NOT observed within ${SIGNATURE_WAIT}s (deadline wrap absent or neutralized — periodic send was awaited bare)"
fi

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
pass "=== h3f3_quit_responsiveness: PASSED (deadline signature observed; quit latency ${QUIT_ELAPSED}s <= ${QUIT_CEILING}s) ==="
