#!/usr/bin/env bash
# tests/integration/run_signal_storm.sh — signal-storm re-entrancy test
#
# Exercises the busy-flag + lock-free coalescer under signal delivery:
#
#   1. Start nginx with otel_error_log enabled (error-log export path).
#   2. Run a 30-second flood of /flood requests (broken upstream, generates
#      "connect() failed" error-log entries at ERR level).
#   3. Simultaneously send SIGUSR1 to worker PIDs every 1s (SIGUSR1 causes
#      nginx to reopen logs, firing ngx_log_error NOTICE internally — exercises
#      the re-entrancy path where a signal handler calls the error writer while
#      the writer is already executing on the request path).
#   4. HARD-assert: no crash (nginx still running at end), no "panicked at" /
#      "signal 6" / "signal 11" in error.log, drain progressed (LOGS_LOG grew),
#      no torn records in LOGS_LOG (all lines are valid JSON).
#
# On Linux arm64 this also serves as the pre-TSAN exerciser: the same shared
# state paths (busy-flag swap, AtomicU64 fetch_add, CoalesceSlot count.swap)
# run under TSAN via `make tsan-test` which includes this script.
#
# Exit codes: 0 = all assertions passed; 1 = preflight failure; 2 = HARD-FAIL.

set -euo pipefail

# ─── Resolve paths ───────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPO_ROOT="$(cd "${CRATE_DIR}/.." && pwd)"

CONF_TEMPLATE="${SCRIPT_DIR}/nginx_error_log.conf"

. "${CRATE_DIR}/test-harness/lib.sh"
resolve_nginx_binary || true

case "$(uname -s)" in
    Darwin) MODULE_EXT="dylib" ;;
    *)      MODULE_EXT="so"    ;;
esac
MODULE_PATH="${CRATE_DIR}/target/release/libngx_http_otel_module.${MODULE_EXT}"

# TSAN-aware module path: when CARGO_BUILD_TARGET is set, cargo puts the cdylib
# in target/<triple>/release/ instead of target/release/.
if [[ -n "${CARGO_BUILD_TARGET:-}" ]]; then
    MODULE_PATH="${CRATE_DIR}/target/${CARGO_BUILD_TARGET}/release/libngx_http_otel_module.${MODULE_EXT}"
fi

SERVICE_NAME="ngx-otel-error-log-test"
STORM_DURATION_S="${STORM_DURATION_S:-30}"
METRIC_INTERVAL_S=2
FLUSH_WAIT_S=$(( METRIC_INTERVAL_S + 3 ))
LISTEN_PORT=9108

# ─── Colour helpers ──────────────────────────────────────────────────────────

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass()      { echo -e "${GREEN}[PASS]${NC} $*"; }
hard_fail() { echo -e "${RED}[HARD-FAIL]${NC} $*" >&2; FAILED=1; }
info()      { echo -e "${YELLOW}[INFO]${NC} $*"; }

# ─── Pre-flight ───────────────────────────────────────────────────────────────

FAILED=0

info "Pre-flight checks..."
if [[ ! -x "${NGINX_BINARY}" ]]; then
    echo "ERROR: nginx binary not found at ${NGINX_BINARY}" >&2; exit 1
fi
ensure_collector_running || exit 1

# ─── Build ───────────────────────────────────────────────────────────────────

info "Building release module..."
(
    cd "${CRATE_DIR}"
    NGINX_SOURCE_DIR="${NGINX_SOURCE_DIR:-${REPO_ROOT}/nginx}" \
    NGINX_BUILD_DIR="${NGINX_BUILD_DIR:-${REPO_ROOT}/nginx/objs}" \
    cargo build --release 2>&1
)
if [[ ! -f "${MODULE_PATH}" ]]; then
    echo "ERROR: module not found after build: ${MODULE_PATH}" >&2; exit 1
fi
info "Module built: ${MODULE_PATH}"

# ─── Sandbox ─────────────────────────────────────────────────────────────────

PREFIX="$(mktemp -d /tmp/ngx-otel-signal-storm.XXXXXX)"
NGINX_PID=""
FLOOD_PID=""
SIGNAL_PID=""

cleanup() {
    [[ -n "${FLOOD_PID:-}" ]]  && kill "${FLOOD_PID}"  2>/dev/null || true
    [[ -n "${SIGNAL_PID:-}" ]] && kill "${SIGNAL_PID}" 2>/dev/null || true
    [[ -n "${NGINX_PID:-}" ]]  && kill "${NGINX_PID}"  2>/dev/null || true
    echo ""
    echo "=== error.log (last 30 lines) ==="
    tail -30 "${PREFIX}/logs/error.log" 2>/dev/null || echo "(not found)"
    info "Tearing down ${PREFIX}"
    rm -rf "${PREFIX}"
}
trap cleanup EXIT

mkdir -p "${PREFIX}/logs"
mkdir -p "${PREFIX}/client_body_temp"

sed \
    -e "s|@MODULE_PATH@|${MODULE_PATH}|g" \
    -e "s|@PREFIX@|${PREFIX}|g" \
    -e "s|@ERROR_LEVEL@|debug|g" \
    -e "s|@OTEL_ERROR_ARGS@|warn|g" \
    -e "s|@COALESCE_FLAG@|on|g" \
    -e "s|@LISTEN_PORT@|${LISTEN_PORT}|g" \
    "${CONF_TEMPLATE}" > "${PREFIX}/nginx.conf"

# Snapshot collector size before test.
PRE_LOGS_SIZE=0
[[ -f "${LOGS_LOG}" ]] && PRE_LOGS_SIZE=$(wc -c < "${LOGS_LOG}")

# ─── Start nginx ──────────────────────────────────────────────────────────────

info "Starting nginx..."
"${NGINX_BINARY}" -p "${PREFIX}" -c "${PREFIX}/nginx.conf" &
NGINX_PID=$!
sleep 1

if ! kill -0 "${NGINX_PID}" 2>/dev/null; then
    echo "ERROR: nginx exited immediately. Check ${PREFIX}/logs/error.log" >&2
    cat "${PREFIX}/logs/error.log" >&2
    exit 1
fi
info "nginx master running (PID ${NGINX_PID})"

# ─── Storm loop (background) ─────────────────────────────────────────────────

# Flood: continuous /flood requests for STORM_DURATION_S seconds.
(
    END=$(( $(date +%s) + STORM_DURATION_S ))
    while (( $(date +%s) < END )); do
        curl -sf "http://127.0.0.1:${LISTEN_PORT}/flood" >/dev/null 2>&1 || true
    done
    info "Flood loop finished."
) &
FLOOD_PID=$!

# Signal storm: send SIGUSR1 to nginx master every 1 second.
# SIGUSR1 causes nginx to reopen log files, which triggers internal
# ngx_log_error(NOTICE, ...) calls — exercises re-entrancy with the flood.
(
    END=$(( $(date +%s) + STORM_DURATION_S ))
    while (( $(date +%s) < END )); do
        # SIGUSR1 to master → reopen logs (logs a NOTICE internally).
        kill -USR1 "${NGINX_PID}" 2>/dev/null || true
        sleep 1
    done
    info "Signal storm finished."
) &
SIGNAL_PID=$!

info "Storm running (${STORM_DURATION_S}s flood + SIGUSR1 storm)..."

# Wait for both loops.
wait "${FLOOD_PID}" 2>/dev/null || true
wait "${SIGNAL_PID}" 2>/dev/null || true
FLOOD_PID=""
SIGNAL_PID=""

info "Storm complete."

# ─── Wait for export flush ────────────────────────────────────────────────────

info "Waiting ${FLUSH_WAIT_S}s for final export flush..."
sleep "${FLUSH_WAIT_S}"

# ─── Graceful shutdown ───────────────────────────────────────────────────────

info "Sending nginx -s quit..."
"${NGINX_BINARY}" -p "${PREFIX}" -c "${PREFIX}/nginx.conf" -s quit 2>/dev/null || true
for i in $(seq 1 15); do
    if ! kill -0 "${NGINX_PID}" 2>/dev/null; then break; fi
    sleep 1
done

# HARD: nginx must have exited gracefully (not crashed).
if kill -0 "${NGINX_PID}" 2>/dev/null; then
    hard_fail "nginx did not exit after graceful quit — may be hung"
    kill -9 "${NGINX_PID}" 2>/dev/null || true
else
    pass "nginx exited gracefully after signal storm"
fi
NGINX_PID=""

sleep 1

# ─── Assertions ──────────────────────────────────────────────────────────────

info "Running assertions..."

ERROR_LOG="${PREFIX}/logs/error.log"

# HARD: no "panicked at" in error.log (Rust panic during signal handling).
if grep -q "panicked at" "${ERROR_LOG}" 2>/dev/null; then
    hard_fail "Rust panic found in error.log:"
    grep "panicked at" "${ERROR_LOG}" >&2
else
    pass "No Rust panics in error.log"
fi

# HARD: no "signal 6" (SIGABRT, abort from assert/panic) in error.log.
if grep -qE "signal 6|signal(6)" "${ERROR_LOG}" 2>/dev/null; then
    hard_fail "SIGABRT (signal 6) found in error.log — possible assertion failure"
    grep -E "signal 6|signal(6)" "${ERROR_LOG}" >&2
else
    pass "No SIGABRT (signal 6) in error.log"
fi

# HARD: no "signal 11" (SIGSEGV, segfault) in error.log.
if grep -qE "signal 11|signal(11)" "${ERROR_LOG}" 2>/dev/null; then
    hard_fail "SIGSEGV (signal 11) found in error.log — segfault during storm"
    grep -E "signal 11|signal(11)" "${ERROR_LOG}" >&2
else
    pass "No SIGSEGV (signal 11) in error.log"
fi

# HARD: no ThreadSanitizer warnings (belt-and-suspenders; halt_on_error=1 would
# already have caused a crash, but check anyway).
if grep -q "WARNING: ThreadSanitizer" "${ERROR_LOG}" 2>/dev/null; then
    hard_fail "ThreadSanitizer warning found in error.log:"
    grep "WARNING: ThreadSanitizer" "${ERROR_LOG}" >&2
else
    pass "No ThreadSanitizer warnings in error.log"
fi

# HARD: drain progressed — LOGS_LOG grew during the storm.
POST_LOGS_SIZE=0
[[ -f "${LOGS_LOG}" ]] && POST_LOGS_SIZE=$(wc -c < "${LOGS_LOG}")
if (( POST_LOGS_SIZE > PRE_LOGS_SIZE )); then
    NEW_LOGS=$(tail -c "+$(( PRE_LOGS_SIZE + 1 ))" "${LOGS_LOG}")
    LOG_BYTES=$(( POST_LOGS_SIZE - PRE_LOGS_SIZE ))
    pass "Drain progressed — LOGS_LOG grew by ${LOG_BYTES} bytes during storm"
else
    hard_fail "LOGS_LOG did not grow — drain may be stalled or writer not active"
fi

# HARD: no torn records — every line in new LOGS_LOG content is valid JSON.
if [[ -n "${NEW_LOGS:-}" ]]; then
    TORN=0
    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        if ! echo "${line}" | python3 -c "import sys, json; json.load(sys.stdin)" 2>/dev/null; then
            TORN=$(( TORN + 1 ))
            echo "[TORN] ${line:0:120}" >&2
        fi
    done <<< "${NEW_LOGS}"
    if (( TORN > 0 )); then
        hard_fail "${TORN} torn (invalid JSON) record(s) found in LOGS_LOG during storm"
    else
        pass "All LOGS_LOG records are valid JSON (no torn records)"
    fi
fi

# Informational: how many nginx.error records arrived?
# `grep -o` exits 1 on zero matches; under `set -o pipefail` that fired the old
# `|| echo 0` fallback *in addition to* wc's own "0", producing "0\n0" and a
# `(( ))` syntax error below. Swallow the no-match failure inside the pipeline so
# wc is the single source of the count.
ERROR_LOG_COUNT=$(echo "${NEW_LOGS:-}" | { grep -o '"nginx\.error"' || true; } | wc -l | tr -d ' ')
info "nginx.error records in LOGS_LOG during storm: ${ERROR_LOG_COUNT}"
if (( ERROR_LOG_COUNT > 0 )); then
    pass "nginx.error records arrived during storm (coalescer active under signals)"
else
    info "  (no nginx.error records — may be normal if flood was too short for drain)"
fi

# ─── Final result ─────────────────────────────────────────────────────────────

echo ""
if [[ "${FAILED}" -eq 0 ]]; then
    pass "All signal-storm re-entrancy assertions passed."
    exit 0
else
    hard_fail "One or more signal-storm assertions FAILED."
    exit 2
fi
