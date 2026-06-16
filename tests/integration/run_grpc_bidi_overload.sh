#!/usr/bin/env bash
# tests/integration/run_grpc_bidi_overload.sh — bidi backpressure / livelock
# integration test.
#
# Sets up a 10× rate mismatch:
#   - Echo server: 127.0.0.1:4320 with BIDI_ECHO_DELAY_MS=10 (~100 pong/s)
#   - nginx worker: fires 1 000 ping/s with a 5 ms give-up deadline
#
# This guarantees give_up (5 ms) < server RTT (10 ms) so the channel will
# fill and poll_ready will time out, exercising the give-up drop path and
# incrementing BIDI_BACKPRESSURE_DROPS.
#
# Assertions (7 total):
#   1. error.log contains exactly 1 "bidi overload: sent=..." summary line.
#   2. "dropped" field in the summary line is > 0.
#   3. "received" field in the summary line is > 0.
#   4. error.log contains zero "bidi overload: failed" lines.
#   5. error.log contains zero panic / SIGSEGV / SIGABRT lines.
#   6. HTTP responsiveness p99 < 50 ms during the overload.
#   7. Worker RSS at end < 2× worker RSS at start.
#
# Exit codes:
#   0  all assertions pass
#   1  pre-flight / build failure
#   2  a test assertion failed
#
# Environment (all have defaults):
#   BIDI_OVERLOAD_DURATION_S       — overload duration in seconds (default: 10)
#   BIDI_OVERLOAD_MESSAGES_PER_SEC — target send rate (default: 1000)
#   BIDI_OVERLOAD_GIVE_UP_MS       — per-send deadline in ms (default: 5)
#   BIDI_ECHO_DELAY_MS             — per-pong delay on echo server (default: 10)
#   NGINX_BINARY / NGINX_SOURCE_DIR / NGINX_BUILD_DIR — standard overrides

set -euo pipefail

# ─── Resolve paths ────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPO_ROOT="$(cd "${CRATE_DIR}/.." && pwd)"

NGINX_BINARY="${NGINX_BINARY:-${REPO_ROOT}/nginx/objs/nginx}"
NGINX_SOURCE_DIR="${NGINX_SOURCE_DIR:-${REPO_ROOT}/nginx}"
NGINX_BUILD_DIR="${NGINX_BUILD_DIR:-${REPO_ROOT}/nginx/objs}"
export NGINX_SOURCE_DIR NGINX_BUILD_DIR

# Source the shared harness library.
. "${CRATE_DIR}/test-harness/lib.sh"
resolve_nginx_binary || true

# Detect module extension.
case "$(uname -s)" in
    Darwin) MODULE_EXT="dylib" ;;
    *)      MODULE_EXT="so"    ;;
esac
# When CARGO_BUILD_TARGET is set (e.g., the TSAN gate uses --target so cargo
# can also -Zbuild-std), cargo writes its output to target/<triple>/release/
# rather than target/release/.  Backwards-compatible: unset -> original path.
if [[ -n "${CARGO_BUILD_TARGET:-}" ]]; then
    MODULE_PATH="${CRATE_DIR}/target/${CARGO_BUILD_TARGET}/release/libngx_http_otel_module.${MODULE_EXT}"
else
    MODULE_PATH="${CRATE_DIR}/target/release/libngx_http_otel_module.${MODULE_EXT}"
fi

# ─── Test parameters ──────────────────────────────────────────────────────────

OVERLOAD_DURATION_S="${BIDI_OVERLOAD_DURATION_S:-10}"
OVERLOAD_MSG_PER_SEC="${BIDI_OVERLOAD_MESSAGES_PER_SEC:-1000}"
OVERLOAD_GIVE_UP_MS="${BIDI_OVERLOAD_GIVE_UP_MS:-5}"
ECHO_DELAY_MS="${BIDI_ECHO_DELAY_MS:-10}"

ECHO_PORT=4320
NGINX_HTTP_PORT=9105

# ─── Colour helpers ───────────────────────────────────────────────────────────

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*" >&2; FAILED=1; }
info() { echo -e "${YELLOW}[INFO]${NC} $*"; }

FAILED=0
ECHO_PID=""
NGINX_PID=""
PROBE_PID=""
RSS_PID=""

# ─── Pre-flight checks ────────────────────────────────────────────────────────

info "Pre-flight checks..."

if [[ ! -x "${NGINX_BINARY}" ]]; then
    echo "ERROR: nginx binary not found at ${NGINX_BINARY}" >&2
    exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
    echo "ERROR: curl not found on PATH (needed for responsiveness probe)" >&2
    exit 1
fi

# ─── Build the module WITH test-support feature ───────────────────────────────

info "Building release module with --features test-support..."
(
    cd "${CRATE_DIR}"
    NGINX_SOURCE_DIR="${NGINX_SOURCE_DIR}" \
    NGINX_BUILD_DIR="${NGINX_BUILD_DIR}" \
    cargo build --release --features test-support 2>&1
)
if [[ ! -f "${MODULE_PATH}" ]]; then
    echo "ERROR: module not found after build: ${MODULE_PATH}" >&2
    exit 1
fi
info "Module built: ${MODULE_PATH}"

# ─── Build the echo server example (release for accurate timing) ──────────────

info "Building bidi echo server example (release)..."
(
    cd "${CRATE_DIR}"
    NGINX_SOURCE_DIR="${NGINX_SOURCE_DIR}" \
    NGINX_BUILD_DIR="${NGINX_BUILD_DIR}" \
    cargo build --release --example bidi_echo_server 2>&1
)
ECHO_BINARY="${CRATE_DIR}/target/release/examples/bidi_echo_server"
if [[ ! -x "${ECHO_BINARY}" ]]; then
    # fall back to debug build location
    ECHO_BINARY="${CRATE_DIR}/target/debug/examples/bidi_echo_server"
fi
if [[ ! -x "${ECHO_BINARY}" ]]; then
    echo "ERROR: bidi_echo_server binary not found" >&2
    exit 1
fi
info "Echo server: ${ECHO_BINARY}"

# ─── Sandbox ──────────────────────────────────────────────────────────────────

PREFIX="$(mktemp -d /tmp/ngx-otel-grpc-bidi-overload.XXXXXX)"

# Temp files for background probes.
PROBE_FILE="${PREFIX}/probe_latencies.txt"
RSS_FILE="${PREFIX}/rss_readings.txt"
touch "${PROBE_FILE}" "${RSS_FILE}"

cleanup() {
    [[ -n "${PROBE_PID:-}" ]] && kill "${PROBE_PID}" 2>/dev/null || true
    [[ -n "${RSS_PID:-}"   ]] && kill "${RSS_PID}"   2>/dev/null || true
    [[ -n "${ECHO_PID:-}"  ]] && kill "${ECHO_PID}"  2>/dev/null || true
    [[ -n "${NGINX_PID:-}" ]] && kill "${NGINX_PID}" 2>/dev/null || true
    echo ""
    echo "=== error.log: bidi overload lines ==="
    grep -aE "bidi overload|panicked|signal [0-9]+|exited on signal" \
        "${PREFIX}/logs/error.log" 2>/dev/null | head -30 || echo "(not found)"
    info "Tearing down ${PREFIX} (skipped if KEEP_SANDBOX=1)"
    [[ "${KEEP_SANDBOX:-0}" == "1" ]] || rm -rf "${PREFIX}"
}
trap cleanup EXIT

mkdir -p "${PREFIX}/logs"
mkdir -p "${PREFIX}/client_body_temp"

# ─── Start the bidi echo server (with artificial per-pong delay) ──────────────

# Clear any leftover process on the echo port.
if nc -z 127.0.0.1 "${ECHO_PORT}" 2>/dev/null; then
    info "Port ${ECHO_PORT} already in use; clearing..."
    lsof -ti :"${ECHO_PORT}" 2>/dev/null | xargs kill -9 2>/dev/null || true
    sleep 0.5
fi

info "Launching echo server on 127.0.0.1:${ECHO_PORT} (delay=${ECHO_DELAY_MS}ms)..."
BIDI_ECHO_BIND="127.0.0.1:${ECHO_PORT}" \
BIDI_ECHO_DELAY_MS="${ECHO_DELAY_MS}" \
    "${ECHO_BINARY}" >"${PREFIX}/logs/echo_server.log" 2>&1 &
ECHO_PID=$!

# Wait up to 4 s for the echo server to bind.
ECHO_READY=0
for _ in $(seq 1 20); do
    if nc -z 127.0.0.1 "${ECHO_PORT}" 2>/dev/null; then
        ECHO_READY=1; break
    fi
    sleep 0.2
done
if [[ "${ECHO_READY}" -eq 0 ]]; then
    echo "ERROR: echo server did not bind to port ${ECHO_PORT}" >&2
    exit 1
fi
info "Echo server ready (PID ${ECHO_PID})"

# ─── Write nginx config ────────────────────────────────────────────────────────

# env directives in the main context allow nginx workers to inherit these
# env vars, which fire_bidi_overload reads via std::env::var.
cat > "${PREFIX}/nginx.conf" <<EOF
daemon off;
master_process on;
worker_processes 1;
worker_shutdown_timeout 3s;
error_log ${PREFIX}/logs/error.log debug;
pid       ${PREFIX}/logs/nginx.pid;

# Allow workers to inherit the overload-control env vars.
env BIDI_OVERLOAD_DURATION_S;
env BIDI_OVERLOAD_MESSAGES_PER_SEC;
env BIDI_OVERLOAD_GIVE_UP_MS;

load_module ${MODULE_PATH};

events {
    worker_connections 64;
}

http {
    # Phase 1.1 OTLP/HTTP exporter — keeps is_configured() gate open.
    otel_exporter {
        endpoint http://127.0.0.1:4318;
    }
    otel_service_name ngx-otel-bidi-overload;
    otel_metric_interval 60s;

    # Phase 1.2 Item 3: bidi overload endpoint.
    otel_grpc_bidi_overload_endpoint http://127.0.0.1:${ECHO_PORT};

    server {
        listen 127.0.0.1:${NGINX_HTTP_PORT};
        location / {
            return 200 "ok\n";
        }
    }
}
EOF

info "Sandbox: ${PREFIX}"
info "Overload params: duration=${OVERLOAD_DURATION_S}s rate=${OVERLOAD_MSG_PER_SEC}msg/s give_up=${OVERLOAD_GIVE_UP_MS}ms echo_delay=${ECHO_DELAY_MS}ms"

# ─── Start nginx ──────────────────────────────────────────────────────────────

info "Starting nginx (1 worker)..."
BIDI_OVERLOAD_DURATION_S="${OVERLOAD_DURATION_S}" \
BIDI_OVERLOAD_MESSAGES_PER_SEC="${OVERLOAD_MSG_PER_SEC}" \
BIDI_OVERLOAD_GIVE_UP_MS="${OVERLOAD_GIVE_UP_MS}" \
    "${NGINX_BINARY}" -p "${PREFIX}" -c "${PREFIX}/nginx.conf" &
NGINX_PID=$!

# Wait up to 4 s for nginx to start and listen on the HTTP port.
NGINX_READY=0
for _ in $(seq 1 20); do
    if nc -z 127.0.0.1 "${NGINX_HTTP_PORT}" 2>/dev/null; then
        NGINX_READY=1; break
    fi
    sleep 0.2
done
if [[ "${NGINX_READY}" -eq 0 ]]; then
    echo "ERROR: nginx did not listen on port ${NGINX_HTTP_PORT} within 4s" >&2
    exit 1
fi
info "nginx ready (PID ${NGINX_PID})"

# ─── Record initial worker RSS ────────────────────────────────────────────────

# Locate the worker PID from nginx's pid file or by searching for worker proc.
# Worker spawned right after master; allow 0.5 s for it to appear.
sleep 0.5
WORKER_PID=""
if [[ -f "${PREFIX}/logs/nginx.pid" ]]; then
    MASTER_PID="$(cat "${PREFIX}/logs/nginx.pid")"
    # Find the child process of the master.
    WORKER_PID="$(pgrep -P "${MASTER_PID}" 2>/dev/null | head -1 || true)"
fi
if [[ -z "${WORKER_PID}" ]]; then
    # Fallback: find nginx processes, pick the one that is NOT master.
    WORKER_PID="$(pgrep -f "nginx: worker process" 2>/dev/null | head -1 || true)"
fi

RSS_START=0
if [[ -n "${WORKER_PID}" ]]; then
    RSS_START="$(ps -o rss= -p "${WORKER_PID}" 2>/dev/null | tr -d ' ' || echo 0)"
    info "Worker PID ${WORKER_PID}, RSS at start: ${RSS_START} KB"
    echo "${RSS_START}" >> "${RSS_FILE}"
else
    info "Could not locate worker PID; RSS assertion will be skipped"
fi

# ─── Background: responsiveness probe ─────────────────────────────────────────
# Hits the nginx HTTP endpoint every ~200 ms during the overload and records
# the total response time (in seconds).  Runs for overload duration + 5 s.

PROBE_URL="http://127.0.0.1:${NGINX_HTTP_PORT}/"
PROBE_TOTAL_S=$(( OVERLOAD_DURATION_S + 5 ))

(
    END_TS=$(( SECONDS + PROBE_TOTAL_S ))
    while (( SECONDS < END_TS )); do
        # --connect-timeout 1: fail fast if nginx is dead.
        T="$(curl -s -o /dev/null --connect-timeout 1 \
                  -w '%{time_total}' "${PROBE_URL}" 2>/dev/null || echo '9.999')"
        echo "${T}" >> "${PROBE_FILE}"
        sleep 0.2
    done
) &
PROBE_PID=$!

# ─── Background: RSS monitor ──────────────────────────────────────────────────

if [[ -n "${WORKER_PID}" ]]; then
    (
        END_TS=$(( SECONDS + OVERLOAD_DURATION_S + 10 ))
        while (( SECONDS < END_TS )); do
            R="$(ps -o rss= -p "${WORKER_PID}" 2>/dev/null | tr -d ' ' || echo 0)"
            echo "${R}" >> "${RSS_FILE}"
            sleep 5
        done
    ) &
    RSS_PID=$!
fi

# ─── Wait for the overload summary log line ───────────────────────────────────

WAIT_LIMIT=$(( OVERLOAD_DURATION_S + 15 ))
info "Waiting up to ${WAIT_LIMIT}s for overload to complete..."
DEADLINE=$(( SECONDS + WAIT_LIMIT ))
SUMMARY_FOUND=0
while (( SECONDS < DEADLINE )); do
    if grep -q "bidi overload: sent=" "${PREFIX}/logs/error.log" 2>/dev/null; then
        SUMMARY_FOUND=1
        break
    fi
    sleep 1
done

if [[ "${SUMMARY_FOUND}" -eq 0 ]]; then
    fail "Timed out waiting for 'bidi overload: sent=' in error.log"
fi

# Allow background probes a moment to collect a final sample.
sleep 1

# ─── Graceful shutdown ────────────────────────────────────────────────────────

info "Sending nginx -s quit..."
"${NGINX_BINARY}" -p "${PREFIX}" -c "${PREFIX}/nginx.conf" -s quit 2>/dev/null || true
for _ in $(seq 1 15); do
    if ! kill -0 "${NGINX_PID}" 2>/dev/null; then break; fi
    sleep 0.5
done
NGINX_PID=""

kill "${PROBE_PID}" 2>/dev/null || true; PROBE_PID=""
kill "${RSS_PID}"   2>/dev/null || true; RSS_PID=""
kill "${ECHO_PID}"  2>/dev/null || true; ECHO_PID=""

# ─── Extract summary line fields ──────────────────────────────────────────────

SUMMARY_LINE="$(grep "bidi overload: sent=" "${PREFIX}/logs/error.log" 2>/dev/null | tail -1 || true)"
info "Summary: ${SUMMARY_LINE}"

# Parse sent=N received=N dropped=N from the summary line.
SENT_VAL=0; RECEIVED_VAL=0; DROPPED_VAL=0
if [[ -n "${SUMMARY_LINE}" ]]; then
    SENT_VAL="$(echo "${SUMMARY_LINE}"    | grep -oE 'sent=[0-9]+'    | cut -d= -f2 || echo 0)"
    RECEIVED_VAL="$(echo "${SUMMARY_LINE}" | grep -oE 'received=[0-9]+' | cut -d= -f2 || echo 0)"
    DROPPED_VAL="$(echo "${SUMMARY_LINE}"  | grep -oE 'dropped=[0-9]+'  | cut -d= -f2 || echo 0)"
fi

# ─── Assertions ───────────────────────────────────────────────────────────────

info "Running assertions..."

# 1. Exactly one summary line.
SUMMARY_COUNT=$(grep -c "bidi overload: sent=" "${PREFIX}/logs/error.log" 2>/dev/null) || SUMMARY_COUNT=0
if [[ "${SUMMARY_COUNT}" -eq 1 ]]; then
    pass "error.log: exactly 1 'bidi overload: sent=' summary line"
else
    fail "error.log: expected 1 summary line, got ${SUMMARY_COUNT}"
fi

# 2. dropped > 0: backpressure give-up path was exercised.
if [[ "${DROPPED_VAL}" -gt 0 ]]; then
    pass "dropped=${DROPPED_VAL} > 0 (backpressure give-up path exercised)"
else
    fail "dropped=${DROPPED_VAL}: expected dropped > 0 (give-up path not triggered).
       Summary: ${SUMMARY_LINE}"
fi

# 3. received > 0: at least some pongs arrived.
if [[ "${RECEIVED_VAL}" -gt 0 ]]; then
    pass "received=${RECEIVED_VAL} > 0 (stream was functional)"
else
    fail "received=${RECEIVED_VAL}: expected received > 0.
       Summary: ${SUMMARY_LINE}
       Note: echo server may not have started or port ${ECHO_PORT} was unreachable."
fi

# 4. Zero "bidi overload: failed" lines.
FAIL_COUNT=$(grep -c "bidi overload: failed" "${PREFIX}/logs/error.log" 2>/dev/null) || FAIL_COUNT=0
if [[ "${FAIL_COUNT}" -eq 0 ]]; then
    pass "error.log: zero 'bidi overload: failed' lines"
else
    fail "error.log: ${FAIL_COUNT} 'bidi overload: failed' lines:
$(grep -aE 'bidi overload: failed' "${PREFIX}/logs/error.log" | head -5)"
fi

# 5. No panics / crash signals.
PANIC_COUNT=$(grep -cE "panicked|signal 11|signal 6|exited on signal" \
    "${PREFIX}/logs/error.log" 2>/dev/null) || PANIC_COUNT=0
if [[ "${PANIC_COUNT}" -eq 0 ]]; then
    pass "error.log: zero panic / SIGSEGV / SIGABRT / crash-signal lines"
else
    fail "error.log: ${PANIC_COUNT} crash/panic-related lines:
$(grep -aE 'panicked|signal 11|signal 6|exited on signal' "${PREFIX}/logs/error.log" | head -10)"
fi

# 6. HTTP responsiveness p99 < 50 ms.
PROBE_COUNT="$(wc -l < "${PROBE_FILE}" | tr -d ' ')"
if [[ "${PROBE_COUNT}" -gt 0 ]]; then
    # Sort latencies numerically and pick the 99th percentile.
    P99="$(sort -n "${PROBE_FILE}" | awk -v n="${PROBE_COUNT}" \
        'BEGIN { idx=int(n*0.99); if(idx<1)idx=1 }
         NR==idx { print $1; exit }')"
    # Convert to milliseconds for comparison (P99 is in seconds, e.g. "0.003").
    P99_MS="$(awk "BEGIN { printf \"%.0f\", ${P99} * 1000 }")"
    if [[ "${P99_MS}" -lt 50 ]]; then
        pass "HTTP p99 latency = ${P99_MS} ms < 50 ms (nginx event loop responsive)"
    else
        fail "HTTP p99 latency = ${P99_MS} ms >= 50 ms (event loop may be blocked).
       Probe file (first 10 lines): $(head -10 "${PROBE_FILE}")"
    fi
else
    fail "Responsiveness probe collected 0 samples (curl may have failed)"
fi

# 7. Worker RSS at end < 2× RSS at start (no memory leak from dropping pings).
if [[ -n "${WORKER_PID:-}" ]] && [[ "${RSS_START}" -gt 0 ]]; then
    RSS_MAX="$(sort -n "${RSS_FILE}" | tail -1 | tr -d ' ')"
    RSS_LIMIT=$(( RSS_START * 2 ))
    if [[ "${RSS_MAX}" -lt "${RSS_LIMIT}" ]]; then
        pass "Worker RSS peak=${RSS_MAX} KB < 2× start=${RSS_LIMIT} KB (no memory leak)"
    else
        fail "Worker RSS peak=${RSS_MAX} KB >= 2× start=${RSS_LIMIT} KB (possible memory leak).
       RSS readings: $(cat "${RSS_FILE}")"
    fi
else
    info "Worker PID not determined or RSS_START=0; skipping RSS assertion"
fi

# ─── Summary ──────────────────────────────────────────────────────────────────

echo ""
info "sent=${SENT_VAL} received=${RECEIVED_VAL} dropped=${DROPPED_VAL}"
if [[ "${FAILED}" -eq 0 ]]; then
    pass "All assertions passed.  Phase 1.2 Item 3 bidi backpressure overload COMPLETE."
    exit 0
else
    echo -e "${RED}One or more assertions FAILED.${NC}" >&2
    exit 2
fi
