#!/usr/bin/env bash
# tests/integration/run_grpc_export.sh — Phase 2 (grpc_transport) production
# OTLP/gRPC export end-to-end integration test.
#
# Builds the module WITHOUT --features test-support (production path).
# Starts nginx with `otel_export_protocol otlp_grpc;` pointing at the
# collector's OTLP/gRPC receiver (127.0.0.1:4317).  Sends HTTP traffic,
# waits for a metric flush, then asserts:
#
#   1. error.log contains "protocol=otlp_grpc" in the "export loop started"
#      line — confirming the gRPC transport was selected.
#   2. metrics.json delta contains the expected service.name — confirming
#      the collector actually received metrics via the gRPC receiver.
#   3. metrics.json delta contains http.server.request.duration — end-to-end
#      metric pipeline is intact.
#   4. error.log shows exactly 1 "export loop started" line.
#   5. Graceful-drain integrity (start matches complete when drain fired).
#   6. Workers hold zero collector sockets — none of the nginx worker
#      processes should have an open connection to 4317 or 4318.
#
# Prerequisites
# ─────────────
# - Docker available on PATH (collector auto-started by lib.sh).
# - NGINX binary + source + build dirs as used by the project (see README).
#
# Exit codes
# ──────────
#   0  all assertions passed
#   1  pre-flight or build failure
#   2  a test assertion failed

set -euo pipefail

# ─── Resolve paths ───────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPO_ROOT="$(cd "${CRATE_DIR}/.." && pwd)"

NGINX_BINARY="${NGINX_BINARY:-${REPO_ROOT}/nginx/objs/nginx}"
NGINX_SOURCE_DIR="${NGINX_SOURCE_DIR:-${REPO_ROOT}/nginx}"
NGINX_BUILD_DIR="${NGINX_BUILD_DIR:-${REPO_ROOT}/nginx/objs}"
export NGINX_SOURCE_DIR NGINX_BUILD_DIR

. "${CRATE_DIR}/test-harness/lib.sh"
resolve_nginx_binary || true

case "$(uname -s)" in
    Darwin) MODULE_EXT="dylib" ;;
    *)      MODULE_EXT="so"    ;;
esac
MODULE_PATH="${CRATE_DIR}/target/release/libngx_http_otel_module.${MODULE_EXT}"

SERVICE_NAME="ngx-otel-grpc-export-integration"
GRPC_ENDPOINT="http://127.0.0.1:4317"
# Port 9105 — distinct from run.sh (9100), reload tests, and smoke (9103).
NGINX_PORT=9105
METRIC_INTERVAL_S=2
FLUSH_WAIT_S=$(( METRIC_INTERVAL_S + 3 ))
N_REQUESTS=20

# ─── Colour helpers ──────────────────────────────────────────────────────────

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass()  { echo -e "${GREEN}[PASS]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*" >&2; FAILED=1; }
info()  { echo -e "${YELLOW}[INFO]${NC} $*"; }

FAILED=0

# ─── Pre-flight checks ───────────────────────────────────────────────────────

info "Pre-flight checks..."

if [[ ! -x "${NGINX_BINARY}" ]]; then
    echo "ERROR: nginx binary not found at ${NGINX_BINARY}" >&2
    echo "       Set NGINX_BINARY to the correct path." >&2
    exit 1
fi

ensure_collector_running || exit 1

# ─── Build module (production — no --features test-support) ──────────────────

info "Building release module (production build, no test-support)..."
(
    cd "${CRATE_DIR}"
    NGINX_SOURCE_DIR="${NGINX_SOURCE_DIR}" \
    NGINX_BUILD_DIR="${NGINX_BUILD_DIR}" \
    cargo build --release 2>&1
)
if [[ ! -f "${MODULE_PATH}" ]]; then
    echo "ERROR: module not found after build: ${MODULE_PATH}" >&2
    exit 1
fi
info "Module built: ${MODULE_PATH}"

# ─── Sandbox prefix directory ────────────────────────────────────────────────

PREFIX="$(mktemp -d /tmp/ngx-otel-grpc-export.XXXXXX)"
cleanup() {
    [[ -n "${NGINX_PID:-}" ]] && kill "${NGINX_PID}" 2>/dev/null || true
    echo ""
    echo "=== error.log (first 40 lines) ==="
    head -40 "${PREFIX}/logs/error.log" 2>/dev/null || echo "(not found)"
    echo "..."
    echo "=== error.log (last 30 lines) ==="
    tail -30 "${PREFIX}/logs/error.log" 2>/dev/null
    info "Tearing down ${PREFIX}"
    rm -rf "${PREFIX}"
}
trap cleanup EXIT

mkdir -p "${PREFIX}/logs"
mkdir -p "${PREFIX}/client_body_temp"

# Write the nginx configuration with gRPC transport selected.
cat > "${PREFIX}/nginx.conf" <<EOF
daemon off;
master_process on;
worker_processes 2;
worker_shutdown_timeout 5s;
error_log ${PREFIX}/logs/error.log debug;
pid       ${PREFIX}/logs/nginx.pid;

load_module ${MODULE_PATH};

events {
    worker_connections 64;
}

http {
    otel_exporter {
        # gRPC origin: http://host:port (no /v1/metrics path).
        endpoint ${GRPC_ENDPOINT};
    }
    otel_service_name ${SERVICE_NAME};
    otel_metric_interval ${METRIC_INTERVAL_S}s;
    otel_export_protocol otlp_grpc;

    server {
        listen 127.0.0.1:${NGINX_PORT};
        location / {
            return 200 "grpc-export-test ok\n";
        }
    }
}
EOF

info "Sandbox: ${PREFIX}"

# ─── Snapshot metrics.json BEFORE starting nginx ─────────────────────────────

PRE_SIZE=0
if [[ -f "${METRICS_LOG}" ]]; then
    PRE_SIZE=$(wc -c < "${METRICS_LOG}")
fi
info "metrics.json pre-size: ${PRE_SIZE} bytes"

# ─── Start nginx ─────────────────────────────────────────────────────────────

info "Starting nginx with otel_export_protocol otlp_grpc..."
"${NGINX_BINARY}" \
    -p "${PREFIX}" \
    -c "${PREFIX}/nginx.conf" &
NGINX_PID=$!

sleep 1

if ! kill -0 "${NGINX_PID}" 2>/dev/null; then
    echo "ERROR: nginx exited immediately. Check ${PREFIX}/logs/error.log" >&2
    cat "${PREFIX}/logs/error.log" >&2
    exit 1
fi
info "nginx running (PID ${NGINX_PID})"

# ─── Find worker PIDs (for socket check) ─────────────────────────────────────
#
# Worker PIDs are the nginx worker children of the master.  We record them now
# (before traffic) to run the lsof check.  On both macOS and Linux, pgrep with
# the parent PID filter finds the right children.  We exclude the exporter
# process by only looking at processes named "nginx: worker process".
MASTER_PID="${NGINX_PID}"

# Give master time to fork workers.
sleep 0.5

WORKER_PIDS=()
while IFS= read -r wpid; do
    WORKER_PIDS+=("${wpid}")
done < <(
    ps -eo pid,ppid,args 2>/dev/null \
    | awk -v ppid="${MASTER_PID}" '$2==ppid && /nginx: worker process/ {print $1}' \
    | head -8
)
info "Worker PIDs: ${WORKER_PIDS[*]:-<none found>}"

# ─── Send HTTP traffic ───────────────────────────────────────────────────────

info "Sending ${N_REQUESTS} requests to http://127.0.0.1:${NGINX_PORT}/..."
for i in $(seq 1 "${N_REQUESTS}"); do
    curl -sf "http://127.0.0.1:${NGINX_PORT}/" >/dev/null
done
info "Traffic sent."

# ─── Wait for metrics flush ───────────────────────────────────────────────────

info "Waiting ${FLUSH_WAIT_S}s for gRPC metrics flush (interval=${METRIC_INTERVAL_S}s)..."
sleep "${FLUSH_WAIT_S}"

# ─── Worker socket check (before shutdown) ───────────────────────────────────
#
# No worker should hold a connection to the collector's gRPC (4317) or HTTP
# (4318) ports.  The exporter process owns the gRPC connection; workers only
# write to shm.
SOCKET_FAIL=0
if [[ ${#WORKER_PIDS[@]} -gt 0 ]]; then
    for wpid in "${WORKER_PIDS[@]}"; do
        if ! kill -0 "${wpid}" 2>/dev/null; then
            info "Worker ${wpid} no longer running (skip socket check)"
            continue
        fi
        # lsof -p PID -nP -i lists internet files for the given PID.
        # On macOS, lsof may show other processes' connections to the same port
        # in the output (context rows).  We filter to rows where the PID column
        # matches the worker PID to check ONLY sockets OWNED by that worker.
        # The connection to port 4317 is owned by the exporter process, not workers.
        COLLECTOR_SOCKS=$(
            lsof -p "${wpid}" -nP -i 2>/dev/null \
            | awk -v pid="${wpid}" '$2==pid && /:4317|:4318/' \
            || true
        )
        if [[ -n "${COLLECTOR_SOCKS}" ]]; then
            fail "Worker ${wpid} owns collector socket(s):
${COLLECTOR_SOCKS}"
            SOCKET_FAIL=1
        fi
    done
    if [[ "${SOCKET_FAIL}" -eq 0 ]]; then
        pass "Workers hold zero collector sockets (workers own no 4317/4318 fds)"
    fi
else
    info "No worker PIDs found — skipping lsof socket check (workers may have exited already)"
fi

# ─── Graceful shutdown ───────────────────────────────────────────────────────

info "Sending nginx -s quit (graceful drain)..."
"${NGINX_BINARY}" \
    -p "${PREFIX}" \
    -c "${PREFIX}/nginx.conf" \
    -s quit 2>/dev/null || true

for _ in $(seq 1 15); do
    if ! kill -0 "${NGINX_PID}" 2>/dev/null; then
        break
    fi
    sleep 1
done
NGINX_PID=""

# ─── Collect metrics.json delta ──────────────────────────────────────────────

NEW_CONTENT=""
if [[ -f "${METRICS_LOG}" ]]; then
    POST_SIZE=$(wc -c < "${METRICS_LOG}")
    if (( POST_SIZE > PRE_SIZE )); then
        NEW_CONTENT=$(tail -c "+$(( PRE_SIZE + 1 ))" "${METRICS_LOG}")
    fi
fi

# ─── Assertions ──────────────────────────────────────────────────────────────

info "Running assertions..."

# 1. error.log confirms protocol=otlp_grpc was selected
PROTO_LINE=$(grep "export loop started" "${PREFIX}/logs/error.log" 2>/dev/null | grep "protocol=otlp_grpc" || true)
if [[ -n "${PROTO_LINE}" ]]; then
    pass "error.log: export loop started with protocol=otlp_grpc"
else
    fail "error.log: no 'export loop started ... protocol=otlp_grpc' line found.
       export-loop lines:
$(grep "export loop started" "${PREFIX}/logs/error.log" | head -5)"
fi

# 2. service.name arrived at collector
if echo "${NEW_CONTENT}" | grep -q "${SERVICE_NAME}"; then
    pass "metrics.json delta contains service.name = ${SERVICE_NAME} (gRPC path confirmed)"
else
    fail "metrics.json delta does NOT contain '${SERVICE_NAME}'.
       New content (first 5 lines):
$(echo "${NEW_CONTENT}" | head -5)"
fi

# 3. http.server.request.duration arrived (full pipeline check)
if echo "${NEW_CONTENT}" | grep -q "http.server.request.duration"; then
    pass "metrics.json delta contains http.server.request.duration"
else
    fail "metrics.json delta does NOT contain 'http.server.request.duration'."
fi

# 4. Exactly one "export loop started" line
SPAWN_COUNT=$(grep -c "export loop started" "${PREFIX}/logs/error.log" 2>/dev/null) || SPAWN_COUNT=0
if [[ "${SPAWN_COUNT}" -eq 1 ]]; then
    pass "error.log: exactly 1 'export loop started' line"
else
    fail "error.log: expected 1 'export loop started' line, got ${SPAWN_COUNT}."
fi

# 5. Graceful-drain integrity
DRAIN_START=$(grep -c "graceful drain starting" "${PREFIX}/logs/error.log" 2>/dev/null) || DRAIN_START=0
DRAIN_END=$(grep -c "graceful drain complete" "${PREFIX}/logs/error.log" 2>/dev/null) || DRAIN_END=0
if [[ "${DRAIN_START}" -eq 0 ]]; then
    info "Note: graceful drain did not fire this run."
elif [[ "${DRAIN_START}" -eq "${DRAIN_END}" ]]; then
    pass "graceful drain integrity: ${DRAIN_START} start(s), ${DRAIN_END} complete(s)"
else
    fail "graceful drain started ${DRAIN_START} time(s) but completed ${DRAIN_END} time(s) — drain hung."
fi

# 6. No panics / crashes
PANIC_COUNT=$(grep -cE "panicked|signal 11|signal 6|exited on signal" "${PREFIX}/logs/error.log" 2>/dev/null) || PANIC_COUNT=0
if [[ "${PANIC_COUNT}" -eq 0 ]]; then
    pass "error.log: no panics / crashes"
else
    fail "error.log: ${PANIC_COUNT} crash/panic line(s):
$(grep -aE 'panicked|signal 11|signal 6|exited on signal' "${PREFIX}/logs/error.log" | head -10)"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────

echo ""
if [[ "${FAILED}" -eq 0 ]]; then
    pass "All assertions passed.  Production gRPC export E2E test COMPLETE."
    echo ""
    echo "  New metrics.json tail:"
    echo "${NEW_CONTENT}" | tail -3
    exit 0
else
    echo -e "${RED}One or more assertions FAILED.${NC}" >&2
    exit 2
fi
