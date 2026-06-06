#!/usr/bin/env bash
# tests/integration/run_endpoint_change.sh — Step 10 endpoint-change reload test
#
# Verifies that changing the OTLP collector endpoint across nginx -s reload
# takes effect on the next export tick of the new worker generation.
#
# Scenario:
#   A. nginx starts pointing at the real collector (127.0.0.1:4318) — metrics
#      arrive in metrics.json.
#   B. nginx.conf is rewritten to point at an unreachable endpoint
#      (127.0.0.1:14318) and nginx -s reload is issued.
#   C. New worker's export loop should fail to connect and increment
#      ngx_otel.send_failures.  error.log must contain "send failed" for the
#      new worker generation.
#   D. nginx -s quit.
#
# Assertions:
#   1. metrics.json received batches under service.name = ngx-otel-step10-epchange
#      during phase A (endpoint A worked).
#   2. error.log contains ≥ 2 "otel export: send failed" lines after the reload.
#      Two failures (rather than one) proves the in-memory send_failures counter
#      advanced past 1; this is the only available counter-advancement signal
#      because phase-B batches never reach metrics.json (endpoint B is
#      unreachable by construction).
#   3. error.log contains "otel: SIGHUP reload detected" exactly once.
#   4. ngx_otel.send_failures data point in phase-A content has asInt="0".
#      Phase A's collector was reachable so the counter MUST still be 0 there;
#      any non-zero value would indicate counter leakage from a different
#      worker or malformed JSON.
#
# Prerequisites
# ─────────────
# OTel collector running on 127.0.0.1:4318.  Port 14318 must be unreachable.
#
# Running
# ───────
#   NGINX_SOURCE_DIR=../nginx \
#   NGINX_BUILD_DIR=../nginx/objs \
#   bash tests/integration/run_endpoint_change.sh
#
# Exit codes
#   0  all assertions passed
#   1  pre-flight or build failure
#   2  a test assertion failed

set -euo pipefail

# ─── Resolve paths ───────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPO_ROOT="$(cd "${CRATE_DIR}/.." && pwd)"

# Source the shared harness library.  Sets HARNESS_DIR, METRICS_LOG,
# COLLECTOR_HTTP_ENDPOINT, and exposes ensure_collector_running and
# resolve_nginx_binary.
. "${CRATE_DIR}/test-harness/lib.sh"
resolve_nginx_binary || true   # missing-binary error is produced by the preflight below

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

SERVICE_NAME="ngx-otel-step10-epchange"
ENDPOINT_A="http://127.0.0.1:4318/v1/metrics"   # real collector
ENDPOINT_B="http://127.0.0.1:14318/v1/metrics"  # unreachable (no listener)
METRIC_INTERVAL_S=2
FLUSH_WAIT_S=$(( METRIC_INTERVAL_S + 2 ))
N_REQUESTS=10

# ─── Colour helpers ──────────────────────────────────────────────────────────

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass()  { echo -e "${GREEN}[PASS]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*" >&2; FAILED=1; }
info()  { echo -e "${YELLOW}[INFO]${NC} $*"; }

# ─── Pre-flight checks ───────────────────────────────────────────────────────

info "Pre-flight checks..."
FAILED=0

if [[ ! -x "${NGINX_BINARY}" ]]; then
    echo "ERROR: nginx binary not found at ${NGINX_BINARY}" >&2
    exit 1
fi

ensure_collector_running || exit 1

# Verify port 14318 is NOT reachable (that is what makes it a good dead endpoint).
if curl -s --connect-timeout 1 http://127.0.0.1:14318/ >/dev/null 2>&1; then
    echo "ERROR: something is listening on 127.0.0.1:14318; endpoint B must be unreachable." >&2
    echo "       Choose a different port for ENDPOINT_B or stop the service on 14318." >&2
    exit 1
fi

# ─── Build the module ────────────────────────────────────────────────────────

info "Building release module..."
(
    cd "${CRATE_DIR}"
    NGINX_SOURCE_DIR="${NGINX_SOURCE_DIR:-${REPO_ROOT}/nginx}" \
    NGINX_BUILD_DIR="${NGINX_BUILD_DIR:-${REPO_ROOT}/nginx/objs}" \
    cargo build --release 2>&1
)
if [[ ! -f "${MODULE_PATH}" ]]; then
    echo "ERROR: module not found after build: ${MODULE_PATH}" >&2
    exit 1
fi
info "Module built: ${MODULE_PATH}"

# ─── Sandbox prefix directory ────────────────────────────────────────────────

PREFIX="$(mktemp -d /tmp/ngx-otel-step10-epchange.XXXXXX)"
NGINX_PID=""

cleanup() {
    [[ -n "${NGINX_PID:-}" ]] && kill "${NGINX_PID}" 2>/dev/null || true
    echo ""
    echo "=== error.log (first 40 lines) ==="
    head -40 "${PREFIX}/logs/error.log" 2>/dev/null || echo "(not found)"
    echo "..."
    echo "=== error.log (last 40 lines) ==="
    tail -40 "${PREFIX}/logs/error.log" 2>/dev/null
    info "Tearing down ${PREFIX}"
    rm -rf "${PREFIX}"
}
trap cleanup EXIT

mkdir -p "${PREFIX}/logs"
mkdir -p "${PREFIX}/client_body_temp"

# Helper: write nginx.conf pointing at a specific endpoint.
write_conf() {
    local endpoint="$1"
    cat > "${PREFIX}/nginx.conf" <<CONF
daemon off;
master_process on;
worker_processes 4;
worker_shutdown_timeout 5s;
error_log ${PREFIX}/logs/error.log debug;
pid       ${PREFIX}/logs/nginx.pid;

load_module ${MODULE_PATH};

events {
    worker_connections 64;
}

http {
    otel_exporter {
        endpoint ${endpoint};
    }
    otel_service_name ${SERVICE_NAME};
    otel_metric_interval ${METRIC_INTERVAL_S}s;

    server {
        listen 127.0.0.1:9102;
        location / {
            return 200 "ok\\n";
        }
    }
}
CONF
}

info "Sandbox: ${PREFIX}"

# ─── Snapshot metrics.json BEFORE starting nginx ─────────────────────────────

PRE_SIZE=0
if [[ -f "${METRICS_LOG}" ]]; then
    PRE_SIZE=$(wc -c < "${METRICS_LOG}")
fi
info "metrics.json pre-size: ${PRE_SIZE} bytes"

# ─── Phase A: start with working endpoint ────────────────────────────────────

write_conf "${ENDPOINT_A}"
info "Starting nginx with endpoint A (${ENDPOINT_A})..."
"${NGINX_BINARY}" \
    -p "${PREFIX}" \
    -c "${PREFIX}/nginx.conf" &
NGINX_PID=$!

sleep 1.5

if ! kill -0 "${NGINX_PID}" 2>/dev/null; then
    echo "ERROR: nginx exited immediately." >&2
    cat "${PREFIX}/logs/error.log" >&2
    exit 1
fi
info "nginx running (PID ${NGINX_PID})"

info "Phase A: sending ${N_REQUESTS} requests..."
for i in $(seq 1 "${N_REQUESTS}"); do
    curl -sf http://127.0.0.1:9102/ >/dev/null
done

# Capture metrics.json size after phase A settles (one tick + a bit).
info "Waiting ${FLUSH_WAIT_S}s for phase-A export tick..."
sleep "${FLUSH_WAIT_S}"

POST_A_SIZE=0
if [[ -f "${METRICS_LOG}" ]]; then
    POST_A_SIZE=$(wc -c < "${METRICS_LOG}")
fi

# ─── Swap to endpoint B and reload ───────────────────────────────────────────

write_conf "${ENDPOINT_B}"
info "nginx.conf rewritten to endpoint B (${ENDPOINT_B}); sending nginx -s reload..."
"${NGINX_BINARY}" \
    -p "${PREFIX}" \
    -c "${PREFIX}/nginx.conf" \
    -s reload 2>/dev/null || true

# Wait for the new worker generation to start and attempt (and fail) to send.
# Two ticks = 2 * interval + a bit of slack = enough time for send_failures to
# accumulate and for the "send failed" log lines to appear.
info "Waiting $(( METRIC_INTERVAL_S * 2 + 3 ))s for new-generation export attempts..."
sleep $(( METRIC_INTERVAL_S * 2 + 3 ))

# ─── Graceful shutdown ───────────────────────────────────────────────────────

info "Sending nginx -s quit..."
"${NGINX_BINARY}" \
    -p "${PREFIX}" \
    -c "${PREFIX}/nginx.conf" \
    -s quit 2>/dev/null || true

for i in $(seq 1 15); do
    if ! kill -0 "${NGINX_PID}" 2>/dev/null; then
        break
    fi
    sleep 1
done
NGINX_PID=""

# ─── Collect new metrics.json content from phase A ───────────────────────────

CONTENT_A=""
if [[ -f "${METRICS_LOG}" ]]; then
    if (( POST_A_SIZE > PRE_SIZE )); then
        CONTENT_A=$(tail -c "+$(( PRE_SIZE + 1 ))" "${METRICS_LOG}" | head -c "$(( POST_A_SIZE - PRE_SIZE ))")
    fi
fi

# ─── Assertions ──────────────────────────────────────────────────────────────

info "Running assertions..."

# 1. metrics.json received batches from phase A (endpoint A worked).
if echo "${CONTENT_A}" | grep -q "${SERVICE_NAME}"; then
    pass "metrics.json: phase-A batches present (endpoint A = ${ENDPOINT_A} worked)"
else
    fail "metrics.json: no phase-A batches found under service.name = ${SERVICE_NAME}.
       Content-A (first 200 chars): $(echo "${CONTENT_A}" | head -c 200)"
fi

# 2. error.log contains ≥ 2 "otel export: send failed" lines after reload.
#    Two failures (rather than one) is the meaningful threshold: it proves the
#    in-memory ngx_otel.send_failures counter advanced past 1 across multiple
#    phase-B ticks, not just a single transient failure.  We assert ≥ 2 here
#    because the post-failure counter value can never reach metrics.json
#    directly (phase-B batches go to the unreachable endpoint B), so the
#    error-log count is the only available counter-advancement signal.
SEND_FAIL_COUNT=$(grep -c "otel export: send failed" "${PREFIX}/logs/error.log" 2>/dev/null) || SEND_FAIL_COUNT=0
if [[ "${SEND_FAIL_COUNT}" -ge 2 ]]; then
    pass "error.log: ${SEND_FAIL_COUNT} 'otel export: send failed' line(s) (≥ 2: send_failures counter advanced past 1)"
else
    fail "error.log: expected ≥ 2 'otel export: send failed' lines (got ${SEND_FAIL_COUNT}).
       Two failures are required to prove the in-memory counter advanced past 1.
       Relevant lines (export-related):
$(grep -E 'otel export|send fail|send_failure' "${PREFIX}/logs/error.log" | tail -20)"
fi

# 3. "otel: SIGHUP reload detected" appears exactly once.
RELOAD_COUNT=$(grep -c "otel: SIGHUP reload detected" "${PREFIX}/logs/error.log" 2>/dev/null) || RELOAD_COUNT=0
if [[ "${RELOAD_COUNT}" -eq 1 ]]; then
    pass "error.log: exactly 1 'otel: SIGHUP reload detected' line"
else
    fail "error.log: expected 1 'otel: SIGHUP reload detected' line, got ${RELOAD_COUNT}"
fi

# 4. ngx_otel.send_failures metric in phase A is structurally well-formed and
#    has the expected initial value (asInt="0").  Phase A's collector was
#    reachable, so the counter MUST still be 0 there — any non-zero value
#    would indicate counter leakage from a different worker or malformed JSON.
#    This tightens the previous "metric present" check, which would have
#    passed even if the data point was malformed or carried a garbage value.
#
#    Why we do not check counter advancement here: phase-B batches all target
#    the unreachable endpoint B and never reach the collector, so the
#    post-failure counter values never land in metrics.json.  Counter
#    advancement evidence is provided by assertion 2 (≥ 2 send-failure log
#    lines, each corresponding to one in-memory counter increment).
if echo "${CONTENT_A}" | grep -Eq '"ngx_otel\.send_failures"[^{]*\{[^}]*"asInt":"0"'; then
    pass "metrics.json: ngx_otel.send_failures present in phase-A with asInt=0 (initial value correct)"
else
    fail "metrics.json: ngx_otel.send_failures missing or has non-zero value in phase-A content.
       Expected asInt=\"0\" because endpoint A was reachable; non-zero indicates counter leakage.
       Phase-A excerpt: $(echo "${CONTENT_A}" | grep -oE 'ngx_otel\.send_failures[^}]*\}[^}]*\}' | head -1)"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────

echo ""
if [[ "${FAILED}" -eq 0 ]]; then
    pass "All assertions passed. Step 10 endpoint-change reload test COMPLETE."
    exit 0
else
    echo -e "${RED}One or more assertions FAILED.${NC}" >&2
    echo ""
    echo "  error.log tail:"
    tail -30 "${PREFIX}/logs/error.log" 2>/dev/null || echo "  (not found)"
    exit 2
fi
