#!/usr/bin/env bash
# tests/integration/run_cpp_dropin.sh
#
# Config-level drop-in proof: loads a representative nginx.conf written in
# C++ nginx-otel directive syntax verbatim and asserts that:
#
#   1. nginx starts and accepts the config with no error — startup failure is
#      an unconditional test FAIL (the drop-in proof).
#   2. Traffic produces spans at the collector carrying current OTel HTTP
#      semconv attribute names (http.request.method, url.path,
#      http.response.status_code, url.scheme, network.protocol.version,
#      user_agent.original, server.address, http.route, client.address,
#      network.peer.address).
#   3. No deprecated OTel HTTP semconv v1.16.0 attribute names appear
#      (http.method, http.target, http.status_code, net.sock.peer.addr,
#      net.host.name, http.flavor, http.user_agent).
#   4. The custom `header` sub-directive does not break startup (assertion 1
#      covers this; the header itself goes to the exporter, not a collector
#      assertion).
#   5. The `interval`/`batch_size`/`batch_count` sub-directives do not break
#      startup (also covered by assertion 1 — "accepted and ignored" means
#      nginx must parse them cleanly).
#   6. A custom `otel_span_attr` value appears on the span for /api requests.
#
# C++ nginx-otel module reference:
#   https://github.com/nginxinc/nginx-otel  (directive table in src/http_module.cpp)
#
# Exit codes: 0 = all assertions passed; 1 = preflight failure; 2 = assertion failed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPO_ROOT="$(cd "${CRATE_DIR}/.." && pwd)"

CONF_TEMPLATE="${SCRIPT_DIR}/nginx_cpp_dropin.conf"

. "${CRATE_DIR}/test-harness/lib.sh"
resolve_nginx_binary || true

case "$(uname -s)" in
    Darwin) MODULE_EXT="dylib" ;;
    *)      MODULE_EXT="so"    ;;
esac
if [[ -n "${CARGO_BUILD_TARGET:-}" ]]; then
    MODULE_PATH="${CRATE_DIR}/target/${CARGO_BUILD_TARGET}/release/libngx_http_otel_module.${MODULE_EXT}"
else
    MODULE_PATH="${CRATE_DIR}/target/release/libngx_http_otel_module.${MODULE_EXT}"
fi

SERVICE_NAME="ngx-otel-cpp-dropin-test"
METRIC_INTERVAL_S=5
FLUSH_WAIT_S=$(( METRIC_INTERVAL_S + 4 ))

# Known traceparent used to make the span deterministically findable.
TRACEPARENT="00-c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6-c1d2e3f4a5b6c7d8-01"
TRACE_ID="c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass()  { echo -e "${GREEN}[PASS]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*" >&2; FAILED=1; }
info()  { echo -e "${YELLOW}[INFO]${NC} $*"; }

info "Pre-flight checks..."
if [[ ! -x "${NGINX_BINARY}" ]]; then
    echo "ERROR: nginx binary not found at ${NGINX_BINARY}" >&2
    echo "       Set NGINX_BINARY to the correct path." >&2
    exit 1
fi
ensure_collector_running || exit 1

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

PREFIX="$(mktemp -d /tmp/ngx-otel-cpp-dropin.XXXXXX)"
NGINX_PID=""
FAILED=0

cleanup() {
    [[ -n "${NGINX_PID:-}" ]] && kill "${NGINX_PID}" 2>/dev/null || true
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
    "${CONF_TEMPLATE}" > "${PREFIX}/nginx.conf"

info "Sandbox: ${PREFIX}"

# Snapshot collector output sizes before starting nginx so we only examine
# telemetry produced by this test run.
PRE_TRACES_SIZE=0
if [[ -f "${TRACES_LOG}" ]]; then
    PRE_TRACES_SIZE=$(wc -c < "${TRACES_LOG}")
fi
info "traces.json pre-size: ${PRE_TRACES_SIZE} bytes"

# ─── Assertion 1: nginx starts and accepts the C++ config ────────────────────
# HARD: any startup failure (unknown directive, parse error, etc.) is an
# unconditional FAIL — the C++ config must load unedited.

info "Starting nginx with C++ nginx-otel directive syntax..."
"${NGINX_BINARY}" -p "${PREFIX}" -c "${PREFIX}/nginx.conf" &
NGINX_PID=$!

sleep 1

if ! kill -0 "${NGINX_PID}" 2>/dev/null; then
    echo ""
    echo "=== error.log ==="
    cat "${PREFIX}/logs/error.log" 2>/dev/null || echo "(not found)"
    echo ""
    fail "nginx exited immediately — C++ config was NOT accepted (drop-in FAIL)"
    echo "  This means one of the C++ directives (header, interval, batch_size,"
    echo "  batch_count, otel_span_name, otel_span_attr, otel_trace_context)"
    echo "  was not recognised or caused a parse error."
    exit 2
fi

pass "nginx started with C++ directive syntax — config accepted unedited (drop-in PASS)"
info "nginx running (PID ${NGINX_PID})"

# ─── Send traffic to generate spans ──────────────────────────────────────────

info "Sending 5 GET / requests (200)..."
for i in $(seq 1 5); do
    curl -sf -A "TestAgent/1.0" http://127.0.0.1:9106/ >/dev/null
done

info "Sending 3 GET /api requests with known traceparent (trace_id=${TRACE_ID})..."
for i in $(seq 1 3); do
    curl -sf -A "TestAgent/1.0" \
        -H "traceparent: ${TRACEPARENT}" \
        http://127.0.0.1:9106/api >/dev/null || true
done

info "Sending 1 GET /error request (500) with known traceparent..."
curl -sf -A "TestAgent/1.0" \
    -H "traceparent: ${TRACEPARENT}" \
    http://127.0.0.1:9106/error >/dev/null || true

info "Waiting ${FLUSH_WAIT_S}s for the exporter to flush..."
sleep "${FLUSH_WAIT_S}"

info "Stopping nginx (SIGQUIT)..."
kill -QUIT "${NGINX_PID}" 2>/dev/null || true
sleep 3
NGINX_PID=""

# Extract only the new data written by this test run.
NEW_TRACES=""
if [[ -f "${TRACES_LOG}" ]]; then
    POST_TRACES_SIZE=$(wc -c < "${TRACES_LOG}")
    if (( POST_TRACES_SIZE > PRE_TRACES_SIZE )); then
        NEW_TRACES=$(tail -c "+$(( PRE_TRACES_SIZE + 1 ))" "${TRACES_LOG}")
    fi
fi
info "New traces.json bytes: ${#NEW_TRACES} chars"

echo ""
echo "=== Assertions (C++ config drop-in: span shape + semconv) ==="

# ─── 2a. Spans arrived ───────────────────────────────────────────────────────
# HARD: the span pipeline must deliver at least one span.

if [[ -z "${NEW_TRACES}" ]]; then
    fail "traces.json: NO new data — span did not reach the collector"
    exit 2
fi

if echo "${NEW_TRACES}" | grep -q '"resourceSpans"'; then
    pass "traces.json: ResourceSpans payload received"
else
    fail "traces.json: new data contains no resourceSpans"
fi

# ─── 2b. Known traceId arrived ───────────────────────────────────────────────

if echo "${NEW_TRACES}" | grep -q "\"${TRACE_ID}\""; then
    pass "traces.json: traceId=${TRACE_ID} from known traceparent — extraction works"
else
    fail "traces.json: traceId ${TRACE_ID} NOT found — W3C traceparent extraction broken"
fi

# ─── 2c. Current OTel HTTP semconv attribute names ───────────────────────────
# Each must appear on the spans emitted by this config — the drop-in proves
# that the same data is present under the current (non-deprecated) attribute
# names that the C++ module emitted under the old v1.16.0 names.

for attr in \
    "http.request.method" \
    "url.path" \
    "http.response.status_code" \
    "url.scheme" \
    "network.protocol.version" \
    "http.route" \
    "server.address"
do
    if echo "${NEW_TRACES}" | grep -q "\"${attr}\""; then
        pass "traces.json: current semconv attr '${attr}' present"
    else
        fail "traces.json: current semconv attr '${attr}' MISSING"
    fi
done

# user_agent.original requires a non-empty User-Agent header.
if echo "${NEW_TRACES}" | grep -q '"user_agent.original"'; then
    pass "traces.json: user_agent.original present (User-Agent header was sent)"
else
    fail "traces.json: user_agent.original MISSING — User-Agent capture broken"
fi

# client.address and network.peer.address: present when the realip module is
# compiled in and the connection peer is known.
if echo "${NEW_TRACES}" | grep -q '"client.address"'; then
    pass "traces.json: client.address present"
else
    fail "traces.json: client.address MISSING"
fi

if echo "${NEW_TRACES}" | grep -q '"network.peer.address"'; then
    pass "traces.json: network.peer.address present"
else
    fail "traces.json: network.peer.address MISSING"
fi

# ─── 3. No deprecated OTel HTTP semconv v1.16.0 keys ─────────────────────────
# C++ used the old attribute names; we use current names.  No old names must
# appear in the output — this confirms the migration is clean.
#
# References:
#   Deprecated names: OTel HTTP semconv v1.16.0 (superseded in v1.21+)
#     https://opentelemetry.io/docs/specs/semconv/http/migration-guide/

for deprecated in \
    '"http.method"' \
    '"http.target"' \
    '"http.status_code"' \
    '"http.scheme"' \
    '"http.flavor"' \
    '"http.user_agent"' \
    '"net.sock.peer.addr"' \
    '"net.sock.peer.port"' \
    '"net.host.name"' \
    '"net.host.port"'
do
    if echo "${NEW_TRACES}" | grep -q "${deprecated}"; then
        fail "traces.json: deprecated key ${deprecated} FOUND — must not emit old v1.16.0 names"
    else
        pass "traces.json: deprecated key ${deprecated} absent (correct)"
    fi
done

# ─── 6. Custom otel_span_attr value on /api spans ────────────────────────────
# The config sets `otel_span_attr app.component "api-handler"` on /api.
# That attribute must appear on at least one span.

if echo "${NEW_TRACES}" | grep -q '"app.component"'; then
    pass "traces.json: custom otel_span_attr 'app.component' found on span"
else
    fail "traces.json: custom otel_span_attr 'app.component' NOT found — otel_span_attr broken"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────

echo ""
if [[ "${FAILED}" -eq 0 ]]; then
    echo -e "${GREEN}[PASS]${NC} All assertions passed (C++ config drop-in: config accepted + semconv correct)."
else
    echo -e "${RED}[FAIL]${NC} ${FAILED} assertion(s) failed." >&2
    exit 2
fi
