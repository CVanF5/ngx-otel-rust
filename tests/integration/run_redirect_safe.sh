#!/usr/bin/env bash
# tests/integration/run_redirect_safe.sh — H3F1 redirect-safe E2E integration test.
#
# Proves the three-part H3F1 design end-to-end (mirroring the C++ nginx-otel
# module's redirect-safe handling):
#
#   Test (a) — update-don't-append injection:
#     A `propagate` proxy location with an inbound traceparent must forward
#     EXACTLY ONE traceparent to the upstream (the find-then-update overwrites
#     the inbound header in place), and that header must carry the inbound
#     trace-id.  Asserted against a header-echo backend that records the raw
#     request headers it receives.
#
#   Test (b) — pool-cleanup ctx anchor + recovery:
#     An `error_page 500 = /recover` internal redirect must yield EXACTLY ONE
#     span at the collector for the request (the span SURVIVES the redirect via
#     the cleanup anchor; the r->internal guard prevents a second span-start),
#     and the span's parentSpanId must be the genuine inbound parent.
#
# These are HARD assertions with no soft fallback.
#
# Exit codes: 0 = all passed; 1 = preflight failure; 2 = assertion failed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPO_ROOT="$(cd "${CRATE_DIR}/.." && pwd)"

CONF_TEMPLATE="${SCRIPT_DIR}/nginx_redirect_safe.conf"
BACKEND_STUB="${SCRIPT_DIR}/header_echo_stub.py"

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

BACKEND_PORT=19103
METRIC_INTERVAL_S=2
FLUSH_WAIT_S=$(( METRIC_INTERVAL_S + 4 ))

# Test (a): inbound traceparent for the proxy/propagate request.
PROXY_TRACEPARENT="00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01"
PROXY_TRACE_ID="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

# Test (b): inbound traceparent for the error_page redirect request.
# REDIR_PARENT_SPAN_ID is the genuine inbound parent the surviving span must
# reference (NOT a self/phantom id).
REDIR_TRACEPARENT="00-cccccccccccccccccccccccccccccccc-dddddddddddddddd-01"
REDIR_TRACE_ID="cccccccccccccccccccccccccccccccc"
REDIR_PARENT_SPAN_ID="dddddddddddddddd"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
pass()  { echo -e "${GREEN}[PASS]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*" >&2; FAILED=1; }
info()  { echo -e "${YELLOW}[INFO]${NC} $*"; }

info "Pre-flight checks..."
if [[ ! -x "${NGINX_BINARY}" ]]; then
    echo "ERROR: nginx binary not found at ${NGINX_BINARY}" >&2
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
[[ -f "${MODULE_PATH}" ]] || { echo "ERROR: module not found: ${MODULE_PATH}" >&2; exit 1; }
info "Module built: ${MODULE_PATH}"

PREFIX="$(mktemp -d /tmp/ngx-otel-redirect.XXXXXX)"
NGINX_PID=""
BACKEND_PID=""
FAILED=0
BACKEND_HEADERS="${PREFIX}/backend_headers.txt"
: > "${BACKEND_HEADERS}"

cleanup() {
    [[ -n "${NGINX_PID:-}" ]]   && kill "${NGINX_PID}"   2>/dev/null || true
    [[ -n "${BACKEND_PID:-}" ]] && kill "${BACKEND_PID}" 2>/dev/null || true
    echo ""
    echo "=== error.log (last 30 lines) ==="
    tail -30 "${PREFIX}/logs/error.log" 2>/dev/null || echo "(not found)"
    info "Tearing down ${PREFIX}"
    rm -rf "${PREFIX}"
}
trap cleanup EXIT

mkdir -p "${PREFIX}/logs" "${PREFIX}/client_body_temp"

sed \
    -e "s|@MODULE_PATH@|${MODULE_PATH}|g" \
    -e "s|@PREFIX@|${PREFIX}|g" \
    -e "s|@BACKEND_PORT@|${BACKEND_PORT}|g" \
    "${CONF_TEMPLATE}" > "${PREFIX}/nginx.conf"

# ─── Start the header-echo backend ────────────────────────────────────────────
info "Starting header-echo backend on 127.0.0.1:${BACKEND_PORT}..."
python3 "${BACKEND_STUB}" "${BACKEND_PORT}" "${BACKEND_HEADERS}" &
BACKEND_PID=$!
sleep 1

# ─── Snapshot traces.json size BEFORE starting nginx ──────────────────────────
PRE_TRACES_SIZE=0
[[ -f "${TRACES_LOG}" ]] && PRE_TRACES_SIZE=$(wc -c < "${TRACES_LOG}")
info "traces.json pre-size: ${PRE_TRACES_SIZE} bytes"

# ─── Start NGINX ──────────────────────────────────────────────────────────────
info "Starting nginx..."
"${NGINX_BINARY}" -p "${PREFIX}" -c "${PREFIX}/nginx.conf" &
NGINX_PID=$!
sleep 1
if ! kill -0 "${NGINX_PID}" 2>/dev/null; then
    echo "ERROR: nginx exited immediately. error.log:" >&2
    cat "${PREFIX}/logs/error.log" >&2
    exit 1
fi
info "nginx running (PID ${NGINX_PID})"

# ─── Test (a): propagate proxy request with inbound traceparent ──────────────
info "(a) GET /proxy with inbound traceparent (propagate) → backend..."
curl -sf -H "traceparent: ${PROXY_TRACEPARENT}" http://127.0.0.1:9103/proxy >/dev/null || true

# ─── Test (b): error_page internal-redirect request ──────────────────────────
info "(b) GET /redir with inbound traceparent (error_page → /recover)..."
curl -s -H "traceparent: ${REDIR_TRACEPARENT}" http://127.0.0.1:9103/redir >/dev/null || true

info "Waiting ${FLUSH_WAIT_S}s for the exporter to flush..."
sleep "${FLUSH_WAIT_S}"

info "Stopping nginx (SIGQUIT)..."
kill -QUIT "${NGINX_PID}" 2>/dev/null || true
sleep 3
NGINX_PID=""

# Stop backend and let it flush.
kill "${BACKEND_PID}" 2>/dev/null || true
BACKEND_PID=""
sleep 1

# ─── Extract new traces written during THIS run ──────────────────────────────
NEW_TRACES=""
if [[ -f "${TRACES_LOG}" ]]; then
    POST_TRACES_SIZE=$(wc -c < "${TRACES_LOG}")
    if (( POST_TRACES_SIZE > PRE_TRACES_SIZE )); then
        NEW_TRACES=$(tail -c "+$(( PRE_TRACES_SIZE + 1 ))" "${TRACES_LOG}")
    fi
fi
info "New traces.json bytes: $(( ${#NEW_TRACES} )) chars"

echo ""
echo "=== Assertions ==="

# ─── (a1) EXACTLY ONE traceparent reached the backend ────────────────────────
TP_COUNT=$(grep -ic '^traceparent:' "${BACKEND_HEADERS}" 2>/dev/null || echo 0)
TP_COUNT=$(echo "${TP_COUNT}" | tr -d '[:space:]')
if [[ "${TP_COUNT}" == "1" ]]; then
    pass "(a) backend received EXACTLY ONE traceparent (count=1, update-don't-append holds)"
else
    fail "(a) backend received ${TP_COUNT} traceparent headers (expected exactly 1) — append-not-update bug"
    echo "--- backend headers ---" >&2
    cat "${BACKEND_HEADERS}" >&2
fi

# ─── (a2) The forwarded traceparent carries the inbound trace-id ─────────────
if grep -i '^traceparent:' "${BACKEND_HEADERS}" | grep -qi "${PROXY_TRACE_ID}"; then
    pass "(a) forwarded traceparent carries inbound trace-id ${PROXY_TRACE_ID} (continuity)"
else
    fail "(a) forwarded traceparent does NOT carry inbound trace-id ${PROXY_TRACE_ID}"
    grep -i '^traceparent:' "${BACKEND_HEADERS}" >&2 || true
fi

# ─── (b1) EXACTLY ONE span survived the redirect ─────────────────────────────
# Count the spans (by spanId) whose traceId == REDIR_TRACE_ID across new traces.
# This is the load-bearing assertion for the H3F1 design:
#   • Pre-fix (no cleanup-anchor recovery): ZERO spans — the SpanCtx is orphaned
#     when the redirect zeroes the module-ctx array, so LOG emits nothing.
#   • No r->internal guard: TWO spans — both the intercepted (500) pass and the
#     recovery (200) pass carry a SpanCtx, so LOG emits a span for each.
#   • Correct (guard + recovery): EXACTLY ONE span per request.
if [[ -z "${NEW_TRACES}" ]]; then
    fail "(b) traces.json: NO new data — redirect span did not reach the collector"
    exit 2
fi
REDIR_SPAN_COUNT=$(echo "${NEW_TRACES}" | python3 -c '
import sys, json
tid = sys.argv[1]
ids = set()
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        d = json.loads(line)
    except Exception:
        continue
    for rs in d.get("resourceSpans", []):
        for ss in rs.get("scopeSpans", []):
            for sp in ss.get("spans", []):
                if sp.get("traceId") == tid:
                    ids.add(sp.get("spanId"))
print(len(ids))
' "${REDIR_TRACE_ID}")
if [[ "${REDIR_SPAN_COUNT}" == "1" ]]; then
    pass "(b) EXACTLY ONE span for trace-id ${REDIR_TRACE_ID} — span SURVIVED the redirect, no duplicate (count=1)"
elif [[ "${REDIR_SPAN_COUNT}" == "0" ]]; then
    fail "(b) ZERO spans for trace-id ${REDIR_TRACE_ID} — span lost across redirect (cleanup-anchor recovery broken)"
else
    fail "(b) ${REDIR_SPAN_COUNT} spans for trace-id ${REDIR_TRACE_ID} (expected exactly 1) — internal-redirect guard missing → duplicate span"
fi

# ─── (b2) Span's parentSpanId is the genuine inbound parent ──────────────────
if echo "${NEW_TRACES}" | grep -q "\"${REDIR_PARENT_SPAN_ID}\""; then
    pass "(b) span parentSpanId=${REDIR_PARENT_SPAN_ID} is the genuine inbound parent (not self/phantom)"
else
    fail "(b) parentSpanId ${REDIR_PARENT_SPAN_ID} NOT found — span lost its parent across redirect"
fi

echo ""
if [[ "${FAILED}" -eq 0 ]]; then
    echo -e "${GREEN}[PASS]${NC} All H3F1 redirect-safe assertions passed."
else
    echo -e "${RED}[FAIL]${NC} ${FAILED} assertion(s) failed." >&2
    exit 2
fi
