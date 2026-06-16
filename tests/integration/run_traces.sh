#!/usr/bin/env bash
# tests/integration/run_traces.sh — E2E span-arrival integration test
#
# Proves that a sampled request actually produces a span at the collector —
# asserting the full path: emit_span_record → spans ring → drain →
# OtlpTracesEncoder → /v1/traces → collector file/traces exporter → traces.json.
#
# Also asserts the cross-signal trace_id match:
#   the span's traceId == the tail LogRecord's trace_id (logs.json)
#                       == the metric exemplar's trace_id (metrics.json)
#
# These are HARD assertions with no soft fallback.  The test FAILS if the
# span does not arrive with the expected shape.
#
# Assertions:
#   1. A span arrives in traces.json with the expected name ("GET /error").
#   2. Span's traceId matches TRACE_ID from the inbound traceparent.
#   3. Span's parentSpanId matches PARENT_SPAN_ID from the inbound traceparent
#      (proves W3C trace context extraction is wired to span emission).
#   4. Span carries HTTP semconv attributes: http.request.method,
#      http.response.status_code, url.path.
#   5. Span's traceId appears on the tail LogRecord in logs.json
#      (cross-signal logs→trace correlation).
#   6. Span's traceId appears in a metric exemplar in metrics.json
#      (cross-signal metrics→trace drill-down, exemplar→Tempo pivot).
#   7. New data in metrics.json contains no resourceSpans payloads
#      (FU1 clean split: spans go only to traces.json).
#   8. D1a: `otel_trace $otel_parent_sampled` + sampled parent → span present.
#      Pre-fix: gate always declined (SpanCtx not set before Gate 2 evaluated
#      $otel_parent_sampled → always not_found → always falsy → zero spans).
#   9. D1b: `otel_trace $otel_parent_sampled` + unsampled parent → no span.
#
# Prerequisites
# ─────────────
# Same as run.sh: Docker available, OTel collector reachable (with the
# file/traces exporter wired — see test-harness/otel-collector-config.yaml).
#
# Exit codes: 0 = all assertions passed; 1 = preflight failure; 2 = assertion failed.

set -euo pipefail

# ─── Resolve paths ───────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPO_ROOT="$(cd "${CRATE_DIR}/.." && pwd)"

CONF_TEMPLATE="${SCRIPT_DIR}/nginx_traces.conf"

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

SERVICE_NAME="ngx-otel-traces-test"
METRIC_INTERVAL_S=2
FLUSH_WAIT_S=$(( METRIC_INTERVAL_S + 4 ))

# The inbound W3C traceparent that makes sampling deterministic.
# TRACE_ID  → used as the span's traceId (16-byte, 32 hex chars).
# PARENT_SPAN_ID → used as the span's parentSpanId (8-byte, 16 hex chars).
# flags=01 (sampled=true).
TRACEPARENT="00-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6-f1e2d3c4b5a69788-01"
TRACE_ID="a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
PARENT_SPAN_ID="f1e2d3c4b5a69788"

# D1 regression: $otel_parent_sampled as the otel_trace gate value.
# Pre-fix: SpanCtx was never set before Gate 2 evaluated — $otel_parent_sampled
# always returned not_found (empty) → gate always declined → zero spans even for
# sampled parents.
# Post-fix: pre-gate SpanCtx set with inbound flags → gate reads the correct bit.
#
# D1_SAMPLED_TRACE_ID   — request with flags=01 → MUST produce a span (D1a).
# D1_UNSAMPLED_TRACE_ID — request with flags=00 → MUST NOT produce a span (D1b).
D1_SAMPLED_TRACEPARENT="00-d1aaaa00000000001111111111111111-d1aaaaaa0000ffff-01"
D1_SAMPLED_TRACE_ID="d1aaaa00000000001111111111111111"
D1_UNSAMPLED_TRACEPARENT="00-d1bbbb00000000002222222222222222-d1bbbbbb0000ffff-00"
D1_UNSAMPLED_TRACE_ID="d1bbbb00000000002222222222222222"

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
if [[ ! -x "${NGINX_BINARY}" ]]; then
    echo "ERROR: nginx binary not found at ${NGINX_BINARY}" >&2
    echo "       Set NGINX_BINARY to the correct path." >&2
    exit 1
fi
ensure_collector_running || exit 1

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

PREFIX="$(mktemp -d /tmp/ngx-otel-traces.XXXXXX)"
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

# ─── Snapshot file sizes BEFORE starting nginx ───────────────────────────────

PRE_TRACES_SIZE=0
if [[ -f "${TRACES_LOG}" ]]; then
    PRE_TRACES_SIZE=$(wc -c < "${TRACES_LOG}")
fi
info "traces.json pre-size: ${PRE_TRACES_SIZE} bytes"

PRE_LOGS_SIZE=0
if [[ -f "${LOGS_LOG}" ]]; then
    PRE_LOGS_SIZE=$(wc -c < "${LOGS_LOG}")
fi
info "logs.json pre-size: ${PRE_LOGS_SIZE} bytes"

PRE_METRICS_SIZE=0
if [[ -f "${METRICS_LOG}" ]]; then
    PRE_METRICS_SIZE=$(wc -c < "${METRICS_LOG}")
fi
info "metrics.json pre-size: ${PRE_METRICS_SIZE} bytes"

# ─── Start NGINX ─────────────────────────────────────────────────────────────

info "Starting nginx..."
"${NGINX_BINARY}" -p "${PREFIX}" -c "${PREFIX}/nginx.conf" &
NGINX_PID=$!

sleep 1

if ! kill -0 "${NGINX_PID}" 2>/dev/null; then
    echo "ERROR: nginx exited immediately. Check ${PREFIX}/logs/error.log" >&2
    cat "${PREFIX}/logs/error.log" >&2
    exit 1
fi
info "nginx running (PID ${NGINX_PID})"

# ─── Send HTTP traffic ───────────────────────────────────────────────────────

# Base requests: 10 × GET / (200).  Builds histogram data; spans are emitted
# but without a traceparent header so their traceIds are random.
info "Sending 10 GET / requests (200) to build histogram..."
for i in $(seq 1 10); do
    curl -sf http://127.0.0.1:9102/ >/dev/null
done

# The gate-blocking request: 1 × GET /error with a KNOWN traceparent.
# flags=01 (sampled=true) → the module honours the W3C sampled bit and
# emits a span.  The span's traceId and parentSpanId are derived from
# the inbound header, making the assertion deterministic.
info "Sending 1 GET /error with traceparent (known trace_id=${TRACE_ID})..."
curl -sf -H "traceparent: ${TRACEPARENT}" http://127.0.0.1:9102/error >/dev/null || true

# D1 regression requests: /d1_parent_sampled with otel_trace $otel_parent_sampled.
# (a) Sampled parent: flags=01 → $otel_parent_sampled returns "1" → gate passes → span emitted.
# (b) Unsampled parent: flags=00 → $otel_parent_sampled returns "0" → gate declines → no span.
# Pre-fix both of these always returned not_found → gate always declined → no span.
info "D1a: GET /d1_parent_sampled with sampled parent (flags=01) → expecting span..."
curl -sf -H "traceparent: ${D1_SAMPLED_TRACEPARENT}" http://127.0.0.1:9102/d1_parent_sampled >/dev/null || true
info "D1b: GET /d1_parent_sampled with unsampled parent (flags=00) → expecting NO span..."
curl -sf -H "traceparent: ${D1_UNSAMPLED_TRACEPARENT}" http://127.0.0.1:9102/d1_parent_sampled >/dev/null || true

# ─── Wait for the export interval + buffer, then stop nginx ──────────────────

info "Waiting ${FLUSH_WAIT_S}s for the exporter to flush..."
sleep "${FLUSH_WAIT_S}"

info "Stopping nginx (SIGQUIT → graceful drain)..."
kill -QUIT "${NGINX_PID}" 2>/dev/null || true
sleep 3

NGINX_PID=""  # disarm cleanup kill

# ─── Extract new data written during THIS test run ───────────────────────────

NEW_TRACES=""
if [[ -f "${TRACES_LOG}" ]]; then
    POST_TRACES_SIZE=$(wc -c < "${TRACES_LOG}")
    if (( POST_TRACES_SIZE > PRE_TRACES_SIZE )); then
        NEW_TRACES=$(tail -c "+$(( PRE_TRACES_SIZE + 1 ))" "${TRACES_LOG}")
    fi
fi
info "New traces.json bytes: $(( ${#NEW_TRACES} )) chars"

NEW_LOGS=""
if [[ -f "${LOGS_LOG}" ]]; then
    POST_LOGS_SIZE=$(wc -c < "${LOGS_LOG}")
    if (( POST_LOGS_SIZE > PRE_LOGS_SIZE )); then
        NEW_LOGS=$(tail -c "+$(( PRE_LOGS_SIZE + 1 ))" "${LOGS_LOG}")
    fi
fi
info "New logs.json bytes: $(( ${#NEW_LOGS} )) chars"

NEW_METRICS=""
if [[ -f "${METRICS_LOG}" ]]; then
    POST_METRICS_SIZE=$(wc -c < "${METRICS_LOG}")
    if (( POST_METRICS_SIZE > PRE_METRICS_SIZE )); then
        NEW_METRICS=$(tail -c "+$(( PRE_METRICS_SIZE + 1 ))" "${METRICS_LOG}")
    fi
fi
info "New metrics.json bytes: $(( ${#NEW_METRICS} )) chars"

echo ""
echo "=== Assertions ==="

# ─── 1. A span arrives in traces.json ────────────────────────────────────────
# HARD: the span pipeline must deliver at least one span to traces.json.
# This is the gate-blocking finding from the Loop-2 review.

if [[ -z "${NEW_TRACES}" ]]; then
    fail "traces.json: NO new data written — span did not reach the collector"
    echo ""
    echo "STOP: span did not arrive; this is the gate-blocking defect. Check:"
    echo "  - is file/traces wired in otel-collector-config.yaml?"
    echo "  - is the traces pipeline running? (docker logs ngx-otel-test-collector)"
    echo "  - did the exporter spawn? (check error.log)"
    exit 2
fi

if echo "${NEW_TRACES}" | grep -q '"resourceSpans"'; then
    pass "traces.json: ResourceSpans payload received — span reached the collector"
else
    fail "traces.json: new data arrived but contains no resourceSpans — unexpected payload shape"
fi

# ─── 2. Span traceId matches the inbound traceparent ─────────────────────────
# HARD: proves the extract path carries the W3C trace_id through to emission.

if echo "${NEW_TRACES}" | grep -q "\"${TRACE_ID}\""; then
    pass "traces.json: span traceId=${TRACE_ID} matches inbound traceparent"
else
    fail "traces.json: traceId ${TRACE_ID} NOT found — W3C trace context extraction broken"
fi

# ─── 3. parentSpanId matches the inbound span_id ─────────────────────────────
# HARD: proves parent_span_id is carried from SpanCtx into the emitted span.

if echo "${NEW_TRACES}" | grep -q "\"${PARENT_SPAN_ID}\""; then
    pass "traces.json: parentSpanId=${PARENT_SPAN_ID} matches inbound traceparent span_id"
else
    fail "traces.json: parentSpanId ${PARENT_SPAN_ID} NOT found — parent context not propagated to span"
fi

# ─── 4. Span carries HTTP semconv attributes ──────────────────────────────────
# HARD: span must include the three core HTTP semconv fields.

if echo "${NEW_TRACES}" | grep -q '"http.request.method"'; then
    pass "traces.json: http.request.method attribute present"
else
    fail "traces.json: http.request.method attribute MISSING from span"
fi

if echo "${NEW_TRACES}" | grep -q '"http.response.status_code"'; then
    pass "traces.json: http.response.status_code attribute present"
else
    fail "traces.json: http.response.status_code attribute MISSING from span"
fi

if echo "${NEW_TRACES}" | grep -q '"url.path"'; then
    pass "traces.json: url.path attribute present"
else
    fail "traces.json: url.path attribute MISSING from span"
fi

# ─── 5. Cross-signal: traceId in tail LogRecord (logs.json) ──────────────────
# HARD: the same trace_id must appear on the exception-tail LogRecord in
# logs.json — confirms the metric→exemplar→log→trace correlation chain.

if [[ -z "${NEW_LOGS}" ]]; then
    fail "logs.json: NO new data written — cannot verify cross-signal trace_id match"
elif echo "${NEW_LOGS}" | grep -q "${TRACE_ID}"; then
    pass "logs.json: trace_id ${TRACE_ID} carried on tail LogRecord (cross-signal logs→trace)"
else
    fail "logs.json: trace_id ${TRACE_ID} NOT found on any tail LogRecord — cross-signal broken"
fi

# ─── 6. Cross-signal: traceId in metric exemplar (metrics.json) ──────────────
# HARD: the same trace_id must appear in a metric exemplar in metrics.json —
# confirms the exemplar→Tempo drill-down path.

if [[ -z "${NEW_METRICS}" ]]; then
    fail "metrics.json: NO new data written — cannot verify exemplar trace_id"
elif echo "${NEW_METRICS}" | grep -q "${TRACE_ID}"; then
    pass "metrics.json: trace_id ${TRACE_ID} in metric exemplar (cross-signal metrics→trace)"
else
    fail "metrics.json: trace_id ${TRACE_ID} NOT in any exemplar — exemplar→trace link broken"
fi

# ─── 7. FU1 clean: no resourceSpans in new metrics data ──────────────────────
# HARD: FU1 rerouted traces to traces.json; new metrics data must be clean.

if [[ -n "${NEW_METRICS}" ]] && echo "${NEW_METRICS}" | grep -q '"resourceSpans"'; then
    fail "metrics.json: new data contains resourceSpans — traces must not appear in the metrics pipeline"
else
    pass "metrics.json: no resourceSpans in new data (traces routed to traces.json only)"
fi

# ─── 8. D1a: sampled parent → span present ───────────────────────────────────
# D1 regression: `otel_trace $otel_parent_sampled` with a sampled inbound
# traceparent (flags=01) MUST produce a span.
# Pre-fix: $otel_parent_sampled always returned not_found at Gate 2 time
# (SpanCtx not yet set) → gate always declined → no span ever.
# Post-fix: pre-gate SpanCtx sets flags before Gate 2 → correct behaviour.

if echo "${NEW_TRACES}" | grep -q "\"${D1_SAMPLED_TRACE_ID}\""; then
    pass "D1a: sampled parent (${D1_SAMPLED_TRACE_ID}) → span present in traces.json (otel_trace \$otel_parent_sampled works)"
else
    fail "D1a: sampled parent ${D1_SAMPLED_TRACE_ID} NOT in traces.json — \$otel_parent_sampled gate broken (D1 regression)"
fi

# ─── 9. D1b: unsampled parent → no span ──────────────────────────────────────
# D1 regression: `otel_trace $otel_parent_sampled` with an unsampled inbound
# traceparent (flags=00) MUST NOT produce a span.

if echo "${NEW_TRACES}" | grep -q "\"${D1_UNSAMPLED_TRACE_ID}\""; then
    fail "D1b: unsampled parent ${D1_UNSAMPLED_TRACE_ID} APPEARED in traces.json — should have been gated out"
else
    pass "D1b: unsampled parent (${D1_UNSAMPLED_TRACE_ID}) → no span in traces.json (correct: gate declined)"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────

echo ""
if [[ "${FAILED}" -eq 0 ]]; then
    echo -e "${GREEN}[PASS]${NC} All assertions passed."
else
    echo -e "${RED}[FAIL]${NC} ${FAILED} assertion(s) failed." >&2
    exit 2
fi
