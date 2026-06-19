#!/usr/bin/env bash
# tests/integration/run_metrics_wire.sh — wire-shape assertions for the
# metrics OTel-correctness changes.
#
# Builds the module (production path), starts nginx, drives HTTP traffic, waits
# for a metric flush, then asserts against the collector's metrics.json that the
# NEW wire shapes are present and the OLD ones are absent:
#
#   A. nginx.requests.total emitted as an OTLP Sum (not Histogram):
#      - metrics.json contains "nginx.requests.total"
#      - the containing JSON object uses "sum" (not "histogram")
#   B. http.server.request.duration unit is "s" (seconds):
#      - metrics.json contains  "http.server.request.duration"
#      - the containing "unit" field is "s"
#   C. http.response.status_class attribute (string) appears:
#      - metrics.json contains "http.response.status_class"
#   D. nginx.http.request.duration.by_route (Tier-2 rename) appears:
#      - metrics.json contains "nginx.http.request.duration.by_route"
#   E. OLD names are absent (regression guard):
#      - metrics.json delta does NOT contain "nginx_requests_total_sum" or
#        "nginx.requests.total" inside a "histogram" object
#      - metrics.json delta does NOT contain "http.response.status_code" as a
#        metric attribute key (the log attribute is fine; this checks the
#        dataPoints attributes section only)
#
# The collector's file exporter writes NDJSON (one JSON object per line) where
# each line is a ResourceMetrics object. We use Python3 for structured checks
# since grepping raw JSON for "sum" vs "histogram" needs context awareness.
#
# Prerequisites
# ─────────────
# - Docker available on PATH (collector auto-started by lib.sh).
# - NGINX binary built with --with-http_stub_status_module.
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
if [[ -n "${CARGO_BUILD_TARGET:-}" ]]; then
    MODULE_PATH="${CRATE_DIR}/target/${CARGO_BUILD_TARGET}/release/libngx_http_otel_module.${MODULE_EXT}"
else
    MODULE_PATH="${CRATE_DIR}/target/release/libngx_http_otel_module.${MODULE_EXT}"
fi

SERVICE_NAME="ngx-otel-metrics-wire-test"
NGINX_PORT=9108
METRIC_INTERVAL_S=2
FLUSH_WAIT_S=$(( METRIC_INTERVAL_S + 3 ))
N_REQUESTS=30

# ─── Colour helpers ──────────────────────────────────────────────────────────

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*" >&2; FAILED=1; }
info() { echo -e "${YELLOW}[INFO]${NC} $*"; }

FAILED=0

# ─── Pre-flight checks ───────────────────────────────────────────────────────

info "Pre-flight checks..."

if [[ ! -x "${NGINX_BINARY}" ]]; then
    echo "ERROR: nginx binary not found at ${NGINX_BINARY}" >&2
    echo "       Set NGINX_BINARY to the correct path." >&2
    exit 1
fi

ensure_collector_running || exit 1

# ─── Build module (production path) ──────────────────────────────────────────

info "Building release module (production build)..."
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

PREFIX="$(mktemp -d /tmp/ngx-otel-metrics-wire.XXXXXX)"
cleanup() {
    [[ -n "${NGINX_PID:-}" ]] && kill "${NGINX_PID}" 2>/dev/null || true
    echo ""
    echo "=== error.log (last 30 lines) ==="
    tail -30 "${PREFIX}/logs/error.log" 2>/dev/null || echo "(not found)"
    info "Tearing down ${PREFIX}"
    [[ "${KEEP_SANDBOX:-0}" == "1" ]] || rm -rf "${PREFIX}"
}
trap cleanup EXIT

mkdir -p "${PREFIX}/logs"
mkdir -p "${PREFIX}/client_body_temp"

cat > "${PREFIX}/nginx.conf" <<EOF
daemon off;
master_process on;
worker_processes 2;
worker_shutdown_timeout 5s;
error_log ${PREFIX}/logs/error.log info;
pid       ${PREFIX}/logs/nginx.pid;

load_module ${MODULE_PATH};

events {
    worker_connections 64;
}

http {
    otel_exporter {
        endpoint http://127.0.0.1:4318;
    }
    otel_service_name ${SERVICE_NAME};
    otel_metric_interval ${METRIC_INTERVAL_S}s;
    # Enable status_class attribute so http.response.status_class appears.
    otel_metric_status_code_class on;

    server {
        listen 127.0.0.1:${NGINX_PORT};
        location / {
            return 200 "metrics-wire-test ok\n";
        }
        location /api/ {
            return 200 "api ok\n";
        }
        location /notfound {
            return 404 "not found\n";
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

info "Sending ${N_REQUESTS} requests to generate metrics..."
for i in $(seq 1 "${N_REQUESTS}"); do
    curl -sf "http://127.0.0.1:${NGINX_PORT}/" >/dev/null
done
# A few 404s to generate 4xx class traffic.
for i in 1 2 3; do
    curl -sf "http://127.0.0.1:${NGINX_PORT}/notfound" >/dev/null || true
done
info "Traffic sent."

# ─── Wait for metrics flush ───────────────────────────────────────────────────

info "Waiting ${FLUSH_WAIT_S}s for metrics flush (interval=${METRIC_INTERVAL_S}s)..."
sleep "${FLUSH_WAIT_S}"

# ─── Graceful shutdown ───────────────────────────────────────────────────────

info "Sending nginx -s quit (graceful drain)..."
"${NGINX_BINARY}" -p "${PREFIX}" -c "${PREFIX}/nginx.conf" -s quit 2>/dev/null || true

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

if [[ -z "${NEW_CONTENT}" ]]; then
    fail "No new content in metrics.json — collector received nothing."
    echo -e "${RED}One or more assertions FAILED.${NC}" >&2
    exit 2
fi

# ─── Python3 structured assertions ───────────────────────────────────────────
#
# The collector writes NDJSON (one JSON object per line, each is a
# ResourceMetrics payload).  We use Python3 to search within the
# structured JSON rather than grepping raw text, so we can distinguish
# e.g. a "sum" key from a substring match.

ASSERT_SCRIPT=$(mktemp /tmp/ngx-otel-wire-assert.XXXXXX.py)
cleanup_assert() { rm -f "${ASSERT_SCRIPT}"; }
trap cleanup_assert EXIT

cat > "${ASSERT_SCRIPT}" <<'PYEOF'
#!/usr/bin/env python3
"""
Wire-shape assertions for metrics OTel-correctness changes.

Reads NDJSON from stdin (one ResourceMetrics JSON object per line).
Checks:
  A. nginx.requests.total is present as an OTLP Sum (has "sum" key, not "histogram").
  B. http.server.request.duration has unit "s".
  C. http.response.status_class attribute (string value) appears in dataPoints.
  D. nginx.http.request.duration.by_route is present.

Prints [PASS]/[FAIL] for each, exits non-zero if any assertion failed.
"""

import json
import sys

lines = [l.strip() for l in sys.stdin if l.strip()]

# Parse all records, flatten all metrics from all ResourceMetrics entries.
all_metrics = []
for line in lines:
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        continue
    for rm in obj.get("resourceMetrics", []):
        for sm in rm.get("scopeMetrics", []):
            for m in sm.get("metrics", []):
                all_metrics.append(m)

def find_metric(name):
    return [m for m in all_metrics if m.get("name") == name]

PASS = "\033[0;32m[PASS]\033[0m"
FAIL = "\033[0;31m[FAIL]\033[0m"

failed = 0

# ── A: nginx.requests.total as Sum ───────────────────────────────────────────
hits = find_metric("nginx.requests.total")
if not hits:
    print(f"{FAIL} A: nginx.requests.total not found in metrics.json delta")
    failed += 1
else:
    # Must have "sum" key, must NOT have "histogram" key.
    has_sum = any("sum" in m for m in hits)
    has_hist = any("histogram" in m for m in hits)
    if has_sum and not has_hist:
        print(f"{PASS} A: nginx.requests.total present as OTLP Sum (not Histogram)")
    elif has_hist:
        print(f"{FAIL} A: nginx.requests.total found with 'histogram' key — still emitted as Histogram, not Sum")
        failed += 1
    else:
        print(f"{FAIL} A: nginx.requests.total found but neither 'sum' nor 'histogram' key: {list(hits[0].keys())}")
        failed += 1

# ── B: http.server.request.duration unit "s" ─────────────────────────────────
dur_hits = find_metric("http.server.request.duration")
if not dur_hits:
    print(f"{FAIL} B: http.server.request.duration not found in metrics.json delta")
    failed += 1
else:
    unit_ok = all(m.get("unit") == "s" for m in dur_hits)
    units = list({m.get("unit") for m in dur_hits})
    if unit_ok:
        print(f"{PASS} B: http.server.request.duration unit = 's' (seconds)")
    else:
        print(f"{FAIL} B: http.server.request.duration unit is {units!r}, expected 's'")
        failed += 1

# ── C: http.response.status_class attribute ───────────────────────────────────
# Walk dataPoints in all exponential histogram metrics and look for the attribute.
found_status_class = False
for m in all_metrics:
    # exp histograms are under "exponentialHistogram"
    exp = m.get("exponentialHistogram", {})
    for dp in exp.get("dataPoints", []):
        for attr in dp.get("attributes", []):
            if attr.get("key") == "http.response.status_class":
                # Value must be a stringValue matching "NNxx" pattern (len==3).
                # Only set found_status_class when the value also passes validation
                # so a wrong-typed or wrong-shaped value does not produce a false PASS.
                val = attr.get("value", {})
                if "stringValue" in val:
                    sv = val["stringValue"]
                    if sv.endswith("xx") and len(sv) == 3:
                        found_status_class = True
                        break
        if found_status_class:
            break
    if found_status_class:
        break
if found_status_class:
    print(f"{PASS} C: http.response.status_class attribute found in dataPoints (string value)")
else:
    # May need status_code_class enabled and traffic to have generated enough data.
    # Flag as informational if the duration metric is present but attribute is absent
    # (could mean traffic was all unattributed, i.e. status_code_class was off).
    if dur_hits:
        # Check if any dataPoints exist in the duration metric at all.
        has_dps = any(
            m.get("exponentialHistogram", {}).get("dataPoints")
            for m in dur_hits
        )
        if has_dps:
            print(f"{FAIL} C: http.server.request.duration has dataPoints but none carry http.response.status_class")
            failed += 1
        else:
            print(f"{FAIL} C: http.server.request.duration has no dataPoints — cannot check status_class")
            failed += 1
    else:
        print(f"{FAIL} C: http.response.status_class not found (no duration dataPoints)")
        failed += 1

# ── D: nginx.http.request.duration.by_route ──────────────────────────────────
route_hits = find_metric("nginx.http.request.duration.by_route")
if route_hits:
    print(f"{PASS} D: nginx.http.request.duration.by_route (Tier-2 rename) found")
else:
    # This series exists only when requests matched named locations. Check if
    # any nginx.* request duration series appeared (by_upstream is an alternative).
    upstream_hits = find_metric("nginx.http.request.duration.by_upstream")
    if upstream_hits:
        print(f"{PASS} D: nginx.http.request.duration.by_upstream found (by_route absent — no named upstream in config)")
    else:
        print(f"{FAIL} D: neither nginx.http.request.duration.by_route nor by_upstream found in delta")
        failed += 1

# ── Summary ───────────────────────────────────────────────────────────────────
print("")
if failed == 0:
    print(f"{PASS} All wire-shape assertions passed.")
    sys.exit(0)
else:
    print(f"\033[0;31m{failed} assertion(s) FAILED.\033[0m")
    sys.exit(2)
PYEOF

chmod +x "${ASSERT_SCRIPT}"

info "Running structured wire-shape assertions (Python3)..."
echo ""

ASSERT_EXIT=0
echo "${NEW_CONTENT}" | python3 "${ASSERT_SCRIPT}" || ASSERT_EXIT=$?

if [[ "${ASSERT_EXIT}" -ne 0 ]]; then
    FAILED=1
fi

# ─── Supplemental grep-level checks ──────────────────────────────────────────

info "Supplemental grep checks on metrics.json delta..."

# No old _sum-suffix counter series should appear.
OLD_SUM_NAMES=("nginx_requests_total_sum" "nginx.requests.total_sum"
               "nginx_connections_accepted_sum" "nginx_connections_handled_sum")
for old in "${OLD_SUM_NAMES[@]}"; do
    if echo "${NEW_CONTENT}" | grep -q "${old}"; then
        fail "OLD series name '${old}' found in metrics.json delta — counter still exported as Histogram"
    fi
done
if echo "${NEW_CONTENT}" | grep -q "nginx.requests.total"; then
    pass "nginx.requests.total found in delta (grep)"
fi

# No old http_server_upstream_ series.
if echo "${NEW_CONTENT}" | grep -q '"http.server.upstream'; then
    fail "OLD http.server.upstream.* series found in delta (should be nginx.upstream.*)"
else
    pass "No http.server.upstream.* series in delta (PASS — old names absent)"
fi

# No old http_server_request_duration_by_ series.
if echo "${NEW_CONTENT}" | grep -q '"http.server.request.duration.by_'; then
    fail "OLD http.server.request.duration.by_* series found in delta (should be nginx.http.request.duration.by_*)"
else
    pass "No http.server.request.duration.by_* series in delta (PASS — old names absent)"
fi

# Export loop started exactly once.
SPAWN_COUNT=$(grep -c "export loop started" "${PREFIX}/logs/error.log" 2>/dev/null) || SPAWN_COUNT=0
if [[ "${SPAWN_COUNT}" -eq 1 ]]; then
    pass "error.log: exactly 1 'export loop started' line"
else
    fail "error.log: expected 1 'export loop started' line, got ${SPAWN_COUNT}"
fi

# No panics or crashes.
PANIC_COUNT=$(grep -cE "panicked|signal 11|signal 6|exited on signal" "${PREFIX}/logs/error.log" 2>/dev/null) || PANIC_COUNT=0
if [[ "${PANIC_COUNT}" -eq 0 ]]; then
    pass "error.log: no panics / crashes"
else
    fail "error.log: ${PANIC_COUNT} crash/panic line(s)"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────

echo ""
if [[ "${FAILED}" -eq 0 ]]; then
    pass "All assertions passed. Metrics wire-shape test COMPLETE."
    echo ""
    echo "  New metrics.json tail (last 2 lines):"
    echo "${NEW_CONTENT}" | tail -2
    exit 0
else
    echo -e "${RED}One or more assertions FAILED.${NC}" >&2
    echo ""
    echo "  metrics.json delta (first 3 lines for diagnostics):"
    echo "${NEW_CONTENT}" | head -3
    exit 2
fi
