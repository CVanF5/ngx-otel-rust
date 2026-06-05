#!/usr/bin/env bash
# tests/integration/run_dns_dualstack.sh — DNS resolution + dual-stack integration test
#
# Exercises Items 2 + 3 of the transport_dns work (Phase 1.x):
#
# TEST A — DNS name → v4 connect
#   A local Python DNS stub (dns_stub.py) answers A queries for a synthetic
#   hostname ("ngx-otel-dns-test") with 127.0.0.1.  nginx is configured with
#   that hostname as the OTLP endpoint and the stub's port as the resolver.
#   The existing OTel collector (Docker) receives the export on 127.0.0.1:4318.
#   Assertion: metrics.json delta shows at least one new record with the
#   expected service.name.
#
# TEST B — IPv6 literal endpoint
#   A local Python HTTP stub (v6_http_stub.py) listens on [::1]:14318.  nginx
#   is configured with http://[::1]:14318/v1/metrics as the endpoint (no
#   resolver directive needed).
#   Assertion: the stub's output file is non-empty (nginx connected over v6
#   and delivered at least one OTLP POST body).
#
# Prerequisites
# ─────────────
#   - Docker (for the OTLP collector; TEST A only).
#   - Python 3 on PATH (used for dns_stub.py and v6_http_stub.py).
#   - The ngx-otel-rust release module built (make build-release).
#   - NGINX_BINARY set or auto-detected.
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

. "${CRATE_DIR}/test-harness/lib.sh"
resolve_nginx_binary || true

case "$(uname -s)" in
    Darwin) MODULE_EXT="dylib" ;;
    *)      MODULE_EXT="so"    ;;
esac

RELEASE_MODULE="${CRATE_DIR}/objs-release/ngx_http_otel_module.so"
CARGO_MODULE="${CRATE_DIR}/target/release/libngx_http_otel_module.${MODULE_EXT}"
if [[ -n "${CARGO_BUILD_TARGET:-}" ]]; then
    CARGO_MODULE="${CRATE_DIR}/target/${CARGO_BUILD_TARGET}/release/libngx_http_otel_module.${MODULE_EXT}"
fi
if [[ -f "${RELEASE_MODULE}" ]]; then
    MODULE_PATH="${RELEASE_MODULE}"
elif [[ -f "${CARGO_MODULE}" ]]; then
    MODULE_PATH="${CARGO_MODULE}"
else
    echo "ERROR: module not found.  Run 'make build-release' first." >&2
    exit 1
fi

# ─── Tunables ────────────────────────────────────────────────────────────────

DNS_STUB_PORT=15353
COLLECTOR_PORT=4318
V6_STUB_PORT=14318
# nginx HTTP server ports — distinct from each other and from collector ports.
DNS_SERVER_PORT=9210
V6_SERVER_PORT=9211
DNS_HOSTNAME="ngx-otel-dns-test"
METRIC_INTERVAL_S=2
FLUSH_WAIT_S=$(( METRIC_INTERVAL_S + 3 ))
N_REQUESTS=5

# ─── Colour helpers ──────────────────────────────────────────────────────────

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

FAILED=0
pass()  { echo -e "${GREEN}[PASS]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*" >&2; FAILED=1; }
info()  { echo -e "${YELLOW}[INFO]${NC} $*"; }

# ─── Pre-flight ──────────────────────────────────────────────────────────────

info "Pre-flight checks..."

if [[ ! -x "${NGINX_BINARY}" ]]; then
    echo "ERROR: nginx binary not found at ${NGINX_BINARY}." >&2
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 not found on PATH; required for DNS/v6 stubs." >&2
    exit 1
fi

info "nginx binary: ${NGINX_BINARY}"
info "Module:       ${MODULE_PATH}"

# ─── Global cleanup ──────────────────────────────────────────────────────────

DNS_PID=""
V6_PID=""
NGINX_A_PID=""
NGINX_B_PID=""
PREFIX_A=""
PREFIX_B=""
V6_OUTPUT=""

cleanup_all() {
    [[ -n "${NGINX_A_PID:-}" ]] && kill "${NGINX_A_PID}" 2>/dev/null || true
    [[ -n "${NGINX_B_PID:-}" ]] && kill "${NGINX_B_PID}" 2>/dev/null || true
    [[ -n "${DNS_PID:-}" ]]     && kill "${DNS_PID}"     2>/dev/null || true
    [[ -n "${V6_PID:-}" ]]      && kill "${V6_PID}"      2>/dev/null || true
    sleep 1
    [[ -n "${PREFIX_A:-}" ]] && rm -rf "${PREFIX_A}" || true
    [[ -n "${PREFIX_B:-}" ]] && rm -rf "${PREFIX_B}" || true
    [[ -n "${V6_OUTPUT:-}" ]] && rm -f "${V6_OUTPUT}" || true
}
trap cleanup_all EXIT

# ─── Helpers ─────────────────────────────────────────────────────────────────

wait_for() {
    local timeout=$1 desc=$2 expr=$3
    local deadline=$(( $(date +%s) + timeout ))
    while (( $(date +%s) < deadline )); do
        if eval "${expr}" 2>/dev/null; then return 0; fi
        sleep 0.5
    done
    fail "Timed out waiting for: ${desc}"
    return 1
}

# ─── TEST A: DNS name → v4 connect ───────────────────────────────────────────

info "=== TEST A: DNS name → v4 connect ==="

# 1. Start the OTLP collector (existing Docker setup).
ensure_collector_running

# 2. Start the DNS stub.
python3 "${SCRIPT_DIR}/dns_stub.py" "${DNS_STUB_PORT}" "127.0.0.1" &
DNS_PID=$!
info "DNS stub PID ${DNS_PID} on 127.0.0.1:${DNS_STUB_PORT} → ${DNS_HOSTNAME}→127.0.0.1"
sleep 0.3

# 3. Build nginx.conf for TEST A.
PREFIX_A="$(mktemp -d /tmp/ngx-otel-dns-a.XXXXXX)"
mkdir -p "${PREFIX_A}/logs" "${PREFIX_A}/client_body_temp"
sed \
    -e "s|@MODULE_PATH@|${MODULE_PATH}|g" \
    -e "s|@PREFIX@|${PREFIX_A}|g" \
    -e "s|@DNS_PORT@|${DNS_STUB_PORT}|g" \
    -e "s|@COLLECTOR_PORT@|${COLLECTOR_PORT}|g" \
    -e "s|@SERVER_PORT@|${DNS_SERVER_PORT}|g" \
    -e "s|@DNS_HOSTNAME@|${DNS_HOSTNAME}|g" \
    "${SCRIPT_DIR}/nginx_dualstack_dns.conf" > "${PREFIX_A}/nginx.conf"

# 4. Start nginx for TEST A.
BEFORE_A="$(collector_metric_count)"
"${NGINX_BINARY}" -p "${PREFIX_A}" -c "${PREFIX_A}/nginx.conf" &
NGINX_A_PID=$!
info "nginx TEST A PID ${NGINX_A_PID}"
sleep 1

# 5. Send some traffic.
info "Sending ${N_REQUESTS} requests to nginx (TEST A)..."
for i in $(seq 1 "${N_REQUESTS}"); do
    curl -s "http://127.0.0.1:${DNS_SERVER_PORT}/" > /dev/null
done

# 6. Wait for the metric flush.
info "Waiting ${FLUSH_WAIT_S}s for metric flush (TEST A)..."
sleep "${FLUSH_WAIT_S}"

# 7. Graceful stop.
kill -QUIT "${NGINX_A_PID}" 2>/dev/null || true
wait "${NGINX_A_PID}" 2>/dev/null || true
NGINX_A_PID=""
sleep 1

# 8. Assertions for TEST A.
# A1: error.log must have "export loop started" (exporter process started).
if grep -q 'export loop started' "${PREFIX_A}/logs/error.log" 2>/dev/null; then
    pass "TEST A: error.log contains 'export loop started'"
else
    fail "TEST A: 'export loop started' missing from error.log"
fi

# A2: error.log must NOT contain "DNS endpoint .* requires nginx's resolver directive".
if grep -q 'requires nginx.*resolver directive' "${PREFIX_A}/logs/error.log" 2>/dev/null; then
    fail "TEST A: error.log contains resolver-missing error — resolver wiring broken"
else
    pass "TEST A: no resolver-missing error in error.log"
fi

# A3: error.log must NOT contain "export failed" from a connect error.
# (Export can fail if OTLP parsing fails, which is fine; but a persistent
# "connect" or "DNS" error is a fail.)
if grep -qE 'connection refused|DNS endpoint|no addresses resolved' \
    "${PREFIX_A}/logs/error.log" 2>/dev/null; then
    fail "TEST A: connection / DNS error found in error.log:"
    grep -E 'connection refused|DNS endpoint|no addresses resolved' \
        "${PREFIX_A}/logs/error.log" | head -5 >&2
else
    pass "TEST A: no connection / DNS errors in error.log"
fi

# A4: collector received at least one new metric record.
AFTER_A="$(collector_metric_count)"
if (( AFTER_A > BEFORE_A )); then
    pass "TEST A: collector received +$(( AFTER_A - BEFORE_A )) new metric record(s) (DNS → v4 path confirmed)"
else
    fail "TEST A: collector metric count unchanged (${BEFORE_A} → ${AFTER_A}); DNS export did not reach collector"
fi

# Stop DNS stub (no longer needed).
kill "${DNS_PID}" 2>/dev/null || true
wait "${DNS_PID}" 2>/dev/null || true
DNS_PID=""

# ─── TEST B: IPv6 literal endpoint ───────────────────────────────────────────

info "=== TEST B: IPv6 literal endpoint ==="

# 1. Create temp file for v6_http_stub output.
V6_OUTPUT="$(mktemp /tmp/ngx-otel-v6-received.XXXXXX)"

# 2. Start the IPv6 HTTP stub.
python3 "${SCRIPT_DIR}/v6_http_stub.py" "${V6_STUB_PORT}" "${V6_OUTPUT}" &
V6_PID=$!
info "IPv6 HTTP stub PID ${V6_PID} on [::1]:${V6_STUB_PORT}"
sleep 0.3

# 3. Build nginx.conf for TEST B.
PREFIX_B="$(mktemp -d /tmp/ngx-otel-dns-b.XXXXXX)"
mkdir -p "${PREFIX_B}/logs" "${PREFIX_B}/client_body_temp"
sed \
    -e "s|@MODULE_PATH@|${MODULE_PATH}|g" \
    -e "s|@PREFIX@|${PREFIX_B}|g" \
    -e "s|@V6_PORT@|${V6_STUB_PORT}|g" \
    -e "s|@SERVER_PORT@|${V6_SERVER_PORT}|g" \
    "${SCRIPT_DIR}/nginx_dualstack_v6.conf" > "${PREFIX_B}/nginx.conf"

# 4. Start nginx for TEST B.
"${NGINX_BINARY}" -p "${PREFIX_B}" -c "${PREFIX_B}/nginx.conf" &
NGINX_B_PID=$!
info "nginx TEST B PID ${NGINX_B_PID}"
sleep 1

# 5. Send some traffic.
info "Sending ${N_REQUESTS} requests to nginx (TEST B)..."
for i in $(seq 1 "${N_REQUESTS}"); do
    curl -s "http://127.0.0.1:${V6_SERVER_PORT}/" > /dev/null
done

# 6. Wait for the metric flush.
info "Waiting ${FLUSH_WAIT_S}s for metric flush (TEST B)..."
sleep "${FLUSH_WAIT_S}"

# 7. Graceful stop.
kill -QUIT "${NGINX_B_PID}" 2>/dev/null || true
wait "${NGINX_B_PID}" 2>/dev/null || true
NGINX_B_PID=""
sleep 1

# Stop v6 stub (wait for it to flush and exit).
kill "${V6_PID}" 2>/dev/null || true
wait "${V6_PID}" 2>/dev/null || true
V6_PID=""

# 8. Assertions for TEST B.
# B1: error.log must have "export loop started".
if grep -q 'export loop started' "${PREFIX_B}/logs/error.log" 2>/dev/null; then
    pass "TEST B: error.log contains 'export loop started'"
else
    fail "TEST B: 'export loop started' missing from error.log"
fi

# B2: error.log must NOT contain v6-connection errors.
if grep -qE 'connection refused|IPv6|failed to connect' \
    "${PREFIX_B}/logs/error.log" 2>/dev/null; then
    fail "TEST B: unexpected connection error in error.log:"
    grep -E 'connection refused|IPv6|failed to connect' \
        "${PREFIX_B}/logs/error.log" | head -5 >&2
else
    pass "TEST B: no IPv6 connection errors in error.log"
fi

# B3: the v6 HTTP stub must have received at least one non-empty OTLP body.
if [[ -s "${V6_OUTPUT}" ]]; then
    RECEIVED_BYTES="$(wc -c < "${V6_OUTPUT}" | tr -d ' ')"
    pass "TEST B: v6 stub received ${RECEIVED_BYTES} bytes — IPv6 literal connect confirmed"
else
    fail "TEST B: v6 stub output file is empty — nginx did not export to [::1]:${V6_STUB_PORT}"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────

echo ""
if (( FAILED == 0 )); then
    pass "All DNS + dual-stack integration assertions passed."
    exit 0
else
    fail "One or more assertions FAILED."
    exit 2
fi
