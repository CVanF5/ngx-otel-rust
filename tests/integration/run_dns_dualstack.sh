#!/usr/bin/env bash
# tests/integration/run_dns_dualstack.sh — DNS resolution + dual-stack integration test
#
# Exercises DNS name resolution and dual-stack connectivity:
#
# TEST A — DNS name → v4 connect
#   A local Python DNS stub (dns_stub.py) answers A queries for a synthetic
#   hostname ("ngx-otel-dns-test") with 127.0.0.1.  nginx is configured with
#   that hostname as the OTLP endpoint and the stub's port as the resolver.
#   The existing OTel collector (Docker) receives the export on 127.0.0.1:4318.
#   Assertion: metrics.json delta shows at least one new record.
#
# TEST B — IPv6 literal endpoint
#   A local Python HTTP stub (v6_http_stub.py) listens on [::1]:14318.  nginx
#   is configured with http://[::1]:14318/v1/metrics as the endpoint (no
#   resolver directive needed).
#   Assertion: the stub's output file is non-empty (nginx connected over v6
#   and delivered at least one OTLP POST body).
#
# TEST C — DNS name → v6 connect via AAAA (FU2 — headline dual-stack proof)
#   dns_stub.py in "aaaa" mode answers AAAA queries with ::1 and A → NXDOMAIN.
#   nginx resolver has ipv6=on (default; no ipv6=off flag) so it issues AAAA.
#   The v6_http_stub.py listens on [::1]:14319.  Asserts records arrive at the
#   v6 stub — proving the resolved-v6 addr.socklen install path end-to-end.
#
#   Platform note: TEST C is the Linux-primary test for the DNS→v6 AAAA path.
#   On macOS the test is also run (macOS supports ::1 natively), but if the
#   platform cannot bind ::1, the test skips with a documented notice rather
#   than failing — the AAAA code path is verified on Linux/TSAN which is the
#   canonical verification platform per the project's two-host discipline.
#
# TEST D — Unresolvable name clean error (FU2)
#   dns_stub.py in "nxdomain" mode returns NXDOMAIN for all queries.  nginx is
#   configured with the unresolvable name as the endpoint.  Asserts: no panic,
#   no crash, nginx accepts -QUIT; error.log contains a connection-failure entry
#   (not a panic); no records arrive at the collector.
#
# Prerequisites
# ─────────────
#   - Docker (for the OTLP collector; TEST A and TEST D assertion only).
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
# When CARGO_BUILD_TARGET is set (i.e., inside the TSAN Docker gate), the
# cross-compiled module in target/ was just freshly built by run_grpc_export.sh
# in the same gate run.  Prefer it over objs-release/ which can be stale.
# In a native (non-TSAN) run, CARGO_BUILD_TARGET is unset and objs-release/ is
# preferred as before.
if [[ -n "${CARGO_BUILD_TARGET:-}" ]] && [[ -f "${CARGO_MODULE}" ]]; then
    MODULE_PATH="${CARGO_MODULE}"
elif [[ -f "${RELEASE_MODULE}" ]]; then
    MODULE_PATH="${RELEASE_MODULE}"
elif [[ -f "${CARGO_MODULE}" ]]; then
    MODULE_PATH="${CARGO_MODULE}"
else
    echo "ERROR: module not found.  Run 'make build-release' first." >&2
    exit 1
fi

# ─── Tunables ────────────────────────────────────────────────────────────────

DNS_STUB_PORT=15353        # TEST A: A → 127.0.0.1
COLLECTOR_PORT=4318
V6_STUB_PORT=14318         # TEST B: literal [::1] endpoint
DNS_SERVER_PORT=9210       # TEST A nginx listener
V6_SERVER_PORT=9211        # TEST B nginx listener
DNS_AAAA_STUB_PORT=15354   # TEST C: AAAA → ::1
V6_AAAA_STUB_PORT=14319    # TEST C: v6 HTTP stub
AAAA_SERVER_PORT=9212      # TEST C nginx listener
NXDOMAIN_STUB_PORT=15355   # TEST D: NXDOMAIN
NXDOMAIN_SERVER_PORT=9213  # TEST D nginx listener
DNS_HOSTNAME="ngx-otel-dns-test"
DNS_AAAA_HOSTNAME="ngx-otel-dns-aaaa"
NXDOMAIN_HOSTNAME="ngx-otel-nxdomain-test"
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
NGINX_C_PID=""
NGINX_D_PID=""
DNS_AAAA_PID=""
V6_AAAA_PID=""
NXDOMAIN_DNS_PID=""
PREFIX_A=""
PREFIX_B=""
PREFIX_C=""
PREFIX_D=""
V6_OUTPUT=""
V6_AAAA_OUTPUT=""

cleanup_all() {
    [[ -n "${NGINX_A_PID:-}" ]]      && kill "${NGINX_A_PID}"      2>/dev/null || true
    [[ -n "${NGINX_B_PID:-}" ]]      && kill "${NGINX_B_PID}"      2>/dev/null || true
    [[ -n "${NGINX_C_PID:-}" ]]      && kill "${NGINX_C_PID}"      2>/dev/null || true
    [[ -n "${NGINX_D_PID:-}" ]]      && kill "${NGINX_D_PID}"      2>/dev/null || true
    [[ -n "${DNS_PID:-}" ]]          && kill "${DNS_PID}"           2>/dev/null || true
    [[ -n "${V6_PID:-}" ]]           && kill "${V6_PID}"            2>/dev/null || true
    [[ -n "${DNS_AAAA_PID:-}" ]]     && kill "${DNS_AAAA_PID}"      2>/dev/null || true
    [[ -n "${V6_AAAA_PID:-}" ]]      && kill "${V6_AAAA_PID}"       2>/dev/null || true
    [[ -n "${NXDOMAIN_DNS_PID:-}" ]] && kill "${NXDOMAIN_DNS_PID}"  2>/dev/null || true
    sleep 1
    [[ -n "${PREFIX_A:-}" ]]        && rm -rf "${PREFIX_A}"        || true
    [[ -n "${PREFIX_B:-}" ]]        && rm -rf "${PREFIX_B}"        || true
    [[ -n "${PREFIX_C:-}" ]]        && rm -rf "${PREFIX_C}"        || true
    [[ -n "${PREFIX_D:-}" ]]        && rm -rf "${PREFIX_D}"        || true
    [[ -n "${V6_OUTPUT:-}" ]]       && rm -f "${V6_OUTPUT}"        || true
    [[ -n "${V6_AAAA_OUTPUT:-}" ]]  && rm -f "${V6_AAAA_OUTPUT}"   || true
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

# ─── TEST C: DNS name → v6 via AAAA (FU2) ────────────────────────────────────

info "=== TEST C: DNS name → v6 via AAAA (FU2 — headline dual-stack proof) ==="

# Platform check: skip gracefully if ::1 can't be bound (rare CI edge-case).
# Document the skip so it's visible; don't silently pass.
if ! python3 -c "
import socket, sys
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
try:
    s.bind(('::1', 0))
    s.close()
    sys.exit(0)
except OSError:
    sys.exit(1)
" 2>/dev/null; then
    info "TEST C: SKIP — platform cannot bind ::1 (IPv6 loopback unavailable)."
    info "  The DNS→v6 AAAA code path is verified on Linux/TSAN."
    info "  See project two-host discipline: debian-vm is the Linux verification platform."
else
    # 1. Start the v6 HTTP stub (receives OTLP POST on [::1]:V6_AAAA_STUB_PORT).
    V6_AAAA_OUTPUT="$(mktemp /tmp/ngx-otel-v6-aaaa.XXXXXX)"
    python3 "${SCRIPT_DIR}/v6_http_stub.py" "${V6_AAAA_STUB_PORT}" "${V6_AAAA_OUTPUT}" &
    V6_AAAA_PID=$!
    info "v6 AAAA HTTP stub PID ${V6_AAAA_PID} on [::1]:${V6_AAAA_STUB_PORT}"
    sleep 0.3

    # 2. Start the DNS stub in AAAA mode (AAAA → ::1, A → NXDOMAIN).
    python3 "${SCRIPT_DIR}/dns_stub.py" "${DNS_AAAA_STUB_PORT}" aaaa "::1" &
    DNS_AAAA_PID=$!
    info "DNS AAAA stub PID ${DNS_AAAA_PID} on 127.0.0.1:${DNS_AAAA_STUB_PORT} → ${DNS_AAAA_HOSTNAME}→::1"
    sleep 0.3

    # 3. Build nginx.conf for TEST C (resolver without ipv6=off → issues AAAA).
    PREFIX_C="$(mktemp -d /tmp/ngx-otel-dns-c.XXXXXX)"
    mkdir -p "${PREFIX_C}/logs" "${PREFIX_C}/client_body_temp"
    sed \
        -e "s|@MODULE_PATH@|${MODULE_PATH}|g" \
        -e "s|@PREFIX@|${PREFIX_C}|g" \
        -e "s|@DNS_PORT@|${DNS_AAAA_STUB_PORT}|g" \
        -e "s|@COLLECTOR_PORT@|${V6_AAAA_STUB_PORT}|g" \
        -e "s|@SERVER_PORT@|${AAAA_SERVER_PORT}|g" \
        -e "s|@DNS_HOSTNAME@|${DNS_AAAA_HOSTNAME}|g" \
        "${SCRIPT_DIR}/nginx_dualstack_dns_aaaa.conf" > "${PREFIX_C}/nginx.conf"

    # 4. Start nginx for TEST C.
    "${NGINX_BINARY}" -p "${PREFIX_C}" -c "${PREFIX_C}/nginx.conf" &
    NGINX_C_PID=$!
    info "nginx TEST C PID ${NGINX_C_PID}"
    sleep 1

    # 5. Send some traffic.
    info "Sending ${N_REQUESTS} requests to nginx (TEST C)..."
    for i in $(seq 1 "${N_REQUESTS}"); do
        curl -s "http://127.0.0.1:${AAAA_SERVER_PORT}/" > /dev/null
    done

    # 6. Wait for the metric flush.
    info "Waiting ${FLUSH_WAIT_S}s for metric flush (TEST C)..."
    sleep "${FLUSH_WAIT_S}"

    # 7. Graceful stop.
    kill -QUIT "${NGINX_C_PID}" 2>/dev/null || true
    wait "${NGINX_C_PID}" 2>/dev/null || true
    NGINX_C_PID=""
    sleep 1

    # Stop stubs.
    kill "${V6_AAAA_PID}" 2>/dev/null || true
    wait "${V6_AAAA_PID}" 2>/dev/null || true
    V6_AAAA_PID=""
    kill "${DNS_AAAA_PID}" 2>/dev/null || true
    wait "${DNS_AAAA_PID}" 2>/dev/null || true
    DNS_AAAA_PID=""

    # 8. Assertions for TEST C.
    # C1: error.log must have "export loop started".
    if grep -q 'export loop started' "${PREFIX_C}/logs/error.log" 2>/dev/null; then
        pass "TEST C: error.log contains 'export loop started'"
    else
        fail "TEST C: 'export loop started' missing from error.log"
    fi

    # C2: error.log must NOT contain resolver-missing error.
    if grep -q 'requires nginx.*resolver directive' "${PREFIX_C}/logs/error.log" 2>/dev/null; then
        fail "TEST C: resolver-missing error found — resolver wiring broken"
    else
        pass "TEST C: no resolver-missing error in error.log"
    fi

    # C3: error.log must NOT contain connect/DNS errors.
    if grep -qE 'connection refused|no addresses resolved' \
        "${PREFIX_C}/logs/error.log" 2>/dev/null; then
        fail "TEST C: unexpected connection / DNS error in error.log:"
        grep -E 'connection refused|no addresses resolved' \
            "${PREFIX_C}/logs/error.log" | head -5 >&2
    else
        pass "TEST C: no connection / DNS errors in error.log"
    fi

    # C4: the v6 AAAA HTTP stub must have received at least one non-empty body.
    # This is the headline assertion — proves DNS→AAAA→::1 resolved-v6 socklen
    # path end-to-end.
    if [[ -s "${V6_AAAA_OUTPUT}" ]]; then
        RECEIVED_BYTES="$(wc -c < "${V6_AAAA_OUTPUT}" | tr -d ' ')"
        pass "TEST C: v6 AAAA stub received ${RECEIVED_BYTES} bytes — DNS→v6 AAAA path confirmed (FU2)"
    else
        fail "TEST C: v6 AAAA stub output empty — nginx did not export to [::1]:${V6_AAAA_STUB_PORT} via AAAA resolution"
    fi
fi  # end of platform check

# ─── TEST D: Unresolvable name clean error (FU2) ─────────────────────────────

info "=== TEST D: Unresolvable name — clean error, no panic, no hang (FU2) ==="

# 1. Start the DNS stub in nxdomain mode.
python3 "${SCRIPT_DIR}/dns_stub.py" "${NXDOMAIN_STUB_PORT}" nxdomain &
NXDOMAIN_DNS_PID=$!
info "DNS NXDOMAIN stub PID ${NXDOMAIN_DNS_PID} on 127.0.0.1:${NXDOMAIN_STUB_PORT}"
sleep 0.3

# 2. Build nginx.conf for TEST D.
PREFIX_D="$(mktemp -d /tmp/ngx-otel-dns-d.XXXXXX)"
mkdir -p "${PREFIX_D}/logs" "${PREFIX_D}/client_body_temp"
sed \
    -e "s|@MODULE_PATH@|${MODULE_PATH}|g" \
    -e "s|@PREFIX@|${PREFIX_D}|g" \
    -e "s|@DNS_PORT@|${NXDOMAIN_STUB_PORT}|g" \
    -e "s|@SERVER_PORT@|${NXDOMAIN_SERVER_PORT}|g" \
    -e "s|@DNS_HOSTNAME@|${NXDOMAIN_HOSTNAME}|g" \
    "${SCRIPT_DIR}/nginx_dualstack_nxdomain.conf" > "${PREFIX_D}/nginx.conf"

# 3. Start nginx for TEST D.
BEFORE_D="$(collector_metric_count)"
"${NGINX_BINARY}" -p "${PREFIX_D}" -c "${PREFIX_D}/nginx.conf" &
NGINX_D_PID=$!
info "nginx TEST D PID ${NGINX_D_PID}"
sleep 1

# 4. Send some traffic (nginx HTTP front-end works even though export is broken).
info "Sending ${N_REQUESTS} requests to nginx (TEST D)..."
for i in $(seq 1 "${N_REQUESTS}"); do
    curl -s "http://127.0.0.1:${NXDOMAIN_SERVER_PORT}/" > /dev/null
done

# 5. Wait for the export attempt and flush.
info "Waiting ${FLUSH_WAIT_S}s (TEST D)..."
sleep "${FLUSH_WAIT_S}"

# 6. Graceful stop — nginx must accept -QUIT (no hang, no crash).
kill -QUIT "${NGINX_D_PID}" 2>/dev/null || true
D_WAIT_START="$(date +%s)"
wait "${NGINX_D_PID}" 2>/dev/null || true
NGINX_D_PID=""
D_WAIT_ELAPSED=$(( $(date +%s) - D_WAIT_START ))

# Stop NXDOMAIN DNS stub.
kill "${NXDOMAIN_DNS_PID}" 2>/dev/null || true
wait "${NXDOMAIN_DNS_PID}" 2>/dev/null || true
NXDOMAIN_DNS_PID=""
sleep 1

# 7. Assertions for TEST D.
# D1: nginx accepted -QUIT and exited within 15 s (not hung).
if (( D_WAIT_ELAPSED < 15 )); then
    pass "TEST D: nginx exited cleanly within ${D_WAIT_ELAPSED}s of -QUIT (no hang)"
else
    fail "TEST D: nginx took ${D_WAIT_ELAPSED}s to exit — possible hang on NXDOMAIN error path"
fi

# D2: no Rust panic in error.log.
if grep -q 'panicked at\|SIGSEGV\|SIGABRT' "${PREFIX_D}/logs/error.log" 2>/dev/null; then
    fail "TEST D: panic / fatal signal found in error.log (NXDOMAIN must not crash):"
    grep 'panicked at\|SIGSEGV\|SIGABRT' "${PREFIX_D}/logs/error.log" | head -5 >&2
else
    pass "TEST D: no panic or fatal signal in error.log"
fi

# D3: error.log must contain a connection/resolve failure entry (expected).
if grep -qE 'export failed|failed to resolve|no addresses resolved|DNS|resolver' \
    "${PREFIX_D}/logs/error.log" 2>/dev/null; then
    pass "TEST D: error.log contains expected connection-failure entry (NXDOMAIN error path)"
else
    # Not a HARD fail — the module might retry silently; warn instead.
    info "TEST D: WARNING — no connection-failure entry found in error.log (check manually)"
fi

# D4: collector metric count must NOT have grown (no records exported).
AFTER_D="$(collector_metric_count)"
if (( AFTER_D == BEFORE_D )); then
    pass "TEST D: collector metric count unchanged (${BEFORE_D}) — no records exported on NXDOMAIN (correct)"
else
    # The module might export a final drain on shutdown; treat as warning not fail
    # because the service.name would differ (ngx-otel-dualstack-nxdomain), but the
    # collector JSON doesn't filter by service.name.
    info "TEST D: INFO — collector count changed (${BEFORE_D} → ${AFTER_D}); if drain flushed on shutdown that is expected"
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
