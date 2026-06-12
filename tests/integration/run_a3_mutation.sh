#!/usr/bin/env bash
# tests/integration/run_a3_mutation.sh — A3 security mutation test
#
# Mutation: disables SSL_VERIFY_PEER in tls.rs (sets SSL_VERIFY_NONE in the
# non-insecure branch) → scenario (c) MUST deliver data to the collector
# (because verification is silently bypassed). Without this mutation, scenario
# (c) delivers zero data. After restore, scenario (c) must fail-closed again.
#
# This is the security-critical mutation that a reviewer must re-execute.
#
# Evidence written to: tests/RESULTS-a3-mutation-YYYY-MM-DD.txt
#
# Exit codes: 0 = mutation test PASS (both halves verified), 1 = error,
#             2 = mutation assertion failed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPO_ROOT="$(cd "${CRATE_DIR}/.." && pwd)"

NGINX_SOURCE_DIR="${NGINX_SOURCE_DIR:-${REPO_ROOT}/nginx}"
NGINX_BUILD_DIR="${NGINX_BUILD_DIR:-${CRATE_DIR}/objs-release}"
NGINX_BINARY="${NGINX_BINARY:-${NGINX_BUILD_DIR}/nginx}"

case "$(uname -s)" in
    Darwin) MODULE_EXT="dylib" ;;
    *)      MODULE_EXT="so"    ;;
esac
if [[ -n "${CARGO_BUILD_TARGET:-}" ]]; then
    MODULE_PATH="${CRATE_DIR}/target/${CARGO_BUILD_TARGET}/release/libngx_http_otel_module.${MODULE_EXT}"
else
    MODULE_PATH="${CRATE_DIR}/target/release/libngx_http_otel_module.${MODULE_EXT}"
fi

TLS_RS="${CRATE_DIR}/src/transport/tls.rs"
EVIDENCE="${CRATE_DIR}/tests/RESULTS-a3-mutation-$(date -u +%Y-%m-%d).txt"
A3_SCRATCH="${REPO_ROOT}/a3-scratch"

TLS_HTTP_PORT=4319
TLS_COLLECTOR_NAME="ngx-otel-a3-mut-collector"
METRIC_INTERVAL_S=1
FLUSH_WAIT_S=5

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
pass()  { echo -e "${GREEN}[PASS]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*" >&2; exit 2; }
info()  { echo -e "${YELLOW}[INFO]${NC} $*"; }

# ─── Pre-flight ──────────────────────────────────────────────────────────────

[[ -x "${NGINX_BINARY}" ]] || { echo "ERROR: nginx binary not found: ${NGINX_BINARY}" >&2; exit 1; }
command -v jq >/dev/null || { echo "ERROR: jq required" >&2; exit 1; }
command -v docker >/dev/null || { echo "ERROR: docker required" >&2; exit 1; }
command -v openssl >/dev/null || { echo "ERROR: openssl required" >&2; exit 1; }
[[ -f "${TLS_RS}" ]] || { echo "ERROR: tls.rs not found at ${TLS_RS}" >&2; exit 1; }

# Verify the mutation target line exists (exact string match).
grep -qF 'unsafe { ssl::SSL_CTX_set_verify(ctx, ssl::SSL_VERIFY_PEER, None) };' "${TLS_RS}" \
    || { echo "ERROR: mutation target not found in ${TLS_RS}. Script needs updating." >&2; exit 1; }

PRE_SHA="$(git -C "${CRATE_DIR}" rev-parse HEAD)"
info "Pre-mutation SHA: ${PRE_SHA}"
mkdir -p "${A3_SCRATCH}/logs"

# ─── Cert generation (mirrors run_a3_tls_e2e.sh) ────────────────────────────

PREFIX="$(mktemp -d /tmp/ngx-otel-a3-mut.XXXXXX)"
CERTS="${PREFIX}/certs"
mkdir -p "${PREFIX}/logs" "${PREFIX}/client_body_temp" "${CERTS}"

NGINX_PID=""
COLLECTOR_RUNNING=0
RESTORED=0

cleanup() {
    [[ -n "${NGINX_PID}" ]] && kill -QUIT "${NGINX_PID}" 2>/dev/null || true
    if [[ "${COLLECTOR_RUNNING}" -eq 1 ]]; then
        docker stop "${TLS_COLLECTOR_NAME}" 2>/dev/null || true
        docker rm   "${TLS_COLLECTOR_NAME}" 2>/dev/null || true
    fi
    if [[ "${RESTORED}" -eq 0 ]]; then
        info "Restoring original tls.rs (cleanup)..."
        sed -i 's/SSL_CTX_set_verify(ctx, ssl::SSL_VERIFY_NONE \/\*MUTATION\*\//SSL_CTX_set_verify(ctx, ssl::SSL_VERIFY_PEER/' "${TLS_RS}" 2>/dev/null || true
    fi
    rm -rf "${PREFIX}"
}
trap cleanup EXIT

# Stop any stale mutation collector.
docker stop "${TLS_COLLECTOR_NAME}" 2>/dev/null || true
docker rm   "${TLS_COLLECTOR_NAME}" 2>/dev/null || true

# gen_ca and gen_cert_san (same as main script).
gen_ca() {
    local name="$1" dir="$2"
    mkdir -p "${dir}"
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "${dir}/${name}-ca.key" -out "${dir}/${name}-ca.crt" \
        -subj "/CN=${name}-CA" -days 3650 >/dev/null 2>&1
}
gen_cert_san() {
    local base="$1" cn="$2" san="$3" ca_crt="$4" ca_key="$5"
    local dir; dir="$(dirname "${base}")"
    openssl req -newkey rsa:2048 -nodes \
        -keyout "${base}.key" -out "${base}.csr" \
        -subj "/CN=${cn}" >/dev/null 2>&1
    local ext_file="${dir}/${cn//[^a-zA-Z0-9]/_}.ext"
    printf '[ext]\nsubjectAltName=%s\n' "${san}" > "${ext_file}"
    openssl x509 -req -in "${base}.csr" -CA "${ca_crt}" -CAkey "${ca_key}" \
        -CAcreateserial -out "${base}.crt" -days 3650 \
        -extfile "${ext_file}" -extensions ext >/dev/null 2>&1
    rm -f "${base}.csr" "${ext_file}"
}

gen_ca "our" "${CERTS}/our-ca"
gen_cert_san "${CERTS}/server" "localhost" \
    "DNS:localhost,IP:127.0.0.1" \
    "${CERTS}/our-ca/our-ca.crt" "${CERTS}/our-ca/our-ca.key"
gen_ca "bad" "${CERTS}/bad-ca"
gen_cert_san "${CERTS}/bad-server" "localhost" \
    "DNS:localhost,IP:127.0.0.1" \
    "${CERTS}/bad-ca/bad-ca.crt" "${CERTS}/bad-ca/bad-ca.key"

# TLS collector config (same cert as main script, ports shifted to avoid collision).
MUT_METRICS_LOG="${A3_SCRATCH}/logs/mut-metrics.json"
TLS_COLLECTOR_CONFIG="${PREFIX}/mut-tls-collector-config.yaml"
cat > "${TLS_COLLECTOR_CONFIG}" << YAMLEOF
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4319
        tls:
          cert_file: /certs/server.crt
          key_file:  /certs/server.key

processors:
  batch:
    timeout: 1s

exporters:
  file:
    path: /var/log/otel/mut-metrics.json
    rotation:
      max_megabytes: 10

service:
  telemetry:
    logs:
      level: warn
  pipelines:
    metrics:
      receivers: [otlp]
      processors: [batch]
      exporters: [file]
YAMLEOF

OTEL_HOST_UID="$(id -u)"
OTEL_HOST_GID="$(id -g)"
docker run -d --name "${TLS_COLLECTOR_NAME}" \
    --user "${OTEL_HOST_UID}:${OTEL_HOST_GID}" \
    -p "127.0.0.1:${TLS_HTTP_PORT}:4319" \
    -v "${TLS_COLLECTOR_CONFIG}:/etc/otelcol/config.yaml:ro" \
    -v "${CERTS}:/certs:ro" \
    -v "${A3_SCRATCH}/logs:/var/log/otel" \
    otel/opentelemetry-collector-contrib:0.152.0 \
    --config=/etc/otelcol/config.yaml >/dev/null
COLLECTOR_RUNNING=1

# Wait for collector.
READY=0
for _ in $(seq 1 15); do
    if curl -sk --connect-timeout 2 \
        --cacert "${CERTS}/our-ca/our-ca.crt" \
        "https://127.0.0.1:${TLS_HTTP_PORT}/" >/dev/null 2>&1; then
        READY=1; break
    fi
    sleep 1
done
[[ "${READY}" -eq 1 ]] || fail "TLS collector did not become ready"

snapshot_log() { local f="$1"; [[ -f "$f" ]] && wc -c < "$f" || echo 0; }
delta_log() {
    local f="$1" off="$2"
    [[ -f "$f" ]] || { echo ""; return; }
    local cur; cur="$(wc -c < "$f")"
    (( cur > off )) && tail -c "+$(( off + 1 ))" "$f" || echo ""
}

wait_nginx_up() {
    local pid="$1"; sleep 1
    kill -0 "${pid}" 2>/dev/null || fail "nginx exited at startup"
}
stop_nginx() {
    local pid="$1"
    kill -QUIT "${pid}" 2>/dev/null || true
    for _ in $(seq 1 15); do kill -0 "${pid}" 2>/dev/null || break; sleep 1; done
    NGINX_PID=""
}

make_nginx_conf() {
    local svc="$1" ca_path="$2"
    cat > "${PREFIX}/nginx-mut.conf" << CONFEOF
daemon off;
master_process on;
worker_processes 1;
worker_shutdown_timeout 3s;
error_log ${PREFIX}/logs/error.log notice;
pid       ${PREFIX}/logs/nginx.pid;

load_module ${MODULE_PATH};
events { worker_connections 64; }

http {
    otel_exporter {
        endpoint https://127.0.0.1:${TLS_HTTP_PORT};
        trusted_certificate ${ca_path};
    }
    otel_service_name ${svc};
    otel_metric_interval ${METRIC_INTERVAL_S}s;

    server {
        listen 127.0.0.1:9470;
        location / { return 200 "ok\n"; }
    }
}
CONFEOF
}

# ─── Evidence file header ────────────────────────────────────────────────────

{
echo "# A3 TLS mutation evidence"
echo "# Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# Host: $(hostname) ($(uname -a))"
echo "# Git SHA (pre-mutation): ${PRE_SHA}"
echo "# Mutation: SSL_VERIFY_PEER → SSL_VERIFY_NONE in tls.rs build_ctx"
echo "# Expectation: with mutation, scenario (c) DELIVERS data (assertion catches it);"
echo "#              without mutation, scenario (c) delivers ZERO data."
echo ""
} > "${EVIDENCE}"

# ─── Half 1: MUTATED — verification disabled ─────────────────────────────────

echo "=== HALF 1: MUTATED ===" | tee -a "${EVIDENCE}"
echo "Target line: ssl::SSL_CTX_set_verify(ctx, ssl::SSL_VERIFY_PEER, None)" | tee -a "${EVIDENCE}"

# Apply the mutation: SSL_VERIFY_PEER → SSL_VERIFY_NONE /*MUTATION*/
sed -i 's/SSL_CTX_set_verify(ctx, ssl::SSL_VERIFY_PEER/SSL_CTX_set_verify(ctx, ssl::SSL_VERIFY_NONE \/\*MUTATION\*\//' "${TLS_RS}"
echo "Mutation applied." | tee -a "${EVIDENCE}"

# Verify the mutation landed.
grep -q 'SSL_VERIFY_NONE /\*MUTATION\*/' "${TLS_RS}" \
    || { echo "ERROR: mutation did not land in ${TLS_RS}" >&2; exit 1; }

info "Building MUTATED module..."
(
    cd "${CRATE_DIR}"
    NGINX_SOURCE_DIR="${NGINX_SOURCE_DIR}" NGINX_BUILD_DIR="${NGINX_BUILD_DIR}" \
        cargo build --release 2>&1 | tail -3
) 2>&1 | tee -a "${EVIDENCE}"

# Run scenario (c) with bad CA — MUST deliver data (mutation bypasses verification).
SVC_MUT="ngx-otel-a3-mut-$(date -u +%s)"
OFF_MUT="$(snapshot_log "${MUT_METRICS_LOG}")"

make_nginx_conf "${SVC_MUT}" "${CERTS}/bad-ca/bad-ca.crt"

"${NGINX_BINARY}" -e "${PREFIX}/logs/error.log" -p "${PREFIX}" -c "${PREFIX}/nginx-mut.conf" &
NGINX_PID=$!
wait_nginx_up "${NGINX_PID}"
sleep $(( FLUSH_WAIT_S + 2 ))
stop_nginx "${NGINX_PID}"

DELTA_MUT="$(delta_log "${MUT_METRICS_LOG}" "${OFF_MUT}")"
if [[ -n "${DELTA_MUT}" ]] && echo "${DELTA_MUT}" | jq -e --arg s "${SVC_MUT}" \
    'select([.resourceMetrics[].resource.attributes[]? | select(.key=="service.name").value.stringValue] | index($s))' \
    >/dev/null 2>&1; then
    echo "HALF1 PASS: MUTATED code DELIVERED data with bad CA (verification is disabled)" | tee -a "${EVIDENCE}"
    pass "Half 1 (mutated): bad-CA run delivered data — mutation confirms verification bypass"
else
    echo "HALF1 FAIL: mutation did not produce data delivery — mutation may not have taken effect" | tee -a "${EVIDENCE}"
    fail "Half 1: mutation expected to deliver data, but none received"
fi

# ─── Restore ─────────────────────────────────────────────────────────────────

info "Restoring original tls.rs..."
sed -i 's/SSL_CTX_set_verify(ctx, ssl::SSL_VERIFY_NONE \/\*MUTATION\*\//SSL_CTX_set_verify(ctx, ssl::SSL_VERIFY_PEER/' "${TLS_RS}"
RESTORED=1

# Verify restore.
grep -q 'SSL_CTX_set_verify(ctx, ssl::SSL_VERIFY_PEER' "${TLS_RS}" \
    || fail "Restore failed: SSL_VERIFY_PEER not found after restore"
grep -v 'MUTATION' "${TLS_RS}" | grep -q 'SSL_VERIFY' \
    || true  # just ensure no mutation marker remains
if grep -q 'MUTATION' "${TLS_RS}"; then
    fail "Restore failed: MUTATION marker still present in ${TLS_RS}"
fi
echo "tls.rs restored." | tee -a "${EVIDENCE}"

echo "" | tee -a "${EVIDENCE}"
echo "=== HALF 2: RESTORED ===" | tee -a "${EVIDENCE}"

info "Rebuilding RESTORED module..."
(
    cd "${CRATE_DIR}"
    NGINX_SOURCE_DIR="${NGINX_SOURCE_DIR}" NGINX_BUILD_DIR="${NGINX_BUILD_DIR}" \
        cargo build --release 2>&1 | tail -3
) 2>&1 | tee -a "${EVIDENCE}"

# Run scenario (c) again with bad CA — MUST deliver ZERO data.
SVC_REST="ngx-otel-a3-rest-$(date -u +%s)"
OFF_REST="$(snapshot_log "${MUT_METRICS_LOG}")"

make_nginx_conf "${SVC_REST}" "${CERTS}/bad-ca/bad-ca.crt"

"${NGINX_BINARY}" -e "${PREFIX}/logs/error.log" -p "${PREFIX}" -c "${PREFIX}/nginx-mut.conf" &
NGINX_PID=$!
wait_nginx_up "${NGINX_PID}"
sleep $(( FLUSH_WAIT_S + 2 ))
stop_nginx "${NGINX_PID}"

DELTA_REST="$(delta_log "${MUT_METRICS_LOG}" "${OFF_REST}")"
DELIVERED=0
if [[ -n "${DELTA_REST}" ]] && echo "${DELTA_REST}" | jq -e --arg s "${SVC_REST}" \
    'select([.resourceMetrics[].resource.attributes[]? | select(.key=="service.name").value.stringValue] | index($s))' \
    >/dev/null 2>&1; then
    DELIVERED=1
fi

if [[ "${DELIVERED}" -eq 0 ]]; then
    echo "HALF2 PASS: RESTORED code delivered ZERO data with bad CA (verification enforced)" | tee -a "${EVIDENCE}"
    pass "Half 2 (restored): bad-CA run delivers zero data — verification is enforced"
else
    echo "HALF2 FAIL: restored code still delivered data with bad CA" | tee -a "${EVIDENCE}"
    fail "Half 2: restored code should not deliver data with bad CA"
fi

# ─── Final SHA + summary ─────────────────────────────────────────────────────

POST_SHA="$(git -C "${CRATE_DIR}" rev-parse HEAD)"
{
echo ""
echo "=== SUMMARY ==="
echo "Pre-mutation SHA:  ${PRE_SHA}"
echo "Post-restore SHA:  ${POST_SHA}"
echo "Half 1 (mutated):  PASS — bad CA delivered data (mutation effective)"
echo "Half 2 (restored): PASS — bad CA delivered ZERO data (fix verified)"
echo ""
echo "Mutation: src/transport/tls.rs, build_ctx, SSL_VERIFY_PEER → SSL_VERIFY_NONE"
echo "Evidence file: ${EVIDENCE}"
} | tee -a "${EVIDENCE}"

echo ""
pass "A3 mutation test: BOTH halves passed"
echo "Evidence: ${EVIDENCE}"
