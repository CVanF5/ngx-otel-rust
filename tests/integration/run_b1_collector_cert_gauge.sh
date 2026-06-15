#!/usr/bin/env bash
# tests/integration/run_b1_collector_cert_gauge.sh — B1 collector-cert gauge
#
# Validates `ngx_otel.tls.collector_cert.not_after`:
#
#   (a) TLS HTTP endpoint (https://)   → gauge PRESENT; value == openssl-derived
#       notAfter epoch; attribute server.address == collector hostname.
#   (b) Plaintext endpoint (http://)   → metric name ABSENT from exported metrics.
#   (c) gRPC-over-TLS endpoint         → gauge PRESENT; same cert, same epoch
#       value; confirms transport-agnostic behaviour of poll_handshake /
#       COLLECTOR_CERT_NOT_AFTER (the shared TLS layer writes the atomic for
#       both HTTP and gRPC TLS connections).
#
# Mutation target: break the capture call in poll_handshake (e.g. skip the
# SSL_get1_peer_certificate block) → (a) and (c) FAIL (gauge absent under TLS).
# Restore → (a) and (c) pass, (b) still absent.
#
# Ground truth: openssl CLI reads the notAfter from the server cert PEM and
# converts it to epoch with `date -d`; the gauge value must match exactly.
#
# Platform: Linux (debian-vm) — GNU date -d, jq, openssl CLI, docker.
# NOT macOS: GNU date -d is Linux-specific.
#
# Environment:
#   NGINX_BINARY     — release nginx (default: objs-release/nginx)
#   NGINX_SOURCE_DIR — nginx source tree
#   NGINX_BUILD_DIR  — nginx build dir (default: objs-release)
#   KEEP_SANDBOX     — set to 1 to skip sandbox cleanup on exit
#
# Exit codes: 0 = all assertions passed, 1 = pre-flight failure, 2 = assertion.

set -euo pipefail

# ─── Paths ───────────────────────────────────────────────────────────────────

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

# Scratch lives in home dir, NEVER /tmp (debian-vm /tmp is 2G tmpfs).
B1_SCRATCH="${REPO_ROOT}/b1-cert-gauge-scratch"
PROGRESS_LOG="/tmp/b1-cert-gauge-progress.log"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
pass()  { echo -e "${GREEN}[PASS]${NC} $*"; echo "[$(date -u +%T)] PASS: $*" >> "${PROGRESS_LOG}"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*" >&2; echo "[$(date -u +%T)] FAIL: $*" >> "${PROGRESS_LOG}"; exit 2; }
info()  { echo -e "${YELLOW}[INFO]${NC} $*"; echo "[$(date -u +%T)] INFO: $*" >> "${PROGRESS_LOG}"; }

echo "[$(date -u +%T)] START run_b1_collector_cert_gauge.sh" > "${PROGRESS_LOG}"

# ─── Ports ───────────────────────────────────────────────────────────────────

TLS_HTTP_PORT=4329
TLS_GRPC_PORT=4330
PLAIN_HTTP_PORT=4318
B1_COLLECTOR_NAME="ngx-otel-b1-cert-collector"

# ─── Pre-flight ──────────────────────────────────────────────────────────────

info "Pre-flight checks..."
[[ -x "${NGINX_BINARY}" ]]  || { echo "ERROR: nginx binary not found: ${NGINX_BINARY}" >&2; exit 1; }
command -v openssl >/dev/null || { echo "ERROR: openssl CLI required" >&2; exit 1; }
command -v jq >/dev/null      || { echo "ERROR: jq required" >&2; exit 1; }
command -v docker >/dev/null  || { echo "ERROR: docker required" >&2; exit 1; }
# GNU date -d is Linux-specific (macOS gdate would need special handling).
date -u -d "Jan 1 00:00:00 2030 GMT" +%s >/dev/null 2>&1 \
    || { echo "ERROR: GNU date -d required (run on Linux/debian-vm)" >&2; exit 1; }

# Verify the plain collector (4318) is up — we use it for scenario (b).
. "${CRATE_DIR}/test-harness/lib.sh"
ensure_collector_running || exit 1

# ─── Build module ─────────────────────────────────────────────────────────────

info "Building release module..."
(
    cd "${CRATE_DIR}"
    NGINX_SOURCE_DIR="${NGINX_SOURCE_DIR}" NGINX_BUILD_DIR="${NGINX_BUILD_DIR}" \
        cargo build --release 2>&1 | tail -3
)
[[ -f "${MODULE_PATH}" ]] || { echo "ERROR: module not found: ${MODULE_PATH}" >&2; exit 1; }
info "Module: ${MODULE_PATH}"

# ─── Sandbox ─────────────────────────────────────────────────────────────────

PREFIX="$(mktemp -d /tmp/ngx-otel-b1-cert.XXXXXX)"
CERTS="${PREFIX}/certs"
mkdir -p "${PREFIX}/logs" "${PREFIX}/client_body_temp" "${CERTS}"
mkdir -p "${B1_SCRATCH}/logs"

TLS_METRICS_LOG="${B1_SCRATCH}/logs/b1-tls-metrics.json"

NGINX_PID=""
TLS_COLLECTOR_RUNNING=0

cleanup() {
    [[ -n "${NGINX_PID}" ]] && kill -QUIT "${NGINX_PID}" 2>/dev/null || true
    if [[ "${TLS_COLLECTOR_RUNNING}" -eq 1 ]]; then
        docker stop "${B1_COLLECTOR_NAME}" 2>/dev/null || true
        docker rm   "${B1_COLLECTOR_NAME}" 2>/dev/null || true
    fi
    echo ""
    echo "=== error.log (last 30 lines) ==="
    tail -30 "${PREFIX}/logs/error.log" 2>/dev/null || echo "(none)"
    [[ "${KEEP_SANDBOX:-0}" == "1" ]] || rm -rf "${PREFIX}"
    [[ "${KEEP_SANDBOX:-0}" == "1" ]] || rm -rf "${B1_SCRATCH}"
    echo "[$(date -u +%T)] cleanup done" >> "${PROGRESS_LOG}"
}
trap cleanup EXIT

# Reap any stale container from a prior run.
docker stop "${B1_COLLECTOR_NAME}" 2>/dev/null || true
docker rm   "${B1_COLLECTOR_NAME}" 2>/dev/null || true

# ─── Certificate generation ───────────────────────────────────────────────────

info "Generating collector cert..."

openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "${CERTS}/ca.key" -out "${CERTS}/ca.crt" \
    -subj "/CN=B1-Test-CA" -days 3650 >/dev/null 2>&1

openssl req -newkey rsa:2048 -nodes \
    -keyout "${CERTS}/server.key" -out "${CERTS}/server.csr" \
    -subj "/CN=localhost" >/dev/null 2>&1

printf '[ext]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n' > "${CERTS}/ext.cnf"
openssl x509 -req \
    -in "${CERTS}/server.csr" \
    -CA "${CERTS}/ca.crt" -CAkey "${CERTS}/ca.key" \
    -CAcreateserial \
    -out "${CERTS}/server.crt" \
    -days 3650 \
    -extfile "${CERTS}/ext.cnf" -extensions ext >/dev/null 2>&1

# ── Ground truth: notAfter epoch from the OpenSSL CLI ────────────────────────
# Extract notAfter from the server cert and convert to Unix epoch via GNU date.
# This is the expected value for the B1 gauge.
NOT_AFTER_STR="$(openssl x509 -in "${CERTS}/server.crt" -noout -enddate \
    | sed 's/notAfter=//')"
EXPECTED_EPOCH="$(date -u -d "${NOT_AFTER_STR}" +%s)"
info "Server cert notAfter: '${NOT_AFTER_STR}' → epoch ${EXPECTED_EPOCH}"

# ─── Start TLS collector ─────────────────────────────────────────────────────

TLS_COLLECTOR_CONFIG="${PREFIX}/b1-collector-config.yaml"

cat > "${TLS_COLLECTOR_CONFIG}" << YAMLEOF
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4329
        tls:
          cert_file: /certs/server.crt
          key_file:  /certs/server.key
      grpc:
        endpoint: 0.0.0.0:4330
        tls:
          cert_file: /certs/server.crt
          key_file:  /certs/server.key

processors:
  batch:
    timeout: 1s
    send_batch_size: 512

exporters:
  file:
    path: /var/log/otel/b1-tls-metrics.json
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

info "Starting TLS collector (HTTP=${TLS_HTTP_PORT}, gRPC=${TLS_GRPC_PORT})..."
OTEL_HOST_UID="$(id -u)"
OTEL_HOST_GID="$(id -g)"

docker run -d --name "${B1_COLLECTOR_NAME}" \
    --user "${OTEL_HOST_UID}:${OTEL_HOST_GID}" \
    -p "127.0.0.1:${TLS_HTTP_PORT}:4329" \
    -p "127.0.0.1:${TLS_GRPC_PORT}:4330" \
    -v "${TLS_COLLECTOR_CONFIG}:/etc/otelcol/config.yaml:ro" \
    -v "${CERTS}:/certs:ro" \
    -v "${B1_SCRATCH}/logs:/var/log/otel" \
    otel/opentelemetry-collector-contrib:0.152.0 \
    --config=/etc/otelcol/config.yaml >/dev/null
TLS_COLLECTOR_RUNNING=1

# Wait for TLS collector to become ready (poll up to 15s via HTTPS).
info "Waiting for TLS collector to become ready..."
TLS_READY=0
for _ in $(seq 1 15); do
    if curl -sk --connect-timeout 2 \
        --cacert "${CERTS}/ca.crt" \
        "https://127.0.0.1:${TLS_HTTP_PORT}/" >/dev/null 2>&1; then
        TLS_READY=1; break
    fi
    sleep 1
done
[[ "${TLS_READY}" -eq 1 ]] \
    || fail "TLS collector did not become ready within 15s (docker logs: $(docker logs ${B1_COLLECTOR_NAME} 2>&1 | tail -10))"
pass "TLS collector ready on port ${TLS_HTTP_PORT}/${TLS_GRPC_PORT}"

# ─── Helpers ─────────────────────────────────────────────────────────────────

METRIC_INTERVAL_S=1
FLUSH_WAIT_S=5

wait_nginx_up() {
    local pid="$1"
    sleep 1
    kill -0 "${pid}" 2>/dev/null \
        || { tail -20 "${PREFIX}/logs/error.log" >&2; fail "nginx exited at startup"; }
}

stop_nginx() {
    local pid="$1"
    kill -QUIT "${pid}" 2>/dev/null || true
    for _ in $(seq 1 15); do
        kill -0 "${pid}" 2>/dev/null || break; sleep 1
    done
    NGINX_PID=""
}

snapshot_log() {
    local f="$1"
    [[ -f "$f" ]] && wc -c < "$f" || echo 0
}

delta_log() {
    local f="$1" off="$2"
    [[ -f "$f" ]] || { echo ""; return; }
    local cur
    cur="$(wc -c < "$f")"
    (( cur > off )) && tail -c "+$(( off + 1 ))" "$f" || echo ""
}

# ─── Scenario (a): TLS endpoint → gauge PRESENT ──────────────────────────────

info "=== Scenario (a): TLS endpoint → ngx_otel.tls.collector_cert.not_after PRESENT ==="

SVC_A="ngx-otel-b1-tls-gauge-$$"
OFF_A="$(snapshot_log "${TLS_METRICS_LOG}")"

cat > "${PREFIX}/nginx-a.conf" << CONFEOF
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
        trusted_certificate ${CERTS}/ca.crt;
    }
    otel_service_name ${SVC_A};
    otel_metric_interval ${METRIC_INTERVAL_S}s;

    server {
        listen 127.0.0.1:9490;
        location / { return 200 "ok\n"; }
    }
}
CONFEOF

"${NGINX_BINARY}" -e "${PREFIX}/logs/error.log" -p "${PREFIX}" -c "${PREFIX}/nginx-a.conf" &
NGINX_PID=$!
wait_nginx_up "${NGINX_PID}"

# Send a request to ensure at least one metric export cycle fires.
curl -sf http://127.0.0.1:9490/ >/dev/null
sleep "${FLUSH_WAIT_S}"

stop_nginx "${NGINX_PID}"

DELTA_A="$(delta_log "${TLS_METRICS_LOG}" "${OFF_A}")"
[[ -n "${DELTA_A}" ]] || fail "(a) TLS endpoint: no metrics received by collector"

# DELTA_A is NDJSON (one JSON object per line). Use jq --slurp to read all
# lines into an array, then flatten the metrics across all objects.

# Assert 1: metric name is present.
# Use --slurp so jq collects all NDJSON lines into an array before filtering.
GAUGE_PRESENT="$(echo "${DELTA_A}" | jq --slurp -r \
    '[.[].resourceMetrics[]?.scopeMetrics[]?.metrics[]?.name
      | select(. == "ngx_otel.tls.collector_cert.not_after")] | length' \
    2>/dev/null || echo 0)"
[[ "${GAUGE_PRESENT}" -gt 0 ]] \
    || fail "(a) TLS endpoint: metric ngx_otel.tls.collector_cert.not_after ABSENT — expected PRESENT (mutation target: break SSL_get1_peer_certificate block in poll_handshake)"

pass "(a) TLS endpoint: metric ngx_otel.tls.collector_cert.not_after is PRESENT"

# Assert 2: value equals the OpenSSL-derived notAfter epoch.
GAUGE_VALUE="$(echo "${DELTA_A}" | jq --slurp -r \
    '[.[].resourceMetrics[]?.scopeMetrics[]?.metrics[]?
      | select(.name == "ngx_otel.tls.collector_cert.not_after")
      | .gauge.dataPoints[]?.asInt] | first // empty' \
    2>/dev/null || echo "")"
[[ -n "${GAUGE_VALUE}" ]] \
    || fail "(a) TLS endpoint: could not extract gauge value from metric data"

[[ "${GAUGE_VALUE}" == "${EXPECTED_EPOCH}" ]] \
    || fail "(a) TLS endpoint: gauge value ${GAUGE_VALUE} != expected epoch ${EXPECTED_EPOCH} (ground truth: openssl notAfter -> GNU date -d)"

pass "(a) TLS endpoint: gauge value ${GAUGE_VALUE} == openssl-derived epoch ${EXPECTED_EPOCH} (EXACT MATCH)"

# Assert 3: server.address attribute equals the collector hostname.
ADDR_ATTR="$(echo "${DELTA_A}" | jq --slurp -r \
    '[.[].resourceMetrics[]?.scopeMetrics[]?.metrics[]?
      | select(.name == "ngx_otel.tls.collector_cert.not_after")
      | .gauge.dataPoints[]?.attributes[]?
      | select(.key == "server.address")
      | .value.stringValue] | first // empty' \
    2>/dev/null || echo "")"
[[ -n "${ADDR_ATTR}" ]] \
    || fail "(a) TLS endpoint: server.address attribute absent on ngx_otel.tls.collector_cert.not_after data point"

[[ "${ADDR_ATTR}" == "127.0.0.1" ]] \
    || fail "(a) TLS endpoint: server.address='${ADDR_ATTR}' expected '127.0.0.1'"

pass "(a) TLS endpoint: server.address='${ADDR_ATTR}' CORRECT"

# ─── Scenario (b): Plaintext endpoint → gauge ABSENT ─────────────────────────

info "=== Scenario (b): Plaintext endpoint → metric name ABSENT ==="

SVC_B="ngx-otel-b1-plain-absent-$$"
OFF_B="$(snapshot_log "${METRICS_LOG}")"

cat > "${PREFIX}/nginx-b.conf" << CONFEOF
daemon off;
master_process on;
worker_processes 1;
worker_shutdown_timeout 3s;
error_log ${PREFIX}/logs/error-b.log notice;
pid       ${PREFIX}/logs/nginx-b.pid;

load_module ${MODULE_PATH};
events { worker_connections 64; }

http {
    otel_exporter {
        endpoint http://127.0.0.1:${PLAIN_HTTP_PORT};
    }
    otel_service_name ${SVC_B};
    otel_metric_interval ${METRIC_INTERVAL_S}s;

    server {
        listen 127.0.0.1:9491;
        location / { return 200 "ok\n"; }
    }
}
CONFEOF

"${NGINX_BINARY}" -e "${PREFIX}/logs/error-b.log" -p "${PREFIX}" -c "${PREFIX}/nginx-b.conf" &
NGINX_PID=$!
wait_nginx_up "${NGINX_PID}"

curl -sf http://127.0.0.1:9491/ >/dev/null
sleep "${FLUSH_WAIT_S}"

stop_nginx "${NGINX_PID}"

DELTA_B="$(delta_log "${METRICS_LOG}" "${OFF_B}")"
[[ -n "${DELTA_B}" ]] || fail "(b) Plaintext endpoint: no metrics received by collector (sanity)"

# Find data for this specific service instance.
SVC_B_DATA="$(echo "${DELTA_B}" | jq -c \
    --arg s "${SVC_B}" \
    'select([.resourceMetrics[]?.resource.attributes[]? | select(.key=="service.name").value.stringValue] | index($s))' \
    2>/dev/null || echo "")"
[[ -n "${SVC_B_DATA}" ]] || fail "(b) Plaintext endpoint: no data found for service.name=${SVC_B}"

# Assert: metric name is ABSENT. SVC_B_DATA is NDJSON; use --slurp.
CERT_GAUGE_COUNT="$(echo "${SVC_B_DATA}" | jq --slurp -r \
    '[.[].resourceMetrics[]?.scopeMetrics[]?.metrics[]?.name
      | select(. == "ngx_otel.tls.collector_cert.not_after")] | length' \
    2>/dev/null || echo 0)"
[[ "${CERT_GAUGE_COUNT}" -eq 0 ]] \
    || fail "(b) Plaintext endpoint: metric ngx_otel.tls.collector_cert.not_after PRESENT — expected ABSENT for plaintext endpoint"

pass "(b) Plaintext endpoint: metric ngx_otel.tls.collector_cert.not_after is ABSENT (absent-not-zero)"

# ─── Scenario (c): gRPC-over-TLS → gauge PRESENT ─────────────────────────────
#
# Verifies transport-agnostic behaviour: COLLECTOR_CERT_NOT_AFTER is written by
# TlsNgxConnIo::poll_handshake which is shared by both HTTP and gRPC TLS paths
# (src/transport/tls.rs — the same atomic, the same poll_handshake code path).
# The gRPC transport wraps the stream via wrap_tls_io (same as HTTP) before the
# h2 handshake, so the collector-cert gauge must be PRESENT here exactly as in
# scenario (a).

info "=== Scenario (c): gRPC-over-TLS → ngx_otel.tls.collector_cert.not_after PRESENT ==="

SVC_C="ngx-otel-b1-grpc-tls-gauge-$$"
OFF_C="$(snapshot_log "${TLS_METRICS_LOG}")"

cat > "${PREFIX}/nginx-c.conf" << CONFEOF
daemon off;
master_process on;
worker_processes 1;
worker_shutdown_timeout 3s;
error_log ${PREFIX}/logs/error-c.log notice;
pid       ${PREFIX}/logs/nginx-c.pid;

load_module ${MODULE_PATH};
events { worker_connections 64; }

http {
    otel_exporter {
        endpoint https://127.0.0.1:${TLS_GRPC_PORT};
        trusted_certificate ${CERTS}/ca.crt;
    }
    otel_export_protocol otlp_grpc;
    otel_service_name ${SVC_C};
    otel_metric_interval ${METRIC_INTERVAL_S}s;

    server {
        listen 127.0.0.1:9492;
        location / { return 200 "ok\n"; }
    }
}
CONFEOF

"${NGINX_BINARY}" -e "${PREFIX}/logs/error-c.log" -p "${PREFIX}" -c "${PREFIX}/nginx-c.conf" &
NGINX_PID=$!
wait_nginx_up "${NGINX_PID}"

curl -sf http://127.0.0.1:9492/ >/dev/null
sleep "${FLUSH_WAIT_S}"

stop_nginx "${NGINX_PID}"

DELTA_C="$(delta_log "${TLS_METRICS_LOG}" "${OFF_C}")"
[[ -n "${DELTA_C}" ]] || fail "(c) gRPC-over-TLS: no metrics received by collector"

# Assert 1: metric name is present.
GAUGE_C_PRESENT="$(echo "${DELTA_C}" | jq --slurp -r \
    '[.[].resourceMetrics[]?.scopeMetrics[]?.metrics[]?.name
      | select(. == "ngx_otel.tls.collector_cert.not_after")] | length' \
    2>/dev/null || echo 0)"
[[ "${GAUGE_C_PRESENT}" -gt 0 ]] \
    || fail "(c) gRPC-over-TLS: metric ngx_otel.tls.collector_cert.not_after ABSENT — expected PRESENT (transport-agnostic TLS handshake must write COLLECTOR_CERT_NOT_AFTER regardless of HTTP vs gRPC)"

pass "(c) gRPC-over-TLS: metric ngx_otel.tls.collector_cert.not_after is PRESENT"

# Assert 2: value equals the same OpenSSL-derived notAfter epoch (same cert).
GAUGE_C_VALUE="$(echo "${DELTA_C}" | jq --slurp -r \
    '[.[].resourceMetrics[]?.scopeMetrics[]?.metrics[]?
      | select(.name == "ngx_otel.tls.collector_cert.not_after")
      | .gauge.dataPoints[]?.asInt] | first // empty' \
    2>/dev/null || echo "")"
[[ -n "${GAUGE_C_VALUE}" ]] \
    || fail "(c) gRPC-over-TLS: could not extract gauge value from metric data"

[[ "${GAUGE_C_VALUE}" == "${EXPECTED_EPOCH}" ]] \
    || fail "(c) gRPC-over-TLS: gauge value ${GAUGE_C_VALUE} != expected epoch ${EXPECTED_EPOCH} (ground truth: openssl notAfter -> GNU date -d)"

pass "(c) gRPC-over-TLS: gauge value ${GAUGE_C_VALUE} == openssl-derived epoch ${EXPECTED_EPOCH} (EXACT MATCH)"

# Assert 3: server.address attribute equals the collector hostname.
ADDR_C_ATTR="$(echo "${DELTA_C}" | jq --slurp -r \
    '[.[].resourceMetrics[]?.scopeMetrics[]?.metrics[]?
      | select(.name == "ngx_otel.tls.collector_cert.not_after")
      | .gauge.dataPoints[]?.attributes[]?
      | select(.key == "server.address")
      | .value.stringValue] | first // empty' \
    2>/dev/null || echo "")"
[[ -n "${ADDR_C_ATTR}" ]] \
    || fail "(c) gRPC-over-TLS: server.address attribute absent on ngx_otel.tls.collector_cert.not_after data point"

[[ "${ADDR_C_ATTR}" == "127.0.0.1" ]] \
    || fail "(c) gRPC-over-TLS: server.address='${ADDR_C_ATTR}' expected '127.0.0.1'"

pass "(c) gRPC-over-TLS: server.address='${ADDR_C_ATTR}' CORRECT"

# ─── All scenarios complete ───────────────────────────────────────────────────

echo ""
echo "============================================================"
pass "B1 collector-cert gauge: ALL scenarios (a)-(c) PASSED"
echo "============================================================"
echo "[$(date -u +%T)] COMPLETE run_b1_collector_cert_gauge.sh" >> "${PROGRESS_LOG}"
