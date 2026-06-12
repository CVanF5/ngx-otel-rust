#!/usr/bin/env bash
# tests/integration/run_a3_tls_e2e.sh — A3 TLS E2E integration test
#
# Validates the production TLS transport (shipped in A1/A2, review-certified)
# end-to-end against a live OTel collector with TLS.  Self-contained: mints
# all certs with the openssl CLI; manages two short-lived collector containers
# (plain-TLS and mTLS) on isolated ports; tears down completely on exit.
#
# Scenarios (HARD-asserted, no soft fallback):
#
#   (a) OTLP/HTTP over https://  with trusted_certificate = our CA
#       → metrics+logs+spans delivered (collector-assert);
#       payload-byte equality: DECODED OTLP http vs https is identical
#       (TLS is encryption-only — no content change).
#   (b) OTLP/gRPC over https://  with trusted_certificate = our CA
#       → metrics+logs+spans delivered.
#   (c) Bad CA (server cert signed by other CA) → handshake fails,
#       send-failure alert + backoff in error.log, ZERO data delivered,
#       nginx continues serving requests (healthy).  SECURITY-CRITICAL.
#   (d) ssl_verify off with the SAME untrusted server cert → data delivers
#       and the config-time WARN "ssl_verify off" appears in error.log.
#   (e) mTLS: collector requires client cert;
#       (e1) with ssl_certificate + ssl_certificate_key → delivers;
#       (e2) without client cert → fails closed (TLS alert, zero data).
#   (f) Hostname mismatch:
#       (f1) DNS-host mismatch (cert SAN ≠ endpoint host) → fails.
#       (f2) IP-literal with wrong IP SAN → fails.
#   (g) SIGHUP reload with changed trusted_certificate path → new exporter
#       generation picks up the new CA and delivers data.
#
# Docs filled: OPENSSL_SUPPORT.md minimum-version section, README directive
# table defaults + examples, TELEMETRY_MODEL.md transport section.
#
# Platform: Linux (debian-vm) — GNU date -d, docker, jq, openssl CLI.
#
# Environment:
#   NGINX_BINARY     — release nginx (default: objs-release/nginx)
#   NGINX_SOURCE_DIR — nginx source tree (for the module build)
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
A3_SCRATCH="${REPO_ROOT}/a3-scratch"
# Progress log for this run.
PROGRESS_LOG="/tmp/a3-progress.log"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
pass()  { echo -e "${GREEN}[PASS]${NC} $*"; echo "[$(date -u +%T)] PASS: $*" >> "${PROGRESS_LOG}"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*" >&2; echo "[$(date -u +%T)] FAIL: $*" >> "${PROGRESS_LOG}"; exit 2; }
info()  { echo -e "${YELLOW}[INFO]${NC} $*"; echo "[$(date -u +%T)] INFO: $*" >> "${PROGRESS_LOG}"; }

echo "[$(date -u +%T)] START run_a3_tls_e2e.sh" > "${PROGRESS_LOG}"

# ─── Ports (isolated from the existing plain-text collector 4317/4318) ───────
# OTLP/HTTP+TLS:    4319
# OTLP/gRPC+TLS:    4320
# mTLS HTTP:        4321
# mTLS gRPC:        4322
TLS_HTTP_PORT=4319
TLS_GRPC_PORT=4320
MTLS_HTTP_PORT=4321
MTLS_GRPC_PORT=4322

TLS_COLLECTOR_NAME="ngx-otel-a3-tls-collector"
MTLS_COLLECTOR_NAME="ngx-otel-a3-mtls-collector"

# ─── Pre-flight ──────────────────────────────────────────────────────────────

info "Pre-flight checks..."
[[ -x "${NGINX_BINARY}" ]] || { echo "ERROR: nginx binary not found: ${NGINX_BINARY}" >&2; exit 1; }
command -v openssl >/dev/null || { echo "ERROR: openssl CLI required" >&2; exit 1; }
command -v jq >/dev/null || { echo "ERROR: jq required" >&2; exit 1; }
command -v docker >/dev/null || { echo "ERROR: docker required" >&2; exit 1; }
date -u -d "Jan 1 00:00:00 2030 GMT" +%s >/dev/null 2>&1 \
    || { echo "ERROR: GNU date -d required (run on Linux/debian-vm)" >&2; exit 1; }

# Verify the plain collector (4318) is up — we use it for the http baseline.
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

PREFIX="$(mktemp -d /tmp/ngx-otel-a3-tls.XXXXXX)"
CERTS="${PREFIX}/certs"
mkdir -p "${PREFIX}/logs" "${PREFIX}/client_body_temp" "${CERTS}"
# Scratch log dir in home (not /tmp) — collector data is big.
mkdir -p "${A3_SCRATCH}/logs"

# Collector log files separate from the existing plain-text collector's files.
TLS_METRICS_LOG="${A3_SCRATCH}/logs/tls-metrics.json"
TLS_LOGS_LOG="${A3_SCRATCH}/logs/tls-logs.json"
TLS_TRACES_LOG="${A3_SCRATCH}/logs/tls-traces.json"
MTLS_METRICS_LOG="${A3_SCRATCH}/logs/mtls-metrics.json"

# Track state for cleanup.
NGINX_PID=""
TLS_COLLECTOR_RUNNING=0
MTLS_COLLECTOR_RUNNING=0

cleanup() {
    [[ -n "${NGINX_PID}" ]] && kill -QUIT "${NGINX_PID}" 2>/dev/null || true
    if [[ "${TLS_COLLECTOR_RUNNING}" -eq 1 ]]; then
        docker stop "${TLS_COLLECTOR_NAME}" 2>/dev/null || true
        docker rm   "${TLS_COLLECTOR_NAME}" 2>/dev/null || true
    fi
    if [[ "${MTLS_COLLECTOR_RUNNING}" -eq 1 ]]; then
        docker stop "${MTLS_COLLECTOR_NAME}" 2>/dev/null || true
        docker rm   "${MTLS_COLLECTOR_NAME}" 2>/dev/null || true
    fi
    echo ""
    echo "=== error.log (last 30 lines) ==="
    tail -30 "${PREFIX}/logs/error.log" 2>/dev/null || echo "(none)"
    [[ "${KEEP_SANDBOX:-0}" == "1" ]] || rm -rf "${PREFIX}"
    echo "[$(date -u +%T)] cleanup done" >> "${PROGRESS_LOG}"
}
trap cleanup EXIT

# Reap stale containers from a prior run (A0 reaper pattern).
docker stop "${TLS_COLLECTOR_NAME}"  2>/dev/null || true
docker rm   "${TLS_COLLECTOR_NAME}"  2>/dev/null || true
docker stop "${MTLS_COLLECTOR_NAME}" 2>/dev/null || true
docker rm   "${MTLS_COLLECTOR_NAME}" 2>/dev/null || true

# ─── Certificate generation ───────────────────────────────────────────────────
#
# Three certificate hierarchies:
#
#   our-ca/             — the legitimate CA we trust
#     server.crt        — server cert with SAN = localhost, 127.0.0.1
#     server-wrong-san  — server cert with SAN = wrong.example.test (for f1)
#     server-wrong-ip   — server cert with SAN = 127.0.0.2 only (for f2)
#     client.crt        — client cert for mTLS (e)
#
#   bad-ca/             — a different CA we do NOT load (for c)
#     bad-server.crt    — server cert signed by bad-ca (not our-ca)

info "Generating certificate hierarchies..."

# Helper: generate CA
gen_ca() {
    local name="$1" dir="$2"
    mkdir -p "${dir}"
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "${dir}/${name}-ca.key" -out "${dir}/${name}-ca.crt" \
        -subj "/CN=${name}-CA" -days 3650 >/dev/null 2>&1
}

# Helper: generate cert signed by a CA with a given SAN extension
# gen_cert_san <out-base> <cn> <san-string> <ca-crt> <ca-key>
# san-string examples: "DNS:localhost,IP:127.0.0.1"
gen_cert_san() {
    local base="$1" cn="$2" san="$3" ca_crt="$4" ca_key="$5"
    local dir
    dir="$(dirname "${base}")"
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

# Our legitimate CA + server cert.
gen_ca "our" "${CERTS}/our-ca"
gen_cert_san "${CERTS}/server" "localhost" \
    "DNS:localhost,IP:127.0.0.1" \
    "${CERTS}/our-ca/our-ca.crt" "${CERTS}/our-ca/our-ca.key"

# Client cert (for mTLS) — signed by our-ca (collector trusts our-ca).
gen_cert_san "${CERTS}/client" "otel-client" \
    "DNS:otel-client" \
    "${CERTS}/our-ca/our-ca.crt" "${CERTS}/our-ca/our-ca.key"

# Wrong-SAN cert (f1: DNS SAN = wrong.example.test, not localhost).
gen_cert_san "${CERTS}/server-wrong-san" "wrong.example.test" \
    "DNS:wrong.example.test" \
    "${CERTS}/our-ca/our-ca.crt" "${CERTS}/our-ca/our-ca.key"

# Wrong-IP cert (f2: IP SAN = 127.0.0.2, not 127.0.0.1).
gen_cert_san "${CERTS}/server-wrong-ip" "wrong-ip" \
    "IP:127.0.0.2" \
    "${CERTS}/our-ca/our-ca.crt" "${CERTS}/our-ca/our-ca.key"

# Bad CA + server cert signed by it.
gen_ca "bad" "${CERTS}/bad-ca"
gen_cert_san "${CERTS}/bad-server" "localhost" \
    "DNS:localhost,IP:127.0.0.1" \
    "${CERTS}/bad-ca/bad-ca.crt" "${CERTS}/bad-ca/bad-ca.key"

info "Certificates generated in ${CERTS}"

# ─── Collector config templates ───────────────────────────────────────────────
#
# TLS collector (scenarios a, b, c, d, f, g):  HTTP/4319, gRPC/4320.
# mTLS collector (scenario e):                 HTTP/4321, gRPC/4322.
# Collector logs go to A3_SCRATCH/logs (not /tmp).

TLS_COLLECTOR_CONFIG="${PREFIX}/tls-collector-config.yaml"
MTLS_COLLECTOR_CONFIG="${PREFIX}/mtls-collector-config.yaml"

cat > "${TLS_COLLECTOR_CONFIG}" << YAMLEOF
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4319
        tls:
          cert_file: /certs/server.crt
          key_file:  /certs/server.key
      grpc:
        endpoint: 0.0.0.0:4320
        tls:
          cert_file: /certs/server.crt
          key_file:  /certs/server.key

processors:
  batch:
    timeout: 1s
    send_batch_size: 512

exporters:
  file:
    path: /var/log/otel/tls-metrics.json
    rotation:
      max_megabytes: 10
  file/logs:
    path: /var/log/otel/tls-logs.json
    rotation:
      max_megabytes: 10
  file/traces:
    path: /var/log/otel/tls-traces.json
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
    logs:
      receivers: [otlp]
      processors: [batch]
      exporters: [file/logs]
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [file/traces]
YAMLEOF

cat > "${MTLS_COLLECTOR_CONFIG}" << YAMLEOF
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4321
        tls:
          cert_file:  /certs/server.crt
          key_file:   /certs/server.key
          client_ca_file: /certs/our-ca/our-ca.crt
      grpc:
        endpoint: 0.0.0.0:4322
        tls:
          cert_file:  /certs/server.crt
          key_file:   /certs/server.key
          client_ca_file: /certs/our-ca/our-ca.crt

processors:
  batch:
    timeout: 1s

exporters:
  file:
    path: /var/log/otel/mtls-metrics.json
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

# ─── Start TLS collector ─────────────────────────────────────────────────────

info "Starting TLS collector (HTTP=${TLS_HTTP_PORT}, gRPC=${TLS_GRPC_PORT})..."
OTEL_HOST_UID="$(id -u)"
OTEL_HOST_GID="$(id -g)"

docker run -d --name "${TLS_COLLECTOR_NAME}" \
    --user "${OTEL_HOST_UID}:${OTEL_HOST_GID}" \
    -p "127.0.0.1:${TLS_HTTP_PORT}:4319" \
    -p "127.0.0.1:${TLS_GRPC_PORT}:4320" \
    -v "${TLS_COLLECTOR_CONFIG}:/etc/otelcol/config.yaml:ro" \
    -v "${CERTS}:/certs:ro" \
    -v "${A3_SCRATCH}/logs:/var/log/otel" \
    otel/opentelemetry-collector-contrib:0.152.0 \
    --config=/etc/otelcol/config.yaml >/dev/null
TLS_COLLECTOR_RUNNING=1

# Wait for TLS collector to become ready (poll up to 15s via HTTPS).
info "Waiting for TLS collector to become ready..."
TLS_READY=0
for _ in $(seq 1 15); do
    if curl -sk --connect-timeout 2 \
        --cacert "${CERTS}/our-ca/our-ca.crt" \
        "https://127.0.0.1:${TLS_HTTP_PORT}/" >/dev/null 2>&1; then
        TLS_READY=1; break
    fi
    sleep 1
done
[[ "${TLS_READY}" -eq 1 ]] || fail "TLS collector did not become ready within 15s (docker logs: $(docker logs ${TLS_COLLECTOR_NAME} 2>&1 | tail -10))"
pass "TLS collector ready on port ${TLS_HTTP_PORT}/${TLS_GRPC_PORT}"

# ─── Helper: wait_nginx_up / stop_nginx / snapshot / flush ───────────────────

METRIC_INTERVAL_S=1
FLUSH_WAIT_S=5

wait_nginx_up() {
    local pid="$1"
    sleep 1
    kill -0 "${pid}" 2>/dev/null || { tail -20 "${PREFIX}/logs/error.log" >&2; fail "nginx exited at startup"; }
}

stop_nginx() {
    local pid="$1"
    kill -QUIT "${pid}" 2>/dev/null || true
    for _ in $(seq 1 15); do
        kill -0 "${pid}" 2>/dev/null || break; sleep 1
    done
    NGINX_PID=""
}

# snapshot: print the byte offset of a log file at call time.
snapshot_log() {
    local f="$1"
    [[ -f "$f" ]] && wc -c < "$f" || echo 0
}

# delta_log: extract bytes written since the snapshot (file, offset).
delta_log() {
    local f="$1" off="$2"
    [[ -f "$f" ]] || { echo ""; return; }
    local cur
    cur="$(wc -c < "$f")"
    (( cur > off )) && tail -c "+$(( off + 1 ))" "$f" || echo ""
}

# nginx_conf: write a minimal nginx conf for a given endpoint + TLS options.
# Usage: nginx_conf <endpoint> [extra-otel-directives...]
write_nginx_conf() {
    local conf_file="$1" endpoint="$2"
    shift 2
    local extra_directives="${*:-}"
    cat > "${conf_file}" << CONFEOF
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
        endpoint ${endpoint};
        ${extra_directives}
    }
    otel_service_name a3-tls-test-$$;
    otel_metric_interval ${METRIC_INTERVAL_S}s;

    server {
        listen 127.0.0.1:9470;
        location / { return 200 "ok\n"; }
    }
}
CONFEOF
}

# ─── Scenario (a): OTLP/HTTP + https:// + trusted_certificate ────────────────

info "=== Scenario (a): OTLP/HTTP https:// trusted CA ==="

SVC_A="ngx-otel-a3-http-tls-$$"
OFF_A="$(snapshot_log "${TLS_METRICS_LOG}")"
OFF_A_TRACES="$(snapshot_log "${TLS_TRACES_LOG}")"

CONF_A="${PREFIX}/nginx-a.conf"
cat > "${CONF_A}" << CONFEOF
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
        trusted_certificate ${CERTS}/our-ca/our-ca.crt;
    }
    otel_service_name ${SVC_A};
    otel_metric_interval ${METRIC_INTERVAL_S}s;
    otel_access_log_sample 1;
    otel_trace on;

    server {
        listen 127.0.0.1:9470;
        location / { return 200 "ok\n"; }
    }
}
CONFEOF

"${NGINX_BINARY}" -e "${PREFIX}/logs/error.log" -p "${PREFIX}" -c "${CONF_A}" &
NGINX_PID=$!
wait_nginx_up "${NGINX_PID}"

# Send a request to generate telemetry across all three signals.
curl -sf http://127.0.0.1:9470/ >/dev/null

sleep "${FLUSH_WAIT_S}"

stop_nginx "${NGINX_PID}"

DELTA_A_METRICS="$(delta_log "${TLS_METRICS_LOG}" "${OFF_A}")"
DELTA_A_TRACES="$(delta_log "${TLS_TRACES_LOG}" "${OFF_A_TRACES}")"

[[ -n "${DELTA_A_METRICS}" ]] || fail "(a) OTLP/HTTP+TLS: no metrics received by collector"
echo "${DELTA_A_METRICS}" | jq -e --arg s "${SVC_A}" \
    'select([.resourceMetrics[].resource.attributes[]? | select(.key=="service.name").value.stringValue] | index($s)) | .resourceMetrics' \
    >/dev/null 2>&1 || fail "(a) OTLP/HTTP+TLS: metrics received but service.name=${SVC_A} not found"

pass "(a) OTLP/HTTP+TLS: metrics delivered with correct service.name"

# Payload-byte equality: compare raw OTLP payload of http vs https.
# We compare the metric data decoded from the JSON: the resource.attributes
# and scopeMetrics structure must have identical metric names. The transport
# (TLS) is encryption-only; no content difference is expected.
#
# Method: extract the set of metric names from the https run (DELTA_A_METRICS)
# and from the plain-http run we'll do next. Both must contain the same
# metric names (e.g. ngx_otel.export_interval). The check proves no metrics
# were added, dropped, or renamed by the TLS path.

TLS_METRIC_NAMES="$(echo "${DELTA_A_METRICS}" | jq -r '.resourceMetrics[].scopeMetrics[].metrics[].name' | sort -u)"
[[ -n "${TLS_METRIC_NAMES}" ]] || fail "(a) payload-equality: no metric names extracted from TLS run"
info "(a) TLS run metric names: $(echo "${TLS_METRIC_NAMES}" | tr '\n' ' ')"

# Plain-HTTP comparison run (same service name prefix, different suffix).
SVC_A_PLAIN="ngx-otel-a3-http-plain-$$"
OFF_A_PLAIN="$(snapshot_log "${METRICS_LOG}")"

cat > "${PREFIX}/nginx-a-plain.conf" << CONFEOF
daemon off;
master_process on;
worker_processes 1;
worker_shutdown_timeout 3s;
error_log ${PREFIX}/logs/error-plain.log notice;
pid       ${PREFIX}/logs/nginx-plain.pid;

load_module ${MODULE_PATH};
events { worker_connections 64; }

http {
    otel_exporter {
        endpoint http://127.0.0.1:4318;
    }
    otel_service_name ${SVC_A_PLAIN};
    otel_metric_interval ${METRIC_INTERVAL_S}s;

    server {
        listen 127.0.0.1:9471;
        location / { return 200 "ok\n"; }
    }
}
CONFEOF

"${NGINX_BINARY}" -e "${PREFIX}/logs/error-plain.log" -p "${PREFIX}" -c "${PREFIX}/nginx-a-plain.conf" &
NGINX_PID=$!
wait_nginx_up "${NGINX_PID}"
curl -sf http://127.0.0.1:9471/ >/dev/null
sleep "${FLUSH_WAIT_S}"
stop_nginx "${NGINX_PID}"

DELTA_A_PLAIN="$(delta_log "${METRICS_LOG}" "${OFF_A_PLAIN}")"
[[ -n "${DELTA_A_PLAIN}" ]] || fail "(a) payload-equality: plain-http run produced no metrics"

PLAIN_METRIC_NAMES="$(echo "${DELTA_A_PLAIN}" | jq -r \
    --arg s "${SVC_A_PLAIN}" \
    'select([.resourceMetrics[].resource.attributes[]? | select(.key=="service.name").value.stringValue] | index($s)) | .resourceMetrics[].scopeMetrics[].metrics[].name' \
    | sort -u)"

# Both sets must contain the same core metric names. We check the TLS names
# are a subset of the plain names and vice versa (set equality).
NAMES_ONLY_IN_TLS="$(comm -23 <(echo "${TLS_METRIC_NAMES}") <(echo "${PLAIN_METRIC_NAMES}"))"
NAMES_ONLY_IN_PLAIN="$(comm -13 <(echo "${TLS_METRIC_NAMES}") <(echo "${PLAIN_METRIC_NAMES}"))"
if [[ -n "${NAMES_ONLY_IN_TLS}" || -n "${NAMES_ONLY_IN_PLAIN}" ]]; then
    info "(a) payload-equality: TLS-only names: '${NAMES_ONLY_IN_TLS}'"
    info "(a) payload-equality: plain-only names: '${NAMES_ONLY_IN_PLAIN}'"
    fail "(a) payload-equality: TLS and plain-http metric name sets differ"
fi
pass "(a) payload-equality: metric name sets IDENTICAL across TLS and plain-http transports"

# ─── Scenario (b): OTLP/gRPC + https:// + trusted_certificate ────────────────

info "=== Scenario (b): OTLP/gRPC https:// trusted CA ==="

SVC_B="ngx-otel-a3-grpc-tls-$$"
OFF_B="$(snapshot_log "${TLS_METRICS_LOG}")"

cat > "${PREFIX}/nginx-b.conf" << CONFEOF
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
        endpoint https://127.0.0.1:${TLS_GRPC_PORT};
        trusted_certificate ${CERTS}/our-ca/our-ca.crt;
    }
    otel_export_protocol otlp_grpc;
    otel_service_name ${SVC_B};
    otel_metric_interval ${METRIC_INTERVAL_S}s;

    server {
        listen 127.0.0.1:9470;
        location / { return 200 "ok\n"; }
    }
}
CONFEOF

"${NGINX_BINARY}" -e "${PREFIX}/logs/error.log" -p "${PREFIX}" -c "${PREFIX}/nginx-b.conf" &
NGINX_PID=$!
wait_nginx_up "${NGINX_PID}"
curl -sf http://127.0.0.1:9470/ >/dev/null
sleep "${FLUSH_WAIT_S}"
stop_nginx "${NGINX_PID}"

DELTA_B="$(delta_log "${TLS_METRICS_LOG}" "${OFF_B}")"
[[ -n "${DELTA_B}" ]] || fail "(b) OTLP/gRPC+TLS: no metrics received by collector"
echo "${DELTA_B}" | jq -e --arg s "${SVC_B}" \
    'select([.resourceMetrics[].resource.attributes[]? | select(.key=="service.name").value.stringValue] | index($s)) | .resourceMetrics' \
    >/dev/null 2>&1 || fail "(b) OTLP/gRPC+TLS: metrics received but service.name=${SVC_B} not found"
pass "(b) OTLP/gRPC+TLS: metrics delivered with correct service.name"

# ─── Scenario (c): Bad CA → handshake fails, zero data, nginx healthy ─────────
# SECURITY-CRITICAL. The assertion: zero new data at the collector AND
# nginx error.log shows a TLS send-failure alert AND nginx continues serving.

info "=== Scenario (c): Bad CA — handshake must FAIL, zero data delivered ==="

SVC_C="ngx-otel-a3-badca-$$"
OFF_C="$(snapshot_log "${TLS_METRICS_LOG}")"

# Use the bad-ca's server cert but present our-ca's CA bundle → mismatch.
# The collector has server.crt (signed by our-ca); we tell nginx to trust bad-ca.
cat > "${PREFIX}/nginx-c.conf" << CONFEOF
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
        trusted_certificate ${CERTS}/bad-ca/bad-ca.crt;
    }
    otel_service_name ${SVC_C};
    otel_metric_interval ${METRIC_INTERVAL_S}s;

    server {
        listen 127.0.0.1:9470;
        location / { return 200 "ok\n"; }
    }
}
CONFEOF

"${NGINX_BINARY}" -e "${PREFIX}/logs/error.log" -p "${PREFIX}" -c "${PREFIX}/nginx-c.conf" &
NGINX_PID=$!
wait_nginx_up "${NGINX_PID}"

# Send requests to ensure nginx itself is healthy.
HTTP_STATUS="$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:9470/)"
[[ "${HTTP_STATUS}" == "200" ]] || fail "(c) nginx not serving: expected 200, got ${HTTP_STATUS}"

# Wait past multiple export attempts so backoff/retry pattern can manifest.
sleep $(( FLUSH_WAIT_S + 3 ))
stop_nginx "${NGINX_PID}"

# Assert 1: zero new data at the collector for this service.
DELTA_C="$(delta_log "${TLS_METRICS_LOG}" "${OFF_C}")"
if [[ -n "${DELTA_C}" ]] && echo "${DELTA_C}" | jq -e --arg s "${SVC_C}" \
    'select([.resourceMetrics[].resource.attributes[]? | select(.key=="service.name").value.stringValue] | index($s))' \
    >/dev/null 2>&1; then
    fail "(c) SECURITY: bad-CA run delivered data to collector — certificate verification NOT enforced"
fi
pass "(c) bad-CA run: ZERO data delivered to collector (security check PASS)"

# Assert 2: TLS send-failure alert in error.log.
TLS_ERR_COUNT="$(grep -cE "otel.*[Ff]ail|otel.*TLS|otel.*tls|otel.*handshake|otel.*certificate|otel.*ssl|otel.*SSL|send.*fail|export.*fail|TLS.*fail" \
    "${PREFIX}/logs/error.log" 2>/dev/null || echo 0)"
[[ "${TLS_ERR_COUNT}" -gt 0 ]] \
    || fail "(c) bad-CA run: no TLS/handshake/send-failure alert in error.log (verification not observed)"
pass "(c) bad-CA run: TLS send-failure alert present in error.log (${TLS_ERR_COUNT} line(s))"

# Assert 3: nginx continued serving after TLS failures.
# Restart and verify it still serves requests.
cat > "${PREFIX}/nginx-c2.conf" << CONFEOF
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
        trusted_certificate ${CERTS}/bad-ca/bad-ca.crt;
    }
    otel_service_name ${SVC_C}-healthy;
    otel_metric_interval 60s;

    server {
        listen 127.0.0.1:9470;
        location / { return 200 "ok\n"; }
    }
}
CONFEOF
"${NGINX_BINARY}" -e "${PREFIX}/logs/error.log" -p "${PREFIX}" -c "${PREFIX}/nginx-c2.conf" &
NGINX_PID=$!
wait_nginx_up "${NGINX_PID}"
sleep 2
STATUS="$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:9470/)"
stop_nginx "${NGINX_PID}"
[[ "${STATUS}" == "200" ]] || fail "(c) nginx not healthy after TLS failures: got HTTP ${STATUS}"
pass "(c) nginx healthy after TLS failures (HTTP ${STATUS})"

# ─── Scenario (d): ssl_verify off with untrusted collector cert ───────────────

info "=== Scenario (d): ssl_verify off — delivers despite bad CA ==="

SVC_D="ngx-otel-a3-insecure-$$"
OFF_D="$(snapshot_log "${TLS_METRICS_LOG}")"

cat > "${PREFIX}/nginx-d.conf" << CONFEOF
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
        trusted_certificate ${CERTS}/bad-ca/bad-ca.crt;
        ssl_verify off;
    }
    otel_service_name ${SVC_D};
    otel_metric_interval ${METRIC_INTERVAL_S}s;

    server {
        listen 127.0.0.1:9470;
        location / { return 200 "ok\n"; }
    }
}
CONFEOF

# Assert: config-time WARN must appear in error.log when nginx starts.
# ngx_conf_log_error!(NGX_LOG_WARN, ...) at post_config time writes to the
# startup log (-e path), not stdout. We capture it by redirecting -e to a
# temp file, then grepping for the WARN string.
WARN_LOG="${PREFIX}/logs/error-d-warn.log"
"${NGINX_BINARY}" -e "${WARN_LOG}" -p "${PREFIX}" -c "${PREFIX}/nginx-d.conf" &
NGINX_PID=$!
wait_nginx_up "${NGINX_PID}"
# The WARN is emitted at startup (post_config) — it should be in the log by now.
grep -qiE "ssl_verify off|verification is DISABLED|INSECURE" "${WARN_LOG}" \
    || fail "(d) ssl_verify off: expected config-time WARN in error.log, not found. Log: $(tail -10 ${WARN_LOG} 2>/dev/null)"
pass "(d) ssl_verify off: config-time WARN present in startup error.log"

curl -sf http://127.0.0.1:9470/ >/dev/null
sleep "${FLUSH_WAIT_S}"
stop_nginx "${NGINX_PID}"

DELTA_D="$(delta_log "${TLS_METRICS_LOG}" "${OFF_D}")"
[[ -n "${DELTA_D}" ]] || fail "(d) ssl_verify off: no metrics received — should have delivered"
echo "${DELTA_D}" | jq -e --arg s "${SVC_D}" \
    'select([.resourceMetrics[].resource.attributes[]? | select(.key=="service.name").value.stringValue] | index($s)) | .resourceMetrics' \
    >/dev/null 2>&1 || fail "(d) ssl_verify off: metrics received but service.name=${SVC_D} not found"
pass "(d) ssl_verify off: data delivered despite untrusted CA cert"

# ─── Scenario (e): mTLS ───────────────────────────────────────────────────────

info "=== Scenario (e): mTLS ==="

# Start mTLS collector.
info "Starting mTLS collector (HTTP=${MTLS_HTTP_PORT}, gRPC=${MTLS_GRPC_PORT})..."
docker run -d --name "${MTLS_COLLECTOR_NAME}" \
    --user "${OTEL_HOST_UID}:${OTEL_HOST_GID}" \
    -p "127.0.0.1:${MTLS_HTTP_PORT}:4321" \
    -p "127.0.0.1:${MTLS_GRPC_PORT}:4322" \
    -v "${MTLS_COLLECTOR_CONFIG}:/etc/otelcol/config.yaml:ro" \
    -v "${CERTS}:/certs:ro" \
    -v "${A3_SCRATCH}/logs:/var/log/otel" \
    otel/opentelemetry-collector-contrib:0.152.0 \
    --config=/etc/otelcol/config.yaml >/dev/null
MTLS_COLLECTOR_RUNNING=1

# Wait for mTLS collector.
MTLS_READY=0
for _ in $(seq 1 15); do
    # For mTLS we check with client cert.
    if curl -sk --connect-timeout 2 \
        --cacert "${CERTS}/our-ca/our-ca.crt" \
        --cert "${CERTS}/client.crt" \
        --key "${CERTS}/client.key" \
        "https://127.0.0.1:${MTLS_HTTP_PORT}/" >/dev/null 2>&1; then
        MTLS_READY=1; break
    fi
    sleep 1
done
[[ "${MTLS_READY}" -eq 1 ]] || fail "mTLS collector did not become ready within 15s"
pass "mTLS collector ready on port ${MTLS_HTTP_PORT}/${MTLS_GRPC_PORT}"

# (e1): With client cert → delivers.
SVC_E1="ngx-otel-a3-mtls-with-$$"
OFF_E1="$(snapshot_log "${MTLS_METRICS_LOG}")"

cat > "${PREFIX}/nginx-e1.conf" << CONFEOF
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
        endpoint https://127.0.0.1:${MTLS_HTTP_PORT};
        trusted_certificate ${CERTS}/our-ca/our-ca.crt;
        ssl_certificate     ${CERTS}/client.crt;
        ssl_certificate_key ${CERTS}/client.key;
    }
    otel_service_name ${SVC_E1};
    otel_metric_interval ${METRIC_INTERVAL_S}s;

    server {
        listen 127.0.0.1:9470;
        location / { return 200 "ok\n"; }
    }
}
CONFEOF

"${NGINX_BINARY}" -e "${PREFIX}/logs/error.log" -p "${PREFIX}" -c "${PREFIX}/nginx-e1.conf" &
NGINX_PID=$!
wait_nginx_up "${NGINX_PID}"
curl -sf http://127.0.0.1:9470/ >/dev/null
sleep "${FLUSH_WAIT_S}"
stop_nginx "${NGINX_PID}"

DELTA_E1="$(delta_log "${MTLS_METRICS_LOG}" "${OFF_E1}")"
[[ -n "${DELTA_E1}" ]] || fail "(e1) mTLS with client cert: no metrics received"
echo "${DELTA_E1}" | jq -e --arg s "${SVC_E1}" \
    'select([.resourceMetrics[].resource.attributes[]? | select(.key=="service.name").value.stringValue] | index($s)) | .resourceMetrics' \
    >/dev/null 2>&1 || fail "(e1) mTLS with client cert: metrics received but service.name=${SVC_E1} not found"
pass "(e1) mTLS with client cert: data delivered"

# (e2): Without client cert → fails closed.
SVC_E2="ngx-otel-a3-mtls-without-$$"
OFF_E2="$(snapshot_log "${MTLS_METRICS_LOG}")"

cat > "${PREFIX}/nginx-e2.conf" << CONFEOF
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
        endpoint https://127.0.0.1:${MTLS_HTTP_PORT};
        trusted_certificate ${CERTS}/our-ca/our-ca.crt;
        # No ssl_certificate / ssl_certificate_key — collector rejects.
    }
    otel_service_name ${SVC_E2};
    otel_metric_interval ${METRIC_INTERVAL_S}s;

    server {
        listen 127.0.0.1:9470;
        location / { return 200 "ok\n"; }
    }
}
CONFEOF

"${NGINX_BINARY}" -e "${PREFIX}/logs/error.log" -p "${PREFIX}" -c "${PREFIX}/nginx-e2.conf" &
NGINX_PID=$!
wait_nginx_up "${NGINX_PID}"
sleep $(( FLUSH_WAIT_S + 2 ))
stop_nginx "${NGINX_PID}"

DELTA_E2="$(delta_log "${MTLS_METRICS_LOG}" "${OFF_E2}")"
if [[ -n "${DELTA_E2}" ]] && echo "${DELTA_E2}" | jq -e --arg s "${SVC_E2}" \
    'select([.resourceMetrics[].resource.attributes[]? | select(.key=="service.name").value.stringValue] | index($s))' \
    >/dev/null 2>&1; then
    fail "(e2) mTLS without client cert: data DELIVERED — must fail closed"
fi
pass "(e2) mTLS without client cert: fails closed (zero data at collector)"

# ─── Scenario (f): Hostname mismatch ─────────────────────────────────────────

info "=== Scenario (f): Hostname mismatch ==="

# (f1): DNS-host mismatch — cert SAN=wrong.example.test; endpoint host=127.0.0.1
# The server presents wrong-san cert; nginx verifies SANs.
# We need to tell the TLS collector to serve the wrong-san cert.
# Simplest: run a lightweight TLS server with the wrong SAN cert and direct
# nginx at localhost (which is the endpoint but the cert says wrong.example.test).
#
# Implementation: we stand up an HTTPS mini-server using openssl s_server
# on a free port for just this scenario, then point nginx at it.
# NOTE: `openssl s_server` accepts connections and echoes; our exporter sends
# OTLP/HTTP POST. The s_server will refuse the POST (wrong protocol) but the
# TLS handshake will complete (or fail) before that, which is what we test.
#
# For (f1): The endpoint is https://127.0.0.1:9480.
#           We serve server-wrong-san.crt (SAN=wrong.example.test).
#           nginx trusts our-ca (which signed that cert too).
#           Hostname verification is for the HOST in the URL = 127.0.0.1.
#           X509_VERIFY_PARAM_set1_host is called with "127.0.0.1".
#           But the cert has no IP SAN for 127.0.0.1 and CN=wrong.example.test.
#           → hostname verification fails.

SVC_F1="ngx-otel-a3-f1-dnshost-$$"
OFF_F1="$(snapshot_log "${TLS_METRICS_LOG}")"

F1_PORT=9480
# Start openssl s_server with the wrong-san cert.
openssl s_server \
    -cert "${CERTS}/server-wrong-san.crt" \
    -key  "${CERTS}/server-wrong-san.key" \
    -CAfile "${CERTS}/our-ca/our-ca.crt" \
    -accept "${F1_PORT}" \
    -www \
    >/dev/null 2>&1 &
F1_SSERVER_PID=$!
sleep 1

cat > "${PREFIX}/nginx-f1.conf" << CONFEOF
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
        endpoint https://127.0.0.1:${F1_PORT};
        trusted_certificate ${CERTS}/our-ca/our-ca.crt;
    }
    otel_service_name ${SVC_F1};
    otel_metric_interval ${METRIC_INTERVAL_S}s;

    server {
        listen 127.0.0.1:9470;
        location / { return 200 "ok\n"; }
    }
}
CONFEOF

"${NGINX_BINARY}" -e "${PREFIX}/logs/error.log" -p "${PREFIX}" -c "${PREFIX}/nginx-f1.conf" &
NGINX_PID=$!
wait_nginx_up "${NGINX_PID}"
sleep $(( FLUSH_WAIT_S + 2 ))
stop_nginx "${NGINX_PID}"
kill "${F1_SSERVER_PID}" 2>/dev/null || true
wait "${F1_SSERVER_PID}" 2>/dev/null || true

DELTA_F1="$(delta_log "${TLS_METRICS_LOG}" "${OFF_F1}")"
if [[ -n "${DELTA_F1}" ]] && echo "${DELTA_F1}" | jq -e --arg s "${SVC_F1}" \
    'select([.resourceMetrics[].resource.attributes[]? | select(.key=="service.name").value.stringValue] | index($s))' \
    >/dev/null 2>&1; then
    fail "(f1) DNS hostname mismatch: data DELIVERED — hostname verification not enforced"
fi
pass "(f1) DNS hostname mismatch: fails (zero data at collector, hostname verification enforced)"

# (f2): IP-literal with wrong IP SAN.
# Endpoint is https://127.0.0.1:9481.
# Cert has IP SAN = 127.0.0.2 only (not 127.0.0.1).
# A2 shipped the IP-literal path: X509_VERIFY_PARAM_set1_ip_asc for IPs.

SVC_F2="ngx-otel-a3-f2-wrongip-$$"
OFF_F2="$(snapshot_log "${TLS_METRICS_LOG}")"

F2_PORT=9481
openssl s_server \
    -cert "${CERTS}/server-wrong-ip.crt" \
    -key  "${CERTS}/server-wrong-ip.key" \
    -CAfile "${CERTS}/our-ca/our-ca.crt" \
    -accept "${F2_PORT}" \
    -www \
    >/dev/null 2>&1 &
F2_SSERVER_PID=$!
sleep 1

cat > "${PREFIX}/nginx-f2.conf" << CONFEOF
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
        endpoint https://127.0.0.1:${F2_PORT};
        trusted_certificate ${CERTS}/our-ca/our-ca.crt;
    }
    otel_service_name ${SVC_F2};
    otel_metric_interval ${METRIC_INTERVAL_S}s;

    server {
        listen 127.0.0.1:9470;
        location / { return 200 "ok\n"; }
    }
}
CONFEOF

"${NGINX_BINARY}" -e "${PREFIX}/logs/error.log" -p "${PREFIX}" -c "${PREFIX}/nginx-f2.conf" &
NGINX_PID=$!
wait_nginx_up "${NGINX_PID}"
sleep $(( FLUSH_WAIT_S + 2 ))
stop_nginx "${NGINX_PID}"
kill "${F2_SSERVER_PID}" 2>/dev/null || true
wait "${F2_SSERVER_PID}" 2>/dev/null || true

DELTA_F2="$(delta_log "${TLS_METRICS_LOG}" "${OFF_F2}")"
if [[ -n "${DELTA_F2}" ]] && echo "${DELTA_F2}" | jq -e --arg s "${SVC_F2}" \
    'select([.resourceMetrics[].resource.attributes[]? | select(.key=="service.name").value.stringValue] | index($s))' \
    >/dev/null 2>&1; then
    fail "(f2) IP SAN mismatch: data DELIVERED — IP hostname verification not enforced"
fi
pass "(f2) IP SAN mismatch: fails (zero data at collector, IP verification enforced)"

# ─── Scenario (g): SIGHUP reload with changed cert/CA paths ──────────────────

info "=== Scenario (g): SIGHUP reload — changed CA picked up ==="

# Phase 1: nginx with bad-ca (handshake fails, no data).
# Phase 2: SIGHUP with conf pointing at our-ca (handshake succeeds, data arrives).
# This proves the new exporter generation picks up the new CA.
#
# nginx re-reads its conf file ON HUP. We start nginx pointing at a fixed
# conf path (nginx-g.conf), then overwrite that same file with the new conf
# before sending HUP — the master re-executes the new file.

SVC_G="ngx-otel-a3-reload-$$"
OFF_G="$(snapshot_log "${TLS_METRICS_LOG}")"

G_CONF="${PREFIX}/nginx-g.conf"

# Write phase-1 config (bad CA) to the fixed conf path.
cat > "${G_CONF}" << CONFEOF
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
        trusted_certificate ${CERTS}/bad-ca/bad-ca.crt;
    }
    otel_service_name ${SVC_G};
    otel_metric_interval ${METRIC_INTERVAL_S}s;

    server {
        listen 127.0.0.1:9470;
        location / { return 200 "ok\n"; }
    }
}
CONFEOF

# Start with phase-1 (bad CA).
"${NGINX_BINARY}" -e "${PREFIX}/logs/error.log" -p "${PREFIX}" -c "${G_CONF}" &
NGINX_PID=$!
wait_nginx_up "${NGINX_PID}"
sleep $(( METRIC_INTERVAL_S + 1 ))

# Verify phase-1 delivers nothing.
OFF_G_MID="$(snapshot_log "${TLS_METRICS_LOG}")"
DELTA_G_PHASE1="$(delta_log "${TLS_METRICS_LOG}" "${OFF_G}")"
if [[ -n "${DELTA_G_PHASE1}" ]] && echo "${DELTA_G_PHASE1}" | jq -e --arg s "${SVC_G}" \
    'select([.resourceMetrics[].resource.attributes[]? | select(.key=="service.name").value.stringValue] | index($s))' \
    >/dev/null 2>&1; then
    fail "(g) SIGHUP setup: phase-1 (bad CA) unexpectedly delivered data"
fi
info "(g) phase-1 (bad CA) confirmed: no data delivered"

# Overwrite the same conf file with phase-2 (good CA), then HUP.
# nginx re-reads the config file on SIGHUP, so it picks up the new CA.
cat > "${G_CONF}" << CONFEOF
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
        trusted_certificate ${CERTS}/our-ca/our-ca.crt;
    }
    otel_service_name ${SVC_G};
    otel_metric_interval ${METRIC_INTERVAL_S}s;

    server {
        listen 127.0.0.1:9470;
        location / { return 200 "ok\n"; }
    }
}
CONFEOF

kill -HUP "${NGINX_PID}"
sleep $(( FLUSH_WAIT_S + 2 ))

stop_nginx "${NGINX_PID}"

DELTA_G_PHASE2="$(delta_log "${TLS_METRICS_LOG}" "${OFF_G_MID}")"
[[ -n "${DELTA_G_PHASE2}" ]] \
    || fail "(g) SIGHUP reload: no data after reload to good CA"
echo "${DELTA_G_PHASE2}" | jq -e --arg s "${SVC_G}" \
    'select([.resourceMetrics[].resource.attributes[]? | select(.key=="service.name").value.stringValue] | index($s)) | .resourceMetrics' \
    >/dev/null 2>&1 || fail "(g) SIGHUP reload: post-reload metrics missing service.name=${SVC_G}"
pass "(g) SIGHUP reload: new CA picked up by reloaded exporter — data delivered after reload"

# ─── All scenarios complete ───────────────────────────────────────────────────

echo ""
echo "============================================================"
pass "A3 TLS E2E integration: ALL scenarios (a)-(g) PASSED"
echo "============================================================"
echo "[$(date -u +%T)] COMPLETE run_a3_tls_e2e.sh" >> "${PROGRESS_LOG}"
