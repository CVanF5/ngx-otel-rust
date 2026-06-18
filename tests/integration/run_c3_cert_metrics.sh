#!/usr/bin/env bash
# tests/integration/run_c3_cert_metrics.sh — C3 serving-certificate metrics E2E
#
# Verifies the ServingCertSource export path (src/metric_source/tls_cert.rs,
# registered in export::collect_all_sources) end-to-end against a real OTel
# collector:
#
#   (1) self-signed certs with KNOWN validity → the collector receives all
#       three `ngx_otel.tls.certificate.*` gauges with EXACT not_after /
#       not_before epoch values (ground truth derived independently from
#       `openssl x509 -enddate/-startdate` + GNU date, NOT from our code);
#   (2) time_to_expiration is plausible: |value − (not_after − now)| ≤ slack;
#   (3) dual RSA+ECDSA server block → 2 data points per metric for that
#       server (one per cert) within a single export flush;
#   (4) the per-point attribute set is EXACTLY the 7 scope-guard keys —
#       no extra attribute keys anywhere (privacy/cardinality guard);
#   (5) NGINX Agent's metric name `nginx.certificate.time_to_expiration`
#       does NOT appear anywhere in the collector output (our metric uses a distinct name);
#   (6) reload with a swapped certificate → not_after updates to the new
#       cert's epoch (serves-vs-disk cadence: values change AT reload);
#   (7) no-ssl nginx binary → the module still exports (export_interval
#       present for that service) but the three cert metric names are
#       ABSENT entirely (absent-not-zero, registration level).
#
# Self-contained: generates throwaway self-signed certs; reuses the C2
# pattern for the optional no-ssl scratch build (OUTSIDE /tmp).
#
# Platform: Linux (debian-vm) — GNU `date -d` + jq + docker collector.
#
# Environment:
#   NGINX_BINARY         — ssl-enabled nginx (default: objs-release/nginx)
#   NGINX_SOURCE_DIR     — nginx source tree (module build + no-ssl scratch)
#   NGINX_BUILD_DIR      — nginx build dir for the module build
#   NO_SSL_NGINX_BINARY  — pre-built no-ssl nginx for (7); built if unset
#   C3_SCRATCH_DIR       — scratch root for the no-ssl build
#                          (default: <repo-parent>/c3-scratch — NEVER /tmp)
#
# Exit codes: 0 = all assertions passed, 1 = pre-flight failure, 2 = assertion.

set -euo pipefail

# ─── Resolve paths ───────────────────────────────────────────────────────────

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

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*" >&2; exit 2; }
info() { echo -e "${YELLOW}[INFO]${NC} $*"; }

# ─── Pre-flight ──────────────────────────────────────────────────────────────

[[ -x "${NGINX_BINARY}" ]] || { echo "ERROR: nginx binary not found: ${NGINX_BINARY}" >&2; exit 1; }
command -v openssl >/dev/null || { echo "ERROR: openssl CLI required" >&2; exit 1; }
command -v jq >/dev/null || { echo "ERROR: jq required for metrics.json assertions" >&2; exit 1; }
date -u -d "Jan 1 00:00:00 2030 GMT" +%s >/dev/null 2>&1 \
    || { echo "ERROR: GNU date -d required (run on Linux/debian-vm)" >&2; exit 1; }

# Collector harness (METRICS_LOG, ensure_collector_running).
. "${CRATE_DIR}/test-harness/lib.sh"
ensure_collector_running || exit 1

info "Building release module..."
(
    cd "${CRATE_DIR}"
    NGINX_SOURCE_DIR="${NGINX_SOURCE_DIR}" NGINX_BUILD_DIR="${NGINX_BUILD_DIR}" \
        cargo build --release 2>&1 | tail -2
)
[[ -f "${MODULE_PATH}" ]] || { echo "ERROR: module not found: ${MODULE_PATH}" >&2; exit 1; }

# ─── Sandbox ─────────────────────────────────────────────────────────────────

PREFIX="$(mktemp -d /tmp/ngx-otel-c3-cert.XXXXXX)"
NGINX_PID=""
NOSSL_PID=""
cleanup() {
    [[ -n "${NGINX_PID}" ]] && kill -QUIT "${NGINX_PID}" 2>/dev/null || true
    [[ -n "${NOSSL_PID}" ]] && kill -QUIT "${NOSSL_PID}" 2>/dev/null || true
    rm -rf "${PREFIX}"
}
trap cleanup EXIT

mkdir -p "${PREFIX}/logs" "${PREFIX}/client_body_temp" "${PREFIX}/certs"
CERTS="${PREFIX}/certs"

SVC="ngx-otel-c3-cert-metrics-$$"
SVC_NOSSL="ngx-otel-c3-cert-nossl-$$"
METRIC_INTERVAL_S=1
FLUSH_WAIT_S=5

# ─── Generate throwaway self-signed certs at KNOWN validity ─────────────────

req_supports_not_after() {
    openssl req -help 2>&1 | grep -q -- '-not_after'
}

# gen_cert <basename> <CN> <notAfter YYYYMMDDHHMMSSZ> <rsa|ec>
gen_cert() {
    local base="$1" cn="$2" not_after="$3" alg="$4"
    local keyopts=()
    case "${alg}" in
        rsa) keyopts=(-newkey rsa:2048) ;;
        ec)  keyopts=(-newkey ec -pkeyopt ec_paramgen_curve:P-256) ;;
    esac
    local extra=()
    if req_supports_not_after; then
        extra=(-not_after "${not_after}")
    else
        extra=(-days 365)
    fi
    openssl req -x509 -nodes "${keyopts[@]}" \
        -keyout "${CERTS}/${base}.key" -out "${CERTS}/${base}.crt" \
        -subj "/CN=${cn}" "${extra[@]}" >/dev/null 2>&1
}

# Independent ground truth via openssl CLI + GNU date.
cert_not_after_epoch() {
    local enddate
    enddate="$(openssl x509 -in "$1" -noout -enddate)"
    date -u -d "${enddate#notAfter=}" +%s
}
cert_not_before_epoch() {
    local startdate
    startdate="$(openssl x509 -in "$1" -noout -startdate)"
    date -u -d "${startdate#notBefore=}" +%s
}

info "Generating certs..."
gen_cert a       cert-a.example.test  20300101000000Z rsa
gen_cert rsa     dual.example.test    20310101000000Z rsa
gen_cert ecdsa   dual.example.test    20320101000000Z ec
gen_cert swapped cert-a2.example.test 20350101000000Z rsa

EXP_A="$(cert_not_after_epoch "${CERTS}/a.crt")"
NBF_A="$(cert_not_before_epoch "${CERTS}/a.crt")"
EXP_RSA="$(cert_not_after_epoch "${CERTS}/rsa.crt")"
EXP_EC="$(cert_not_after_epoch "${CERTS}/ecdsa.crt")"
EXP_SWAPPED="$(cert_not_after_epoch "${CERTS}/swapped.crt")"
info "ground truth: a not_after=${EXP_A} not_before=${NBF_A}; dual rsa=${EXP_RSA} ec=${EXP_EC}; swapped=${EXP_SWAPPED}"
[[ "${EXP_A}" != "${EXP_SWAPPED}" ]] || fail "test bug: swapped cert must have a different notAfter"

# ─── nginx.conf ──────────────────────────────────────────────────────────────

cat > "${PREFIX}/nginx.conf" <<EOF
daemon off;
master_process on;
worker_processes 1;
error_log ${PREFIX}/logs/error.log notice;
pid       ${PREFIX}/logs/nginx.pid;

load_module ${MODULE_PATH};

events { worker_connections 64; }

http {
    otel_exporter {
        endpoint ${COLLECTOR_HTTP_ENDPOINT};
    }
    otel_service_name ${SVC};
    otel_metric_interval ${METRIC_INTERVAL_S}s;

    # (1) single RSA cert
    server {
        listen 127.0.0.1:9453 ssl;
        server_name cert-a.example.test;
        ssl_certificate     ${CERTS}/a.crt;
        ssl_certificate_key ${CERTS}/a.key;
        location / { return 200 "a\n"; }
    }

    # (3) DUAL RSA + ECDSA in ONE server block
    server {
        listen 127.0.0.1:9454 ssl;
        server_name dual.example.test;
        ssl_certificate     ${CERTS}/rsa.crt;
        ssl_certificate_key ${CERTS}/rsa.key;
        ssl_certificate     ${CERTS}/ecdsa.crt;
        ssl_certificate_key ${CERTS}/ecdsa.key;
        location / { return 200 "b\n"; }
    }
}
EOF

# ─── Phase 1: start, flush, assert ───────────────────────────────────────────

PRE_SIZE=0
[[ -f "${METRICS_LOG}" ]] && PRE_SIZE=$(wc -c < "${METRICS_LOG}")

info "Starting ssl-enabled nginx (service=${SVC})..."
"${NGINX_BINARY}" -e "${PREFIX}/logs/error.log" -p "${PREFIX}" -c "${PREFIX}/nginx.conf" &
NGINX_PID=$!
sleep 1
kill -0 "${NGINX_PID}" 2>/dev/null || { cat "${PREFIX}/logs/error.log" >&2; fail "nginx exited at startup"; }

info "Waiting ${FLUSH_WAIT_S}s for metric flushes (interval=${METRIC_INTERVAL_S}s)..."
sleep "${FLUSH_WAIT_S}"
NOW_1="$(date -u +%s)"

MID_SIZE=$(wc -c < "${METRICS_LOG}")
(( MID_SIZE > PRE_SIZE )) || fail "collector wrote nothing during phase 1"
DELTA1="${PREFIX}/delta1.ndjson"
tail -c "+$(( PRE_SIZE + 1 ))" "${METRICS_LOG}" \
    | jq -c --arg svc "${SVC}" \
        'select([.resourceMetrics[].resource.attributes[]? | select(.key=="service.name").value.stringValue] | index($svc))' \
    > "${DELTA1}" || true
[[ -s "${DELTA1}" ]] || fail "no collector records for service ${SVC} in phase 1"
info "phase-1 delta: $(wc -l < "${DELTA1}") flush record(s) for ${SVC}"

# jq helper streams: all cert-metric instances across the delta.
CERT_METRICS_JQ='.resourceMetrics[].scopeMetrics[].metrics[] | select(.name | startswith("ngx_otel.tls.certificate."))'

# (1) exact not_after / not_before per cert file, on every flush.
assert_exact_point() {
    local metric="$1" path="$2" expected="$3" label="$4"
    local got
    got="$(jq -r --arg m "${metric}" --arg p "${path}" \
        ".resourceMetrics[].scopeMetrics[].metrics[]
         | select(.name == \$m)
         | .gauge.dataPoints[]
         | select(any(.attributes[]; .key == \"tls.server.certificate.file_path\" and .value.stringValue == \$p))
         | .asInt" "${DELTA1}" | sort -u)"
    [[ "${got}" == "${expected}" ]] \
        || fail "${label}: expected ${metric}=${expected} for ${path}, got '${got}'"
    pass "${label}: ${metric} = ${expected} exact (every flush)"
}
assert_exact_point "ngx_otel.tls.certificate.not_after"  "${CERTS}/a.crt"     "${EXP_A}"   "(1) cert a not_after"
assert_exact_point "ngx_otel.tls.certificate.not_before" "${CERTS}/a.crt"     "${NBF_A}"   "(1) cert a not_before"
assert_exact_point "ngx_otel.tls.certificate.not_after"  "${CERTS}/rsa.crt"   "${EXP_RSA}" "(1) dual rsa not_after"
assert_exact_point "ngx_otel.tls.certificate.not_after"  "${CERTS}/ecdsa.crt" "${EXP_EC}"  "(1) dual ecdsa not_after"

# (2) time_to_expiration plausible: |tte − (not_after − now)| ≤ 300 s.
TTE_A="$(jq -r --arg p "${CERTS}/a.crt" \
    ".resourceMetrics[].scopeMetrics[].metrics[]
     | select(.name == \"ngx_otel.tls.certificate.time_to_expiration\")
     | .gauge.dataPoints[]
     | select(any(.attributes[]; .key == \"tls.server.certificate.file_path\" and .value.stringValue == \$p))
     | .asInt" "${DELTA1}" | tail -1)"
[[ -n "${TTE_A}" ]] || fail "(2) no time_to_expiration point for a.crt"
EXPECTED_TTE=$(( EXP_A - NOW_1 ))
DIFF=$(( TTE_A - EXPECTED_TTE )); (( DIFF < 0 )) && DIFF=$(( -DIFF ))
(( DIFF <= 300 )) || fail "(2) time_to_expiration ${TTE_A} not within 300s of not_after−now=${EXPECTED_TTE}"
pass "(2) time_to_expiration ${TTE_A} ≈ not_after − now (${EXPECTED_TTE}, |Δ|=${DIFF}s ≤ 300s)"

# (3) dual block: 2 data points per metric (server.address=dual.example.test)
#     within ONE flush — check the LAST flush record.
LAST_FLUSH="${PREFIX}/last_flush.json"
tail -1 "${DELTA1}" > "${LAST_FLUSH}"
for m in not_after not_before time_to_expiration; do
    N_DUAL="$(jq -r --arg m "ngx_otel.tls.certificate.${m}" \
        "[.resourceMetrics[].scopeMetrics[].metrics[]
          | select(.name == \$m)
          | .gauge.dataPoints[]
          | select(any(.attributes[]; .key == \"server.address\" and .value.stringValue == \"dual.example.test\"))
         ] | length" "${LAST_FLUSH}")"
    [[ "${N_DUAL}" == "2" ]] || fail "(3) expected 2 dual-block points for ${m}, got ${N_DUAL}"
done
pass "(3) dual RSA+ECDSA block: 2 series per metric in a single flush"

# (4) attribute set EXACTLY the 7 allowed keys on EVERY cert-metric point.
ALLOWED='["server.address","tls.server.certificate.file_path","tls.server.certificate.public_key_algorithm","tls.server.certificate.serial_number","tls.server.certificate.signature_algorithm","tls.server.issuer","tls.server.subject"]'
BAD_SETS="$(jq -c --argjson allowed "${ALLOWED}" \
    "[${CERT_METRICS_JQ} | .gauge.dataPoints[] | [.attributes[].key] | sort | select(. != \$allowed)] | unique" \
    "${DELTA1}" | sort -u | grep -v '^\[\]$' || true)"
[[ -z "${BAD_SETS}" ]] || fail "(4) cert-metric point(s) with wrong attribute set: ${BAD_SETS}"
N_POINTS="$(jq "[${CERT_METRICS_JQ} | .gauge.dataPoints[]] | length" "${DELTA1}" | awk '{s+=$1} END {print s}')"
(( N_POINTS > 0 )) || fail "(4) no cert-metric data points found at all"
pass "(4) attribute set EXACTLY the 7 scope-guard keys on all ${N_POINTS} points"

# ─── Phase 2: reload with swapped cert ───────────────────────────────────────

info "Swapping cert a → swapped (notAfter ${EXP_SWAPPED}) and reloading (HUP)..."
cp "${CERTS}/swapped.crt" "${CERTS}/a.crt"
cp "${CERTS}/swapped.key" "${CERTS}/a.key"
kill -HUP "${NGINX_PID}"
sleep "${FLUSH_WAIT_S}"

# Stop nginx (graceful) so the exporter drains, then take the phase-2 delta.
kill -QUIT "${NGINX_PID}" 2>/dev/null || true
for _ in $(seq 1 15); do
    kill -0 "${NGINX_PID}" 2>/dev/null || break
    sleep 1
done
NGINX_PID=""

END_SIZE=$(wc -c < "${METRICS_LOG}")
DELTA2="${PREFIX}/delta2.ndjson"
tail -c "+$(( MID_SIZE + 1 ))" "${METRICS_LOG}" \
    | jq -c --arg svc "${SVC}" \
        'select([.resourceMetrics[].resource.attributes[]? | select(.key=="service.name").value.stringValue] | index($svc))' \
    > "${DELTA2}" || true
[[ -s "${DELTA2}" ]] || fail "(6) no collector records after reload"

# Membership assertions (NOT order-dependent: `sort | tail -1` is
# locale-collation-fragile for the CN strings, and old-exporter drain
# flushes may interleave with the new exporter's during reload overlap).
NOT_AFTER_VALUES="$(jq -r --arg p "${CERTS}/a.crt" \
    ".resourceMetrics[].scopeMetrics[].metrics[]
     | select(.name == \"ngx_otel.tls.certificate.not_after\")
     | .gauge.dataPoints[]
     | select(any(.attributes[]; .key == \"tls.server.certificate.file_path\" and .value.stringValue == \$p))
     | .asInt" "${DELTA2}" | sort -u)"
grep -qx "${EXP_SWAPPED}" <<< "${NOT_AFTER_VALUES}" \
    || fail "(6) after reload expected not_after=${EXP_SWAPPED} for a.crt; distinct values: $(tr '\n' ' ' <<< "${NOT_AFTER_VALUES}")"
SWAPPED_CNS="$(jq -r --arg p "${CERTS}/a.crt" \
    ".resourceMetrics[].scopeMetrics[].metrics[]
     | select(.name == \"ngx_otel.tls.certificate.not_after\")
     | .gauge.dataPoints[]
     | select(any(.attributes[]; .key == \"tls.server.certificate.file_path\" and .value.stringValue == \$p))
     | .attributes[] | select(.key == \"tls.server.subject\").value.stringValue" \
    "${DELTA2}" | sort -u)"
grep -qx "cert-a2.example.test" <<< "${SWAPPED_CNS}" \
    || fail "(6) after reload expected subject CN cert-a2.example.test; distinct CNs: $(tr '\n' ' ' <<< "${SWAPPED_CNS}")"
# The swapped values must come from the SAME data point (CN + not_after
# updated together): at least one post-reload point carries both.
jq -e --arg p "${CERTS}/a.crt" --arg exp "${EXP_SWAPPED}" \
    "[.resourceMetrics[].scopeMetrics[].metrics[]
      | select(.name == \"ngx_otel.tls.certificate.not_after\")
      | .gauge.dataPoints[]
      | select(any(.attributes[]; .key == \"tls.server.certificate.file_path\" and .value.stringValue == \$p))
      | select(.asInt == \$exp)
      | select(any(.attributes[]; .key == \"tls.server.subject\" and .value.stringValue == \"cert-a2.example.test\"))
     ] | length > 0" "${DELTA2}" >/dev/null \
    || fail "(6) no post-reload point carries BOTH not_after=${EXP_SWAPPED} and CN=cert-a2.example.test"
pass "(6) reload: swapped cert exported (not_after=${EXP_SWAPPED}, CN=cert-a2.example.test on the same point)"

# (5) NGINX Agent's metric name appears NOWHERE in our collector output.
if grep -qF 'nginx.certificate.time_to_expiration' "${DELTA1}" "${DELTA2}"; then
    fail "(5) Agent metric name nginx.certificate.time_to_expiration found in collector output"
fi
pass "(5) Agent name nginx.certificate.time_to_expiration ABSENT from collector output"

# ─── Phase 3: no-ssl binary → cert series ABSENT ─────────────────────────────

NOSSL_BIN="${NO_SSL_NGINX_BINARY:-}"
if [[ -z "${NOSSL_BIN}" ]]; then
    SCRATCH="${C3_SCRATCH_DIR:-${REPO_ROOT}/c3-scratch}/objs-nossl"
    NOSSL_BIN="${SCRATCH}/nginx"
    if [[ ! -x "${NOSSL_BIN}" ]]; then
        info "(7) building no-ssl nginx into ${SCRATCH}..."
        mkdir -p "${SCRATCH}"
        SAVED_MK=""
        if [[ -f "${NGINX_SOURCE_DIR}/Makefile" ]]; then
            SAVED_MK="$(mktemp /tmp/ngx-c3-mk.XXXXXX)"
            cp "${NGINX_SOURCE_DIR}/Makefile" "${SAVED_MK}"
        fi
        (
            cd "${NGINX_SOURCE_DIR}"
            auto/configure --with-compat --with-http_stub_status_module \
                --builddir="${SCRATCH}" >/dev/null
            make -f "${SCRATCH}/Makefile" -j"$(nproc 2>/dev/null || echo 2)" >/dev/null
        )
        if [[ -n "${SAVED_MK}" ]]; then
            mv "${SAVED_MK}" "${NGINX_SOURCE_DIR}/Makefile"
        fi
    else
        info "(7) reusing cached no-ssl nginx: ${NOSSL_BIN}"
    fi
fi
[[ -x "${NOSSL_BIN}" ]] || fail "(7) no-ssl nginx binary not available: ${NOSSL_BIN}"
if "${NOSSL_BIN}" -V 2>&1 | grep -q "http_ssl_module"; then
    fail "(7) supposed no-ssl binary was built WITH http_ssl_module"
fi

cat > "${PREFIX}/nginx-nossl.conf" <<EOF
daemon off;
master_process on;
worker_processes 1;
error_log ${PREFIX}/logs/error-nossl.log notice;
pid       ${PREFIX}/logs/nginx-nossl.pid;

load_module ${MODULE_PATH};

events { worker_connections 64; }

http {
    otel_exporter {
        endpoint ${COLLECTOR_HTTP_ENDPOINT};
    }
    otel_service_name ${SVC_NOSSL};
    otel_metric_interval ${METRIC_INTERVAL_S}s;

    server {
        listen 127.0.0.1:9455;
        location / { return 200 "nossl\n"; }
    }
}
EOF

PRE3_SIZE=$(wc -c < "${METRICS_LOG}")
info "(7) starting no-ssl nginx (service=${SVC_NOSSL})..."
"${NOSSL_BIN}" -e "${PREFIX}/logs/error-nossl.log" -p "${PREFIX}" -c "${PREFIX}/nginx-nossl.conf" &
NOSSL_PID=$!
sleep 1
kill -0 "${NOSSL_PID}" 2>/dev/null \
    || { cat "${PREFIX}/logs/error-nossl.log" >&2; fail "(7) no-ssl nginx exited at startup"; }
sleep "${FLUSH_WAIT_S}"
kill -QUIT "${NOSSL_PID}" 2>/dev/null || true
for _ in $(seq 1 15); do
    kill -0 "${NOSSL_PID}" 2>/dev/null || break
    sleep 1
done
NOSSL_PID=""

DELTA3="${PREFIX}/delta3.ndjson"
tail -c "+$(( PRE3_SIZE + 1 ))" "${METRICS_LOG}" \
    | jq -c --arg svc "${SVC_NOSSL}" \
        'select([.resourceMetrics[].resource.attributes[]? | select(.key=="service.name").value.stringValue] | index($svc))' \
    > "${DELTA3}" || true
[[ -s "${DELTA3}" ]] || fail "(7) no-ssl run exported nothing — absence check would be hollow"

# Export proven (some non-cert series arrived for this service)...
jq -e '.resourceMetrics[].scopeMetrics[].metrics[] | select(.name == "ngx_otel.export_interval")' \
    "${DELTA3}" >/dev/null || fail "(7) ngx_otel.export_interval missing — export not proven"
# ...and the three cert metric names are ABSENT entirely.
if grep -qF 'ngx_otel.tls.certificate' "${DELTA3}"; then
    fail "(7) no-ssl run must NOT export any ngx_otel.tls.certificate.* series"
fi
pass "(7) no-ssl binary: export proven (export_interval present), cert series ABSENT"

echo ""
pass "C3 cert-metrics integration: ALL assertions passed (1)-(7)"
