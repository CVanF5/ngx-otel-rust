#!/usr/bin/env bash
# tests/integration/run_c2_cert_walk.sh — C2 config-time cert walk functional test
#
# Verifies the config-time TLS serving-certificate table (src/cert_table.rs +
# src/shim/ngx_otel_ssl_shim.c) via the per-cert config-time NOTICEs (there are
# no cert metrics yet — that is C3):
#
#   (a) one self-signed cert server      → one NOTICE with the exact configured
#       path, subject CN and notAfter epoch (epoch independently derived from
#       `openssl x509 -enddate` + GNU date, NOT from our own code);
#   (b) DUAL RSA+ECDSA same server block → BOTH certs enumerated, one NOTICE
#       each (full-enumeration acceptance test for dual-cert server blocks);
#   (c) multi-server_name block          → the first NON-wildcard name is
#       recorded (wildcard + dot-prefix names skipped);
#   (d) `ssl_certificate $var`           → skipped with a NOTICE; nothing
#       enumerated for that server (nginx defers variable certs to handshake);
#   (e) no-ssl nginx binary              → module still loads and serves, one
#       "cert metrics unavailable" NOTICE, zero cert lines, no crash.
#
# Self-contained: generates throwaway self-signed certs (openssl CLI) at known
# notAfter dates into the sandbox, and (for (e)) builds a --with-compat nginx
# WITHOUT --with-http_ssl_module into a scratch dir OUTSIDE /tmp unless
# NO_SSL_NGINX_BINARY is provided.
#
# Platform: Linux (debian-vm) — requires GNU `date -d` for the independent
# epoch derivation.
#
# Environment:
#   NGINX_BINARY         — ssl-enabled nginx (default: objs-release/nginx)
#   NGINX_SOURCE_DIR     — nginx source tree (module build + (e) scratch build)
#   NGINX_BUILD_DIR      — nginx build dir for the module build
#   NO_SSL_NGINX_BINARY  — pre-built no-ssl nginx for (e); built if unset
#   C2_SCRATCH_DIR       — scratch root for the (e) build
#                          (default: <repo-parent>/c2-scratch — NEVER /tmp)
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
date -u -d "Jan 1 00:00:00 2030 GMT" +%s >/dev/null 2>&1 \
    || { echo "ERROR: GNU date -d required (run on Linux/debian-vm)" >&2; exit 1; }

info "Building release module..."
(
    cd "${CRATE_DIR}"
    NGINX_SOURCE_DIR="${NGINX_SOURCE_DIR}" NGINX_BUILD_DIR="${NGINX_BUILD_DIR}" \
        cargo build --release 2>&1 | tail -2
)
[[ -f "${MODULE_PATH}" ]] || { echo "ERROR: module not found: ${MODULE_PATH}" >&2; exit 1; }

# ─── Sandbox ─────────────────────────────────────────────────────────────────

PREFIX="$(mktemp -d /tmp/ngx-otel-c2-cert.XXXXXX)"
NGINX_PID=""
NOSSL_PID=""
cleanup() {
    [[ -n "${NGINX_PID}" ]] && kill -QUIT "${NGINX_PID}" 2>/dev/null || true
    [[ -n "${NOSSL_PID}" ]] && kill -QUIT "${NOSSL_PID}" 2>/dev/null || true
    echo ""
    echo "=== ssl error.log (cert-metric lines) ==="
    grep "cert metrics" "${PREFIX}/logs/error.log" 2>/dev/null || echo "(none)"
    echo "=== no-ssl error.log (cert-metric lines) ==="
    grep "cert metrics" "${PREFIX}/logs/error-nossl.log" 2>/dev/null || echo "(none)"
    rm -rf "${PREFIX}"
}
trap cleanup EXIT

mkdir -p "${PREFIX}/logs" "${PREFIX}/client_body_temp" "${PREFIX}/certs"
CERTS="${PREFIX}/certs"

# ─── Generate throwaway self-signed certs at KNOWN notAfter dates ───────────
#
# Primary: explicit `-not_after` (OpenSSL ≥ 3.4).  Fallback: `-days`.  The
# expected epoch asserted below is ALWAYS derived independently from
# `openssl x509 -enddate` + GNU date, so the assertion is exact either way.

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

# Independent ground truth: notAfter epoch per openssl CLI + GNU date.
cert_not_after_epoch() {
    local enddate
    enddate="$(openssl x509 -in "$1" -noout -enddate)"   # notAfter=Jun ...
    date -u -d "${enddate#notAfter=}" +%s
}

info "Generating certs..."
gen_cert a     cert-a.example.test 20300101000000Z rsa
gen_cert rsa   dual.example.test   20310101000000Z rsa
gen_cert ecdsa dual.example.test   20320101000000Z ec
gen_cert multi multi.example.test  20330101000000Z rsa
gen_cert var   var.example.test    20340101000000Z rsa

EXP_A="$(cert_not_after_epoch "${CERTS}/a.crt")"
EXP_RSA="$(cert_not_after_epoch "${CERTS}/rsa.crt")"
EXP_EC="$(cert_not_after_epoch "${CERTS}/ecdsa.crt")"
EXP_MULTI="$(cert_not_after_epoch "${CERTS}/multi.crt")"
info "expected notAfter epochs: a=${EXP_A} rsa=${EXP_RSA} ecdsa=${EXP_EC} multi=${EXP_MULTI}"

# ─── nginx.conf: servers (a)-(d) ─────────────────────────────────────────────

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
        endpoint http://127.0.0.1:24317;   # dead port — config-time test only
    }
    otel_service_name ngx-otel-c2-cert-walk;

    # (d) variable cert path — nginx defers loading to handshake time.
    map \$ssl_server_name \$c2_cert { default "${CERTS}/var.crt"; }
    map \$ssl_server_name \$c2_key  { default "${CERTS}/var.key"; }

    # (a) single RSA cert
    server {
        listen 127.0.0.1:9443 ssl;
        server_name cert-a.example.test;
        ssl_certificate     ${CERTS}/a.crt;
        ssl_certificate_key ${CERTS}/a.key;
        location / { return 200 "a\n"; }
    }

    # (b) DUAL RSA + ECDSA in ONE server block (dual-cert enumeration)
    server {
        listen 127.0.0.1:9444 ssl;
        server_name dual.example.test;
        ssl_certificate     ${CERTS}/rsa.crt;
        ssl_certificate_key ${CERTS}/rsa.key;
        ssl_certificate     ${CERTS}/ecdsa.crt;
        ssl_certificate_key ${CERTS}/ecdsa.key;
        location / { return 200 "b\n"; }
    }

    # (c) wildcard + dot-prefix + literal server_names: first NON-wildcard wins
    server {
        listen 127.0.0.1:9445 ssl;
        server_name *.wild.test .dot.test real.example.test;
        ssl_certificate     ${CERTS}/multi.crt;
        ssl_certificate_key ${CERTS}/multi.key;
        location / { return 200 "c\n"; }
    }

    # (d) \$var cert path → config-time skip NOTICE
    server {
        listen 127.0.0.1:9446 ssl;
        server_name var.example.test;
        ssl_certificate     \$c2_cert;
        ssl_certificate_key \$c2_key;
        location / { return 200 "d\n"; }
    }
}
EOF

# ─── Start ssl-enabled nginx and assert (a)-(d) ──────────────────────────────

info "Starting ssl-enabled nginx..."
# -e: config-time NOTICEs are written via the STARTUP log (cf->log), which the
# conf's own error_log directive does not control; pin it to the same file.
"${NGINX_BINARY}" -e "${PREFIX}/logs/error.log" -p "${PREFIX}" -c "${PREFIX}/nginx.conf" &
NGINX_PID=$!
sleep 1
kill -0 "${NGINX_PID}" 2>/dev/null || { cat "${PREFIX}/logs/error.log" >&2; fail "nginx exited at startup"; }

ERR="${PREFIX}/logs/error.log"

# (a) one cert, exact path + CN + notAfter epoch
grep -qF "otel: cert metrics: certificate path=\"${CERTS}/a.crt\" server=\"cert-a.example.test\" subject_cn=\"cert-a.example.test\" not_after=${EXP_A}" "${ERR}" \
    || fail "(a) expected NOTICE for a.crt (path/CN/not_after=${EXP_A}) not found"
pass "(a) single cert: path + CN + not_after=${EXP_A} exact"

# (b) BOTH certs of the dual RSA+ECDSA block enumerated
grep -qF "certificate path=\"${CERTS}/rsa.crt\" server=\"dual.example.test\" subject_cn=\"dual.example.test\" not_after=${EXP_RSA}" "${ERR}" \
    || fail "(b) RSA cert of dual block not enumerated"
grep -qF "certificate path=\"${CERTS}/ecdsa.crt\" server=\"dual.example.test\" subject_cn=\"dual.example.test\" not_after=${EXP_EC}" "${ERR}" \
    || fail "(b) ECDSA cert of dual block not enumerated"
DUAL_COUNT="$(grep -c "certificate path=.*server=\"dual.example.test\"" "${ERR}")"
[[ "${DUAL_COUNT}" -eq 2 ]] || fail "(b) expected exactly 2 certs for dual block, got ${DUAL_COUNT}"
pass "(b) dual RSA+ECDSA: both certs enumerated (rsa=${EXP_RSA}, ecdsa=${EXP_EC})"

# (c) first non-wildcard server_name recorded
grep -qF "certificate path=\"${CERTS}/multi.crt\" server=\"real.example.test\" subject_cn=\"multi.example.test\" not_after=${EXP_MULTI}" "${ERR}" \
    || fail "(c) expected server=\"real.example.test\" (first non-wildcard) on multi.crt NOTICE"
pass "(c) multi-server_name: first non-wildcard name recorded"

# (d) variable path skipped, nothing enumerated for that server
grep -qF 'otel: cert metrics: skipping variable certificate path "$c2_cert" (server "var.example.test")' "${ERR}" \
    || fail "(d) expected skip NOTICE for \$c2_cert not found"
VAR_ENUM="$(grep -c "certificate path=.*server=\"var.example.test\"" "${ERR}" || true)"
[[ "${VAR_ENUM}" -eq 0 ]] || fail "(d) variable-cert server must have NO enumerated certs, got ${VAR_ENUM}"
pass "(d) \$var cert path: skip NOTICE present, nothing enumerated"

# Whole-run sanity: exactly 4 enumerated certs (a + 2×dual + multi)
TOTAL="$(grep -c "otel: cert metrics: certificate path=" "${ERR}")"
[[ "${TOTAL}" -eq 4 ]] || fail "expected exactly 4 enumerated certs total, got ${TOTAL}"
pass "total enumeration count = 4 (no spurious entries)"

kill -QUIT "${NGINX_PID}" 2>/dev/null || true
wait "${NGINX_PID}" 2>/dev/null || true
NGINX_PID=""

# ─── (e) no-ssl nginx binary ─────────────────────────────────────────────────

NOSSL_BIN="${NO_SSL_NGINX_BINARY:-}"
if [[ -z "${NOSSL_BIN}" ]]; then
    # Build a --with-compat nginx WITHOUT --with-http_ssl_module into scratch.
    # Scratch lives OUTSIDE /tmp (debian-vm /tmp is a small tmpfs).
    SCRATCH="${C2_SCRATCH_DIR:-${REPO_ROOT}/c2-scratch}/objs-nossl"
    NOSSL_BIN="${SCRATCH}/nginx"
    if [[ ! -x "${NOSSL_BIN}" ]]; then
        info "(e) building no-ssl nginx into ${SCRATCH}..."
        mkdir -p "${SCRATCH}"
        # auto/configure rewrites the source-root wrapper Makefile; save/restore
        # so the main checkout's build state is untouched.
        SAVED_MK=""
        if [[ -f "${NGINX_SOURCE_DIR}/Makefile" ]]; then
            SAVED_MK="$(mktemp /tmp/ngx-c2-mk.XXXXXX)"
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
        info "(e) reusing cached no-ssl nginx: ${NOSSL_BIN}"
    fi
fi
[[ -x "${NOSSL_BIN}" ]] || fail "(e) no-ssl nginx binary not available: ${NOSSL_BIN}"

# Sanity: the binary really lacks the ssl module.
if "${NOSSL_BIN}" -V 2>&1 | grep -q "http_ssl_module"; then
    fail "(e) supposed no-ssl binary was built WITH http_ssl_module"
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
        endpoint http://127.0.0.1:24317;   # dead port — config-time test only
    }
    otel_service_name ngx-otel-c2-cert-walk-nossl;

    server {
        listen 127.0.0.1:9448;
        location / { return 200 "nossl\n"; }
    }
}
EOF

info "(e) starting no-ssl nginx with our module..."
# -e: see above — keeps this instance's config-time NOTICEs out of the first
# instance's startup log.
"${NOSSL_BIN}" -e "${PREFIX}/logs/error-nossl.log" -p "${PREFIX}" -c "${PREFIX}/nginx-nossl.conf" &
NOSSL_PID=$!
sleep 1
kill -0 "${NOSSL_PID}" 2>/dev/null \
    || { cat "${PREFIX}/logs/error-nossl.log" >&2; fail "(e) no-ssl nginx exited — module failed to load?"; }

NOSSL_ERR="${PREFIX}/logs/error-nossl.log"
UNAVAIL="$(grep -c "otel: cert metrics unavailable: nginx built without http_ssl_module" "${NOSSL_ERR}")"
[[ "${UNAVAIL}" -eq 1 ]] || fail "(e) expected exactly 1 'unavailable' NOTICE, got ${UNAVAIL}"
NOSSL_ENUM="$(grep -c "otel: cert metrics: certificate path=" "${NOSSL_ERR}" || true)"
[[ "${NOSSL_ENUM}" -eq 0 ]] || fail "(e) no-ssl run must enumerate zero certs, got ${NOSSL_ENUM}"
curl -sf http://127.0.0.1:9448/ | grep -q nossl || fail "(e) no-ssl nginx not serving"
kill -0 "${NOSSL_PID}" 2>/dev/null || fail "(e) no-ssl nginx crashed after startup"
pass "(e) no-ssl binary: module loads, 1 'unavailable' NOTICE, serves, no crash"

kill -QUIT "${NOSSL_PID}" 2>/dev/null || true
wait "${NOSSL_PID}" 2>/dev/null || true
NOSSL_PID=""

echo ""
pass "C2 cert-walk integration: ALL assertions passed (a)-(e)"
