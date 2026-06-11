#!/usr/bin/env bash
# tests/integration/run_h2f5_signal_endpoint_warn.sh — H2F5 nginx -t warning test
#
# Asserts that the per-signal endpoint warning (warn_if_has_authority) fires
# during config parse when a full URL is supplied, and is absent for path-only
# values.
#
# Two cases:
#
#   POSITIVE — metrics_endpoint http://other:9999/v1/metrics
#     nginx -t must emit the warning line to the error.log (warn level set).
#
#   NEGATIVE — metrics_endpoint /v1/metrics  (path-only, no scheme)
#     nginx -t must NOT emit the warning.
#
# Mutation-evidence bar for H2F5 (unit test covers the predicate; this script
# covers the config-level plumbing — that warn_if_has_authority is actually
# wired into the directive handler):
#   Neuter production has_authority (replace with `false`) → POSITIVE case FAILS
#   → restore → PASSES.
#
# Exit codes:
#   0   all assertions passed
#   1   pre-flight / build error
#   2   an assertion failed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPO_ROOT="$(cd "${CRATE_DIR}/.." && pwd)"

CONF_TEMPLATE="${SCRIPT_DIR}/nginx_h2f5_warn.conf"

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

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass()  { echo -e "${GREEN}[PASS]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*" >&2; exit 2; }
info()  { echo -e "${YELLOW}[INFO]${NC} $*"; }

WARN_TEXT="metrics_endpoint contains a host/scheme"

# ─── Pre-flight ───────────────────────────────────────────────────────────────

if [[ ! -x "${NGINX_BINARY}" ]]; then
    echo "ERROR: nginx binary not found at ${NGINX_BINARY:-<unset>}" >&2
    exit 1
fi

# ─── Build ────────────────────────────────────────────────────────────────────

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

# ─── POSITIVE case ───────────────────────────────────────────────────────────
# metrics_endpoint http://other:9999/v1/metrics → warning must appear.

info "--- POSITIVE case: metrics_endpoint http://other:9999/v1/metrics ---"

POS_PREFIX="$(mktemp -d /tmp/ngx-otel-h2f5-pos.XXXXXX)"
_cleanup_pos() { rm -rf "${POS_PREFIX}"; }
trap _cleanup_pos EXIT
mkdir -p "${POS_PREFIX}/logs"

sed \
    -e "s|@MODULE_PATH@|${MODULE_PATH}|g" \
    -e "s|@PREFIX@|${POS_PREFIX}|g" \
    -e "s|@METRICS_EP@|http://other:9999/v1/metrics|g" \
    "${CONF_TEMPLATE}" > "${POS_PREFIX}/nginx.conf"

# nginx -t exits 0 on a valid config (warning does not make it invalid).
# Capture stderr too — ngx_conf_log_error may write there on some builds.
NGINX_T_OUT="$("${NGINX_BINARY}" \
    -p "${POS_PREFIX}" \
    -c "${POS_PREFIX}/nginx.conf" \
    -t 2>&1 || true)"

info "nginx -t stdout+stderr (positive):"
echo "${NGINX_T_OUT}"

# Primary check: error.log (warn-level logging set in conf).
if grep -q "${WARN_TEXT}" "${POS_PREFIX}/logs/error.log" 2>/dev/null; then
    WARN_LINE="$(grep "${WARN_TEXT}" "${POS_PREFIX}/logs/error.log" | head -1)"
    pass "POSITIVE: warning line in error.log: ${WARN_LINE}"
elif echo "${NGINX_T_OUT}" | grep -q "${WARN_TEXT}"; then
    WARN_LINE="$(echo "${NGINX_T_OUT}" | grep "${WARN_TEXT}" | head -1)"
    pass "POSITIVE: warning line in nginx -t output: ${WARN_LINE}"
else
    echo "=== error.log ==="
    cat "${POS_PREFIX}/logs/error.log" 2>/dev/null || echo "(not found)"
    fail "POSITIVE: warning '${WARN_TEXT}' not found in error.log or nginx -t output"
fi

trap - EXIT
rm -rf "${POS_PREFIX}"

# ─── NEGATIVE case ───────────────────────────────────────────────────────────
# metrics_endpoint /v1/metrics (path-only) → warning must NOT appear.

info "--- NEGATIVE case: metrics_endpoint /v1/metrics (path-only) ---"

NEG_PREFIX="$(mktemp -d /tmp/ngx-otel-h2f5-neg.XXXXXX)"
_cleanup_neg() { rm -rf "${NEG_PREFIX}"; }
trap _cleanup_neg EXIT
mkdir -p "${NEG_PREFIX}/logs"

sed \
    -e "s|@MODULE_PATH@|${MODULE_PATH}|g" \
    -e "s|@PREFIX@|${NEG_PREFIX}|g" \
    -e "s|@METRICS_EP@|/v1/metrics|g" \
    "${CONF_TEMPLATE}" > "${NEG_PREFIX}/nginx.conf"

"${NGINX_BINARY}" \
    -p "${NEG_PREFIX}" \
    -c "${NEG_PREFIX}/nginx.conf" \
    -t 2>&1 | tee /dev/stderr || true

if grep -q "${WARN_TEXT}" "${NEG_PREFIX}/logs/error.log" 2>/dev/null; then
    echo "=== error.log (unexpected warning) ==="
    cat "${NEG_PREFIX}/logs/error.log"
    fail "NEGATIVE: spurious warning found for path-only value '/v1/metrics'"
else
    pass "NEGATIVE: no warning for path-only endpoint (error.log clean)"
fi

trap - EXIT
rm -rf "${NEG_PREFIX}"

# ─── Summary ─────────────────────────────────────────────────────────────────

echo ""
pass "H2F5 nginx -t warning test: all assertions passed"
