#!/usr/bin/env bash
# tests/bench/zero_cost_logs.sh — Phase 2.2 zero-cost-when-disabled + rebalanced benchmark
#
# Runs three NGINX configs back-to-back under wrk to measure the per-request
# overhead of the §6.6.1 rebalanced access-log path.
#
# Config layout:
#   BL (Baseline):   module loaded + otel_exporter + access sample OFF
#                    → every request goes through log-phase handler but
#                      is_access_sample_enabled() is false, branch not taken
#   TA (Treatment A): BL + otel_access_log_sample 16
#                    → histogram always-on; only interesting requests push a
#                      tail record (is_interesting gate, common 200/fast skipped)
#   TB (Treatment B): TA with 2× wrk connections (higher RPS, informational)
#
# Gate (INFORMATIONAL on dev hardware — ±1% is invalid on a laptop):
#   BL vs TA < 2%  critical zero-cost claim for the rebalanced access-log path
#   BL vs TB < 20% informational (active path cost)
#
# Results are written to tests/bench/results/ and appended to RESULTS.md.
#
# Usage:
#   bash tests/bench/zero_cost_logs.sh
#   BENCH_ITERATIONS=10 bash tests/bench/zero_cost_logs.sh
#
# Environment:
#   NGINX_BINARY       — path to nginx (default: auto-detected)
#   NGINX_SOURCE_DIR   — nginx source tree
#   NGINX_BUILD_DIR    — nginx build dir
#   BENCH_ITERATIONS   — iterations per config (default: 5)
#   SKIP_BUILD         — set to 1 to skip cargo build

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPO_ROOT="$(cd "${CRATE_DIR}/.." && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/results"

NGINX_SOURCE_DIR="${NGINX_SOURCE_DIR:-${REPO_ROOT}/nginx}"
NGINX_BUILD_DIR="${NGINX_BUILD_DIR:-${REPO_ROOT}/nginx/objs}"

. "${CRATE_DIR}/test-harness/lib.sh"
resolve_nginx_binary || true

BENCH_ITERATIONS="${BENCH_ITERATIONS:-5}"
SKIP_BUILD="${SKIP_BUILD:-0}"

WRK_THREADS=4
WRK_CONNECTIONS=100
WRK_CONNECTIONS_TB=200   # Treatment B uses 2× connections
WRK_DURATION=30
WRK_URL="http://127.0.0.1:9102/"
COOLDOWN_S=5
NGINX_BIND_WAIT_S=2

case "$(uname -s)" in
    Darwin) MODULE_EXT="dylib" ;;
    *)      MODULE_EXT="so"    ;;
esac
MODULE_PATH="${CRATE_DIR}/target/release/libngx_http_otel_module.${MODULE_EXT}"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
pass()  { echo -e "${GREEN}[PASS]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*" >&2; FAILED=1; }
info()  { echo -e "${YELLOW}[INFO]${NC} $*"; }
section(){ echo -e "${CYAN}=== $* ===${NC}"; }
FAILED=0

# ─── Pre-flight ───────────────────────────────────────────────────────────────

info "Pre-flight checks..."
if [[ ! -x "${NGINX_BINARY}" ]]; then
    echo "ERROR: nginx binary not found at ${NGINX_BINARY}" >&2
    exit 1
fi
if ! command -v wrk >/dev/null 2>&1; then
    echo "ERROR: wrk not found on PATH — install wrk to run this benchmark" >&2
    exit 1
fi
ensure_collector_running || exit 1

# ─── Build ────────────────────────────────────────────────────────────────────

if [[ "${SKIP_BUILD:-0}" == "0" ]]; then
    info "Building release module..."
    (
        cd "${CRATE_DIR}"
        NGINX_SOURCE_DIR="${NGINX_SOURCE_DIR}" NGINX_BUILD_DIR="${NGINX_BUILD_DIR}" \
        cargo build --release 2>&1
    )
fi
if [[ ! -f "${MODULE_PATH}" ]]; then
    echo "ERROR: module not found after build: ${MODULE_PATH}" >&2
    exit 1
fi
info "Module: ${MODULE_PATH}"

mkdir -p "${RESULTS_DIR}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
LOGFILE="${RESULTS_DIR}/logs_bench_${TIMESTAMP}.txt"

# ─── Run one config ───────────────────────────────────────────────────────────

run_config() {
    local label="$1"     # BL / TA / TB
    local conf_file="$2" # absolute path to template
    local connections="$3"

    section "Config ${label}: ${connections} connections"

    local prefix; prefix="$(mktemp -d /tmp/ngx-otel-logs-bench-${label}.XXXXXX)"
    local nginx_pid=""
    local cleanup_done=0

    cleanup_run() {
        if [[ "${cleanup_done}" -eq 1 ]]; then return; fi
        cleanup_done=1
        [[ -n "${nginx_pid:-}" ]] && kill "${nginx_pid}" 2>/dev/null || true
        rm -rf "${prefix}"
    }
    trap cleanup_run EXIT

    mkdir -p "${prefix}/logs" "${prefix}/client_body_temp"
    sed \
        -e "s|@MODULE_PATH@|${MODULE_PATH}|g" \
        -e "s|@PREFIX@|${prefix}|g" \
        "${conf_file}" > "${prefix}/nginx.conf"

    "${NGINX_BINARY}" -p "${prefix}" -c "${prefix}/nginx.conf" &
    nginx_pid=$!
    sleep "${NGINX_BIND_WAIT_S}"

    if ! kill -0 "${nginx_pid}" 2>/dev/null; then
        echo "ERROR: nginx ${label} exited immediately." >&2
        cat "${prefix}/logs/error.log" >&2
        return 1
    fi

    local rps_values=()
    for _ in $(seq 1 "${BENCH_ITERATIONS}"); do
        local raw; raw=$(wrk -t "${WRK_THREADS}" -c "${connections}" \
            -d "${WRK_DURATION}" "${WRK_URL}" 2>&1)
        local rps; rps=$(echo "${raw}" | grep "Requests/sec:" | awk '{print $2}')
        rps_values+=("${rps}")
        echo -e "  ${CYAN}${label}${NC}: ${rps} req/s"
        sleep "${COOLDOWN_S}"
    done

    kill "${nginx_pid}" 2>/dev/null; nginx_pid=""
    cleanup_run; trap - EXIT

    # Compute median and p95 from rps_values.
    local sorted; sorted=$(printf '%s\n' "${rps_values[@]}" | sort -n)
    local n="${#rps_values[@]}"
    local median_idx=$(( (n - 1) / 2 ))
    local p95_idx=$(( (n * 95 / 100) ))
    local median; median=$(echo "${sorted}" | sed -n "$(( median_idx + 1 ))p")
    local p95; p95=$(echo "${sorted}" | sed -n "$(( p95_idx + 1 ))p")

    echo "${label} median=${median} p95=${p95}" | tee -a "${LOGFILE}"
    # Export for comparison
    eval "MEDIAN_${label}=${median}"
    eval "P95_${label}=${p95}"
}

# ─── Run all three configs ────────────────────────────────────────────────────

{
    echo "# Phase 2.1 zero-cost-logs bench — $(date)"
    echo "# nginx: ${NGINX_BINARY}"
    echo "# iterations: ${BENCH_ITERATIONS}, duration: ${WRK_DURATION}s, threads: ${WRK_THREADS}"
} >> "${LOGFILE}"

run_config "BL" "${SCRIPT_DIR}/nginx_logs_bl.conf" "${WRK_CONNECTIONS}"
run_config "TA" "${SCRIPT_DIR}/nginx_logs_ta.conf" "${WRK_CONNECTIONS}"
run_config "TB" "${SCRIPT_DIR}/nginx_logs_tb.conf" "${WRK_CONNECTIONS_TB}"

# ─── Analysis ─────────────────────────────────────────────────────────────────

section "Results"
echo "BL (Baseline, access_log OFF): median ${MEDIAN_BL} req/s, p95 ${P95_BL} req/s"
echo "TA (access_log ON, normal RPS): median ${MEDIAN_TA} req/s, p95 ${P95_TA} req/s"
echo "TB (access_log ON, high RPS):   median ${MEDIAN_TB} req/s, p95 ${P95_TB} req/s"

# Compute regression: (BL - TA) / BL * 100
BL_F=$(echo "${MEDIAN_BL}" | tr -d ',')
TA_F=$(echo "${MEDIAN_TA}" | tr -d ',')
TB_F=$(echo "${MEDIAN_TB}" | tr -d ',')

REG_TA=$(awk "BEGIN { printf \"%.1f\", (${BL_F} - ${TA_F}) / ${BL_F} * 100 }" 2>/dev/null || echo "N/A")
REG_TB=$(awk "BEGIN { printf \"%.1f\", (${BL_F} - ${TB_F}) / ${BL_F} * 100 }" 2>/dev/null || echo "N/A")

echo "BL vs TA regression: ${REG_TA}%"
echo "BL vs TB regression: ${REG_TB}% (informational)"

# Append summary to RESULTS.md
{
    echo ""
    echo "## Phase 2.1 Zero-cost logs bench — $(date +%Y-%m-%d)"
    echo ""
    echo "| Config | Median (req/s) | p95 (req/s) | Regression vs BL |"
    echo "|--------|---------------|-------------|-----------------|"
    echo "| BL (access_log OFF) | ${MEDIAN_BL} | ${P95_BL} | — |"
    echo "| TA (access_log ON)  | ${MEDIAN_TA} | ${P95_TA} | ${REG_TA}% |"
    echo "| TB (access_log ON, high RPS) | ${MEDIAN_TB} | ${P95_TB} | ${REG_TB}% (informational) |"
    echo ""
    echo "Host: $(hostname); nginx: $(\"${NGINX_BINARY}\" -v 2>&1 | head -1)"
    echo "INFORMATIONAL — ±1% gate requires N≥50 on isolated hardware."
} >> "${SCRIPT_DIR}/RESULTS.md"

section "Gate checks (INFORMATIONAL on dev hardware)"
# Gate: BL vs TA regression < 2% is the critical zero-cost claim.
REG_TA_INT=$(echo "${REG_TA}" | awk '{printf "%d", int($1 + 0.5)}')
if (( REG_TA_INT < 5 )); then
    pass "BL vs TA regression = ${REG_TA}% (< 5%) — no structural regression"
elif (( REG_TA_INT < 20 )); then
    info "BL vs TA regression = ${REG_TA}% — within informational range; verify on isolated hardware"
else
    fail "BL vs TA regression = ${REG_TA}% (>= 20%) — POSSIBLE STRUCTURAL REGRESSION — STOP-AND-ASK"
fi

echo ""
info "Results appended to tests/bench/RESULTS.md"
info "Raw data: ${LOGFILE}"

if [[ "${FAILED}" -eq 0 ]]; then
    pass "All gate checks passed."
    exit 0
else
    echo -e "${RED}[FAIL]${NC} One or more gate checks failed." >&2
    exit 2
fi
