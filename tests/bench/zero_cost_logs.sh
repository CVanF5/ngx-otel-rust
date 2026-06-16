#!/usr/bin/env bash
# tests/bench/zero_cost_logs.sh — zero-cost-when-disabled + rebalanced access/error-log benchmark
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
# FU5: bench must use the RELEASE binary (for accurate throughput measurement).
# Prefer objs-release/nginx; fall back to objs-debug only if release is absent.
if [[ -x "${CRATE_DIR}/objs-release/nginx" ]]; then
    NGINX_BUILD_DIR="${NGINX_BUILD_DIR:-${CRATE_DIR}/objs-release}"
    NGINX_BINARY="${NGINX_BINARY:-${CRATE_DIR}/objs-release/nginx}"
else
    NGINX_BUILD_DIR="${NGINX_BUILD_DIR:-${REPO_ROOT}/nginx/objs}"
fi

. "${CRATE_DIR}/test-harness/lib.sh"
resolve_nginx_binary || true

# Confirm we're using a real executable (not a stale path).
if [[ ! -x "${NGINX_BINARY}" ]]; then
    echo "ERROR: NGINX_BINARY not executable: ${NGINX_BINARY}" >&2
    exit 1
fi

BENCH_ITERATIONS="${BENCH_ITERATIONS:-5}"
SKIP_BUILD="${SKIP_BUILD:-0}"

WRK_THREADS=4
WRK_CONNECTIONS=100
WRK_CONNECTIONS_TB=200   # Treatment B uses 2× connections
WRK_DURATION=30
WRK_URL="http://127.0.0.1:9102/"
WRK_URL_TD="http://127.0.0.1:9103/flood"  # Treatment D: flood → 502s
COOLDOWN_S=5
NGINX_BIND_WAIT_S=2

case "$(uname -s)" in
    Darwin) MODULE_EXT="dylib" ;;
    *)      MODULE_EXT="so"    ;;
esac
# When CARGO_BUILD_TARGET is set (e.g., the TSAN gate uses --target so cargo
# can also -Zbuild-std), cargo writes its output to target/<triple>/release/
# rather than target/release/.  Backwards-compatible: unset -> original path.
if [[ -n "${CARGO_BUILD_TARGET:-}" ]]; then
    MODULE_PATH="${CRATE_DIR}/target/${CARGO_BUILD_TARGET}/release/libngx_http_otel_module.${MODULE_EXT}"
else
    MODULE_PATH="${CRATE_DIR}/target/release/libngx_http_otel_module.${MODULE_EXT}"
fi

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
    local label="$1"     # BL / TA / TB / TC / TD
    local conf_file="$2" # absolute path to template
    local connections="$3"
    local url="${4:-${WRK_URL}}"  # optional URL override (Treatment D uses /flood)

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
            -d "${WRK_DURATION}" "${url}" 2>&1 || true)  # || true: wrk exits non-zero on 5xx (TD)
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
    echo "# Phase 2.2 zero-cost-logs bench — $(date)"
    echo "# nginx: ${NGINX_BINARY}"
    echo "# iterations: ${BENCH_ITERATIONS}, duration: ${WRK_DURATION}s, threads: ${WRK_THREADS}"
} >> "${LOGFILE}"

run_config "BL" "${SCRIPT_DIR}/nginx_logs_bl.conf" "${WRK_CONNECTIONS}"
run_config "TA" "${SCRIPT_DIR}/nginx_logs_ta.conf" "${WRK_CONNECTIONS}"
run_config "TB" "${SCRIPT_DIR}/nginx_logs_tb.conf" "${WRK_CONNECTIONS_TB}"
# Error-log treatments (TC/TD):
# TC: otel_error_log on, no errors → idle writer (zero-cost claim for error path)
# TD: otel_error_log on, /flood → every request generates proxy error (flood cost)
run_config "TC" "${SCRIPT_DIR}/nginx_logs_tc.conf" "${WRK_CONNECTIONS}"
run_config "TD" "${SCRIPT_DIR}/nginx_logs_td.conf" "${WRK_CONNECTIONS}" "${WRK_URL_TD}"

# ─── Analysis ─────────────────────────────────────────────────────────────────

section "Results"
echo "BL (Baseline, access_log OFF):            median ${MEDIAN_BL} req/s, p95 ${P95_BL} req/s"
echo "TA (access_log ON, normal RPS):            median ${MEDIAN_TA} req/s, p95 ${P95_TA} req/s"
echo "TB (access_log ON, high RPS):              median ${MEDIAN_TB} req/s, p95 ${P95_TB} req/s"
echo "TC (error_log ON, no errors — idle):       median ${MEDIAN_TC} req/s, p95 ${P95_TC} req/s"
echo "TD (error_log ON, flood errors — active):  median ${MEDIAN_TD} req/s, p95 ${P95_TD} req/s"

# Compute regression: (BL - TA) / BL * 100
BL_F=$(echo "${MEDIAN_BL}" | tr -d ',')
TA_F=$(echo "${MEDIAN_TA}" | tr -d ',')
TB_F=$(echo "${MEDIAN_TB}" | tr -d ',')
TC_F=$(echo "${MEDIAN_TC}" | tr -d ',')
TD_F=$(echo "${MEDIAN_TD}" | tr -d ',')

REG_TA=$(awk "BEGIN { printf \"%.1f\", (${BL_F} - ${TA_F}) / ${BL_F} * 100 }" 2>/dev/null || echo "N/A")
REG_TB=$(awk "BEGIN { printf \"%.1f\", (${BL_F} - ${TB_F}) / ${BL_F} * 100 }" 2>/dev/null || echo "N/A")
REG_TC=$(awk "BEGIN { printf \"%.1f\", (${BL_F} - ${TC_F}) / ${BL_F} * 100 }" 2>/dev/null || echo "N/A")
REG_TD=$(awk "BEGIN { printf \"%.1f\", (${BL_F} - ${TD_F}) / ${BL_F} * 100 }" 2>/dev/null || echo "N/A")

echo "BL vs TA regression: ${REG_TA}%"
echo "BL vs TB regression: ${REG_TB}% (informational)"
echo "BL vs TC regression: ${REG_TC}% (error_log idle — zero-cost claim)"
echo "BL vs TD regression: ${REG_TD}% (error_log flood — active path, informational)"

# Append summary to RESULTS.md
{
    echo ""
    echo "## Phase 2.2 + 2.3 Zero-cost logs bench — $(date +%Y-%m-%d)"
    echo ""
    echo "> ⚠️ **DEV-BOX SMOKE ONLY** — these numbers are INFORMATIONAL."
    echo "> The ±1% zero-cost gate and the 'enabled path is cheaper' proof"
    echo "> run **only on host-1** (the dedicated c7a EPYC), N≥50."
    echo "> See RALPH_PHASE_2_2.md Step 2.2.6 and RALPH_PHASE_2_3.md Step 2.3.8."
    echo ""
    echo "| Config | Median (req/s) | p95 (req/s) | Regression vs BL |"
    echo "|--------|---------------|-------------|-----------------|"
    echo "| BL (sample OFF, histogram always-on) | ${MEDIAN_BL} | ${P95_BL} | — |"
    echo "| TA (otel_access_log_sample 16) | ${MEDIAN_TA} | ${P95_TA} | ${REG_TA}% |"
    echo "| TB (otel_access_log_sample 16, high RPS) | ${MEDIAN_TB} | ${P95_TB} | ${REG_TB}% (informational) |"
    echo "| TC (otel_error_log warn, no errors — idle writer) | ${MEDIAN_TC} | ${P95_TC} | ${REG_TC}% |"
    echo "| TD (otel_error_log warn, flood → 502 — active writer) | ${MEDIAN_TD} | ${P95_TD} | ${REG_TD}% (informational) |"
    echo ""
    echo "Host: $(hostname); nginx: $(\"${NGINX_BINARY}\" -v 2>&1 | head -1)"
    echo "INFORMATIONAL — ±1% gate requires N≥50 on isolated hardware (host-1 / c7a EPYC)."
} >> "${SCRIPT_DIR}/RESULTS.md"

section "Structural-sentinel checks (dev box: functional smoke only — no timing verdicts)"
#
# On the dev box (macOS laptop / co-located VM) ±1% timing is invalid.
# These checks are STRUCTURAL SENTINELS only:
#   < 20%  → neutral smoke; real timing verdict deferred to host-1 (c7a EPYC)
#   ≥ 20%  → hard fail: something is catastrophically broken (stop and investigate)
#
# No green [PASS] is emitted for any below-threshold result.
# A green pass requires N≥50 on isolated hardware (host-1).

REG_TA_INT=$(echo "${REG_TA}" | awk '{printf "%d", int($1 + 0.5)}')
if (( REG_TA_INT < 20 )); then
    info "BL vs TA regression = ${REG_TA}% — functional smoke: output well-formed (timing verdict deferred to host-1)"
else
    fail "BL vs TA regression = ${REG_TA}% (>= 20%) — POSSIBLE STRUCTURAL REGRESSION — STOP-AND-ASK"
fi

REG_TC_INT=$(echo "${REG_TC}" | awk '{printf "%d", int($1 + 0.5)}')
if (( REG_TC_INT < 20 )); then
    info "BL vs TC regression = ${REG_TC}% — functional smoke: output well-formed (timing verdict deferred to host-1)"
else
    fail "BL vs TC regression = ${REG_TC}% (>= 20%) — POSSIBLE STRUCTURAL REGRESSION — STOP-AND-ASK"
fi

echo ""
info "Results appended to tests/bench/RESULTS.md"
info "Raw data: ${LOGFILE}"

if [[ "${FAILED}" -eq 0 ]]; then
    info "Functional smoke complete — no structural regressions detected (timing verdict deferred to host-1 / c7a EPYC)."
    exit 0
else
    echo -e "${RED}[FAIL]${NC} One or more structural-sentinel checks failed." >&2
    exit 2
fi
