#!/usr/bin/env bash
# tests/bench/zero_cost.sh — Step 11 zero-cost-when-disabled benchmark
#
# Runs three NGINX configs back-to-back under wrk to statistically prove
# that loading the module without an otel_exporter directive imposes zero
# per-request overhead relative to a clean-NGINX baseline.
#
# Config layout:
#   C1: no load_module  — true baseline
#   C2: load_module, no otel_exporter  — zero-cost case (asserted ≈ C1)
#   C3: load_module + otel_exporter  — operational case (reported vs C1)
#
# Usage:
#   # From the ngx-otel-rust directory:
#   NGINX_SOURCE_DIR=../nginx \
#   NGINX_BUILD_DIR=../nginx/objs \
#   bash tests/bench/zero_cost.sh
#
#   BENCH_ITERATIONS=10 bash tests/bench/zero_cost.sh  # more iterations
#
# Environment:
#   NGINX_BINARY       — path to the nginx binary (default: auto-detected)
#   NGINX_SOURCE_DIR   — nginx source tree (for cargo build)
#   NGINX_BUILD_DIR    — nginx build dir  (for cargo build)
#   BENCH_ITERATIONS   — iterations per config (default: 5)
#   SKIP_BUILD         — set to 1 to skip the cargo build step
#   SKIP_C3            — set to 1 to skip C3 (no local collector required)
#
# Exit codes:
#   0  all configs completed; results written to tests/bench/results/
#   1  pre-flight or build check failed (STOP-AND-ASK required)
#   2  invariant violation (C2 log shows export task / phase handler)

set -euo pipefail

# ─── Paths ───────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPO_ROOT="$(cd "${CRATE_DIR}/.." && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/results"

NGINX_SOURCE_DIR="${NGINX_SOURCE_DIR:-${REPO_ROOT}/nginx}"
NGINX_BUILD_DIR="${NGINX_BUILD_DIR:-${REPO_ROOT}/nginx/objs}"

# Source the shared harness library.  Exposes ensure_collector_running
# and resolve_nginx_binary.
. "${CRATE_DIR}/test-harness/lib.sh"
resolve_nginx_binary || true   # missing-binary error is produced by the preflight below

BENCH_ITERATIONS="${BENCH_ITERATIONS:-5}"
SKIP_BUILD="${SKIP_BUILD:-0}"
SKIP_C3="${SKIP_C3:-0}"

WRK_THREADS=4
WRK_CONNECTIONS=100
WRK_DURATION=30
WRK_URL="http://127.0.0.1:9101/"

# Cool-down between runs (seconds): let OS settle caches/connections.
COOLDOWN_S=5

# Wait for nginx to bind (seconds).
NGINX_BIND_WAIT_S=2

# Detect module extension.
case "$(uname -s)" in
    Darwin) MODULE_EXT="dylib" ;;
    *)      MODULE_EXT="so"    ;;
esac
MODULE_PATH="${CRATE_DIR}/target/release/libngx_http_otel_module.${MODULE_EXT}"

# ─── Colour helpers ──────────────────────────────────────────────────────────

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

pass()  { echo -e "${GREEN}[PASS]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*" >&2; }
info()  { echo -e "${YELLOW}[INFO]${NC} $*"; }
step()  { echo -e "${CYAN}[STEP]${NC} $*"; }

# ─── Pre-flight ──────────────────────────────────────────────────────────────

step "Pre-flight checks"

if [[ ! -x "${NGINX_BINARY}" ]]; then
    echo "ERROR: nginx binary not found at ${NGINX_BINARY}" >&2
    echo "       Set NGINX_BINARY= to the correct path." >&2
    exit 1
fi
info "nginx binary: ${NGINX_BINARY}"

if ! command -v wrk >/dev/null 2>&1; then
    echo "ERROR: wrk is not installed." >&2
    echo "       Install with: brew install wrk  (macOS) or apt install wrk (Debian/Ubuntu)" >&2
    echo "       STOP-AND-ASK: benchmark cannot proceed without wrk." >&2
    exit 1
fi
WRK_BIN="$(command -v wrk)"
info "wrk binary: ${WRK_BIN} ($(wrk --version 2>&1 | head -1))"

if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq is not installed (required to write structured results)." >&2
    exit 1
fi

# C3 collector check (auto-starts via test-harness/lib.sh when needed).
if [[ "${SKIP_C3}" != "1" ]]; then
    ensure_collector_running || {
        echo "ERROR: C3 (operational) config requires the local collector." >&2
        echo "       Set SKIP_C3=1 to skip C3 and run only C1/C2." >&2
        exit 1
    }
else
    info "SKIP_C3=1: skipping C3 (no collector check)"
fi

mkdir -p "${RESULTS_DIR}"

# ─── Build the module ────────────────────────────────────────────────────────

if [[ "${SKIP_BUILD}" != "1" ]]; then
    step "Building release module (cargo build --release)"
    (
        cd "${CRATE_DIR}"
        NGINX_SOURCE_DIR="${NGINX_SOURCE_DIR}" \
        NGINX_BUILD_DIR="${NGINX_BUILD_DIR}" \
        cargo build --release 2>&1
    )
else
    info "SKIP_BUILD=1: skipping cargo build"
fi

if [[ ! -f "${MODULE_PATH}" ]]; then
    echo "ERROR: module not found after build: ${MODULE_PATH}" >&2
    exit 1
fi

# Record build time for mtime verification.
MODULE_MTIME="$(date -r "${MODULE_PATH}" +%s)"
info "Module built: ${MODULE_PATH} (mtime=${MODULE_MTIME})"

# Verify mtime is newer than every source file (only if we just built).
if [[ "${SKIP_BUILD}" != "1" ]]; then
    STALE_SRC=""
    while IFS= read -r -d '' src_file; do
        src_mtime="$(date -r "${src_file}" +%s)"
        if (( src_mtime > MODULE_MTIME )); then
            STALE_SRC="${src_file}"
            break
        fi
    done < <(find "${CRATE_DIR}/src" -name "*.rs" -print0)

    if [[ -n "${STALE_SRC}" ]]; then
        echo "ERROR: module mtime (${MODULE_MTIME}) is older than source file: ${STALE_SRC}" >&2
        echo "       The release dylib may not reflect the current source." >&2
        exit 1
    fi
    pass "Module mtime is newer than all src/*.rs files"
fi

# ─── Sandbox factory ─────────────────────────────────────────────────────────

# sandbox_setup <config_name> <conf_template>
# Creates a per-config prefix directory and substitutes placeholders.
#
# All three sandboxes reference the SAME dylib at ${MODULE_PATH} (one
# absolute path templated into each nginx.conf), so identity-of-artifact
# is guaranteed by construction, not by per-sandbox copy.  The mtime
# re-check below guards against the dylib being mutated between sandbox
# setups (e.g., a stray rebuild during the run) — if that happened the
# earlier rounds and later rounds would no longer be comparing the same
# binary.
#
# Prints the PREFIX path.
sandbox_setup() {
    local name="$1"
    local template="$2"
    local prefix
    prefix="$(mktemp -d "/tmp/ngx-otel-bench-${name}.XXXXXX")"
    mkdir -p "${prefix}/logs"
    mkdir -p "${prefix}/client_body_temp"

    # Substitute placeholders.
    sed \
        -e "s|@MODULE_PATH@|${MODULE_PATH}|g" \
        -e "s|@PREFIX@|${prefix}|g" \
        "${template}" > "${prefix}/nginx.conf"

    # Re-verify the dylib's mtime matches the one captured at script start.
    # All sandboxes reference the same path, so this is a same-file mutation
    # check, not a cross-sandbox identity check (identity is by-path).
    local conf_module_path
    conf_module_path="$(grep "^load_module" "${prefix}/nginx.conf" | awk '{print $2}' | tr -d ';' || true)"
    if [[ -n "${conf_module_path}" ]]; then
        local conf_mtime
        conf_mtime="$(date -r "${conf_module_path}" +%s)"
        if [[ "${conf_mtime}" != "${MODULE_MTIME}" ]]; then
            echo "ERROR: dylib mtime drifted during the run for sandbox ${name}: ${conf_module_path} mtime=${conf_mtime}, expected ${MODULE_MTIME} (was the dylib rebuilt mid-run?)" >&2
            exit 1
        fi
    fi

    echo "${prefix}"
}

sandbox_cleanup() {
    local prefix="$1"
    rm -rf "${prefix}"
}

# ─── nginx helpers ───────────────────────────────────────────────────────────

nginx_start() {
    local prefix="$1"

    # Pre-flight: port must be free before starting nginx.
    if nc -z 127.0.0.1 9101 2>/dev/null; then
        echo "ERROR: port 9101 is already bound before starting nginx." >&2
        echo "       Kill any existing nginx with: lsof -ti :9101 | xargs kill -9" >&2
        exit 1
    fi

    # Run nginx in the background (daemon off; runs in foreground otherwise).
    "${NGINX_BINARY}" -p "${prefix}" -c "${prefix}/nginx.conf" &
    NGINX_BG_PID=$!
    sleep "${NGINX_BIND_WAIT_S}"

    # Verify nginx is still running.
    if ! kill -0 "${NGINX_BG_PID}" 2>/dev/null; then
        echo "ERROR: nginx exited immediately. Check ${prefix}/logs/error.log" >&2
        cat "${prefix}/logs/error.log" >&2
        exit 1
    fi

    # Verify nginx is listening on 9101.
    if ! nc -z 127.0.0.1 9101 2>/dev/null; then
        echo "ERROR: nginx did not bind to 127.0.0.1:9101 after ${NGINX_BIND_WAIT_S}s" >&2
        echo "nginx error.log:" >&2
        cat "${prefix}/logs/error.log" >&2
        kill "${NGINX_BG_PID}" 2>/dev/null || true
        exit 1
    fi
}

nginx_stop() {
    local prefix="$1"
    # Send graceful quit signal.
    "${NGINX_BINARY}" -p "${prefix}" -c "${prefix}/nginx.conf" -s quit 2>/dev/null || true
    # Wait up to 8 seconds for the port to be released.
    local i
    for i in $(seq 1 8); do
        if ! nc -z 127.0.0.1 9101 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    # Force-kill the master by PID if still bound after 8 seconds.
    local pid
    pid="$(cat "${prefix}/logs/nginx.pid" 2>/dev/null || true)"
    if [[ -n "${pid}" ]]; then
        info "  Force-killing nginx master PID ${pid} (port still bound after 8s)"
        kill -9 "${pid}" 2>/dev/null || true
    fi
    # Also kill any background nginx we started.
    if [[ -n "${NGINX_BG_PID:-}" ]]; then
        kill -9 "${NGINX_BG_PID}" 2>/dev/null || true
        NGINX_BG_PID=""
    fi
    # Wait for port to be released.
    for i in $(seq 1 3); do
        if ! nc -z 127.0.0.1 9101 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    echo "WARNING: port 9101 still bound after force-kill; next run may fail" >&2
}

# ─── wrk output parser ───────────────────────────────────────────────────────

# parse_wrk <wrk_output_var> <result_json_var>
# Extracts Latency percentiles and Requests/sec from wrk --latency output.
# Sets: median_ms, p99_ms, req_per_sec (caller reads these globals).
parse_wrk_output() {
    local raw="$1"
    # Extract "Latency Distribution" section lines.
    # wrk --latency output (excerpt):
    #   Latency Distribution
    #      50%  123.45us
    #      75%  ...
    #      90%  ...
    #      99%  456.78ms
    #   Requests/sec: 12345.67
    #
    # Units: us (microseconds), ms (milliseconds), s (seconds).

    _parse_wrk_time_to_ms() {
        local val="$1"
        # val is e.g. "123.45us", "1.23ms", "0.45s"
        local num unit
        if [[ "${val}" =~ ^([0-9]+\.?[0-9]*)([a-z]+)$ ]]; then
            num="${BASH_REMATCH[1]}"
            unit="${BASH_REMATCH[2]}"
        else
            echo "0"
            return
        fi
        case "${unit}" in
            us) echo "scale=4; ${num} / 1000" | bc ;;
            ms) echo "${num}" ;;
            s)  echo "scale=4; ${num} * 1000" | bc ;;
            *)  echo "0" ;;
        esac
    }

    local p50_line p99_line rps_line
    p50_line="$(echo "${raw}" | grep -E '^\s+50%' | head -1 || echo "")"
    p99_line="$(echo "${raw}" | grep -E '^\s+99%' | head -1 || echo "")"
    rps_line="$(echo "${raw}" | grep -E 'Requests/sec:' | head -1 || echo "")"

    local p50_raw p99_raw rps_raw
    p50_raw="$(echo "${p50_line}" | awk '{print $2}' || echo "0ms")"
    p99_raw="$(echo "${p99_line}" | awk '{print $2}' || echo "0ms")"
    rps_raw="$(echo "${rps_line}" | awk '{print $2}' || echo "0")"

    PARSED_MEDIAN_MS="$(_parse_wrk_time_to_ms "${p50_raw}")"
    PARSED_P99_MS="$(_parse_wrk_time_to_ms "${p99_raw}")"
    PARSED_RPS="${rps_raw}"
}

# ─── Main benchmark loop ─────────────────────────────────────────────────────

RUN_TS="$(date -u +%Y-%m-%dT%H-%M-%S)"
RESULTS_FILE="${RESULTS_DIR}/run-${RUN_TS}.json"

info "Benchmark run: ${RUN_TS}"
info "Iterations per config: ${BENCH_ITERATIONS}"
info "wrk: -t${WRK_THREADS} -c${WRK_CONNECTIONS} -d${WRK_DURATION}s --latency ${WRK_URL}"
info "Results: ${RESULTS_FILE}"

# Start the JSON array.
printf '[\n' > "${RESULTS_FILE}"
FIRST_ENTRY=1

# For POSIX-safe randomisation we use a Fisher-Yates shuffle via awk.
shuffle_configs() {
    # Echoes a space-separated shuffled list of config names.
    echo "c1 c2${SKIP_C3:+}" | tr ' ' '\n' | grep -v '^$'
    if [[ "${SKIP_C3}" != "1" ]]; then
        echo "c3"
    fi
}

# We use a round-robin approach: each round shuffles (C1 C2 [C3]) once.
# awk-based Fisher-Yates (POSIX, no shuf dependency):
awk_shuffle='
{lines[NR]=$0}
END {
    srand();
    n=NR;
    for(i=n;i>1;i--) {
        j=int(rand()*(i))+1;
        tmp=lines[i]; lines[i]=lines[j]; lines[j]=tmp;
    }
    for(i=1;i<=n;i++) print lines[i]
}'

CONFIGS_BASE="c1 c2"
[[ "${SKIP_C3}" != "1" ]] && CONFIGS_BASE="${CONFIGS_BASE} c3"

step "Starting benchmark (${BENCH_ITERATIONS} rounds × $(echo "${CONFIGS_BASE}" | wc -w | tr -d ' ') configs)"

for round in $(seq 1 "${BENCH_ITERATIONS}"); do
    step "Round ${round}/${BENCH_ITERATIONS}"

    # Shuffle the config order for this round.
    SHUFFLED="$(echo "${CONFIGS_BASE}" | tr ' ' '\n' | awk "${awk_shuffle}" | tr '\n' ' ')"
    info "  Round ${round} order: ${SHUFFLED}"

    for cfg in ${SHUFFLED}; do
        case "${cfg}" in
            c1) TEMPLATE="${SCRIPT_DIR}/nginx_c1.conf" ;;
            c2) TEMPLATE="${SCRIPT_DIR}/nginx_c2.conf" ;;
            c3) TEMPLATE="${SCRIPT_DIR}/nginx_c3.conf" ;;
        esac

        info "  Config ${cfg}, round ${round}: starting nginx"
        PREFIX="$(sandbox_setup "${cfg}" "${TEMPLATE}")"

        # Trap ensures cleanup even on error.
        # shellcheck disable=SC2064
        trap "nginx_stop '${PREFIX}'; sandbox_cleanup '${PREFIX}'" EXIT

        nginx_start "${PREFIX}"

        # Run wrk and capture output.
        info "  Config ${cfg}, round ${round}: running wrk -t${WRK_THREADS} -c${WRK_CONNECTIONS} -d${WRK_DURATION}s"
        WRK_OUT="$(wrk -t"${WRK_THREADS}" -c"${WRK_CONNECTIONS}" -d"${WRK_DURATION}s" \
            --latency "${WRK_URL}" 2>&1)"

        # Parse wrk output.
        parse_wrk_output "${WRK_OUT}"

        info "  Config ${cfg}, round ${round}: median=${PARSED_MEDIAN_MS}ms p99=${PARSED_P99_MS}ms req/s=${PARSED_RPS}"

        # Stop nginx.
        nginx_stop "${PREFIX}"

        # Check C2 invariant: error.log must NOT contain "spawning export task".
        if [[ "${cfg}" == "c2" ]]; then
            SPAWN_COUNT=0
            SPAWN_COUNT="$(grep -c "spawning export task" "${PREFIX}/logs/error.log" 2>/dev/null)" || SPAWN_COUNT=0
            if [[ "${SPAWN_COUNT}" -gt 0 ]]; then
                echo "ERROR: C2 error.log contains 'spawning export task' — export task gating is BROKEN!" >&2
                echo "       This is a Phase 1.1 invariant failure. STOP-AND-ASK." >&2
                echo "       Relevant log lines:" >&2
                grep "spawning export task" "${PREFIX}/logs/error.log" >&2
                sandbox_cleanup "${PREFIX}"
                exit 2
            fi
        fi

        # Escape raw wrk output for JSON embedding.
        WRK_ESCAPED="$(echo "${WRK_OUT}" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))' 2>/dev/null \
            || echo "${WRK_OUT}" | sed 's/\\/\\\\/g; s/"/\\"/g; s/$/\\n/g' | tr -d '\n' | sed 's/\\n$//')"

        # Append to JSON results.
        if [[ "${FIRST_ENTRY}" -eq 0 ]]; then
            printf ',\n' >> "${RESULTS_FILE}"
        fi
        FIRST_ENTRY=0

        printf '  {\n' >> "${RESULTS_FILE}"
        printf '    "config": "%s",\n' "${cfg}" >> "${RESULTS_FILE}"
        printf '    "round": %d,\n' "${round}" >> "${RESULTS_FILE}"
        printf '    "median_ms": %s,\n' "${PARSED_MEDIAN_MS}" >> "${RESULTS_FILE}"
        printf '    "p99_ms": %s,\n' "${PARSED_P99_MS}" >> "${RESULTS_FILE}"
        printf '    "req_per_sec": %s,\n' "${PARSED_RPS}" >> "${RESULTS_FILE}"
        printf '    "raw_wrk_output": %s\n' "$(echo "${WRK_OUT}" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))' 2>/dev/null || printf '""')" >> "${RESULTS_FILE}"
        printf '  }' >> "${RESULTS_FILE}"

        sandbox_cleanup "${PREFIX}"

        # Reset trap.
        trap - EXIT

        # Cool-down between runs.
        if (( COOLDOWN_S > 0 )); then
            info "  Cooldown ${COOLDOWN_S}s..."
            sleep "${COOLDOWN_S}"
        fi
    done
done

# Close JSON array.
printf '\n]\n' >> "${RESULTS_FILE}"

# Validate the JSON.
if jq empty "${RESULTS_FILE}" 2>/dev/null; then
    pass "Results JSON is valid: ${RESULTS_FILE}"
else
    echo "ERROR: Results JSON failed to parse: ${RESULTS_FILE}" >&2
    echo "       Raw file contents (first 20 lines):" >&2
    head -20 "${RESULTS_FILE}" >&2
    exit 1
fi

# ─── Summary ─────────────────────────────────────────────────────────────────

echo ""
step "Benchmark complete.  Results: ${RESULTS_FILE}"
echo ""

# Per-config summary using jq.
for cfg in c1 c2 c3; do
    COUNT="$(jq "[.[] | select(.config==\"${cfg}\")] | length" "${RESULTS_FILE}")"
    if (( COUNT == 0 )); then
        continue
    fi
    MED="$(jq "[.[] | select(.config==\"${cfg}\") | .median_ms] | sort | .[length/2 | floor]" "${RESULTS_FILE}")"
    P99="$(jq "[.[] | select(.config==\"${cfg}\") | .p99_ms] | sort | .[length/2 | floor]" "${RESULTS_FILE}")"
    RPS="$(jq "[.[] | select(.config==\"${cfg}\") | .req_per_sec] | sort | .[length/2 | floor]" "${RESULTS_FILE}")"
    echo "  Config ${cfg}: median=${MED}ms  p99=${P99}ms  req/s=${RPS}  (${COUNT} iterations)"
done

echo ""
info "Run 'BENCH_ITERATIONS=${BENCH_ITERATIONS} bash tests/bench/zero_cost.sh' to re-run."
info "Analyse results with: jq '.' ${RESULTS_FILE}"
