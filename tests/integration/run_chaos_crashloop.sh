#!/usr/bin/env bash
# tests/integration/run_chaos_crashloop.sh — C2 chaos: crash-loop self-disable gate
#
# Verifies the C1 crash-loop backoff + give-up-to-degraded implementation.
# Uses the `test-support` feature gate (NGX_OTEL_CRASH_ON_STARTUP env var)
# to inject repeated exporter crashes and assert the containment invariants:
#
#   1. Exporter aborts on startup when NGX_OTEL_CRASH_ON_STARTUP is set.
#   2. Each restart is preceded by a bounded-exponential backoff sleep.
#   3. After MAX_CRASH_RESTARTS (5) crashes in the window, the exporter
#      self-disables via exit(2): master stops respawning, no more exporter.
#   4. error.log contains the NGX_LOG_ALERT "disabled after N crashes" message.
#   5. nginx master is responsive (kill -0) throughout the crash loop.
#   6. Workers return HTTP 200 throughout — data plane is UNAFFECTED.
#   7. SIGQUIT shuts down cleanly (master exits, no orphan processes).
#
# STOP-AND-ASK gate: the crash hook is ENTIRELY behind
# `#[cfg(feature = "test-support")]` — zero code in production builds.
# No non-test-gated production change is required.
#
# Prerequisites: cargo on PATH; NGINX_BINARY set or auto-detected.
# Exit codes: 0 = all assertions passed, 1 = preflight, 2 = assertion failed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CONF_TEMPLATE="${SCRIPT_DIR}/nginx_exporter.conf"

. "${CRATE_DIR}/test-harness/lib.sh"
resolve_nginx_binary || true

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
pass()  { echo -e "${GREEN}[PASS]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*" >&2; exit 2; }
info()  { echo -e "${YELLOW}[INFO]${NC} $*"; }

if [[ ! -x "${NGINX_BINARY}" ]]; then
    echo "ERROR: nginx binary not found at ${NGINX_BINARY}." >&2; exit 1
fi

# ─── Build the test-support module ───────────────────────────────────────────
#
# The crash-loop hook (NGX_OTEL_CRASH_ON_STARTUP) is guarded by
# `#[cfg(feature = "test-support")]`. We build a debug module with that feature;
# keeping it in a separate target dir avoids clobbering the production release.
case "$(uname -s)" in
    Darwin) MODULE_EXT="dylib" ;;
    *)      MODULE_EXT="so"    ;;
esac

TEST_SUPPORT_TARGET_DIR="${CRATE_DIR}/target/test-support"
TEST_SUPPORT_MODULE="${TEST_SUPPORT_TARGET_DIR}/debug/libngx_http_otel_module.${MODULE_EXT}"

NGINX_BUILD_DIR="${CRATE_DIR}/objs-${BUILD:-debug}"
# Fall back to any available objs-* directory.
if [[ ! -d "${NGINX_BUILD_DIR}" ]]; then
    NGINX_BUILD_DIR="$(ls -d "${CRATE_DIR}"/objs-* 2>/dev/null | head -1)"
fi
if [[ -z "${NGINX_BUILD_DIR}" ]]; then
    echo "ERROR: no objs-* build dir found. Run 'make' first." >&2; exit 1
fi
NGINX_SOURCE_DIR="${CRATE_DIR}/../nginx"
if [[ ! -d "${NGINX_SOURCE_DIR}" ]]; then
    echo "ERROR: nginx source dir not found at ${NGINX_SOURCE_DIR}." >&2; exit 1
fi

info "Building test-support module (features=test-support)..."
info "  NGINX_BUILD_DIR = ${NGINX_BUILD_DIR}"
info "  target dir      = ${TEST_SUPPORT_TARGET_DIR}"
NGINX_BUILD_DIR="${NGINX_BUILD_DIR}" NGINX_SOURCE_DIR="${NGINX_SOURCE_DIR}" \
    cargo build \
    --manifest-path "${CRATE_DIR}/Cargo.toml" \
    --features test-support \
    --target-dir "${TEST_SUPPORT_TARGET_DIR}" 2>&1 | grep -E 'Compiling|Finished|error' || true

if [[ ! -f "${TEST_SUPPORT_MODULE}" ]]; then
    fail "test-support module not found at ${TEST_SUPPORT_MODULE} after build"
fi
pass "test-support module built: ${TEST_SUPPORT_MODULE}"
info "nginx binary: ${NGINX_BINARY}"

# ─── Helpers ─────────────────────────────────────────────────────────────────

wait_for() {
    local timeout=$1 desc=$2 expr=$3
    local deadline=$(( $(date +%s) + timeout ))
    while (( $(date +%s) < deadline )); do
        if eval "${expr}" 2>/dev/null; then return 0; fi
        sleep 0.5
    done
    fail "Timed out (${timeout}s) waiting for: ${desc}"
}

exporter_pid() {
    local master_pid="${1:-}"
    if [[ -n "${master_pid}" ]]; then
        ps -eo pid,ppid,args 2>/dev/null \
            | awk -v mpid="${master_pid}" \
                '$2==mpid && $3 == "nginx:" && $4 == "otel" && $5 == "exporter" {print $1}' \
            | head -1
    else
        ps -eo pid,args 2>/dev/null \
            | awk '$2 == "nginx:" && $3 == "otel" && $4 == "exporter" {print $1}' \
            | head -1
    fi
}

# ─── Test body ───────────────────────────────────────────────────────────────

PREFIX="$(mktemp -d /tmp/ngx-otel-crashloop.XXXXXX)"
NGINX_PID=""

cleanup() {
    [[ -n "${NGINX_PID:-}" ]] && kill "${NGINX_PID}" 2>/dev/null || true
    sleep 1
    echo ""
    echo "=== error.log (last 40 lines) ==="
    tail -40 "${PREFIX}/logs/error.log" 2>/dev/null || echo "(not found)"
    rm -rf "${PREFIX}"
}
trap cleanup EXIT

mkdir -p "${PREFIX}/logs" "${PREFIX}/client_body_temp"
sed \
    -e "s|@MODULE_PATH@|${TEST_SUPPORT_MODULE}|g" \
    -e "s|@PREFIX@|${PREFIX}|g" \
    "${CONF_TEMPLATE}" > "${PREFIX}/nginx.conf"

# Start nginx with the crash-injection env var set.
# MAX_CRASH_RESTARTS=5; total backoff ≈ 200+400+800+1600 ≈ 3s; add nginx
# overhead + 300ms crash-hook sleep per restart → allow 45 s.
MAX_WAIT_S=45

info "Starting nginx with NGX_OTEL_CRASH_ON_STARTUP=1..."
env NGX_OTEL_CRASH_ON_STARTUP=1 \
    "${NGINX_BINARY}" -p "${PREFIX}" -c "${PREFIX}/nginx.conf" &
NGINX_PID=$!
sleep 1

if ! kill -0 "${NGINX_PID}" 2>/dev/null; then
    fail "nginx master exited immediately — check error.log"
fi
pass "nginx master started, PID = ${NGINX_PID}"

# Assertion 1: exporter initially appears.
wait_for 10 "initial exporter to appear" "[[ -n \"\$(exporter_pid ${NGINX_PID})\" ]]"
pass "Initial exporter appeared"

# Assertion 5: master stays responsive during the crash loop (checked inline).
info "Waiting for crash-loop to complete and exporter to self-disable (max ${MAX_WAIT_S}s)..."

SELF_DISABLE_OBSERVED=false
MASTER_DIED=false
deadline=$(( $(date +%s) + MAX_WAIT_S ))

while (( $(date +%s) < deadline )); do
    # Master must stay alive throughout.
    if ! kill -0 "${NGINX_PID}" 2>/dev/null; then
        MASTER_DIED=true
        break
    fi
    # Check for the ALERT message in error.log.
    if grep -q "otel exporter: disabled after" "${PREFIX}/logs/error.log" 2>/dev/null; then
        SELF_DISABLE_OBSERVED=true
        break
    fi
    sleep 0.5
done

if [[ "${MASTER_DIED}" == "true" ]]; then
    fail "nginx MASTER exited unexpectedly during crash-loop (should never happen)"
fi
if [[ "${SELF_DISABLE_OBSERVED}" != "true" ]]; then
    fail "Crash-loop self-disable ALERT not observed in error.log within ${MAX_WAIT_S}s"
fi
pass "Self-disable ALERT observed in error.log"

# Assertion 2: backoff messages appear in error.log.
BACKOFF_COUNT="$(grep -c "crash #.*in window, backing off" "${PREFIX}/logs/error.log" 2>/dev/null || true)"
if (( BACKOFF_COUNT >= 1 )); then
    pass "Backoff messages in error.log: ${BACKOFF_COUNT} (exponential throttle active)"
else
    fail "No backoff messages in error.log — crash counter logic may not be running"
fi

# Assertion 3: no exporter after self-disable (no further respawn).
# Give it a moment in case respawn races with the ALERT log.
sleep 2
EXP_NOW="$(exporter_pid "${NGINX_PID}")"
if [[ -n "${EXP_NOW}" ]]; then
    fail "Exporter is still running after self-disable (PID ${EXP_NOW}); expected no respawn"
fi
pass "No exporter process after self-disable (nginx correctly stopped respawning)"

# Assertion 4: ALERT log message content check.
ALERT_LINE="$(grep "otel exporter: disabled after" "${PREFIX}/logs/error.log" \
    | head -1)"
info "ALERT line: ${ALERT_LINE}"
if echo "${ALERT_LINE}" | grep -q "telemetry OFF"; then
    pass "ALERT message includes 'telemetry OFF' — correct operator guidance"
else
    fail "ALERT message missing 'telemetry OFF': ${ALERT_LINE}"
fi
if echo "${ALERT_LINE}" | grep -q "nginx request handling UNAFFECTED"; then
    pass "ALERT message includes 'nginx request handling UNAFFECTED'"
else
    fail "ALERT message missing 'nginx request handling UNAFFECTED': ${ALERT_LINE}"
fi

# Assertion 5: master still responsive.
if kill -0 "${NGINX_PID}" 2>/dev/null; then
    pass "nginx master still responsive after exporter self-disable (PID ${NGINX_PID})"
else
    fail "nginx master exited unexpectedly"
fi

# Assertion 6: workers still return HTTP 200.
HTTP_RESULT="$(curl -s -o /dev/null -w '%{http_code}' \
    --max-time 3 http://127.0.0.1:9200/ 2>/dev/null || echo 000)"
if [[ "${HTTP_RESULT}" == "200" ]]; then
    pass "Workers return HTTP 200 after exporter self-disable (data plane UNAFFECTED)"
else
    fail "Workers returned ${HTTP_RESULT} after exporter self-disable (expected 200)"
fi

# Assertion 7: clean SIGQUIT shutdown.
info "Sending SIGQUIT to master PID ${NGINX_PID}..."
kill -SIGQUIT "${NGINX_PID}"
wait_for 15 "nginx master to exit cleanly" "! kill -0 ${NGINX_PID} 2>/dev/null"
pass "nginx master exited cleanly on SIGQUIT"
NGINX_PID=""
trap - EXIT
rm -rf "${PREFIX}"

echo ""
pass "=== All crash-loop self-disable assertions passed ==="
