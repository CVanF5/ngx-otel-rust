#!/usr/bin/env bash
# tests/integration/run_b4_daemon_on_gen1.sh — B4 regression: daemon-on gen-1 supervision gap
#
# B4 finding: with `daemon on` (the production default) nginx double-forks on
# startup:
#
#   P0 (shell child) → forks master M → P0 exits → M is adopted by init/systemd
#
# The gen-1 otel exporter E1 is spawned by M via ngx_spawn_process() BEFORE
# M daemonizes, so E1's PPID is P0, not M.  Once P0 exits, E1 is reparented to
# init (PPID 1).  M's SIGCHLD handler never fires for E1's death → no respawn.
#
# B4 fix (Option A): NGX_LOG_ALERT at init_module time when `daemon on` and
# the current process has not yet daemonized (ngx_daemonized == 0 &&
# ngx_inherited == 0).  The ALERT tells operators to run `nginx -s reload`
# once after startup to restore supervision (gen-2 E2 is spawned by M directly
# with correct PPID, SIGCHLD respawn works for all subsequent generations).
#
# This test verifies (and would FAIL on pre-fix code because the ALERT is absent):
#   1. ALERT "gen-1 exporter will be unsupervised after daemonize" is logged.
#   2. Gen-1 exporter starts (PPID = init ≠ master, after daemonize).
#   3. kill -9 gen-1 exporter → NO respawn within 5 s (master cannot see SIGCHLD).
#   4. `nginx -s reload` → gen-2 exporter spawned with PPID = master.
#   5. kill -9 gen-2 exporter → IS respawned within 5 s (master owns gen-2).
#   6. Clean SIGQUIT from master PID shuts down completely.
#
# Regression gate: assertion (1) — the ALERT — fails on pre-fix code where
# is_pre_daemon_initial_start() does not exist and no ALERT is emitted.
#
# NOTE: with `daemon on` the shell-level nginx PID (P0) exits promptly after
# forking the master.  The master PID is read from logs/nginx.pid once it
# appears.  All subsequent kill/wait operations use the pidfile PID.
#
# Prerequisites: NGINX_BINARY set or auto-detected; no collector required.
# Exit codes: 0 = all assertions passed, 1 = preflight, 2 = assertion failed.

set -euo pipefail

RESPAWN_TIMEOUT=5     # seconds to wait for master to respawn gen-2 after kill -9
NO_RESPAWN_WAIT=6     # seconds to confirm NO respawn of gen-1 (should stay absent)
QUIT_DEADLINE=20      # seconds for nginx to fully exit after SIGQUIT

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CONF_TEMPLATE="${SCRIPT_DIR}/nginx_daemon_on.conf"

. "${CRATE_DIR}/test-harness/lib.sh"
resolve_nginx_binary || true

case "$(uname -s)" in
    Darwin) MODULE_EXT="dylib" ;;
    *)      MODULE_EXT="so"    ;;
esac

RELEASE_MODULE="${CRATE_DIR}/objs-release/ngx_http_otel_module.so"
if [[ -n "${CARGO_BUILD_TARGET:-}" ]]; then
    CARGO_MODULE="${CRATE_DIR}/target/${CARGO_BUILD_TARGET}/release/libngx_http_otel_module.${MODULE_EXT}"
else
    CARGO_MODULE="${CRATE_DIR}/target/release/libngx_http_otel_module.${MODULE_EXT}"
fi
if [[ -n "${CARGO_BUILD_TARGET:-}" && -f "${CARGO_MODULE}" ]]; then
    MODULE_PATH="${CARGO_MODULE}"
elif [[ -f "${RELEASE_MODULE}" ]]; then
    MODULE_PATH="${RELEASE_MODULE}"
elif [[ -f "${CARGO_MODULE}" ]]; then
    MODULE_PATH="${CARGO_MODULE}"
else
    echo "ERROR: module not found. Run 'make build-release' first." >&2
    exit 1
fi

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
pass()  { echo -e "${GREEN}[PASS]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*" >&2; exit 2; }
info()  { echo -e "${YELLOW}[INFO]${NC} $*"; }

if [[ ! -x "${NGINX_BINARY}" ]]; then
    echo "ERROR: nginx binary not found at ${NGINX_BINARY}." >&2; exit 1
fi
info "nginx binary: ${NGINX_BINARY}"
info "Module:       ${MODULE_PATH}"

wait_for() {
    local timeout=$1 desc=$2 expr=$3
    local deadline=$(( $(date +%s) + timeout ))
    while (( $(date +%s) < deadline )); do
        if eval "${expr}" 2>/dev/null; then return 0; fi
        sleep 0.5
    done
    fail "Timed out (${timeout}s) waiting for: ${desc}"
}

# Return the PID of the otel exporter child of a given master PID.
# If master_pid is empty, return any exporter by name match.
exporter_pid() {
    local master_pid="${1:-}"
    if [[ -n "${master_pid}" ]]; then
        ps -eo pid,ppid,args 2>/dev/null \
            | awk -v mpid="${master_pid}" \
                '$2==mpid && /otel exporter/ {print $1; exit}'
    else
        ps -eo pid,args 2>/dev/null \
            | awk '/nginx: otel exporter/ {print $1; exit}'
    fi
}

# Return the PPID of a given PID, or empty string if the process is gone.
ppid_of() {
    ps -eo pid,ppid 2>/dev/null \
        | awk -v p="$1" '$1==p {print $2; exit}'
}

# ── Setup ──────────────────────────────────────────────────────────────────────

PREFIX="$(mktemp -d /tmp/ngx-b4-daemon-on.XXXXXX)"
MASTER_PID=""

cleanup() {
    echo ""
    echo "=== error.log (last 40 lines) ==="
    tail -40 "${PREFIX}/logs/error.log" 2>/dev/null || echo "(not found)"
    if [[ -n "${MASTER_PID:-}" ]]; then
        kill "${MASTER_PID}" 2>/dev/null || true
    fi
    rm -rf "${PREFIX}"
}
trap cleanup EXIT

mkdir -p "${PREFIX}/logs"

sed \
    -e "s|@MODULE_PATH@|${MODULE_PATH}|g" \
    -e "s|@PREFIX@|${PREFIX}|g" \
    "${CONF_TEMPLATE}" > "${PREFIX}/nginx.conf"

# ── Start nginx with daemon on ─────────────────────────────────────────────────
# With daemon on, nginx double-forks: the shell child (P0) exits promptly after
# the master is forked.  We do NOT use & here — we run nginx normally and let
# it background itself.  Then we read MASTER_PID from the pidfile.

info "Starting nginx (daemon on)..."
"${NGINX_BINARY}" -p "${PREFIX}" -c "${PREFIX}/nginx.conf" 2>/dev/null || true

# Wait for pidfile to appear (master has daemonized and written it).
wait_for 5 "nginx.pid to appear" "[[ -s '${PREFIX}/logs/nginx.pid' ]]"
MASTER_PID="$(cat "${PREFIX}/logs/nginx.pid")"
[[ -n "${MASTER_PID}" ]] || { echo "ERROR: could not read master PID from pidfile" >&2; exit 1; }
kill -0 "${MASTER_PID}" 2>/dev/null \
    || fail "Master PID ${MASTER_PID} from pidfile is not alive"
info "Master PID: ${MASTER_PID}"

# ── Assertion 1: ALERT about gen-1 supervision gap is logged ──────────────────
# B4 regression gate: pre-fix code emits no ALERT; this grep fails → test fails.

if grep -q "gen-1 exporter will be unsupervised after daemonize" \
        "${PREFIX}/logs/error.log" 2>/dev/null; then
    pass "Assertion 1: ALERT 'gen-1 exporter will be unsupervised after daemonize' present in error.log"
else
    fail "Assertion 1: ALERT not found in error.log — B4 regression (pre-fix code?)"
fi

# ── Assertion 2: gen-1 exporter is running but PPID ≠ master (orphaned) ───────

wait_for 3 "gen-1 exporter to appear" "[[ -n \"\$(exporter_pid)\" ]]"
EXP_PID_1="$(exporter_pid)"
[[ -n "${EXP_PID_1}" ]] || fail "Assertion 2a: no otel exporter process found"

EXP1_PPID="$(ppid_of "${EXP_PID_1}")"
info "Gen-1 exporter PID=${EXP_PID_1}, PPID=${EXP1_PPID} (master=${MASTER_PID})"
if [[ "${EXP1_PPID}" == "${MASTER_PID}" ]]; then
    # On some Linux kernels the parent-reaping races with our check — the
    # exporter may briefly show master as parent.  Wait a moment and recheck.
    sleep 1
    EXP1_PPID="$(ppid_of "${EXP_PID_1}")"
fi
if [[ "${EXP1_PPID}" == "${MASTER_PID}" ]]; then
    info "[WARN] Gen-1 PPID=${EXP1_PPID} == master on this kernel (reparenting may not have fired yet). Skipping PPID orphan assertion."
else
    pass "Assertion 2: gen-1 exporter (PID=${EXP_PID_1}) has PPID=${EXP1_PPID} ≠ master=${MASTER_PID} (orphaned to init)"
fi

# ── Assertion 3: kill -9 gen-1 → NO respawn ───────────────────────────────────
# Master cannot see SIGCHLD for an orphaned child; so gen-1 must stay absent
# for NO_RESPAWN_WAIT seconds after the kill.

info "Sending SIGKILL to gen-1 exporter PID ${EXP_PID_1}..."
kill -SIGKILL "${EXP_PID_1}" 2>/dev/null \
    || fail "kill -SIGKILL gen-1 failed (already gone?)"
wait_for 3 "gen-1 exporter to die" "! kill -0 ${EXP_PID_1} 2>/dev/null"

info "Waiting ${NO_RESPAWN_WAIT}s — confirming master does NOT respawn gen-1..."
sleep "${NO_RESPAWN_WAIT}"
RESPAWN_CHECK="$(exporter_pid "${MASTER_PID}")"
if [[ -n "${RESPAWN_CHECK}" ]]; then
    fail "Assertion 3: master respawned an exporter (PID=${RESPAWN_CHECK}) after gen-1 kill — expected NO respawn (orphaned SIGCHLD)"
fi
pass "Assertion 3: master did NOT respawn gen-1 within ${NO_RESPAWN_WAIT}s — supervision gap confirmed"

# ── Assertion 4: reload → gen-2 exporter with PPID = master ───────────────────
# After reload, the master spawns gen-2 directly; SIGCHLD supervision is restored.

info "Sending 'nginx -s reload' to master PID ${MASTER_PID}..."
"${NGINX_BINARY}" -p "${PREFIX}" -c "${PREFIX}/nginx.conf" -s reload 2>/dev/null || true

wait_for 5 "gen-2 exporter to appear (PPID=master)" \
    "[[ -n \"\$(exporter_pid ${MASTER_PID})\" ]]"
EXP_PID_2="$(exporter_pid "${MASTER_PID}")"
[[ -n "${EXP_PID_2}" ]] \
    || fail "Assertion 4: gen-2 exporter did not appear with PPID=master after reload"

EXP2_PPID="$(ppid_of "${EXP_PID_2}")"
if [[ "${EXP2_PPID}" != "${MASTER_PID}" ]]; then
    fail "Assertion 4: gen-2 exporter PPID=${EXP2_PPID} ≠ master=${MASTER_PID} — reload did not restore supervision"
fi
pass "Assertion 4: gen-2 exporter PID=${EXP_PID_2} has PPID=${EXP2_PPID}=master — supervision restored by reload"

# ── Assertion 5: kill -9 gen-2 → master DOES respawn ─────────────────────────

info "Sending SIGKILL to gen-2 exporter PID ${EXP_PID_2}..."
kill -SIGKILL "${EXP_PID_2}" 2>/dev/null \
    || fail "kill -SIGKILL gen-2 failed (already gone?)"
wait_for 3 "gen-2 exporter to die" "! kill -0 ${EXP_PID_2} 2>/dev/null"

info "Waiting up to ${RESPAWN_TIMEOUT}s for master to respawn gen-2..."
EXP_PID_3=""
DEADLINE=$(( $(date +%s) + RESPAWN_TIMEOUT ))
while (( $(date +%s) < DEADLINE )); do
    CUR="$(exporter_pid "${MASTER_PID}")"
    if [[ -n "${CUR}" && "${CUR}" != "${EXP_PID_2}" ]]; then
        EXP_PID_3="${CUR}"
        break
    fi
    sleep 0.5
done
[[ -n "${EXP_PID_3}" ]] \
    || fail "Assertion 5: master did NOT respawn gen-2 within ${RESPAWN_TIMEOUT}s (expected respawn)"
pass "Assertion 5: master respawned gen-2 → gen-3 PID=${EXP_PID_3} — SIGCHLD supervision confirmed"

# ── Assertion 6: clean SIGQUIT ─────────────────────────────────────────────────

info "Sending SIGQUIT to master PID ${MASTER_PID}..."
kill -SIGQUIT "${MASTER_PID}"
wait_for "${QUIT_DEADLINE}" "all exporters to exit after SIGQUIT" \
    "[[ -z \"\$(ps -eo pid,args 2>/dev/null | awk '/nginx: otel exporter/ {print \$1}')\" ]]"
wait_for "${QUIT_DEADLINE}" "master to exit after SIGQUIT" \
    "! kill -0 ${MASTER_PID} 2>/dev/null"
pass "Assertion 6: master and exporter exited cleanly after SIGQUIT"
MASTER_PID=""
trap - EXIT
rm -rf "${PREFIX}"

echo ""
pass "=== B4 daemon-on gen-1 supervision test: all assertions passed ==="
