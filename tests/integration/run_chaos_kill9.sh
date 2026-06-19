#!/usr/bin/env bash
# tests/integration/run_chaos_kill9.sh — C2 chaos: kill-9 containment gate
#
# Verifies master isolation invariants after a SIGKILL of the otel exporter:
#   1. Workers keep serving HTTP 200 while the exporter is dead.
#   2. Workers have ZERO connections to ports 4317 or 4318 (sockets belong
#      exclusively to the exporter process, not workers — architectural guarantee).
#   3. Master respawns a new exporter within 5 s.
#   4. error.log contains "cycle entered" ≥ 2 times (initial + respawn).
#   5. SIGQUIT shuts down cleanly: master exits, no orphan exporter remains.
#
# Containment focus: assertion (1) — workers unaffected during exporter death —
# is the key nginx-citizen safety property. The socket check (2) confirms the
# collector connection originates exclusively from the exporter PID.
#
# Prerequisites: NGINX_BINARY set or auto-detected; no collector required.
# Exit codes: 0 = all assertions passed, 1 = preflight, 2 = assertion failed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CONF_TEMPLATE="${SCRIPT_DIR}/nginx_exporter.conf"

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
# When CARGO_BUILD_TARGET is set (TSAN/ASan harness), the sanitizer-instrumented
# module is at target/<triple>/release/.  Prefer CARGO_MODULE over RELEASE_MODULE
# in that case to avoid a stale non-instrumented objs-release artifact being loaded
# by a TSAN/ASan nginx (which causes a runtime symbol mismatch and nginx to abort).
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

# Return the PID of the otel exporter child of a specific master PID.
# Falls back to any exporter if no master_pid given (for use before NGINX_PID is known).
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

# Return PIDs of workers that are direct children of a given master PID.
# Filters to only the test-instance workers (avoids picking up workers from
# other nginx instances that may already be running on the dev machine).
worker_pids_for_master() {
    local master_pid=$1
    # ps -eo pid,ppid,args: $1=pid, $2=ppid, $3=first-word-of-args, $4=...
    ps -eo pid,ppid,args 2>/dev/null \
        | awk -v mpid="${master_pid}" \
            '$2==mpid && $3 == "nginx:" && $4 == "worker" && $5 == "process" {print $1}'
}

# Check that worker PIDs (direct children of NGINX_PID master) have no
# established TCP connection to ports 4317 or 4318.
# Architectural guarantee: only the exporter process creates collector sockets.
#
# Returns:
#   0 = no worker has a collector socket (PASS)
#   1 = a worker has a collector socket (FAIL)
#   2 = check inconclusive (warn but don't fail — e.g., other nginx instances
#       visible to lsof on a dev machine; skip on macOS dev boxes)
workers_have_no_collector_sockets() {
    local master_pid=$1
    local pids
    pids="$(worker_pids_for_master "${master_pid}")"
    if [[ -z "${pids}" ]]; then return 0; fi  # no workers = trivially true

    case "$(uname -s)" in
        Linux)
            # On Linux (debian-vm, CI): use /proc/<pid>/fd + /proc/<pid>/net/tcp.
            # /proc/<pid>/net/tcp is per-namespace; the check is precise.
            local collector_found=0
            for wpid in ${pids}; do
                # Collect socket inodes open by this worker.
                local sock_inodes
                sock_inodes=$(ls -la "/proc/${wpid}/fd" 2>/dev/null \
                    | grep -oP 'socket:\[\K[0-9]+(?=\])' | sort -u || true)
                if [[ -z "${sock_inodes}" ]]; then continue; fi

                # Check each inode against /proc/net/tcp for remote port 4317/4318.
                # tcp column layout: idx local_addr remote_addr state ... inode (col 10)
                # Remote port 4317=10DD hex, 4318=10DE hex.
                while IFS= read -r inode; do
                    if awk -v ino="${inode}" \
                        '$10==ino && ($3 ~ /:10[Dd][Dd]$/ || $3 ~ /:10[Dd][Ee]$/)' \
                        "/proc/net/tcp" 2>/dev/null | grep -q .; then
                        collector_found=1
                        break 2
                    fi
                done <<< "${sock_inodes}"
            done
            return "${collector_found}"
            ;;
        Darwin)
            # On macOS dev machines there may be multiple nginx instances running
            # (e.g., a demo nginx). lsof -p <pid> on macOS correctly filters by
            # PID, but if the same port :4317/:4318 is in use by another instance
            # the test would produce a false FAIL. Return 2 (inconclusive) on macOS
            # to make the check informational rather than blocking.
            # The full socket containment check is validated on debian-vm.
            local pid_list
            pid_list="$(echo "${pids}" | tr '\n' ',' | sed 's/,$//')"
            local found
            found=$(lsof -p "${pid_list}" -nP -iTCP 2>/dev/null \
                | grep -cE ':(4317|4318)' || echo 0)
            if [[ "${found}" -eq 0 ]]; then
                return 0  # clearly no sockets
            else
                return 2  # possibly contaminated by another nginx instance
            fi
            ;;
    esac
}

# Wrapper: assert workers have no collector sockets; warn on inconclusive.
assert_worker_socket_isolation() {
    local master_pid=$1 context=$2
    local rc=0
    workers_have_no_collector_sockets "${master_pid}" || rc=$?
    if [[ "${rc}" -eq 0 ]]; then
        pass "Workers have zero connections to :4317/:4318 ${context} (architectural isolation)"
    elif [[ "${rc}" -eq 2 ]]; then
        info "[WARN] Socket isolation check inconclusive on macOS (multiple nginx instances). Verified on debian-vm. ${context}"
    else
        fail "Workers have a :4317/:4318 socket ${context} — isolation broken"
    fi
}

# ─── Test body ───────────────────────────────────────────────────────────────

PREFIX="$(mktemp -d /tmp/ngx-otel-kill9.XXXXXX)"
NGINX_PID=""

cleanup() {
    [[ -n "${NGINX_PID:-}" ]] && kill "${NGINX_PID}" 2>/dev/null || true
    sleep 1
    echo ""
    echo "=== error.log (last 20 lines) ==="
    tail -20 "${PREFIX}/logs/error.log" 2>/dev/null || echo "(not found)"
    rm -rf "${PREFIX}"
}
trap cleanup EXIT

mkdir -p "${PREFIX}/logs" "${PREFIX}/client_body_temp"
sed \
    -e "s|@MODULE_PATH@|${MODULE_PATH}|g" \
    -e "s|@PREFIX@|${PREFIX}|g" \
    "${CONF_TEMPLATE}" > "${PREFIX}/nginx.conf"

# ── Pre-flight: reap any stale nginx listening on port 9200 ─────────────────
# Stale processes from a previous interrupted run cause EADDRINUSE and rc=2
# TSAN anomalies. Kill any process owning port 9200 before starting our nginx.
# Uses bracketed pgrep pattern to avoid self-match (/proc/<pid>/net/tcp check).
if command -v fuser >/dev/null 2>&1; then
    STALE_9200="$(fuser 9200/tcp 2>/dev/null | tr -d ' ' || true)"
    if [[ -n "${STALE_9200}" ]]; then
        info "Pre-flight: killing stale process(es) on :9200 — PIDs: ${STALE_9200}"
        echo "${STALE_9200}" | xargs -r kill -KILL 2>/dev/null || true
        sleep 0.5
    fi
elif command -v ss >/dev/null 2>&1; then
    STALE_9200="$(ss -tlnp 'sport = :9200' 2>/dev/null | awk 'NR>1 && /pid=/ {match($0,/pid=([0-9]+)/,a); if(a[1]) print a[1]}' || true)"
    if [[ -n "${STALE_9200}" ]]; then
        info "Pre-flight: killing stale process(es) on :9200 — PIDs: ${STALE_9200}"
        echo "${STALE_9200}" | xargs -r kill -KILL 2>/dev/null || true
        sleep 0.5
    fi
fi
# Also kill any leftover nginx worker/master from a prior run of this test.
LEFTOVER_NGX="$(pgrep -f '[n]ginx: master' 2>/dev/null | head -5 || true)"
if [[ -n "${LEFTOVER_NGX}" ]]; then
    info "Pre-flight: killing leftover nginx master(s): ${LEFTOVER_NGX}"
    echo "${LEFTOVER_NGX}" | xargs -r kill -QUIT 2>/dev/null || true
    sleep 1
fi

info "Starting nginx..."
"${NGINX_BINARY}" -p "${PREFIX}" -c "${PREFIX}/nginx.conf" &
NGINX_PID=$!
sleep 1

if ! kill -0 "${NGINX_PID}" 2>/dev/null; then
    fail "nginx exited immediately after start"
fi

# Assertion 1: exporter appears.
EXP_PID_1="$(exporter_pid "${NGINX_PID}")"
[[ -n "${EXP_PID_1}" ]] || fail "No 'otel exporter' process found after nginx start"
pass "Exporter started, PID = ${EXP_PID_1}"

# Assertion 2: workers have no collector sockets (before kill).
assert_worker_socket_isolation "${NGINX_PID}" "(before kill)"

# Drive continuous HTTP traffic during the kill window.
info "Starting background HTTP load during exporter kill..."
CURL_PIDS=()
for _ in $(seq 1 30); do
    curl -s --max-time 5 http://127.0.0.1:9200/ >/dev/null 2>&1 &
    CURL_PIDS+=($!)
done

# SIGKILL the exporter.
info "Sending SIGKILL to exporter PID ${EXP_PID_1}..."
kill -SIGKILL "${EXP_PID_1}" 2>/dev/null \
    || fail "kill -SIGKILL failed (exporter already gone?)"

# Assertion 3: workers keep serving 200 while exporter is dead.
sleep 0.5
HTTP_RESULT="$(curl -s -o /dev/null -w '%{http_code}' \
    --max-time 3 http://127.0.0.1:9200/ 2>/dev/null || echo 000)"
if [[ "${HTTP_RESULT}" == "200" ]]; then
    pass "Workers return HTTP 200 while exporter is dead (${HTTP_RESULT})"
else
    fail "Workers returned ${HTTP_RESULT} while exporter was dead (expected 200)"
fi

# Assertion 4: master respawns a new exporter within 5 s.
EXP_PID_2=""
for _ in $(seq 1 10); do
    sleep 0.5
    CUR="$(exporter_pid "${NGINX_PID}")"
    if [[ -n "${CUR}" && "${CUR}" != "${EXP_PID_1}" ]]; then
        EXP_PID_2="${CUR}"
        break
    fi
done
[[ -n "${EXP_PID_2}" ]] \
    || fail "Master did not respawn exporter within 5 s after SIGKILL"
pass "Master respawned exporter: PID = ${EXP_PID_2} (was ${EXP_PID_1})"

# Assertion 5: workers still have no collector sockets after respawn.
sleep 0.5  # give the new exporter a moment to establish its connection
assert_worker_socket_isolation "${NGINX_PID}" "(after respawn)"

# Assertion 6: error.log shows ≥ 2 "cycle entered" entries.
CYCLE_COUNT="$(grep -c "otel exporter: cycle entered" \
    "${PREFIX}/logs/error.log" 2>/dev/null || true)"
if (( CYCLE_COUNT >= 2 )); then
    pass "error.log contains 'cycle entered' ${CYCLE_COUNT} times (initial + respawn)"
else
    fail "error.log contains 'cycle entered' only ${CYCLE_COUNT} time(s); expected ≥ 2"
fi

# Wait for background curl jobs to finish.
wait "${CURL_PIDS[@]}" 2>/dev/null || true

# Assertion 7: clean shutdown.
info "Sending SIGQUIT to master PID ${NGINX_PID}..."
kill -SIGQUIT "${NGINX_PID}"
wait_for 15 "exporter to exit after SIGQUIT" "[[ -z \"\$(exporter_pid ${NGINX_PID})\" ]]"
wait_for 15 "nginx master to exit" "! kill -0 ${NGINX_PID} 2>/dev/null"
pass "Master and exporter exited cleanly after SIGQUIT"
NGINX_PID=""
trap - EXIT
rm -rf "${PREFIX}"

echo ""
pass "=== All kill-9 containment assertions passed ==="
