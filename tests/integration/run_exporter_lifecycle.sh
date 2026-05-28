#!/usr/bin/env bash
# tests/integration/run_exporter_lifecycle.sh — Phase 1.3.1 exporter lifecycle gate
#
# Verifies that the `nginx: otel exporter` child process:
#   1. Appears in the process tree when otel_exporter is configured.
#   2. Runs as the configured nginx user (NOT root). On macOS dev machines
#      geteuid() != 0, so privilege drop is skipped and the exporter runs as
#      the developer's current user — which is NOT root, so the invariant holds.
#   3. Survives SIGUSR1 (log reopen) with pid unchanged and "reopening logs"
#      in error.log.
#   4. Survives SIGHUP (reload): exactly one exporter remains after reload,
#      and its PID differs from the pre-reload PID.
#   5. Exits cleanly on SIGQUIT: no exporter remains after graceful shutdown.
#   6. Zero-cost gate: when otel_exporter is NOT configured, no exporter child
#      appears.
#
# Prerequisites
# ─────────────
#   - NGINX_BINARY set (or auto-detected from objs-release/nginx)
#   - MODULE_PATH set (or auto-detected from objs-release/)
#   - No external collector required (export failures are non-fatal)
#
# Exit codes: 0 = all assertions passed, 1 = preflight failed, 2 = assertion failed.

set -euo pipefail

# ─── Resolve paths ───────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

CONF_TEMPLATE="${SCRIPT_DIR}/nginx_exporter.conf"

# Source the shared harness library for resolve_nginx_binary.
. "${CRATE_DIR}/test-harness/lib.sh"
resolve_nginx_binary || true

# Detect module extension and path.
case "$(uname -s)" in
    Darwin) MODULE_EXT="dylib" ;;
    *)      MODULE_EXT="so"    ;;
esac

# Prefer the objs-release module (already built by make build-release);
# fall back to cargo's target/release output.
RELEASE_MODULE="${CRATE_DIR}/objs-release/ngx_http_otel_module.so"
CARGO_MODULE="${CRATE_DIR}/target/release/libngx_http_otel_module.${MODULE_EXT}"
if [[ -f "${RELEASE_MODULE}" ]]; then
    MODULE_PATH="${RELEASE_MODULE}"
elif [[ -f "${CARGO_MODULE}" ]]; then
    MODULE_PATH="${CARGO_MODULE}"
else
    echo "ERROR: module not found. Run 'make build-release' first." >&2
    exit 1
fi

# ─── Colour helpers ──────────────────────────────────────────────────────────

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass()  { echo -e "${GREEN}[PASS]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*" >&2; exit 2; }
info()  { echo -e "${YELLOW}[INFO]${NC} $*"; }

# ─── Pre-flight checks ───────────────────────────────────────────────────────

info "Pre-flight checks..."

if [[ ! -x "${NGINX_BINARY}" ]]; then
    echo "ERROR: nginx binary not found at ${NGINX_BINARY}." >&2
    echo "       Set NGINX_BINARY to the nginx binary built alongside the module." >&2
    exit 1
fi

info "nginx binary: ${NGINX_BINARY}"
info "Module:       ${MODULE_PATH}"

# ─── Helpers ─────────────────────────────────────────────────────────────────

# Poll until a condition holds or the timeout expires.
# Usage: wait_for <timeout_s> <description> <shell_expr>
wait_for() {
    local timeout=$1 desc=$2 expr=$3
    local deadline=$(( $(date +%s) + timeout ))
    while (( $(date +%s) < deadline )); do
        if eval "${expr}" 2>/dev/null; then
            return 0
        fi
        sleep 0.5
    done
    fail "Timed out waiting for: ${desc}"
}

# Return the PID of the otel exporter child (first match).
#
# WHY ps -eo pid,args (not pid,comm):
#   Linux `comm` reads /proc/PID/comm, which holds the 15-byte TASK_COMM_LEN
#   kernel name set by exec or prctl(PR_SET_NAME) — NOT by argv[0] rewrites.
#   nginx's ngx_setproctitle() rewrites argv[0] in-place; it never calls
#   prctl(PR_SET_NAME), so /proc/PID/comm always shows the original exec name
#   ("nginx"), losing the "nginx: otel exporter" title entirely on Linux.
#   macOS ps(1) happens to surface argv[0] via its own comm column, which is
#   why the old `comm` pattern worked there but silently failed on Linux.
#   `args` (POSIX) returns the full argv joined, so it captures argv[0]
#   rewrites on both platforms.
#
# WHY field-anchored awk ($2=="nginx:" && $3=="otel" && $4=="exporter"):
#   The regex /nginx: otel exporter/ self-matches: the awk process appears in
#   ps -eo args with its own script containing "nginx: otel exporter", causing
#   exporter_pid() to return the awk PID even when no nginx exporter is running.
#   Field-anchored equality ($2, $3, $4) only matches lines where the second
#   whitespace-delimited field is exactly "nginx:" — the awk process has $2="awk"
#   or similar, not "nginx:". No self-match; no false positives from grep/ugrep
#   processes that may appear in the process list with this pattern in their args.
exporter_pid() {
    ps -eo pid,args 2>/dev/null \
        | awk '$2 == "nginx:" && $3 == "otel" && $4 == "exporter" {print $1}' \
        | head -1
}

# ─── Test 1: exporter appears when otel_exporter is configured ───────────────

run_with_exporter() {
    local label=$1
    PREFIX="$(mktemp -d /tmp/ngx-otel-lifecycle.XXXXXX)"
    NGINX_PID=""

    cleanup_with_exporter() {
        [[ -n "${NGINX_PID:-}" ]] && kill "${NGINX_PID}" 2>/dev/null || true
        sleep 1
        rm -rf "${PREFIX}"
    }
    trap cleanup_with_exporter RETURN

    mkdir -p "${PREFIX}/logs" "${PREFIX}/client_body_temp"

    sed \
        -e "s|@MODULE_PATH@|${MODULE_PATH}|g" \
        -e "s|@PREFIX@|${PREFIX}|g" \
        "${CONF_TEMPLATE}" > "${PREFIX}/nginx.conf"

    "${NGINX_BINARY}" -p "${PREFIX}" -c "${PREFIX}/nginx.conf" &
    NGINX_PID=$!

    # Wait for nginx to fork workers and the exporter.
    sleep 1

    if ! kill -0 "${NGINX_PID}" 2>/dev/null; then
        fail "${label}: nginx exited immediately. Log:"
    fi

    eval "$2"  # run the body of the test
}

# ─── Test 1 + 2: exporter appears + privilege check ──────────────────────────

info "=== Test 1+2: exporter appears in ps and does not run as root ==="

PREFIX_T1="$(mktemp -d /tmp/ngx-otel-lifecycle.XXXXXX)"
NGINX_PID_T1=""

cleanup_t1() {
    [[ -n "${NGINX_PID_T1:-}" ]] && kill "${NGINX_PID_T1}" 2>/dev/null || true
    sleep 1
    rm -rf "${PREFIX_T1}"
}
trap cleanup_t1 EXIT

mkdir -p "${PREFIX_T1}/logs" "${PREFIX_T1}/client_body_temp"
sed -e "s|@MODULE_PATH@|${MODULE_PATH}|g" -e "s|@PREFIX@|${PREFIX_T1}|g" \
    "${CONF_TEMPLATE}" > "${PREFIX_T1}/nginx.conf"

"${NGINX_BINARY}" -p "${PREFIX_T1}" -c "${PREFIX_T1}/nginx.conf" &
NGINX_PID_T1=$!
sleep 1

if ! kill -0 "${NGINX_PID_T1}" 2>/dev/null; then
    fail "nginx exited immediately"
fi

EXP_PID_INITIAL="$(exporter_pid)"
if [[ -z "${EXP_PID_INITIAL}" ]]; then
    fail "No 'otel exporter' process found in ps after nginx start"
fi
pass "Exporter PID = ${EXP_PID_INITIAL}"

# Privilege check: exporter must NOT run as root.
# Use pid,user,args (not pid,user,comm) — see exporter_pid() comment above.
EXP_USER="$(ps -eo pid,user,args 2>/dev/null \
    | awk -v pid="${EXP_PID_INITIAL}" '$1==pid{print $2}' | head -1)"
if [[ "${EXP_USER}" == "root" ]]; then
    fail "Exporter is running as root (expected non-root user '${EXP_USER}')"
fi
pass "Exporter user = '${EXP_USER}' (not root)"

# ─── Test 3: SIGUSR1 — log reopen ─────────────────────────────────────────────

info "=== Test 3: SIGUSR1 (log reopen) ==="

kill -SIGUSR1 "${NGINX_PID_T1}"
sleep 1

EXP_PID_AFTER_USR1="$(exporter_pid)"
if [[ -z "${EXP_PID_AFTER_USR1}" ]]; then
    fail "Exporter disappeared after SIGUSR1"
fi
if [[ "${EXP_PID_AFTER_USR1}" != "${EXP_PID_INITIAL}" ]]; then
    fail "Exporter PID changed after SIGUSR1 (before=${EXP_PID_INITIAL} after=${EXP_PID_AFTER_USR1})"
fi
pass "Exporter pid ${EXP_PID_INITIAL} unchanged after SIGUSR1"

# Check error.log for the reopen log line.
if ! grep -q "reopening logs" "${PREFIX_T1}/logs/error.log" 2>/dev/null; then
    fail "error.log does not contain 'reopening logs' after SIGUSR1"
fi
pass "error.log contains 'reopening logs' from the exporter"

# ─── Test 4: SIGHUP — reload ──────────────────────────────────────────────────

info "=== Test 4: SIGHUP (reload) ==="

kill -SIGHUP "${NGINX_PID_T1}"
# Wait up to 5s for the new exporter to appear with a different PID.
NEW_EXP_PID=""
for _ in $(seq 1 10); do
    sleep 0.5
    CUR="$(exporter_pid)"
    if [[ -n "${CUR}" && "${CUR}" != "${EXP_PID_INITIAL}" ]]; then
        NEW_EXP_PID="${CUR}"
        break
    fi
done

if [[ -z "${NEW_EXP_PID}" ]]; then
    fail "No new exporter PID appeared after SIGHUP (old PID was ${EXP_PID_INITIAL})"
fi
pass "New exporter PID = ${NEW_EXP_PID} (was ${EXP_PID_INITIAL})"

# Wait for the old exporter to exit and confirm exactly one exporter remains.
# Use field-anchored awk (same logic as exporter_pid) to avoid grep self-match:
# `grep -c "nginx: otel exporter"` would count the grep process itself, whose
# args contain the pattern string, producing false positives.
sleep 2
EXPORTER_COUNT="$(ps -eo pid,args 2>/dev/null \
    | awk '$2 == "nginx:" && $3 == "otel" && $4 == "exporter" {c++} END{print c+0}')"
if [[ "${EXPORTER_COUNT}" -ne 1 ]]; then
    fail "Expected exactly 1 exporter after SIGHUP reload, found ${EXPORTER_COUNT}"
fi
pass "Exactly 1 exporter process after SIGHUP reload"

# ─── Test 5: SIGQUIT — graceful shutdown ─────────────────────────────────────

info "=== Test 5: SIGQUIT (graceful shutdown) ==="

kill -SIGQUIT "${NGINX_PID_T1}"
# Wait up to 5s for the exporter to exit.
wait_for 5 "exporter to exit after SIGQUIT" \
    "[[ -z \"\$(exporter_pid)\" ]]"
pass "No exporter process remains after SIGQUIT"

NGINX_PID_T1=""  # prevent cleanup from killing again
trap - EXIT

# ─── Test 6: zero-cost gate — no exporter when NOT configured ─────────────────

info "=== Test 6: zero-cost gate (no otel_exporter block) ==="

PREFIX_T6="$(mktemp -d /tmp/ngx-otel-lifecycle.XXXXXX)"
NGINX_PID_T6=""

cleanup_t6() {
    [[ -n "${NGINX_PID_T6:-}" ]] && kill "${NGINX_PID_T6}" 2>/dev/null || true
    sleep 1
    rm -rf "${PREFIX_T6}"
}
trap cleanup_t6 EXIT

mkdir -p "${PREFIX_T6}/logs" "${PREFIX_T6}/client_body_temp"

cat > "${PREFIX_T6}/nginx.conf" << CONF
daemon off;
master_process on;
worker_processes 2;
error_log ${PREFIX_T6}/logs/error.log debug;
pid       ${PREFIX_T6}/logs/nginx.pid;
load_module ${MODULE_PATH};
events { worker_connections 64; }
http {
    server {
        listen 127.0.0.1:9201;
        location / { return 200 "ok\n"; }
    }
}
CONF

"${NGINX_BINARY}" -p "${PREFIX_T6}" -c "${PREFIX_T6}/nginx.conf" &
NGINX_PID_T6=$!
sleep 1

if ! kill -0 "${NGINX_PID_T6}" 2>/dev/null; then
    fail "nginx (no-otel config) exited immediately"
fi

if exporter_pid | grep -q .; then
    EXP="$(exporter_pid)"
    fail "Exporter appeared (PID ${EXP}) even though otel_exporter is NOT configured"
fi
pass "No exporter process when otel_exporter is not configured (zero-cost gate)"

kill -SIGQUIT "${NGINX_PID_T6}"
wait_for 5 "nginx (no-otel) to exit" \
    "! kill -0 ${NGINX_PID_T6} 2>/dev/null"
NGINX_PID_T6=""
trap - EXIT

# ─── Summary ─────────────────────────────────────────────────────────────────

echo ""
pass "=== All exporter lifecycle assertions passed ==="
