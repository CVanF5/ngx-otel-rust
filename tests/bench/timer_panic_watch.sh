#!/usr/bin/env bash
# tests/bench/timer_panic_watch.sh — Phase 1.2 sub-item 3.2
#
# Regression watchpoint for the hyper Time::sleep() panic path.
# Invokes run_grpc_smoke.sh in a bounded loop and checks each iteration's
# error.log for hyper timer panics and worker crash signals.
#
# Background: the panic at hyper/src/common/time.rs:37 ("You must supply a
# timer") is structurally unreachable in our config: we use the function-form
# hyper::client::conn::http2::handshake (no Builder, no keep_alive_interval,
# default keep_alive_interval = None) so ping::channel is never called.  This
# loop is a regression watchpoint that guards against future config drift
# toward keep-alive that would silently make the panic reachable.
#
# Usage (from the ngx-otel-rust directory):
#   bash tests/bench/timer_panic_watch.sh          # 60-second ad-hoc run
#   LOOP_FOR=3600 bash tests/bench/timer_panic_watch.sh  # formal 1-hour gate
#
# Environment:
#   LOOP_FOR         — total wall-clock seconds to run (default: 60)
#   LOOP_INTERVAL_S  — sleep between iterations in seconds (default: 1)
#   TIMEOUT_S        — per-iteration timeout in seconds (default: 10)
#   NGINX_BINARY     — path to the nginx binary (default: auto-detected)
#   NGINX_SOURCE_DIR — nginx source tree (default: ../nginx)
#   NGINX_BUILD_DIR  — nginx build dir   (default: ../nginx/objs)
#
# Exit codes:
#   0  all iterations completed; zero panics or crash signals
#   1  a hyper Time::sleep panic or worker crash signal was detected
#   2  run_grpc_smoke.sh itself failed (non-zero exit or per-iteration timeout)

set -euo pipefail

# ─── Resolve paths ───────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPO_ROOT="$(cd "${CRATE_DIR}/.." && pwd)"

LOOP_FOR="${LOOP_FOR:-60}"
LOOP_INTERVAL_S="${LOOP_INTERVAL_S:-1}"
TIMEOUT_S="${TIMEOUT_S:-10}"

NGINX_SOURCE_DIR="${NGINX_SOURCE_DIR:-${REPO_ROOT}/nginx}"
NGINX_BUILD_DIR="${NGINX_BUILD_DIR:-${REPO_ROOT}/nginx/objs}"
# NGINX_BINARY left unset so run_grpc_smoke.sh auto-detects unless the caller
# sets it explicitly.

# ─── Helpers ─────────────────────────────────────────────────────────────────

info()  { echo "[timer_panic_watch] $*"; }
warn()  { echo "[timer_panic_watch] WARNING: $*" >&2; }
fail()  { echo "[timer_panic_watch] FAIL: $*" >&2; }

# Detect the per-iteration timeout command.  Linux ships GNU coreutils timeout;
# macOS ships nothing but Homebrew's coreutils provides gtimeout.  If neither
# is available (unlikely in CI), run without a per-iteration guard.
TIMEOUT_CMD=""
if command -v timeout >/dev/null 2>&1; then
    TIMEOUT_CMD="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
    TIMEOUT_CMD="gtimeout"
else
    warn "timeout command not found; per-iteration guard disabled"
fi

# ─── Pre-flight build ────────────────────────────────────────────────────────
# Build the module once before the loop.  Subsequent cargo build invocations
# inside run_grpc_smoke.sh will be cache hits (~0.1s), keeping each iteration
# well within TIMEOUT_S.

info "LOOP_FOR=${LOOP_FOR}s  LOOP_INTERVAL_S=${LOOP_INTERVAL_S}s  TIMEOUT_S=${TIMEOUT_S}s"
info "Pre-building module (--features test-support)..."
(
    cd "${CRATE_DIR}"
    NGINX_SOURCE_DIR="${NGINX_SOURCE_DIR}" \
    NGINX_BUILD_DIR="${NGINX_BUILD_DIR}" \
    cargo build --release --features test-support 2>&1
)
info "Module built.  Starting watch loop..."

# ─── Watch loop ──────────────────────────────────────────────────────────────

ITERATION=0
SUCCESS=0
START=${SECONDS}

# Export vars that are stable across iterations.
export NGINX_SOURCE_DIR NGINX_BUILD_DIR

while (( SECONDS - START < LOOP_FOR )); do
    ITERATION=$(( ITERATION + 1 ))

    # Remove any sandbox left by a previous iteration so the find-after-run
    # step picks up exactly one directory for THIS iteration.
    rm -rf /tmp/ngx-otel-grpc-smoke.* 2>/dev/null || true

    # Run the smoke script.
    #   KEEP_SANDBOX=1 — preserve the sandbox dir so we can read error.log.
    #   TIMEOUT_S      — abort if nginx hangs (exit 124 from timeout(1)).
    # Env vars exported above are inherited; NGINX_BINARY is forwarded only
    # when the caller set it (avoids overriding the script's auto-detection).
    SMOKE_ENV=(
        "KEEP_SANDBOX=1"
        "NGINX_SOURCE_DIR=${NGINX_SOURCE_DIR}"
        "NGINX_BUILD_DIR=${NGINX_BUILD_DIR}"
    )
    [[ -n "${NGINX_BINARY:-}" ]] && SMOKE_ENV+=("NGINX_BINARY=${NGINX_BINARY}")

    TIMEOUT_PREFIX=()
    [[ -n "${TIMEOUT_CMD}" ]] && TIMEOUT_PREFIX=("${TIMEOUT_CMD}" "${TIMEOUT_S}")

    if ! env "${SMOKE_ENV[@]}" "${TIMEOUT_PREFIX[@]}" \
            bash "${CRATE_DIR}/tests/integration/run_grpc_smoke.sh"; then
        fail "iteration ${ITERATION}: run_grpc_smoke.sh exited non-zero (timeout or error)"
        SANDBOX="$(ls -d /tmp/ngx-otel-grpc-smoke.* 2>/dev/null | head -1 || true)"
        if [[ -n "${SANDBOX}" && -f "${SANDBOX}/logs/error.log" ]]; then
            echo "=== error.log (last 30 lines) ===" >&2
            tail -30 "${SANDBOX}/logs/error.log" >&2
        fi
        exit 2
    fi

    # Locate the preserved sandbox for this iteration.
    SANDBOX="$(ls -d /tmp/ngx-otel-grpc-smoke.* 2>/dev/null | head -1 || true)"
    LOG=""
    [[ -n "${SANDBOX}" && -f "${SANDBOX}/logs/error.log" ]] && LOG="${SANDBOX}/logs/error.log"

    if [[ -n "${LOG}" ]]; then
        # ── Pattern 1: hyper Time::sleep() panic ─────────────────────────────
        # Matches:   panicked at 'You must supply a timer', hyper/src/common/time.rs:37
        # and newer: panicked at hyper/src/common/time.rs:37: You must supply a timer
        if grep -qE "panicked at .*(hyper.src.common.time|You must supply a timer)" \
                "${LOG}" 2>/dev/null; then
            fail "iteration ${ITERATION}: Time::sleep panic detected — STOP-AND-ASK"
            grep -E "panicked at .*(hyper.src.common.time|You must supply a timer)" "${LOG}" >&2
            exit 1
        fi

        # ── Pattern 2: worker crash signals ──────────────────────────────────
        # SIGABRT (6) = Rust panic reaching nginx; SIGSEGV (11) = memory fault.
        if grep -qE "signal (6|11)" "${LOG}" 2>/dev/null; then
            fail "iteration ${ITERATION}: worker crash signal detected"
            grep -E "signal (6|11)" "${LOG}" >&2
            exit 1
        fi

        # Clean up the preserved sandbox now that checks passed.
        rm -rf "${SANDBOX}"
    fi

    SUCCESS=$(( SUCCESS + 1 ))

    # Brief inter-iteration sleep; keeps the loop at ≥1 effective RPS even
    # when the smoke test completes in under 1s.
    sleep "${LOOP_INTERVAL_S}"
done

ELAPSED=$(( SECONDS - START ))
echo "timer_panic_watch: ${ITERATION} runs in ${ELAPSED}s, zero panics"
