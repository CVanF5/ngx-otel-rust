#!/usr/bin/env bash
# build/asan-run.sh — run the integration suite under AddressSanitizer (ASan).
#
# WHY THIS EXISTS
# ──────────────
# ngx-rust PR #295 ("async: always defer task wakes via ngx_post_event") drops
# the synchronous inline re-poll from the executor and always defers wakes one
# event-loop tick.  The open review concern (bavshin-f5) is a *use-after-free*:
# a deferred wake could be processed after nginx has already torn down / freed
# the connection or event context the woken task then touches.  TSAN catches
# data races, not UAF — so this harness runs the suite under ASan to surface
# any UAF that actually occurs on the exercised wake paths (resolver wake,
# Sleep timer wake, hyper/h2 connection setup+teardown, reload/cancellation).
#
# ASan cannot prove the *absence* of UAF (only exercised paths are checked),
# but it loudly catches the ones that do occur.
#
# DESIGN (mirrors build/tsan-run.sh)
# ──────────────────────────────────
#   Step 1 – Compile sanity: `make build BUILD=sanitize` (build/build-sanitize.mk)
#            verifies all ASan flags are accepted by clang + rustc.
#   Step 2 – Plain ASan nginx (no --add-module) so the module can be loaded
#            dynamically via load_module without the "already loaded" guard.
#            NGX_DEBUG_PALLOC=1 (from build-sanitize.mk) routes nginx pool
#            allocations through malloc so ASan can poison freed pool memory —
#            this is what makes a UAF on a freed nginx connection detectable.
#   Step 2.5 Pre-build examples/bidi_echo_server WITHOUT ASan (Tokio binary;
#            its sanitizer-runtime symbols are unresolved when linked stand-
#            alone, and we don't want Tokio internals instrumented).
#   Step 3 – Export ASan RUSTFLAGS + build-std steering so each integration
#            script's own `cargo build --release` produces an ASan cdylib.
#   Step 4 – Run the wake-path-relevant integration scripts.
#   Step 5 – Scan the ASan log dir for any report files (a UAF / heap-overflow
#            writes ${RUNDIR}/asan.<pid>); fail the gate if any exist.
#
# RUN: on the Linux verification host (debian-vm), NOT macOS.
#   bash build/asan-run.sh                 # default script set
#   ASAN_SCRIPTS="run_traces.sh ..." bash build/asan-run.sh   # override

set -euo pipefail

CRATE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NGINX_SRC="${NGINX_SOURCE_DIR:-$(cd "${CRATE}/../nginx" && pwd)}"
PLAIN_OBJS="${CRATE}/objs-asan-plain"
RUNDIR="${ASAN_RUNDIR:-${CRATE}/tests/asan-logs-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "${RUNDIR}"

# ── Provenance header (embedded in artifact by the F2 bar) ───────────────────
# Emit the git commit hash and run date so the artifact is self-provable.
# Inside Docker the container runs as root; the bind-mounted project dir is
# owned by the host user → git "dubious ownership" check.  Mark it safe.
log() { echo "[asan-run] $*"; }
git config --global --add safe.directory "${CRATE}"
GIT_COMMIT="$(git -C "${CRATE}" rev-parse HEAD)"
RUN_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "PROVENANCE: GIT_COMMIT=${GIT_COMMIT} DATE=${RUN_DATE}"

# Wake-path-relevant scripts (override via ASAN_SCRIPTS):
#   grpc_export        — production hyper/h2 persistent export (Sleep timer + h2 wake)
#   grpc_bidi_smoke    — h2 bidi-stream connection lifecycle (honors ECHO_BINARY;
#                        do NOT use run_grpc_bidi_overload.sh — it unconditionally
#                        rebuilds the standalone Tokio example, which cannot link
#                        under -Zsanitizer=address: undefined __asan_* refs)
#   dns_dualstack      — Resolver::handler wake (1 of 2 production wake sites) + connect
#   reload             — nginx reload drops/recreates worker task contexts
#   traces             — full span export E2E
#   access_log         — metrics + exemplars + exception-tail export
#
# Chaos scripts are run separately after the main loop (they need special env
# overrides for timeouts under ASan overhead), controlled by ASAN_CHAOS_SCRIPTS.
#
# run_exporter_reload_overlap.sh is intentionally NOT in the default set: its
# export-content assertion depends on a collector endpoint that returns 404 in
# this harness (orthogonal config, not a memory error), so it would make the
# gate falsely red.  The reload/teardown wake path it covers is exercised by
# run_reload.sh.  Add it back via ASAN_SCRIPTS=... once the endpoint is sorted.
ASAN_SCRIPTS="${ASAN_SCRIPTS:-run_grpc_export.sh run_grpc_bidi_smoke.sh run_dns_dualstack.sh run_reload.sh run_traces.sh run_access_log.sh}"
# Chaos scripts: run after the main loop with ASan-overhead-aware timeout overrides.
# Set ASAN_CHAOS_SCRIPTS="" to skip chaos scripts (e.g. for a quick wake-path-only run).
# FU4: run_b4_daemon_on_gen1.sh and run_b1_spsc_reload_chaos.sh added; both were
# absent from the prior ASan artifact.
# H3F3 gate: run_chaos_quit_responsiveness.sh added (discriminating periodic-send
# deadline assertion; required by the Final Gate F2 bar).
ASAN_CHAOS_SCRIPTS="${ASAN_CHAOS_SCRIPTS:-run_chaos_kill9.sh run_chaos_crashloop.sh run_chaos_dead_collector.sh run_b4_daemon_on_gen1.sh run_b1_spsc_reload_chaos.sh run_chaos_quit_responsiveness.sh}"

cd "${CRATE}"

# ── Step 1: Compile sanity check ─────────────────────────────────────────────
log "Step 1: Compile sanity check (make build BUILD=sanitize)..."
NGINX_SOURCE_DIR="${NGINX_SRC}" \
NGINX_BUILD_DIR="${CRATE}/objs-sanitize" \
make build BUILD=sanitize
log "Step 1: OK — ASan flags accepted by clang + rustc."

# ── Step 2: Plain ASan nginx (no --add-module) for integration tests ─────────
log "Step 2: Building plain ASan nginx (no --add-module)..."
mkdir -p "${PLAIN_OBJS}"
cd "${NGINX_SRC}"
[[ -f Makefile ]] && cp -f Makefile Makefile.asan-bak

auto/configure \
    --with-compat \
    --with-http_stub_status_module \
    --with-cc=clang \
    --with-cc-opt="-O1 -fsanitize=address -fno-omit-frame-pointer -DNGX_DEBUG_PALLOC=1 -DNGX_SUPPRESS_WARN=1" \
    --with-ld-opt="-fsanitize=address" \
    --with-debug \
    --builddir="${PLAIN_OBJS}"

rm -f "${NGINX_SRC}/Makefile"
[[ -f "${NGINX_SRC}/Makefile.asan-bak" ]] && mv -f "${NGINX_SRC}/Makefile.asan-bak" "${NGINX_SRC}/Makefile"

make -f "${PLAIN_OBJS}/Makefile" binary
cd "${CRATE}"
log "Step 2: OK — plain ASan nginx at ${PLAIN_OBJS}/nginx"

# ── Step 2.5: Pre-build bidi_echo_server example WITHOUT ASan ─────────────────
log "Step 2.5: Pre-building bidi_echo_server example (no ASan)..."
(
    cd "${CRATE}"
    NGINX_SOURCE_DIR="${NGINX_SRC}" \
    NGINX_BUILD_DIR="${PLAIN_OBJS}" \
    cargo build --example bidi_echo_server
)
export ECHO_BINARY="${CRATE}/target/debug/examples/bidi_echo_server"
log "Step 2.5: OK — example at ${ECHO_BINARY}"

# ── Step 3: Export ASan env for integration scripts ──────────────────────────
log "Step 3: Exporting ASan env for integration scripts..."
export RUSTFLAGS="-Cforce-frame-pointers=yes -Zsanitizer=address -Zexternal-clangrt"
export RUSTC_BOOTSTRAP=1
export CARGO_BUILD_TARGET="$(rustc -vV | awk '/^host: / { print $2 }')"
export CARGO_UNSTABLE_BUILD_STD="std,panic_abort"

export NGINX_BINARY="${PLAIN_OBJS}/nginx"
export NGINX_SOURCE_DIR="${NGINX_SRC}"
export NGINX_BUILD_DIR="${PLAIN_OBJS}"

# ASan runtime options.
#   log_path        — write reports to ${RUNDIR}/asan.<pid> so a UAF is captured
#                     even when an nginx worker dies (worker stderr is unreliable).
#   detect_leaks=0  — focus the gate on USE-AFTER-FREE (the PR concern); nginx has
#                     intentional pool non-frees that would otherwise be LSan noise.
#   abort_on_error=1 — a real UAF aborts loudly after writing the report.
export ASAN_OPTIONS="detect_leaks=0:detect_stack_use_after_return=1:detect_odr_violation=0:abort_on_error=1:log_path=${RUNDIR}/asan"
export LSAN_OPTIONS="suppressions=${CRATE}/build/lsan-suppressions.txt"

log "ASan nginx:  ${NGINX_BINARY}"
log "RUSTFLAGS:   ${RUSTFLAGS}"
log "ASAN_OPTIONS:${ASAN_OPTIONS}"
log "Report dir:  ${RUNDIR}"

# ── Step 3.5: nm-verification — confirm __asan_* symbols in the cdylib ───────
#
# FU4: the previous ASan artifact contained no evidence that __asan_*
# instrumentation symbols are actually present in the .so the test nginx loads.
# This step counts __asan_* symbols in the exact release cdylib produced under
# the ASan RUSTFLAGS above and fails the run if zero are found.
#
# Pre-build once here; subsequent scripts get a cache hit.
log "Step 3.5: Pre-building ASan-instrumented cdylib..."
(
    cd "${CRATE}"
    NGINX_SOURCE_DIR="${NGINX_SRC}" \
    NGINX_BUILD_DIR="${PLAIN_OBJS}" \
    cargo build --release 2>&1
)

case "$(uname -s)" in
    Darwin) _MEXT="dylib" ;;
    *)      _MEXT="so"    ;;
esac
if [[ -n "${CARGO_BUILD_TARGET:-}" ]]; then
    NM_SO="${CRATE}/target/${CARGO_BUILD_TARGET}/release/libngx_http_otel_module.${_MEXT}"
else
    NM_SO="${CRATE}/target/release/libngx_http_otel_module.${_MEXT}"
fi

log "Step 3.5: nm-check: ${NM_SO}"
if [[ ! -f "${NM_SO}" ]]; then
    log "FAIL: cdylib not found at ${NM_SO}" >&2
    exit 1
fi

ASAN_SYM_COUNT="$(nm "${NM_SO}" 2>/dev/null | grep -c '__asan_' || echo 0)"
log "Step 3.5: __asan_* symbol count in cdylib: ${ASAN_SYM_COUNT}"
if [[ "${ASAN_SYM_COUNT}" -eq 0 ]]; then
    log "FAIL: zero __asan_* symbols in ${NM_SO} — module was NOT compiled with -Zsanitizer=address." >&2
    log "      RUSTFLAGS=${RUSTFLAGS}" >&2
    exit 1
fi
log "Step 3.5: OK — ${ASAN_SYM_COUNT} __asan_* symbols confirmed in $(basename "${NM_SO}")."
log "Step 3.5: full path: ${NM_SO}"

# ── Step 4: Run integration scripts ──────────────────────────────────────────
FAILED_SCRIPTS=()
for s in ${ASAN_SCRIPTS}; do
    echo ""
    log "=== Running ${s} under ASan ==="
    if bash "tests/integration/${s}"; then
        log "${s}: exit 0"
    else
        rc=$?
        log "${s}: NON-ZERO exit ${rc}"
        FAILED_SCRIPTS+=("${s}(rc=${rc})")
    fi
done

# ── Step 4b: Run chaos scripts with ASan-overhead-aware timeout overrides ────
# The chaos scripts build the test-support module (NGX_OTEL_CRASH_ON_STARTUP hook)
# and run crash-loop / dead-collector / kill-9 scenarios.  Under ASan ~5x overhead
# the backoff sleeps are real wall-clock (unaffected), but cargo build and nginx
# spawn overhead may take longer.  MAX_WAIT_S/MAX_WAIT_C=120s is conservative.
CHAOS_KILL9_RC=0
CHAOS_CRASHLOOP_RC=0
CHAOS_DEADCOLL_RC=0
if [[ -n "${ASAN_CHAOS_SCRIPTS}" ]]; then
    for s in ${ASAN_CHAOS_SCRIPTS}; do
        echo ""
        log "=== Running ${s} under ASan (chaos) ==="
        case "${s}" in
            run_chaos_kill9.sh)
                bash "tests/integration/${s}" || CHAOS_KILL9_RC=$?
                if [[ "${CHAOS_KILL9_RC}" -ne 0 ]]; then
                    log "${s}: NON-ZERO exit ${CHAOS_KILL9_RC} — continuing" >&2
                    FAILED_SCRIPTS+=("${s}(rc=${CHAOS_KILL9_RC})")
                fi
                ;;
            run_chaos_crashloop.sh)
                MAX_WAIT_S=120 bash "tests/integration/${s}" || CHAOS_CRASHLOOP_RC=$?
                if [[ "${CHAOS_CRASHLOOP_RC}" -ne 0 ]]; then
                    log "${s}: NON-ZERO exit ${CHAOS_CRASHLOOP_RC} — continuing" >&2
                    FAILED_SCRIPTS+=("${s}(rc=${CHAOS_CRASHLOOP_RC})")
                fi
                ;;
            run_chaos_dead_collector.sh)
                MAX_WAIT_C=120 bash "tests/integration/${s}" || CHAOS_DEADCOLL_RC=$?
                if [[ "${CHAOS_DEADCOLL_RC}" -ne 0 ]]; then
                    log "${s}: NON-ZERO exit ${CHAOS_DEADCOLL_RC} — continuing" >&2
                    FAILED_SCRIPTS+=("${s}(rc=${CHAOS_DEADCOLL_RC})")
                fi
                ;;
            run_b4_daemon_on_gen1.sh)
                # B4: no special timeout override needed; daemon-on lifecycle
                # test has its own internal timing (kill-9 + respawn checks).
                B4_RC=0
                bash "tests/integration/${s}" || B4_RC=$?
                if [[ "${B4_RC}" -ne 0 ]]; then
                    log "${s}: NON-ZERO exit ${B4_RC} — continuing" >&2
                    FAILED_SCRIPTS+=("${s}(rc=${B4_RC})")
                fi
                ;;
            run_b1_spsc_reload_chaos.sh)
                # B1-chaos: USE_SLOW_SINK=1 enables the Python slow-proxy (2s
                # POST delay) to widen the SIGHUP overlap window so mutation (a)
                # is reliable on Linux under ASan overhead.
                B1_RC=0
                USE_SLOW_SINK=1 bash "tests/integration/${s}" || B1_RC=$?
                if [[ "${B1_RC}" -ne 0 ]]; then
                    log "${s}: NON-ZERO exit ${B1_RC} — continuing" >&2
                    FAILED_SCRIPTS+=("${s}(rc=${B1_RC})")
                fi
                ;;
            run_chaos_quit_responsiveness.sh)
                # H3F3 gate: discriminating periodic-send deadline assertion.
                # Wall-clock timers (PERIODIC_SEND_BUDGET = 15s real-time) are
                # unaffected by ASan ~5x CPU overhead, so default
                # SIGNATURE_WAIT=22s / QUIT_CEILING=25s are sufficient.
                QUITRESP_RC=0
                bash "tests/integration/${s}" || QUITRESP_RC=$?
                if [[ "${QUITRESP_RC}" -ne 0 ]]; then
                    log "${s}: NON-ZERO exit ${QUITRESP_RC} — continuing" >&2
                    FAILED_SCRIPTS+=("${s}(rc=${QUITRESP_RC})")
                fi
                ;;
            *)
                if bash "tests/integration/${s}"; then
                    log "${s}: exit 0"
                else
                    rc=$?
                    log "${s}: NON-ZERO exit ${rc}" >&2
                    FAILED_SCRIPTS+=("${s}(rc=${rc})")
                fi
                ;;
        esac
    done
fi

# ── Step 5: Scan for AddressSanitizer reports ────────────────────────────────
echo ""
log "Scanning ${RUNDIR} for AddressSanitizer reports..."
shopt -s nullglob
REPORTS=( "${RUNDIR}"/asan.* )
shopt -u nullglob

if (( ${#REPORTS[@]} > 0 )); then
    log "FAIL: ${#REPORTS[@]} AddressSanitizer report file(s) written:" >&2
    for r in "${REPORTS[@]}"; do
        echo "----- ${r} -----" >&2
        sed -n '1,40p' "${r}" >&2
    done
    log "STOP-AND-ASK: AddressSanitizer findings present — surface the full reports for review." >&2
    exit 1
fi

if (( ${#FAILED_SCRIPTS[@]} > 0 )); then
    log "NOTE: no ASan reports, but these scripts exited non-zero: ${FAILED_SCRIPTS[*]}" >&2
    log "      (functional/assertion failure, not a memory error — inspect separately)" >&2
    exit 2
fi

log "Zero AddressSanitizer reports across: ${ASAN_SCRIPTS} ${ASAN_CHAOS_SCRIPTS}"
log "ASan gate: PASS (no use-after-free / heap error on the exercised wake paths)."
