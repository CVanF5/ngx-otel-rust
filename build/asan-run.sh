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
# run_exporter_reload_overlap.sh is intentionally NOT in the default set: its
# export-content assertion depends on a collector endpoint that returns 404 in
# this harness (orthogonal config, not a memory error), so it would make the
# gate falsely red.  The reload/teardown wake path it covers is exercised by
# run_reload.sh.  Add it back via ASAN_SCRIPTS=... once the endpoint is sorted.
ASAN_SCRIPTS="${ASAN_SCRIPTS:-run_grpc_export.sh run_grpc_bidi_smoke.sh run_dns_dualstack.sh run_reload.sh run_traces.sh run_access_log.sh}"

log() { echo "[asan-run] $*"; }

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

log "Zero AddressSanitizer reports across: ${ASAN_SCRIPTS}"
log "ASan gate: PASS (no use-after-free / heap error on the exercised wake paths)."
