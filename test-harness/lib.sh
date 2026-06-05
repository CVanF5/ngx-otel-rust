#!/usr/bin/env bash
# test-harness/lib.sh — shared helpers for ngx-otel-rust integration scripts.
#
# Sourcing this file gives callers:
#
#   - HARNESS_DIR             — absolute path to test-harness/
#   - COLLECTOR_CONTAINER     — docker container name (ngx-otel-test-collector)
#   - COLLECTOR_HTTP_ENDPOINT — http://127.0.0.1:4318
#   - METRICS_LOG             — test-harness/logs/metrics.json
#
#   - ensure_collector_running   — start the collector if not already up;
#                                  wait until OTLP/HTTP receiver answers.
#                                  Honors OTEL_COLLECTOR_AUTOSTART=0 to skip
#                                  auto-start (CI envs that manage the
#                                  collector externally).
#   - collector_status           — pretty-print whether the container is up.
#   - collector_down             — stop the container via docker compose.
#
# Designed to be `source`-d, not executed directly.  Callers typically do:
#
#   THIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
#   . "${THIS_DIR}/../../test-harness/lib.sh"
#   ensure_collector_running

# Idempotent: don't re-source the contents if already loaded.
if [[ -n "${_NGX_OTEL_HARNESS_LIB_LOADED:-}" ]]; then
    return 0
fi
_NGX_OTEL_HARNESS_LIB_LOADED=1

# Resolve our own location so callers don't need to compute it.
HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The crate root is the parent of test-harness/.
HARNESS_CRATE_DIR="$(dirname "${HARNESS_DIR}")"

COLLECTOR_CONTAINER="${COLLECTOR_CONTAINER:-ngx-otel-test-collector}"
COLLECTOR_HTTP_ENDPOINT="${COLLECTOR_HTTP_ENDPOINT:-http://127.0.0.1:4318}"
METRICS_LOG="${METRICS_LOG:-${HARNESS_DIR}/logs/metrics.json}"
LOGS_LOG="${LOGS_LOG:-${HARNESS_DIR}/logs/logs.json}"

# Tunables (override via env in callers if needed):
COLLECTOR_STARTUP_TIMEOUT_S="${COLLECTOR_STARTUP_TIMEOUT_S:-15}"
COLLECTOR_POLL_INTERVAL_S="${COLLECTOR_POLL_INTERVAL_S:-1}"

# ─── Internal helpers ────────────────────────────────────────────────────────

# Echo to stderr without the calling script's color prefixes.
_harness_info() { echo "[harness] $*" >&2; }
_harness_err()  { echo "[harness] ERROR: $*" >&2; }

# Is the named container currently running?
_collector_container_running() {
    docker ps --filter "name=^/${COLLECTOR_CONTAINER}\$" --filter "status=running" --format '{{.Names}}' 2>/dev/null \
        | grep -qx "${COLLECTOR_CONTAINER}"
}

# Does the OTLP/HTTP receiver answer?  Empty response on /v1/metrics with no
# body is still a successful TCP+HTTP roundtrip; we only care about reachability.
_collector_endpoint_reachable() {
    curl -s --connect-timeout 2 --max-time 3 "${COLLECTOR_HTTP_ENDPOINT}/" >/dev/null 2>&1
}

# Block until the endpoint answers or COLLECTOR_STARTUP_TIMEOUT_S elapses.
_wait_for_collector() {
    local deadline=$(( SECONDS + COLLECTOR_STARTUP_TIMEOUT_S ))
    while (( SECONDS < deadline )); do
        if _collector_endpoint_reachable; then
            return 0
        fi
        sleep "${COLLECTOR_POLL_INTERVAL_S}"
    done
    return 1
}

# ─── Public API ──────────────────────────────────────────────────────────────

# Ensure the OTel collector is up and accepting OTLP/HTTP.  Idempotent.
#
# Behavior:
#   - If OTEL_COLLECTOR_AUTOSTART=0 is set: only check reachability, bail
#     with an actionable error message if down.
#   - Otherwise: check whether the container is running; if not, run
#     `docker compose up -d` against test-harness/docker-compose.yml,
#     then wait up to COLLECTOR_STARTUP_TIMEOUT_S seconds for the OTLP/HTTP
#     endpoint to answer.
#
# Returns 0 on success, non-zero on failure.  Prints progress to stderr.
ensure_collector_running() {
    # Fast path: already running and reachable.
    if _collector_endpoint_reachable; then
        _harness_info "collector reachable at ${COLLECTOR_HTTP_ENDPOINT}"
        return 0
    fi

    if [[ "${OTEL_COLLECTOR_AUTOSTART:-1}" == "0" ]]; then
        _harness_err "collector not reachable at ${COLLECTOR_HTTP_ENDPOINT} (autostart disabled)"
        _harness_err "start it manually: cd ${HARNESS_DIR} && docker compose up -d"
        return 1
    fi

    if ! command -v docker >/dev/null 2>&1; then
        _harness_err "docker not found on PATH; cannot auto-start the collector"
        _harness_err "either install docker or start an OTLP/HTTP receiver on ${COLLECTOR_HTTP_ENDPOINT} yourself"
        return 1
    fi

    if _collector_container_running; then
        # Container is up but endpoint didn't answer above — likely still
        # warming up.  Just wait.
        _harness_info "container ${COLLECTOR_CONTAINER} is running; waiting for endpoint to answer..."
    else
        # The collector image's default user is UID 10001. The host script
        # later reads test-harness/logs/metrics.json directly, so files
        # created by the container must be readable by the host user.
        # Run the container as the host user; docker-compose.yml consumes
        # these via ${OTEL_HOST_UID}/${OTEL_HOST_GID} substitution.
        export OTEL_HOST_UID="$(id -u)"
        export OTEL_HOST_GID="$(id -g)"
        _harness_info "starting collector via docker compose (uid=${OTEL_HOST_UID} gid=${OTEL_HOST_GID})..."
        if ! ( cd "${HARNESS_DIR}" && docker compose up -d >&2 ); then
            _harness_err "docker compose up failed"
            return 1
        fi
    fi

    if _wait_for_collector; then
        _harness_info "collector reachable at ${COLLECTOR_HTTP_ENDPOINT}"
        return 0
    fi

    _harness_err "collector did not become reachable within ${COLLECTOR_STARTUP_TIMEOUT_S}s"
    _harness_err "diagnose: docker logs ${COLLECTOR_CONTAINER}"
    return 1
}

# Print a one-line status of the collector container.
collector_status() {
    if _collector_container_running; then
        local id
        id=$(docker ps --filter "name=^/${COLLECTOR_CONTAINER}\$" --format '{{.ID}} ({{.Status}})' 2>/dev/null)
        echo "collector ${COLLECTOR_CONTAINER} is up: ${id}"
    else
        echo "collector ${COLLECTOR_CONTAINER} is NOT running"
    fi
}

# ─── Collector receipt verification ──────────────────────────────────────────
#
# The collector's `file` exporter appends one NDJSON record per export flush to
# METRICS_LOG (test-harness/logs/metrics.json — same path on both the docker
# collector and the host-1 native otelcol-contrib). These helpers let a
# benchmark PROVE a configured exporter actually delivered telemetry during a
# run. Without this, a silent export failure (collector down, wrong port,
# exporter never spawned) makes C3 == C1 and the comparison "passes" for the
# wrong reason — the exact blind spot that motivated this gate.

# Echo the number of metric flush records the collector has written so far.
# 0 if the file is absent. (NDJSON: one ResourceMetrics object per line.)
collector_metric_count() {
    if [[ -f "${METRICS_LOG}" ]]; then
        wc -l < "${METRICS_LOG}" | tr -d ' '
    else
        echo 0
    fi
}

# assert_collector_received <before_count> [label]
# Re-counts METRICS_LOG and returns non-zero if the collector received NO new
# metric records since <before_count>. Prints the delta either way. Capture
# <before_count> immediately before the load run and call this after the
# exporter has had a chance to flush (e.g. after nginx graceful stop drains it):
#   before="$(collector_metric_count)"; <run wrk>; <stop nginx>
#   assert_collector_received "${before}" C3 || exit 2
assert_collector_received() {
    local before="${1:-0}"
    local label="${2:-export}"
    local after
    after="$(collector_metric_count)"
    if (( after > before )); then
        _harness_info "collector-receipt[${label}]: +$(( after - before )) metric record(s) received (${before} -> ${after})"
        return 0
    fi
    if (( after < before )); then
        # The file exporter rotated (10 MB cap) — only happens after heavy
        # writes, so export is confirmed by the rotation itself.
        _harness_info "collector-receipt[${label}]: METRICS_LOG rotated (${before} -> ${after}); export confirmed by rotation"
        return 0
    fi
    _harness_err "collector-receipt[${label}]: NO new metric records received (count unchanged at ${after})."
    _harness_err "  A configured exporter that delivers nothing makes the C3-vs-C1 comparison meaningless."
    _harness_err "  Check: collector reachable on \${COLLECTOR_HTTP_ENDPOINT}? exporter process spawned? endpoint/port correct?"
    return 1
}

# Resolve NGINX_BINARY by checking candidate paths in priority order.
# Honors a pre-existing NGINX_BINARY env value if it points at an
# executable.  Otherwise prefers the make-built artifacts under the
# crate's objs-<flavor>/ directories, falling back to a pre-built
# sibling nginx checkout (../nginx/objs/nginx — the pre-Phase-A
# prototyping path).
#
# Returns 0 if NGINX_BINARY was set to a real executable, 1 otherwise.
# In the failure case, NGINX_BINARY is left set to the last candidate
# so the caller's preflight check produces an actionable error message.
resolve_nginx_binary() {
    if [[ -n "${NGINX_BINARY:-}" && -x "${NGINX_BINARY}" ]]; then
        return 0
    fi
    local candidates=(
        "${HARNESS_CRATE_DIR}/objs-debug/nginx"
        "${HARNESS_CRATE_DIR}/objs-release/nginx"
        "${HARNESS_CRATE_DIR}/../nginx/objs/nginx"
    )
    local c
    for c in "${candidates[@]}"; do
        if [[ -x "$c" ]]; then
            NGINX_BINARY="$c"
            return 0
        fi
    done
    # No match; expose the last candidate so the caller's "binary not
    # found at X" message points somewhere recognisable.
    NGINX_BINARY="${candidates[-1]}"
    return 1
}

# Stop the collector (idempotent).
collector_down() {
    if ! command -v docker >/dev/null 2>&1; then
        _harness_err "docker not found on PATH"
        return 1
    fi
    ( cd "${HARNESS_DIR}" && docker compose down ) || return 1
}
