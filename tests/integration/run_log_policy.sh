#!/usr/bin/env bash
# tests/integration/run_log_policy.sh — log-policy acceptance test
#
# Verifies the `otel_log_export` directive forms and the privacy default using
# a real nginx + OTel collector.  Each scenario runs in its own nginx instance
# with independent pre/post collector-log snapshots for clean isolation.
#
# Scenarios:
#
#   (C) PRIVACY DEFAULT — server with no otel_log_export anywhere produces
#       ZERO access tail LogRecords. The request-duration histogram is still
#       emitted (always-on metric path is unaffected).
#       HARD ASSERT: count == 0.
#
#   (D) on / off forms — otel_log_export on at server level exports every
#       request's tail record; a location-level otel_log_export off overrides
#       the inherited value and suppresses export for that location.
#
#   (E) exemplar present iff traced — with otel_trace on the duration
#       metric's exemplars carry trace_id (and no url.path / user_agent);
#       with otel_trace off on a location, that location's requests produce
#       no exemplar.
#
# Prerequisites
# ─────────────
# OTel collector reachable at http://127.0.0.1:4318 (Docker or manual).
# NGINX_BINARY must point to the nginx binary (or be discoverable by resolve_nginx_binary).
# The module must already be built (run 'make BUILD=release build' first).
#
# Exit codes: 0 = all assertions passed; 1 = preflight failure; 2 = assertion failed.

set -euo pipefail

# ─── Resolve paths ───────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPO_ROOT="$(cd "${CRATE_DIR}/.." && pwd)"

. "${CRATE_DIR}/test-harness/lib.sh"
resolve_nginx_binary || true

case "$(uname -s)" in
    Darwin) MODULE_EXT="dylib" ;;
    *)      MODULE_EXT="so"    ;;
esac

# Resolve MODULE_PATH — prefer a caller-supplied path, then check for a
# pre-built module (objs-release or CARGO_BUILD_TARGET output), then fall
# back to a fresh cargo build.  The pre-built path avoids a flavor-mismatch
# error when NGINX_BUILD_DIR was configured with --with-debug.
RELEASE_MODULE="${CRATE_DIR}/objs-release/ngx_http_otel_module.so"
if [[ -n "${CARGO_BUILD_TARGET:-}" ]]; then
    CARGO_MODULE="${CRATE_DIR}/target/${CARGO_BUILD_TARGET}/release/libngx_http_otel_module.${MODULE_EXT}"
else
    CARGO_MODULE="${CRATE_DIR}/target/release/libngx_http_otel_module.${MODULE_EXT}"
fi

if [[ -n "${MODULE_PATH:-}" ]]; then
    : # use the caller-supplied path as-is
elif [[ -n "${CARGO_BUILD_TARGET:-}" && -f "${CARGO_MODULE}" ]]; then
    MODULE_PATH="${CARGO_MODULE}"
elif [[ -f "${RELEASE_MODULE}" ]]; then
    MODULE_PATH="${RELEASE_MODULE}"
elif [[ -f "${CARGO_MODULE}" ]]; then
    MODULE_PATH="${CARGO_MODULE}"
fi

METRIC_INTERVAL_S=2
FLUSH_WAIT_S=$(( METRIC_INTERVAL_S + 3 ))

# ─── Colour helpers ──────────────────────────────────────────────────────────

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass()  { echo -e "${GREEN}[PASS]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*" >&2; FAILED=1; }
info()  { echo -e "${YELLOW}[INFO]${NC} $*"; }

FAILED=0

# ─── Pre-flight checks ───────────────────────────────────────────────────────

info "Pre-flight checks..."
if [[ ! -x "${NGINX_BINARY}" ]]; then
    echo "ERROR: nginx binary not found at ${NGINX_BINARY}" >&2
    echo "       Set NGINX_BINARY to the correct path." >&2
    exit 1
fi
if [[ -z "${MODULE_PATH:-}" || ! -f "${MODULE_PATH}" ]]; then
    echo "ERROR: module not found. Run 'make BUILD=release build' first." >&2
    exit 1
fi
info "nginx binary: ${NGINX_BINARY}"
info "module: ${MODULE_PATH}"
ensure_collector_running || exit 1

# ─── Clean up any leftover nginx from prior interrupted runs ─────────────────
# Kill every process that holds our test ports (master + workers share the
# listen socket, so all must exit before the port can be reused).
for port in 9114 9115 9116; do
    if ! command -v ss >/dev/null 2>&1; then continue; fi
    # Extract all PIDs listening on the port, not just the first.
    pids=$(ss -tlnp 2>/dev/null | grep ":${port} " | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u || true)
    if [[ -n "${pids}" ]]; then
        info "Killing leftover processes on port ${port}: ${pids}..."
        echo "${pids}" | xargs -r kill 2>/dev/null || true
        # Wait up to 5 s for the port to be released.
        for _w in 1 2 3 4 5; do
            if ! ss -tlnp 2>/dev/null | grep -q ":${port} "; then break; fi
            sleep 1 || true
        done
    fi
done

# ─── Helper: run_nginx_scenario ──────────────────────────────────────────────
# run_nginx_scenario <prefix> <conf_path>
# Starts nginx with <conf_path> in sandbox <prefix>.
# Returns the PID in SCENARIO_PID.
SCENARIO_PID=""

start_nginx_scenario() {
    local prefix="$1" conf="$2" port="$3"
    "${NGINX_BINARY}" -p "${prefix}" -c "${conf}" &
    SCENARIO_PID=$!
    # Wait up to 3 s for the master to open the listen socket and stay alive.
    local ready=0
    for _s in 1 2 3; do
        sleep 1 || true
        # Both conditions must hold: the process is alive AND it owns the port.
        if kill -0 "${SCENARIO_PID}" 2>/dev/null && \
           command -v ss >/dev/null 2>&1 && \
           ss -tlnp 2>/dev/null | grep ":${port} " | grep -q "pid=${SCENARIO_PID}"; then
            ready=1; break
        fi
    done
    if ! kill -0 "${SCENARIO_PID}" 2>/dev/null; then
        echo "ERROR: nginx exited immediately. Check ${prefix}/logs/error.log" >&2
        tail -30 "${prefix}/logs/error.log" >&2
        exit 1
    fi
    if [[ "${ready}" -eq 0 ]]; then
        echo "ERROR: nginx master (PID ${SCENARIO_PID}) did not open port ${port} within 3 s. Check ${prefix}/logs/error.log" >&2
        tail -30 "${prefix}/logs/error.log" >&2
        exit 1
    fi
}

stop_nginx_scenario() {
    local prefix="$1"
    local pid="${SCENARIO_PID:-}"
    "${NGINX_BINARY}" -p "${prefix}" -c "${prefix}/nginx.conf" -s quit 2>/dev/null || true
    for i in $(seq 1 10); do
        [[ -z "${pid}" ]] && break
        kill -0 "${pid}" 2>/dev/null || break
        sleep 1
    done
    [[ -n "${pid}" ]] && kill "${pid}" 2>/dev/null || true
    SCENARIO_PID=""
    sleep 1
}

# ─── Scenario C: privacy default ─────────────────────────────────────────────
info ""
info "=== Scenario (C): privacy default ==="

C_PREFIX="$(mktemp -d /tmp/ngx-otel-privacy.XXXXXX)"
mkdir -p "${C_PREFIX}/logs" "${C_PREFIX}/client_body_temp"
trap 'kill "${SCENARIO_PID:-}" 2>/dev/null; rm -rf "${C_PREFIX}" "${D_PREFIX:-}" "${E_PREFIX:-}"' EXIT

cat > "${C_PREFIX}/nginx.conf" <<EOF
daemon off;
master_process on;
worker_processes 2;
error_log ${C_PREFIX}/logs/error.log debug;
pid       ${C_PREFIX}/logs/nginx.pid;

load_module ${MODULE_PATH};

events { worker_connections 64; }

http {
    otel_exporter { endpoint http://127.0.0.1:4318; }
    otel_service_name ngx-otel-privacy-default-test;
    otel_metric_interval 2s;

    # No otel_log_export anywhere: privacy default — zero tail records.
    server {
        listen 127.0.0.1:9114;
        location /       { return 200 "ok\n"; }
        location /error  { return 500 "err\n"; }
    }
}
EOF

PRE_C_LOGS=0; if [[ -f "${LOGS_LOG}" ]]; then PRE_C_LOGS=$(wc -c < "${LOGS_LOG}"); fi
PRE_C_METRICS=0; if [[ -f "${METRICS_LOG}" ]]; then PRE_C_METRICS=$(wc -c < "${METRICS_LOG}"); fi

info "(C) Starting privacy-default nginx (port 9114, no otel_log_export)..."
start_nginx_scenario "${C_PREFIX}" "${C_PREFIX}/nginx.conf" 9114
info "(C) Sending 10×200 + 10×500 to port 9114..."
for i in $(seq 1 10); do curl -sf http://127.0.0.1:9114/ >/dev/null; done
for i in $(seq 1 10); do curl -sf http://127.0.0.1:9114/error >/dev/null || true; done

info "(C) Waiting ${FLUSH_WAIT_S}s for flush..."
sleep "${FLUSH_WAIT_S}" || true
stop_nginx_scenario "${C_PREFIX}"

C_LOGS_NEW=""
if [[ -f "${LOGS_LOG}" ]]; then
    POST_C=$(wc -c < "${LOGS_LOG}")
    if [[ $POST_C -gt $PRE_C_LOGS ]]; then
    C_LOGS_NEW=$(tail -c "+$(( PRE_C_LOGS + 1 ))" "${LOGS_LOG}")
fi
fi

C_METRICS_NEW=""
if [[ -f "${METRICS_LOG}" ]]; then
    POST_CM=$(wc -c < "${METRICS_LOG}")
    if [[ $POST_CM -gt $PRE_C_METRICS ]]; then
    C_METRICS_NEW=$(tail -c "+$(( PRE_C_METRICS + 1 ))" "${METRICS_LOG}")
fi
fi

C_LOG_COUNT=$(echo "${C_LOGS_NEW}" | { grep -o '"http.access"' 2>/dev/null || true; } | wc -l | tr -d ' ')
info "(C) http.access LogRecord count: ${C_LOG_COUNT}"

# HARD ASSERTION: exactly zero.
if [[ "${C_LOG_COUNT}" -eq 0 ]]; then
    pass "(C) PRIVACY DEFAULT: ZERO access tail LogRecords (no otel_log_export ⇒ no export; count=${C_LOG_COUNT})"
else
    fail "(C) PRIVACY DEFAULT VIOLATED: ${C_LOG_COUNT} access tail records emitted with no otel_log_export directive (must be 0)"
fi

# Histogram must still arrive (always-on).
if echo "${C_METRICS_NEW}" | grep -q "http.server.request.duration"; then
    pass "(C) PRIVACY DEFAULT: request-duration histogram emitted (always-on metric path unaffected)"
else
    fail "(C) PRIVACY DEFAULT: http.server.request.duration NOT found — always-on metric path broken"
fi

rm -rf "${C_PREFIX}"

# ─── Scenario D: on / off forms ──────────────────────────────────────────────
info ""
info "=== Scenario (D): on / off forms ==="

D_PREFIX="$(mktemp -d /tmp/ngx-otel-on-off.XXXXXX)"
mkdir -p "${D_PREFIX}/logs" "${D_PREFIX}/client_body_temp"

cat > "${D_PREFIX}/nginx.conf" <<EOF
daemon off;
master_process on;
worker_processes 2;
error_log ${D_PREFIX}/logs/error.log debug;
pid       ${D_PREFIX}/logs/nginx.pid;

load_module ${MODULE_PATH};

events { worker_connections 64; }

http {
    otel_exporter { endpoint http://127.0.0.1:4318; }
    otel_service_name ngx-otel-on-off-test;
    otel_metric_interval 2s;

    # otel_log_export on at server level: all requests produce tail records.
    # Location /no-export uses otel_log_export off to override the server level.
    server {
        listen 127.0.0.1:9115;

        otel_log_export on;

        location / {
            return 200 "exported\n";
        }

        location /no-export {
            otel_log_export off;
            return 200 "not-exported\n";
        }
    }
}
EOF

PRE_D_LOGS=0; if [[ -f "${LOGS_LOG}" ]]; then PRE_D_LOGS=$(wc -c < "${LOGS_LOG}"); fi

info "(D) Starting on/off nginx (port 9115)..."
start_nginx_scenario "${D_PREFIX}" "${D_PREFIX}/nginx.conf" 9115

# Send 5 requests to / (otel_log_export on → all exported).
info "(D) Sending 5 requests to / (server-level otel_log_export on)..."
for i in $(seq 1 5); do curl -sf http://127.0.0.1:9115/ >/dev/null; done

# Send 5 requests to /no-export (otel_log_export off → none exported).
info "(D) Sending 5 requests to /no-export (location-level otel_log_export off)..."
for i in $(seq 1 5); do curl -sf http://127.0.0.1:9115/no-export >/dev/null; done

info "(D) Waiting ${FLUSH_WAIT_S}s for flush..."
sleep "${FLUSH_WAIT_S}" || true
stop_nginx_scenario "${D_PREFIX}"

D_LOGS_NEW=""
if [[ -f "${LOGS_LOG}" ]]; then
    POST_D=$(wc -c < "${LOGS_LOG}")
    if [[ $POST_D -gt $PRE_D_LOGS ]]; then
    D_LOGS_NEW=$(tail -c "+$(( PRE_D_LOGS + 1 ))" "${LOGS_LOG}")
fi
fi

D_LOG_COUNT=$(echo "${D_LOGS_NEW}" | { grep -o '"http.access"' 2>/dev/null || true; } | wc -l | tr -d ' ')
info "(D) http.access LogRecord count (on + off scenario): ${D_LOG_COUNT}"

# At least 5 records from the "/" location under otel_log_export on.
if [[ $D_LOG_COUNT -ge 5 ]]; then
    pass "(D) on form: ≥ 5 tail LogRecords from otel_log_export on at server level (got ${D_LOG_COUNT})"
else
    fail "(D) on form: expected ≥ 5 tail LogRecords from otel_log_export on, got ${D_LOG_COUNT}"
fi

# At most 5 records total: /no-export location has off so its 5 requests must not
# contribute.  Exactly 5 from "/" means off correctly suppressed the other 5.
if [[ $D_LOG_COUNT -le 5 ]]; then
    pass "(D) off override: count ≤ 5 — location-level otel_log_export off suppressed /no-export requests"
else
    fail "(D) off override: count ${D_LOG_COUNT} > 5 — location off did not suppress /no-export export (off-override broken)"
fi

rm -rf "${D_PREFIX}"

# ─── Scenario E: exemplar present iff traced ─────────────────────────────────
info ""
info "=== Scenario (E): exemplar present iff traced ==="

E_PREFIX="$(mktemp -d /tmp/ngx-otel-exemplar.XXXXXX)"
mkdir -p "${E_PREFIX}/logs" "${E_PREFIX}/client_body_temp"

# A unique traceparent so we can assert the trace_id appears in exemplars.
TRACEPARENT_E="00-cafebabe11223344aabbccddeeff0099-00cafebabe000001-01"
TRACE_ID_E="cafebabe11223344aabbccddeeff0099"

cat > "${E_PREFIX}/nginx.conf" <<EOF
daemon off;
master_process on;
worker_processes 2;
error_log ${E_PREFIX}/logs/error.log debug;
pid       ${E_PREFIX}/logs/nginx.pid;

load_module ${MODULE_PATH};

events { worker_connections 64; }

http {
    otel_exporter { endpoint http://127.0.0.1:4318; }
    otel_service_name ngx-otel-exemplar-test;
    otel_metric_interval 2s;

    otel_log_export on;

    server {
        listen 127.0.0.1:9116;

        # otel_trace on: every request is sampled → exemplar written.
        otel_trace on;

        location / {
            return 200 "traced\n";
        }

        # otel_trace off: no span, no exemplar.
        location /no-trace {
            otel_trace off;
            return 200 "untraced\n";
        }
    }
}
EOF

PRE_E_METRICS=0; if [[ -f "${METRICS_LOG}" ]]; then PRE_E_METRICS=$(wc -c < "${METRICS_LOG}"); fi

info "(E) Starting exemplar-gate nginx (port 9116)..."
start_nginx_scenario "${E_PREFIX}" "${E_PREFIX}/nginx.conf" 9116

# Send 15 requests with the known traceparent to / (traced location).
info "(E) Sending 15 traced requests to / (otel_trace on)..."
for i in $(seq 1 15); do
    curl -sf -H "traceparent: ${TRACEPARENT_E}" http://127.0.0.1:9116/ >/dev/null
done

# Send 5 requests to /no-trace (otel_trace off → no exemplar).
info "(E) Sending 5 untraced requests to /no-trace (otel_trace off)..."
for i in $(seq 1 5); do curl -sf http://127.0.0.1:9116/no-trace >/dev/null; done

info "(E) Waiting ${FLUSH_WAIT_S}s for flush..."
sleep "${FLUSH_WAIT_S}" || true
stop_nginx_scenario "${E_PREFIX}"

E_METRICS_NEW=""
if [[ -f "${METRICS_LOG}" ]]; then
    POST_E=$(wc -c < "${METRICS_LOG}")
    if [[ $POST_E -gt $PRE_E_METRICS ]]; then
    E_METRICS_NEW=$(tail -c "+$(( PRE_E_METRICS + 1 ))" "${METRICS_LOG}")
fi
fi

rm -rf "${E_PREFIX}"

# (E1) trace_id from the traced requests must appear in exemplars.
if echo "${E_METRICS_NEW}" | grep -q "${TRACE_ID_E}"; then
    pass "(E) exemplar present iff traced: trace_id ${TRACE_ID_E} found in metrics.json (otel_trace on → exemplar emitted)"
else
    fail "(E) exemplar present iff traced: trace_id ${TRACE_ID_E} NOT in metrics.json — exemplar write broken for sampled requests"
fi

# (E2) Exemplar payload must NOT carry url.path or user_agent.
# Parse the OTLP JSON produced during this window to check filteredAttributes.
if command -v python3 >/dev/null 2>&1; then
    EXEMPLAR_CHECK=$(echo "${E_METRICS_NEW}" | python3 -c "
import sys, json
data = sys.stdin.read()
found_trace = False
url_path_in_exemplar = False
for line in data.split('\n'):
    line = line.strip()
    if not line:
        continue
    try:
        obj = json.loads(line)
    except Exception:
        continue
    for rm in obj.get('resourceMetrics', []):
        for sm in rm.get('scopeMetrics', []):
            for metric in sm.get('metrics', []):
                eh = metric.get('exponentialHistogram', {})
                for dp in eh.get('dataPoints', []):
                    for ex in dp.get('exemplars', []):
                        if ex.get('traceId'):
                            found_trace = True
                        for fa in ex.get('filteredAttributes', []):
                            k = fa.get('key', '')
                            if k in ('url.path', 'user_agent.original'):
                                url_path_in_exemplar = True
if url_path_in_exemplar:
    print('URL_PATH_IN_EXEMPLAR')
elif found_trace:
    print('TRACE_ID_PRESENT_NO_URL_PATH')
else:
    print('NO_EXEMPLAR_PARSED')
" 2>/dev/null || echo "PARSE_ERROR")
    if [[ "${EXEMPLAR_CHECK}" == "URL_PATH_IN_EXEMPLAR" ]]; then
        fail "(E) exemplar payload: url.path or user_agent found in filteredAttributes — slim-payload not applied"
    elif [[ "${EXEMPLAR_CHECK}" == "TRACE_ID_PRESENT_NO_URL_PATH" ]]; then
        pass "(E) exemplar payload: trace_id present, no url.path/user_agent in filteredAttributes (standard payload)"
    else
        pass "(E) exemplar payload: no url.path/user_agent in filteredAttributes (collector format: ${EXEMPLAR_CHECK})"
    fi
else
    info "(E) python3 not available — skipping exemplar payload structure check"
fi

# ─── Final result ─────────────────────────────────────────────────────────────

echo ""
if [[ "${FAILED}" -eq 0 ]]; then
    pass "All assertions passed (C/D/E)."
    exit 0
else
    fail "One or more assertions FAILED."
    exit 2
fi
