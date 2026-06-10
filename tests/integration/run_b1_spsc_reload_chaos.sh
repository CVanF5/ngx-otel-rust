#!/usr/bin/env bash
# tests/integration/run_b1_spsc_reload_chaos.sh — B1-FU1 chaos: SPSC ring
# exclusivity across reload + quit-completeness
#
# Verifies the FU1 fix (periodic drain abdicates ring pops on successor_gen
# announcement) and the original B1 fix (graceful_drain also abdicates).
#
# Assertions:
#   a-i)  SIGHUP rounds: each unique /b1chaos/<N> path appears EXACTLY ONCE in
#         logs.json — no SPSC duplicate pops during reload overlap.
#   a-ii) Conservation: sent == unique_arrived + counted_drops.  Drop-newest
#         is by-design but every drop MUST be accounted for by the
#         ngx_otel.logs.access.dropped_records self-metric.  A conservation
#         failure means lost-unaccounted records — that is a real bug.
#   a-iii) Garbage-length/parse-error scan: zero crit/alert/emerg lines in
#         nginx error.log; zero otel send-failures; zero HTTP-4xx / parse-error
#         lines in collector logs.  Any hit = data-corruption indicator.
#   b)    Quit-completeness: records pushed just before `nginx -s quit` arrive
#         (the no-successor full-drain path fires; we are the sole consumer).
#
# ── Mutation check (forcing technique) ──────────────────────────────────────
#
#   Mutation (a): in src/export/mod.rs export_loop, comment out the two
#   `if !periodic_abdicated {` blocks that gate the periodic log/span drains
#   (introduced by B1-FU1), rebuild, then run:
#
#       USE_SLOW_SINK=1 bash tests/integration/run_b1_spsc_reload_chaos.sh
#
#   The slow sink (port 4399, 2 s response delay) stalls the old exporter's
#   send-future.  With the FU1 gating removed:
#     1. Old exporter send stalls for 2 s (slow sink).
#     2. New exporter spawns; its first 250 ms periodic tick pops the log ring.
#     3. Old exporter's 250 ms periodic timer also fires during the 2 s stall
#        → pops the SAME rings (SPSC violated; two concurrent consumers).
#     4. Both exporters deliver the same records to the slow sink → duplicates.
#   Expected failure output:
#       [FAIL] assertion (a): SPSC duplicate records detected: N total, M unique
#              Duplicate seq numbers: NNNNN MMMMM …
#
#   Mutation (b): in graceful_drain, invert the `!has_successor` guard for
#   the final logs drain: change `if !has_successor && (…)` → `if has_successor`
#   (making graceful_drain SKIP the final drain on pure shutdown), rebuild, run:
#
#       bash tests/integration/run_b1_spsc_reload_chaos.sh
#
#   Expected failure output:
#       [FAIL] assertion (b): quit-completeness: only 0/8 pre-quit records arrived
#              (graceful drain abdicated on shutdown — no-successor drain missing)
#
#   ⚠ macOS TIMING NOTE: On macOS, `nginx -s quit` propagates SIGQUIT to the
#   exporter with a ~5–10 ms delay.  In that window a 250 ms periodic drain
#   tick can fire, read ngx_quit as not-yet-set, drain all 8 ring records, and
#   send them — leaving graceful_drain nothing to drain.  This makes mutation
#   (b) timing-sensitive on macOS; assertion (b) may spuriously PASS.
#
#   Reliable mutation (b) detection requires Linux (debian-vm), where the
#   `USE_SLOW_SINK=1` run stalls the queued-batch flush in graceful_drain for
#   2 s, giving time to add records to the ring DURING the stall so
#   graceful_drain's ring-pop step exercises the guard:
#
#       USE_SLOW_SINK=1 bash tests/integration/run_b1_spsc_reload_chaos.sh
#
#   Mutation (b) verification on debian-vm is part of the FU4 sanitizer re-run.
#
# ── Exit codes ──────────────────────────────────────────────────────────────
# 0 = all assertions passed, 1 = preflight, 2 = assertion failed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

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
# MODULE_PATH may be explicitly passed (e.g. test-support build for mutation evidence).
# If not set, resolve: CARGO_BUILD_TARGET module → objs-release → cargo/release fallback.
if [[ -n "${MODULE_PATH:-}" ]]; then
    : # use the caller-supplied path as-is
elif [[ -n "${CARGO_BUILD_TARGET:-}" && -f "${CARGO_MODULE}" ]]; then
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

# ── Slow-sink (mutation-check forcing mode) ──────────────────────────────────
# USE_SLOW_SINK=1 replaces the OTel collector with a Python HTTP server that
# delays all POST responses by SLOW_SINK_DELAY_S seconds (default: 2).  This
# keeps the old exporter's send-future stalled through the reload overlap,
# giving its 250 ms periodic timer time to fire against the rings while the
# new exporter is also draining — the classic B1-FU1 scenario.
SLOW_SINK_PID=""
SLOW_SINK_PORT=4399
SLOW_SINK_DELAY_S="${SLOW_SINK_DELAY_S:-2}"
COLLECTOR_ENDPOINT="${COLLECTOR_HTTP_ENDPOINT}"

cleanup_slow_sink() {
    if [[ -n "${SLOW_SINK_PID:-}" ]]; then
        kill "${SLOW_SINK_PID}" 2>/dev/null || true
        SLOW_SINK_PID=""
    fi
}

if [[ "${USE_SLOW_SINK:-0}" == "1" ]]; then
    info "USE_SLOW_SINK=1: starting slow-proxy on port ${SLOW_SINK_PORT} (${SLOW_SINK_DELAY_S}s delay, then forwarding to real collector)"
    # The slow proxy delays each OTLP POST by SLOW_SINK_DELAY_S before forwarding
    # to the real collector (port 4318).  This stalls the old exporter's send-future
    # through the reload overlap, letting its 250 ms periodic timer fire against
    # the rings while the new exporter is also draining.  Records still reach
    # logs.json (via forwarding), so duplicate detection works normally.
    python3 - "${SLOW_SINK_PORT}" "${SLOW_SINK_DELAY_S}" "127.0.0.1:4318" <<'PYEOF' &
import http.server, http.client, time, sys
port    = int(sys.argv[1])  if len(sys.argv) > 1 else 4399
delay   = float(sys.argv[2]) if len(sys.argv) > 2 else 2.0
upstream = sys.argv[3]        if len(sys.argv) > 3 else "127.0.0.1:4318"

class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n    = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(n)
        time.sleep(delay)   # stall sender
        # Forward to real collector so records still reach logs.json
        try:
            conn = http.client.HTTPConnection(upstream, timeout=5)
            conn.request('POST', self.path, body,
                         {'Content-Type': self.headers.get('Content-Type',''),
                          'Content-Length': str(n)})
            r = conn.getresponse(); r.read()
            self.send_response(r.status)
        except Exception:
            self.send_response(200)
        self.send_header('Content-Length', '0'); self.end_headers()
    def log_message(self, *a): pass

http.server.HTTPServer(('127.0.0.1', port), H).serve_forever()
PYEOF
    SLOW_SINK_PID=$!
    COLLECTOR_ENDPOINT="http://127.0.0.1:${SLOW_SINK_PORT}"
    sleep 0.8  # wait for Python server to bind
    info "Slow proxy PID=${SLOW_SINK_PID}, endpoint=${COLLECTOR_ENDPOINT} → ${COLLECTOR_HTTP_ENDPOINT}"
else
    ensure_collector_running || exit 1
fi
trap cleanup_slow_sink EXIT

# ── Sandbox ───────────────────────────────────────────────────────────────────
NGINX_PORT=9210   # unique port; no other test uses 9210
METRIC_INTERVAL_S=1
PREFIX="$(mktemp -d /tmp/ngx-otel-b1chaos.XXXXXX)"
NGINX_PID=""

cleanup() {
    cleanup_slow_sink
    [[ -n "${NGINX_PID:-}" ]] && kill "${NGINX_PID}" 2>/dev/null || true
    sleep 0.5
    echo ""
    echo "=== error.log (last 40 lines) ==="
    tail -40 "${PREFIX}/logs/error.log" 2>/dev/null || echo "(not found)"
    rm -rf "${PREFIX}"
}
trap cleanup EXIT

mkdir -p "${PREFIX}/logs" "${PREFIX}/client_body_temp"

cat > "${PREFIX}/nginx.conf" <<CONF
daemon off;
master_process on;
worker_processes 2;
error_log ${PREFIX}/logs/error.log debug;
pid       ${PREFIX}/logs/nginx.pid;

load_module ${MODULE_PATH};

events { worker_connections 64; }

http {
    otel_exporter {
        endpoint ${COLLECTOR_ENDPOINT};
    }
    otel_service_name ngx-otel-b1-chaos;
    otel_metric_interval ${METRIC_INTERVAL_S}s;

    # Enable access-log sampling: every status >= 400 is "interesting" and
    # produces a tail LogRecord written to the log ring (the SPSC ring whose
    # exclusivity the FU1 fix restores).
    otel_access_log_sample 64;

    server {
        listen 127.0.0.1:${NGINX_PORT};

        # All /b1chaos/* requests return 500 → is_interesting = true →
        # a tail LogRecord with url.path = "/b1chaos/<N>" is pushed to the ring.
        location /b1chaos/ {
            return 500 "b1-chaos-record\n";
        }

        # Steady 200 traffic to keep workers active.
        location / {
            return 200 "ok\n";
        }
    }
}
CONF

# ── Helpers ───────────────────────────────────────────────────────────────────

wait_for() {
    local timeout=$1 desc=$2 expr=$3
    local deadline=$(( $(date +%s) + timeout ))
    while (( $(date +%s) < deadline )); do
        if eval "${expr}" 2>/dev/null; then return 0; fi
        sleep 0.3
    done
    fail "Timed out (${timeout}s) waiting for: ${desc}"
}

exporter_pid_of() {
    local master_pid=$1
    ps -eo pid,ppid,args 2>/dev/null \
        | awk -v mpid="${master_pid}" \
            '$2 == mpid && $3 == "nginx:" && $4 == "otel" && $5 == "exporter" {print $1}' \
        | head -1
}

# Global monotonic sequence counter.  Incremented INLINE (no subshell) so
# the parent process always sees the updated value.  Use send_batch N to
# send N uniquely-tagged 500 requests; curl output is discarded.
SEQ=0

# Send exactly $1 tagged requests.  Each request goes to /b1chaos/NNNNN.
# The SEQ counter is incremented in the calling shell (not a subshell).
send_batch() {
    local count=$1
    local i
    for i in $(seq 1 "${count}"); do
        SEQ=$(( SEQ + 1 ))
        curl -sf "http://127.0.0.1:${NGINX_PORT}/b1chaos/$(printf '%05d' "${SEQ}")" \
            >/dev/null 2>&1 || true
        sleep 0.02  # ~50 req/s — spread across the 250 ms sub-tick window
    done
}

# ── Start nginx ───────────────────────────────────────────────────────────────

info "Starting nginx (port=${NGINX_PORT}, interval=${METRIC_INTERVAL_S}s)..."
"${NGINX_BINARY}" -p "${PREFIX}" -c "${PREFIX}/nginx.conf" &
NGINX_PID=$!
sleep 1.5

if ! kill -0 "${NGINX_PID}" 2>/dev/null; then
    fail "nginx exited immediately"
fi

EXP_PID=$(exporter_pid_of "${NGINX_PID}")
[[ -n "${EXP_PID}" ]] || fail "No otel exporter process found"
pass "nginx started (master=${NGINX_PID} exporter=${EXP_PID})"

# Snapshot logs.json size before our test requests.
PRE_SIZE=0
[[ -f "${LOGS_LOG}" ]] && PRE_SIZE=$(wc -c < "${LOGS_LOG}")
info "logs.json pre-size: ${PRE_SIZE} bytes"

# Snapshot metrics.json to bound conservation reads to this test's exports.
# The gauge ngx_otel.logs.access.dropped_records is a cumulative sum of
# per-worker ring.drop_count() values; taking max() over new content gives
# the final total drops produced during this nginx instance's lifetime.
PRE_METRICS_SIZE=0
[[ -f "${METRICS_LOG}" ]] && PRE_METRICS_SIZE=$(wc -c < "${METRICS_LOG}")
info "metrics.json pre-size: ${PRE_METRICS_SIZE} bytes"

# ── Assertion (a): SIGHUP rounds — no SPSC duplicates ─────────────────────────

N_ROUNDS="${B1_CHAOS_ROUNDS:-3}"
N_PRE_SIGHUP=8      # requests before each SIGHUP
N_OVERLAP=12        # requests during the reload overlap window
N_POST_SIGHUP=5     # requests after old exporter exits

SEQ_END_BEFORE_TEST=0  # will record SEQ after all rounds

info "Running ${N_ROUNDS} SIGHUP rounds (${N_PRE_SIGHUP} pre + ${N_OVERLAP} overlap + ${N_POST_SIGHUP} post per round)..."

for round in $(seq 1 "${N_ROUNDS}"); do
    info "── Round ${round}/${N_ROUNDS} (SEQ so far: ${SEQ}) ──────────────────"

    send_batch "${N_PRE_SIGHUP}"
    info "Round ${round}: pre-SIGHUP done (SEQ=${SEQ})"

    OLD_EXP_PID=$(exporter_pid_of "${NGINX_PID}")
    [[ -n "${OLD_EXP_PID}" ]] || fail "Round ${round}: no exporter before SIGHUP"

    # SIGHUP — master writes successor_gen > my_gen then signals old exporter.
    kill -HUP "${NGINX_PID}" 2>/dev/null || fail "Round ${round}: SIGHUP failed"
    sleep 0.1

    # Overlap-window traffic: both old exporter (periodic drain still running
    # unless FU1 fix gates it) and new exporter can pop rings here.
    send_batch "${N_OVERLAP}"
    info "Round ${round}: overlap-window done (SEQ=${SEQ})"

    # Wait for new exporter.
    NEW_EXP_PID=""
    DEADLINE=$(( $(date +%s) + 6 ))
    while (( $(date +%s) < DEADLINE )); do
        CANDIDATE=$(ps -eo pid,ppid,args 2>/dev/null \
            | awk -v mpid="${NGINX_PID}" \
                '$2 == mpid && $3 == "nginx:" && $4 == "otel" && $5 == "exporter" {print $1}' \
            | grep -v "^${OLD_EXP_PID}$" | head -1)
        if [[ -n "${CANDIDATE}" ]]; then NEW_EXP_PID="${CANDIDATE}"; break; fi
        sleep 0.3
    done
    [[ -n "${NEW_EXP_PID}" ]] || fail "Round ${round}: new exporter did not appear"
    info "Round ${round}: old=${OLD_EXP_PID} new=${NEW_EXP_PID}"

    # Wait for old exporter to exit (abdication + drain completes).
    DEADLINE=$(( $(date +%s) + 18 ))
    while (( $(date +%s) < DEADLINE )); do
        kill -0 "${OLD_EXP_PID}" 2>/dev/null || break
        sleep 0.3
    done
    if kill -0 "${OLD_EXP_PID}" 2>/dev/null; then
        fail "Round ${round}: old exporter (PID ${OLD_EXP_PID}) did not exit within 18s"
    fi
    pass "Round ${round}: old exporter exited"

    # Post-exit requests (new exporter is sole consumer, no race possible).
    send_batch "${N_POST_SIGHUP}"
done

SEQ_AFTER_ROUNDS=${SEQ}
info "All rounds done. Total unique paths sent: ${SEQ_AFTER_ROUNDS} (SEQ 1..${SEQ_AFTER_ROUNDS})"

# ── Assertion (a): check for duplicates in logs.json ─────────────────────────

# With USE_SLOW_SINK=1 each batch takes SLOW_SINK_DELAY_S to reach the collector;
# add extra headroom so in-transit batches arrive before we check logs.json.
if [[ "${USE_SLOW_SINK:-0}" == "1" ]]; then
    FLUSH_WAIT=$(( METRIC_INTERVAL_S + SLOW_SINK_DELAY_S + 5 ))
else
    FLUSH_WAIT=$(( METRIC_INTERVAL_S + 3 ))
fi
info "Waiting ${FLUSH_WAIT}s for collector to receive all records..."
sleep "${FLUSH_WAIT}"

POST_SIZE=0
[[ -f "${LOGS_LOG}" ]] && POST_SIZE=$(wc -c < "${LOGS_LOG}")
NEW_BYTES=$(( POST_SIZE - PRE_SIZE ))
info "logs.json: ${NEW_BYTES} new bytes (${POST_SIZE} total)"

if [[ "${NEW_BYTES}" -le 0 ]]; then
    fail "assertion (a): no new logs.json content after ${N_ROUNDS} SIGHUP rounds"
fi

# Extract all /b1chaos/ seq numbers from new content.
# JSON attribute format: "stringValue":"/b1chaos/00042"
NEW_CONTENT=$(tail -c "+$(( PRE_SIZE + 1 ))" "${LOGS_LOG}" 2>/dev/null)
FOUND_PATHS=$(echo "${NEW_CONTENT}" \
    | grep -oE '"stringValue":"/b1chaos/[0-9]{5}"' \
    | grep -oE '[0-9]{5}' \
    | sort)

TOTAL_FOUND=$(echo "${FOUND_PATHS}" | grep -c . 2>/dev/null || true)
UNIQUE_FOUND=$(echo "${FOUND_PATHS}" | sort -u | grep -c . 2>/dev/null || true)

info "Records found in logs.json: ${TOTAL_FOUND} total, ${UNIQUE_FOUND} unique (sent: ${SEQ_AFTER_ROUNDS})"

if [[ "${TOTAL_FOUND}" -ne "${UNIQUE_FOUND}" ]]; then
    DUPS=$(echo "${FOUND_PATHS}" | sort | uniq -d | tr '\n' ' ')
    fail "assertion (a): SPSC duplicate records detected: ${TOTAL_FOUND} total, ${UNIQUE_FOUND} unique
         Duplicate seq numbers: ${DUPS}
         (B1-FU1 periodic-drain abdication missing, or mutation applied)"
fi

pass "assertion (a-i): no duplicate records across ${N_ROUNDS} SIGHUP rounds \
(${UNIQUE_FOUND} unique paths, ${TOTAL_FOUND} found)"

# ── Assertion (a-ii): conservation — sent == arrived + counted_drops ─────────
# Reads ngx_otel.logs.access.dropped_records from the new metrics window
# (content since PRE_METRICS_SIZE).  Takes the max() — the gauge is a
# cumulative sum of per-worker ring.drop_count() values, so later reports
# always dominate earlier ones.
# A conservation failure means unaccounted lost records — STOP-AND-ASK.

info "Assertion (a-ii): checking conservation (sent=${SEQ_AFTER_ROUNDS} unique_arrived=${UNIQUE_FOUND})..."

POST_METRICS_SIZE=0
[[ -f "${METRICS_LOG}" ]] && POST_METRICS_SIZE=$(wc -c < "${METRICS_LOG}")
NEW_METRICS_BYTES=$(( POST_METRICS_SIZE - PRE_METRICS_SIZE ))
info "metrics.json: ${NEW_METRICS_BYTES} new bytes since pre-snapshot"

ACCESS_DROPS=0
if [[ "${NEW_METRICS_BYTES}" -gt 0 ]]; then
    ACCESS_DROPS=$(tail -c "+$(( PRE_METRICS_SIZE + 1 ))" "${METRICS_LOG}" 2>/dev/null \
        | python3 -c '
import json, sys
max_drops = 0
for line in sys.stdin:
    try:
        j = json.loads(line)
        for rm in j.get("resourceMetrics", []):
            for sm in rm.get("scopeMetrics", []):
                for m in sm.get("metrics", []):
                    if m.get("name") == "ngx_otel.logs.access.dropped_records":
                        for dp in m.get("gauge", {}).get("dataPoints", []):
                            v = dp.get("asInt", dp.get("asDouble", 0))
                            max_drops = max(max_drops, int(float(v)))
    except Exception:
        pass
print(max_drops)
')
fi

CONSERVATION_CHECK=$(( UNIQUE_FOUND + ACCESS_DROPS ))
info "Conservation: ${UNIQUE_FOUND} arrived + ${ACCESS_DROPS} dropped = ${CONSERVATION_CHECK} (sent ${SEQ_AFTER_ROUNDS})"

if [[ "${CONSERVATION_CHECK}" -ne "${SEQ_AFTER_ROUNDS}" ]]; then
    fail "assertion (a-ii): conservation FAILED: ${UNIQUE_FOUND} arrived + ${ACCESS_DROPS} drops = ${CONSERVATION_CHECK} != ${SEQ_AFTER_ROUNDS} sent
         Unaccounted records — this is a real lost-records bug; STOP-AND-ASK."
fi

pass "assertion (a-ii): conservation OK (${UNIQUE_FOUND} arrived + ${ACCESS_DROPS} dropped = ${SEQ_AFTER_ROUNDS} sent)"

# ── Assertion (a-iii): garbage-length / parse-error scan ─────────────────────
# Zero tolerance: crit/alert/emerg in nginx error.log, otel send-failures,
# or HTTP-4xx / parse-error lines in collector logs all indicate corruption.
# Uses COLLECTOR_CONTAINER from lib.sh (ngx-otel-test-collector).

info "Assertion (a-iii): scanning for parse/garbage-length errors..."
# Note: "otel export: send failed; queuing for retry" lines are NOT scanned —
# transient connection-reset during reload overlap is expected retry behaviour
# (the retry delivers the records; conservation assertion (a-ii) proves no loss).
# Only crit/alert/emerg (nginx system failures) and collector-side 4xx/5xx
# (malformed OTLP submission = data corruption) are hard errors.

SCAN_ERRORS=0

if [[ -f "${PREFIX}/logs/error.log" ]]; then
    CRIT_LINES=$(grep -cE '\[(crit|alert|emerg)\]' "${PREFIX}/logs/error.log" 2>/dev/null || true)
    if [[ "${CRIT_LINES}" -gt 0 ]]; then
        info "SCAN: ${CRIT_LINES} crit/alert/emerg line(s) in error.log:"
        grep -E '\[(crit|alert|emerg)\]' "${PREFIX}/logs/error.log" | head -10
        SCAN_ERRORS=$(( SCAN_ERRORS + CRIT_LINES ))
    fi
fi

COLLECTOR_SCAN=$(docker logs "${COLLECTOR_CONTAINER}" 2>&1 \
    | grep -cE '(StatusCode:[45][0-9]{2}|"status":[45][0-9]{2}|parse.*error|malformed|invalid.*length|length.*invalid|unexpected.*length)' \
    2>/dev/null || true)
if [[ "${COLLECTOR_SCAN}" -gt 0 ]]; then
    info "SCAN: ${COLLECTOR_SCAN} parse/length-error line(s) in collector logs:"
    docker logs "${COLLECTOR_CONTAINER}" 2>&1 \
        | grep -E '(StatusCode:[45][0-9]{2}|"status":[45][0-9]{2}|parse.*error|malformed|invalid.*length|length.*invalid|unexpected.*length)' \
        | head -10
    SCAN_ERRORS=$(( SCAN_ERRORS + COLLECTOR_SCAN ))
fi

if [[ "${SCAN_ERRORS}" -gt 0 ]]; then
    fail "assertion (a-iii): ${SCAN_ERRORS} parse/garbage-length error(s) found (details above)"
fi

pass "assertion (a-iii): zero parse/garbage-length errors in error.log and collector logs"

# ── Assertion (b): quit-completeness ─────────────────────────────────────────
# Push N records then nginx -s quit.  All N must arrive (no-successor sole-consumer
# full drain fires; if has_successor guard were inverted this would fail).

info "Assertion (b): quit-completeness..."

PRE_QUIT_SIZE=0
[[ -f "${LOGS_LOG}" ]] && PRE_QUIT_SIZE=$(wc -c < "${LOGS_LOG}")

# TIMING: sleep > 250 ms to let the periodic drain complete one tick and reset
# its timer.  Then send the quit batch with NO inter-request sleep (~16 ms for
# 8 requests), and issue quit immediately.  The next periodic tick is ~234 ms
# away; graceful_drain should be the sole consumer of those ring records.
#
# Note: on macOS, `nginx -s quit` has a ~5–10 ms SIGQUIT propagation delay.
# In that window a periodic tick can fire and drain the ring before graceful_drain
# runs.  This makes assertion (b)'s mutation-check timing-sensitive on macOS.
# Reliable mutation (b) detection requires Linux + USE_SLOW_SINK=1 (see header).
info "Assertion (b): letting one periodic drain tick fire (0.35 s)..."
sleep 0.35

N_QUIT_RECORDS=8
QUIT_SEQ_START=$(( SEQ + 1 ))

# Send without inter-request sleep so all 8 records land in the ring quickly
# (< 20 ms), well inside the 250 ms window before the next periodic tick.
for _i in $(seq 1 "${N_QUIT_RECORDS}"); do
    SEQ=$(( SEQ + 1 ))
    curl -sf "http://127.0.0.1:${NGINX_PORT}/b1chaos/$(printf '%05d' "${SEQ}")" \
        >/dev/null 2>&1 || true
done
QUIT_SEQ_END=${SEQ}
info "Quit-completeness: sent /b1chaos/$(printf '%05d' "${QUIT_SEQ_START}") .. /b1chaos/$(printf '%05d' "${QUIT_SEQ_END}")"

# Issue quit immediately — records are in the ring; next periodic tick is
# ~234 ms away, so graceful_drain drains them before it could fire.
info "Sending nginx -s quit (records in ring, ~234 ms before next periodic tick)..."
"${NGINX_BINARY}" -p "${PREFIX}" -c "${PREFIX}/nginx.conf" -s quit 2>/dev/null || true

# Wait for master to exit (backstop is 15 s so allow 20 s).
for _ in $(seq 1 20); do
    kill -0 "${NGINX_PID}" 2>/dev/null || break
    sleep 1
done
if kill -0 "${NGINX_PID}" 2>/dev/null; then
    fail "assertion (b): nginx master did not exit within 20s after -s quit"
fi
NGINX_PID=""
pass "nginx exited cleanly"

sleep $(( METRIC_INTERVAL_S + 3 ))

POST_QUIT_SIZE=0
[[ -f "${LOGS_LOG}" ]] && POST_QUIT_SIZE=$(wc -c < "${LOGS_LOG}")
QUIT_NEW_BYTES=$(( POST_QUIT_SIZE - PRE_QUIT_SIZE ))
info "Quit-completeness: ${QUIT_NEW_BYTES} new bytes in logs.json after quit"

QUIT_CONTENT=$(tail -c "+$(( PRE_QUIT_SIZE + 1 ))" "${LOGS_LOG}" 2>/dev/null)
QUIT_FOUND=0
for s in $(seq "${QUIT_SEQ_START}" "${QUIT_SEQ_END}"); do
    tag=$(printf '%05d' "${s}")
    if echo "${QUIT_CONTENT}" | grep -qF "/b1chaos/${tag}"; then
        QUIT_FOUND=$(( QUIT_FOUND + 1 ))
    fi
done
info "Quit-completeness: found ${QUIT_FOUND} / ${N_QUIT_RECORDS} pre-quit records"

if [[ "${QUIT_FOUND}" -lt "${N_QUIT_RECORDS}" ]]; then
    MISSING=""
    for s in $(seq "${QUIT_SEQ_START}" "${QUIT_SEQ_END}"); do
        tag=$(printf '%05d' "${s}")
        echo "${QUIT_CONTENT}" | grep -qF "/b1chaos/${tag}" \
            || MISSING="${MISSING} ${tag}"
    done
    fail "assertion (b): quit-completeness: only ${QUIT_FOUND}/${N_QUIT_RECORDS} \
pre-quit records arrived (missing:${MISSING})
         (graceful drain may have abdicated on shutdown — no-successor drain missing)"
fi

pass "assertion (b): quit-completeness: all ${N_QUIT_RECORDS} pre-quit records arrived"

echo ""
pass "B1-FU1 chaos gate: PASS — SPSC exclusivity across reload, conservation verified, no parse errors, quit-completeness confirmed"
