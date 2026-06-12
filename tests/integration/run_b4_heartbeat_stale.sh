#!/usr/bin/env bash
# tests/integration/run_b4_heartbeat_stale.sh — B4-FU2: heartbeat-stale ALERT, both polarities
#
# Phase A — SATURATION polarity (exporter ALIVE, ring saturated):
#   A1. Heartbeat advances (dedicated beat timer is running).
#   A2. Sustained 404 bursts against a tiny (1k) ring for > 2× the staleness
#       threshold produce ring-full DROPS (verified via otel_status access_dropped).
#   A3. ZERO heartbeat-stale ALERTs — saturation must NOT look like death.
#
# Phase B — DEATH polarity (silent exporter death, the real B4 case):
#   B1. daemon on → gen-1 exporter is unsupervised (PPID=init); heartbeat
#       advances while it is alive.
#   B2. kill -9 the exporter (NO reload): master never sees SIGCHLD, no
#       respawn — beats freeze (verified: last_beat_msec stops advancing).
#   B3. After the staleness threshold, a 404 burst (ring-full drop = trigger)
#       produces the ALERT with the documented text, promptly.
#   B4. Continued drop traffic for > threshold produces NO additional alert
#       (latched once per worker; worker_processes 1 → exactly 1 line).
#   B5. nginx -s reload (the remedy named in the alert text): gen-2 exporter
#       is supervised and beating; continued drop traffic for > threshold
#       produces NO new alert (alive exporter + re-armed latch ≠ false fire).
#
# The staleness threshold is 5 s (5 × 1 s beat period — see src/liveness.rs).
#
# Prerequisites: NGINX_BINARY set or auto-detected; no collector required
# (beats are independent of send progress — the endpoint is unreachable here,
# which doubles as a live check of that independence).
# Exit codes: 0 = all assertions passed, 1 = preflight, 2 = assertion failed.

set -euo pipefail

STALE_THRESHOLD_S=5    # must match HEARTBEAT_STALE_THRESHOLD_MS / 1000
ALERT_RE="otel exporter heartbeat stale"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CONF_ALIVE="${SCRIPT_DIR}/nginx_b4_heartbeat_alive.conf"
CONF_DEAD="${SCRIPT_DIR}/nginx_b4_heartbeat_dead.conf"

. "${CRATE_DIR}/test-harness/lib.sh"
resolve_nginx_binary || true

case "$(uname -s)" in
    Darwin) MODULE_EXT="dylib" ;;
    *)      MODULE_EXT="so"    ;;
esac

if [[ -n "${CARGO_BUILD_TARGET:-}" ]]; then
    MODULE_PATH="${CRATE_DIR}/target/${CARGO_BUILD_TARGET}/release/libngx_http_otel_module.${MODULE_EXT}"
else
    MODULE_PATH="${CRATE_DIR}/target/release/libngx_http_otel_module.${MODULE_EXT}"
fi

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
pass()  { echo -e "${GREEN}[PASS]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*" >&2; exit 2; }
info()  { echo -e "${YELLOW}[INFO]${NC} $*"; }

if [[ ! -x "${NGINX_BINARY:-}" ]]; then
    echo "ERROR: nginx binary not found at ${NGINX_BINARY:-<unset>}." >&2
    exit 1
fi
info "nginx binary: ${NGINX_BINARY}"

# ── Build module with test-support (otel_status_endpoint) ─────────────────────
info "Building release module with --features test-support..."
(
    cd "${CRATE_DIR}"
    NGINX_SOURCE_DIR="${NGINX_SOURCE_DIR:-${CRATE_DIR}/../nginx}" \
    NGINX_BUILD_DIR="${NGINX_BUILD_DIR:-${CRATE_DIR}/objs-release}" \
    cargo build --release --features test-support 2>&1 | tail -2
)
[[ -f "${MODULE_PATH}" ]] || { echo "ERROR: module not found: ${MODULE_PATH}" >&2; exit 1; }
info "Module: ${MODULE_PATH}"

# ── Helpers ────────────────────────────────────────────────────────────────────

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
    # [o] bracket trick: without it the awk process matches its OWN args.
    ps -eo pid,args 2>/dev/null | awk '/nginx: [o]tel exporter/ {print $1; exit}'
}

# status_field <port> <key>  — read a key=value line from /otel_status.
status_field() {
    curl -sf --max-time 3 "http://127.0.0.1:$1/otel_status" \
        | awk -F= -v k="$2" '$1==k {print $2; exit}'
}

# burst_404 <port> <count>  — fire <count> sequential 404 requests.
burst_404() {
    local port=$1 count=$2 i
    for (( i = 0; i < count; i++ )); do
        curl -s -o /dev/null --max-time 2 "http://127.0.0.1:${port}/missing" || true
    done
}

alert_count() {
    local n
    n="$(grep -c "${ALERT_RE}" "$1" 2>/dev/null || true)"
    echo "${n:-0}"
}

PREFIX_A=""
PREFIX_B=""
NGINX_A_PID=""
MASTER_B_PID=""

cleanup() {
    if [[ -n "${NGINX_A_PID:-}" ]]; then
        kill -QUIT "${NGINX_A_PID}" 2>/dev/null || kill "${NGINX_A_PID}" 2>/dev/null || true
    fi
    if [[ -n "${MASTER_B_PID:-}" ]]; then
        # SIGTERM (not SIGQUIT): under daemon-on the gen-1 SIGCHLD gap can hang
        # a graceful quit (B4 known limitation; see run_b4_daemon_on_gen1.sh).
        kill -TERM "${MASTER_B_PID}" 2>/dev/null || true
    fi
    sleep 1
    [[ "${KEEP_SANDBOX:-0}" == "1" ]] || rm -rf "${PREFIX_A}" "${PREFIX_B}"
}
trap cleanup EXIT

# ── Leftover cleanup ───────────────────────────────────────────────────────────
# Phase B identifies the exporter by proctitle, so stray nginx instances and
# orphaned exporters from earlier test runs must go.  Masters first (otherwise
# a surviving master respawns its exporter between our kill and the check).
# This assumes a dedicated test host — it kills ANY nginx master.
pgrep -f "[n]ginx: master process" | xargs -r kill -KILL 2>/dev/null || true
sleep 1
pgrep -f "[n]ginx: " | xargs -r kill -KILL 2>/dev/null || true
sleep 1
[[ -z "$(exporter_pid)" ]] || fail "Preflight: stray otel exporter (PID $(exporter_pid)) survived cleanup"

# ═══ Phase A — saturation polarity: alive + saturated → ZERO alerts ═══════════

info "=== Phase A: saturation polarity (exporter alive, ring saturated) ==="
PREFIX_A="$(mktemp -d /tmp/ngx-b4-hb-alive.XXXXXX)"
mkdir -p "${PREFIX_A}/logs" "${PREFIX_A}/client_body_temp"
sed -e "s|@MODULE_PATH@|${MODULE_PATH}|g" -e "s|@PREFIX@|${PREFIX_A}|g" \
    "${CONF_ALIVE}" > "${PREFIX_A}/nginx.conf"

"${NGINX_BINARY}" -p "${PREFIX_A}" -c "${PREFIX_A}/nginx.conf" &
NGINX_A_PID=$!
sleep 2
kill -0 "${NGINX_A_PID}" 2>/dev/null || {
    cat "${PREFIX_A}/logs/error.log" >&2; fail "Phase A: nginx exited at startup"; }

# A1: dedicated beat timer is running — last_beat_msec advances.
wait_for 5 "first heartbeat" "[[ -n \"\$(status_field 9221 last_beat_msec)\" && \"\$(status_field 9221 last_beat_msec)\" != 0 ]]"
BEAT_1="$(status_field 9221 last_beat_msec)"
sleep 2
BEAT_2="$(status_field 9221 last_beat_msec)"
if (( BEAT_2 > BEAT_1 )); then
    pass "A1: heartbeat advances while alive (${BEAT_1} → ${BEAT_2})"
else
    fail "A1: heartbeat did not advance (${BEAT_1} → ${BEAT_2}) — beat timer not running?"
fi

# A2: saturate the tiny ring for > 2× threshold; drops must occur.
DROPS_BEFORE="$(status_field 9221 access_dropped)"
ROUNDS=$(( STALE_THRESHOLD_S * 2 + 2 ))   # 12 rounds ≈ 12+ s of sustained drop traffic
info "A2: driving 404 bursts for ${ROUNDS}s (60/burst against a 1k ring)..."
for (( round = 0; round < ROUNDS; round++ )); do
    burst_404 9221 60
    sleep 0.5
done
DROPS_AFTER="$(status_field 9221 access_dropped)"
if (( DROPS_AFTER > DROPS_BEFORE )); then
    pass "A2: ring-full drops occurred while exporter alive (access_dropped ${DROPS_BEFORE} → ${DROPS_AFTER})"
else
    fail "A2: no drops recorded (${DROPS_BEFORE} → ${DROPS_AFTER}) — saturation polarity is vacuous; raise burst size?"
fi

# A3: ZERO heartbeat-stale alerts.
COUNT_A="$(alert_count "${PREFIX_A}/logs/error.log")"
if [[ "${COUNT_A}" == "0" ]]; then
    pass "A3: ZERO heartbeat-stale alerts under saturation (drops=$((DROPS_AFTER - DROPS_BEFORE)))"
else
    grep "${ALERT_RE}" "${PREFIX_A}/logs/error.log" >&2
    fail "A3: ${COUNT_A} false-positive alert(s) while the exporter was alive"
fi

kill -QUIT "${NGINX_A_PID}" 2>/dev/null || true
wait "${NGINX_A_PID}" 2>/dev/null || true
NGINX_A_PID=""

# ═══ Phase B — death polarity: silent kill -9 → ONE latched alert ═════════════

info "=== Phase B: death polarity (daemon on, gen-1 exporter, kill -9) ==="
# Phase A teardown is graceful; give its exporter a moment, then verify clean.
wait_for 10 "no exporter left from Phase A" "[[ -z \"\$(exporter_pid)\" ]]"
PREFIX_B="$(mktemp -d /tmp/ngx-b4-hb-dead.XXXXXX)"
mkdir -p "${PREFIX_B}/logs" "${PREFIX_B}/client_body_temp"
sed -e "s|@MODULE_PATH@|${MODULE_PATH}|g" -e "s|@PREFIX@|${PREFIX_B}|g" \
    "${CONF_DEAD}" > "${PREFIX_B}/nginx.conf"

"${NGINX_BINARY}" -p "${PREFIX_B}" -c "${PREFIX_B}/nginx.conf" 2>/dev/null || true
wait_for 5 "nginx.pid (daemonized master)" "[[ -s '${PREFIX_B}/logs/nginx.pid' ]]"
MASTER_B_PID="$(cat "${PREFIX_B}/logs/nginx.pid")"
kill -0 "${MASTER_B_PID}" 2>/dev/null || fail "Phase B: master ${MASTER_B_PID} not alive"
info "Master PID: ${MASTER_B_PID}"

# B1: exporter present and beating.
wait_for 5 "gen-1 exporter" "[[ -n \"\$(exporter_pid)\" ]]"
EXP_PID="$(exporter_pid)"
wait_for 5 "first heartbeat" "[[ -n \"\$(status_field 9222 last_beat_msec)\" && \"\$(status_field 9222 last_beat_msec)\" != 0 ]]"
B_BEAT_1="$(status_field 9222 last_beat_msec)"
sleep 2
B_BEAT_2="$(status_field 9222 last_beat_msec)"
(( B_BEAT_2 > B_BEAT_1 )) || fail "B1: heartbeat not advancing pre-kill (${B_BEAT_1} → ${B_BEAT_2})"
pass "B1: gen-1 exporter PID=${EXP_PID} beating (${B_BEAT_1} → ${B_BEAT_2})"

# B2: kill -9 (NO reload). daemon-on gen-1 → no SIGCHLD → no respawn.
T_KILL=$(date +%s)
info "B2: kill -9 exporter PID ${EXP_PID} (no reload)..."
kill -9 "${EXP_PID}" 2>/dev/null || fail "B2: kill -9 failed"
wait_for 3 "exporter death" "! kill -0 ${EXP_PID} 2>/dev/null"
sleep 2
[[ -z "$(exporter_pid)" ]] || fail "B2: an exporter respawned — daemon-on gen-1 premise broken"
B_BEAT_3="$(status_field 9222 last_beat_msec)"
sleep 2
B_BEAT_4="$(status_field 9222 last_beat_msec)"
[[ "${B_BEAT_3}" == "${B_BEAT_4}" ]] || fail "B2: heartbeat still advancing after kill (${B_BEAT_3} → ${B_BEAT_4})"
pass "B2: exporter dead, no respawn, heartbeat frozen at ${B_BEAT_4}"

# B3: wait out the staleness threshold, then trigger via ring-full drops.
REMAIN=$(( STALE_THRESHOLD_S + 2 - ($(date +%s) - T_KILL) ))
(( REMAIN > 0 )) && { info "B3: waiting ${REMAIN}s for staleness threshold..."; sleep "${REMAIN}"; }
T_LOAD=$(date +%s)
DEADLINE=$(( T_LOAD + 10 ))
ALERTED=0
while (( $(date +%s) < DEADLINE )); do
    burst_404 9222 60
    if [[ "$(alert_count "${PREFIX_B}/logs/error.log")" != "0" ]]; then
        ALERTED=1
        break
    fi
    sleep 0.5
done
T_ALERT=$(date +%s)
(( ALERTED == 1 )) || fail "B3: no heartbeat-stale alert within 10s of post-threshold drop traffic"
ALERT_LINE="$(grep -m1 "${ALERT_RE}" "${PREFIX_B}/logs/error.log")"
echo "${ALERT_LINE}" | grep -q "\[alert\]" || fail "B3: stale line is not at ALERT severity: ${ALERT_LINE}"
echo "${ALERT_LINE}" | grep -q "telemetry suspended" || fail "B3: alert text missing telemetry suspended: ${ALERT_LINE}"
echo "${ALERT_LINE}" | grep -q "nginx -s reload restores" || fail "B3: alert text missing remedy: ${ALERT_LINE}"
pass "B3: ALERT within $(( T_ALERT - T_LOAD ))s of drop traffic ($(( T_ALERT - T_KILL ))s after kill): ${ALERT_LINE#*: }"

B_DROPS="$(status_field 9222 access_dropped)"
(( B_DROPS > 0 )) || fail "B3: access_dropped is 0 — alert fired without a drop trigger?"

# B4: latch — continued drop traffic for > threshold adds NO second alert.
info "B4: continuing drop traffic for $(( STALE_THRESHOLD_S + 3 ))s (latch check)..."
for (( round = 0; round < STALE_THRESHOLD_S + 3; round++ )); do
    burst_404 9222 60
    sleep 0.5
done
COUNT_B="$(alert_count "${PREFIX_B}/logs/error.log")"
if [[ "${COUNT_B}" == "1" ]]; then
    pass "B4: exactly ONE alert after sustained post-death drops (latched; worker_processes=1)"
else
    grep "${ALERT_RE}" "${PREFIX_B}/logs/error.log" >&2
    fail "B4: expected exactly 1 alert, found ${COUNT_B} — latch broken"
fi

# B5: remedy — reload spawns a supervised gen-2; no new alert despite re-armed latch.
info "B5: nginx -s reload (remedy from the alert text)..."
"${NGINX_BINARY}" -p "${PREFIX_B}" -c "${PREFIX_B}/nginx.conf" -s reload 2>/dev/null || true
wait_for 5 "gen-2 exporter" "[[ -n \"\$(exporter_pid)\" ]]"
sleep 2
B_BEAT_5="$(status_field 9222 last_beat_msec)"
(( B_BEAT_5 > B_BEAT_4 )) || fail "B5: heartbeat did not resume after reload (${B_BEAT_4} → ${B_BEAT_5})"
info "B5: driving drop traffic for $(( STALE_THRESHOLD_S * 2 ))s against the live gen-2..."
for (( round = 0; round < STALE_THRESHOLD_S * 2 * 2; round++ )); do
    burst_404 9222 60
    sleep 0.5
done
COUNT_B5="$(alert_count "${PREFIX_B}/logs/error.log")"
if [[ "${COUNT_B5}" == "1" ]]; then
    pass "B5: reload restored telemetry; re-armed latch did NOT false-fire (still 1 alert)"
else
    fail "B5: alert count changed after reload+live traffic (1 → ${COUNT_B5})"
fi

echo ""
pass "ALL B4 heartbeat-stale assertions passed (saturation: 0 alerts; death: 1 latched alert; reload remedy clean)"
