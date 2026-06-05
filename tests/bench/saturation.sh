#!/usr/bin/env bash
# tests/bench/saturation.sh — CPU-saturation / cycle-steal benchmark.
#
# WHY THIS EXISTS
# ---------------
# zero_cost.sh is a latency-bound, closed-loop test on a box with spare cores.
# It correctly shows the *per-request* hot path is free (bump-and-defer), but it
# CANNOT see the exporter task's own CPU cost, because nothing saturates the CPU
# — the exporter runs on idle cores and steals nothing. "C3 indistinguishable
# from C1" is therefore an under-powered claim.
#
# This script removes the spare-core escape hatch:
#   * nginx (master + workers + the `nginx: otel exporter` child) is pinned to a
#     SMALL core budget (SERVER_CORES, default 0,1) so the exporter MUST compete
#     with request-serving for the same cycles.
#   * wrk and the collector are pinned OFF those cores (LOAD_CORES, default 2,3)
#     so the load generator and the collector cannot perturb the server cores.
#   * offered load is high enough to PEG the server cores; we read /proc/stat
#     per-core before/after each run and report busy% to PROVE saturation (if
#     the server cores are the bottleneck, load-side contention can't explain a
#     C3-vs-C1 delta — the delta is server-side, i.e. the module + exporter).
#   * for C3 we sample the exporter process's own CPU directly from
#     /proc/<pid>/stat (utime+stime) and its RSS, so the cost is quantified in
#     absolute terms, not merely inferred from latency.
#   * the collector-receipt gate (lib.sh) proves C3 actually exported.
#
# Compared configs, randomized per round:
#   c1       — clean nginx, NO module (true baseline ceiling)
#   c3_10s   — module + exporter, otel_metric_interval 10s (realistic)
#   c3_1s    — module + exporter, otel_metric_interval  1s (worst-case export
#              pressure: 10x more encode+egress; conservative upper bound)
#
# It loops rounds until a wall-clock deadline (DEADLINE_HOURS, default 9) so it
# doubles as an over-time soak: exporter RSS and throughput are tracked per
# round to surface drift / leaks.
#
# HOST: dedicated hardware only (host-1). Needs Linux /proc, taskset, wrk, jq,
# and a native OTLP collector already listening on COLLECTOR_HTTP_ENDPOINT whose
# `file` exporter writes METRICS_LOG (test-harness/logs/metrics.json).
#
# Usage (on host-1, from the crate dir):
#   NGINX_BINARY=objs-release/nginx \
#   MODULE_PATH=$PWD/target/release/libngx_http_otel_module.so \
#   OTEL_COLLECTOR_AUTOSTART=0 \
#   bash tests/bench/saturation.sh
#
#   SMOKE=1 bash tests/bench/saturation.sh   # 1 short round, fast self-test
#
# Exit codes: 0 ok (deadline reached); 1 preflight failure; 2 invariant (C3 did
# not export).

set -euo pipefail

# ─── Paths / harness ─────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/results"
. "${CRATE_DIR}/test-harness/lib.sh"

# ─── Tunables ────────────────────────────────────────────────────────────────
SERVER_CORES="${SERVER_CORES:-0,1}"     # nginx master+workers+exporter
LOAD_CORES="${LOAD_CORES:-2,3}"         # wrk + collector (quarantined off server)
WORKERS="${WORKERS:-2}"                 # worker_processes (fit SERVER_CORES)
CONN="${CONN:-200}"                     # wrk connections (must peg server cores)
WRK_THREADS="${WRK_THREADS:-2}"
DUR="${DUR:-60}"                        # seconds per run
COOLDOWN_S="${COOLDOWN_S:-8}"
DEADLINE_HOURS="${DEADLINE_HOURS:-9}"
NGINX_BIND_WAIT_S="${NGINX_BIND_WAIT_S:-2}"
WRK_URL="${WRK_URL:-http://127.0.0.1:9101/}"
SERVICE_NAME="${SERVICE_NAME:-ngx-otel-saturation}"

if [[ "${SMOKE:-0}" == "1" ]]; then
    DUR=8; CONN=50; DEADLINE_HOURS=0; COOLDOWN_S=2
fi

CLK_TCK="$(getconf CLK_TCK 2>/dev/null || echo 100)"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*" >&2; }
info() { echo -e "${YELLOW}[INFO]${NC} $*"; }
step() { echo -e "${CYAN}[STEP]${NC} $*"; }

# ─── Resolve binaries ────────────────────────────────────────────────────────
resolve_nginx_binary || true
case "$(uname -s)" in Darwin) EXT=dylib;; *) EXT=so;; esac
MODULE_PATH="${MODULE_PATH:-${CRATE_DIR}/target/release/libngx_http_otel_module.${EXT}}"

# ─── Preflight ───────────────────────────────────────────────────────────────
step "Preflight"
[[ -x "${NGINX_BINARY}" ]]    || { fail "nginx binary not found/executable: ${NGINX_BINARY}"; exit 1; }
[[ -f "${MODULE_PATH}" ]]     || { fail "module not found: ${MODULE_PATH}"; exit 1; }
command -v wrk >/dev/null     || { fail "wrk not installed"; exit 1; }
command -v jq  >/dev/null     || { fail "jq not installed"; exit 1; }
command -v taskset >/dev/null || { fail "taskset not installed (need it to pin cores)"; exit 1; }
[[ -r /proc/stat ]]           || { fail "no /proc/stat — this script is Linux/host-1 only"; exit 1; }
ensure_collector_running      || { fail "collector not reachable at ${COLLECTOR_HTTP_ENDPOINT}"; exit 1; }
info "nginx=${NGINX_BINARY}"
info "module=${MODULE_PATH} (mtime=$(date -r "${MODULE_PATH}" +%s))"
info "SERVER_CORES=${SERVER_CORES} LOAD_CORES=${LOAD_CORES} workers=${WORKERS} conn=${CONN} dur=${DUR}s clk_tck=${CLK_TCK}"
mkdir -p "${RESULTS_DIR}"

# Quarantine the running collector onto LOAD_CORES so it cannot touch the
# server cores. The collector runs as our user, so taskset needs no sudo;
# fall back to sudo if affinity is denied.
COLLECTOR_PID="$(pgrep -f 'otelcol' | head -1 || true)"
if [[ -n "${COLLECTOR_PID}" ]]; then
    if taskset -cp "${LOAD_CORES}" "${COLLECTOR_PID}" >/dev/null 2>&1 \
       || sudo -n taskset -cp "${LOAD_CORES}" "${COLLECTOR_PID}" >/dev/null 2>&1; then
        info "pinned collector (pid ${COLLECTOR_PID}) to cores ${LOAD_CORES}"
    else
        info "WARNING: could not pin collector pid ${COLLECTOR_PID}; it may share server cores"
    fi
else
    info "WARNING: no otelcol process found to pin (receipt gate will still catch a dead collector)"
fi

# ─── /proc samplers ──────────────────────────────────────────────────────────
# Echo "busy total" summed across the comma-separated core list.
_cpu_snapshot() {
    local cores="$1" b=0 t=0 c line
    local -a corelist
    IFS=',' read -ra corelist <<<"${cores}"   # split core list; IFS scoped to read only
    for c in "${corelist[@]}"; do
        line="$(grep -E "^cpu${c} " /proc/stat || true)"
        [[ -z "${line}" ]] && continue
        # Default IFS (whitespace) here so the /proc/stat fields split correctly.
        # shellcheck disable=SC2086
        set -- ${line}   # $1=cpuN $2=user $3=nice $4=system $5=idle $6=iowait $7=irq $8=softirq $9=steal
        local idleall=$(( ${5:-0} + ${6:-0} ))
        local total=$(( ${2:-0} + ${3:-0} + ${4:-0} + ${5:-0} + ${6:-0} + ${7:-0} + ${8:-0} + ${9:-0} ))
        b=$(( b + total - idleall )); t=$(( t + total ))
    done
    echo "${b} ${t}"
}
# busy% between two snapshots "b1 t1" "b2 t2"
_cpu_busy_pct() {
    local b1 t1 b2 t2; read -r b1 t1 <<<"$1"; read -r b2 t2 <<<"$2"
    local db=$(( b2 - b1 )) dt=$(( t2 - t1 ))
    if (( dt <= 0 )); then echo "0"; return; fi
    awk -v db="${db}" -v dt="${dt}" 'BEGIN{printf "%.1f", 100.0*db/dt}'
}
_exporter_pid() { pgrep -f 'otel exporter' | head -1 || true; }
# utime+stime ticks for a pid, robust to spaces/parens in comm.
_proc_cpu_ticks() {
    local pid="$1" stat rest
    stat="$(cat "/proc/${pid}/stat" 2>/dev/null)" || { echo 0; return; }
    rest="${stat#*) }"          # strip "pid (comm) "
    # shellcheck disable=SC2086
    set -- ${rest}              # $1=state(field3); utime=field14 -> ${12}, stime=field15 -> ${13}
    echo $(( ${12:-0} + ${13:-0} ))
}
_proc_rss_kb() { awk '/^VmRSS:/{print $2}' "/proc/$1/status" 2>/dev/null || echo 0; }
_nginx_total_rss_kb() {
    local total=0 p
    for p in $(pgrep -f 'nginx:' 2>/dev/null); do
        total=$(( total + $(_proc_rss_kb "${p}") ))
    done
    echo "${total}"
}

# ─── nginx conf generator ────────────────────────────────────────────────────
# make_conf <prefix> <with_module:0|1> <interval_or_empty>
make_conf() {
    local prefix="$1" with_module="$2" interval="$3"
    mkdir -p "${prefix}/logs" "${prefix}/client_body_temp"
    {
        echo "daemon off;"
        echo "master_process on;"
        echo "worker_processes ${WORKERS};"
        echo "error_log ${prefix}/logs/error.log error;"
        echo "pid ${prefix}/logs/nginx.pid;"
        [[ "${with_module}" == "1" ]] && echo "load_module ${MODULE_PATH};"
        echo "events { worker_connections 4096; }"
        echo "http {"
        echo "    access_log off;"
        if [[ "${with_module}" == "1" ]]; then
            echo "    otel_exporter { endpoint ${COLLECTOR_HTTP_ENDPOINT}/v1/metrics; }"
            echo "    otel_service_name ${SERVICE_NAME};"
            echo "    otel_metric_interval ${interval};"
        fi
        echo "    server { listen 127.0.0.1:9101; location / { return 200 'ok\\n'; } }"
        echo "}"
    } > "${prefix}/nginx.conf"
}

nginx_start_pinned() {
    local prefix="$1"
    if command -v nc >/dev/null && nc -z 127.0.0.1 9101 2>/dev/null; then
        fail "port 9101 already bound before start"; exit 1
    fi
    taskset -c "${SERVER_CORES}" "${NGINX_BINARY}" -p "${prefix}" -c "${prefix}/nginx.conf" &
    NGINX_BG_PID=$!
    sleep "${NGINX_BIND_WAIT_S}"
    if ! kill -0 "${NGINX_BG_PID}" 2>/dev/null; then
        fail "nginx exited immediately"; cat "${prefix}/logs/error.log" >&2 || true; exit 1
    fi
}
nginx_stop() {
    local prefix="$1" pid i
    pid="$(cat "${prefix}/logs/nginx.pid" 2>/dev/null || true)"
    [[ -n "${pid}" ]] && kill -QUIT "${pid}" 2>/dev/null || true
    for i in $(seq 1 8); do
        if command -v nc >/dev/null && ! nc -z 127.0.0.1 9101 2>/dev/null; then break; fi
        sleep 1
    done
    [[ -n "${pid}" ]] && kill -9 "${pid}" 2>/dev/null || true
    [[ -n "${NGINX_BG_PID:-}" ]] && kill -9 "${NGINX_BG_PID}" 2>/dev/null || true
    NGINX_BG_PID=""
    sleep 1
}

# ─── wrk parser (us/ms/s -> ms) ──────────────────────────────────────────────
parse_wrk() {
    local raw="$1" p50 p99 rps
    _to_ms() {
        local v="$1" n u
        [[ "${v}" =~ ^([0-9]+\.?[0-9]*)([a-z]+)$ ]] && { n="${BASH_REMATCH[1]}"; u="${BASH_REMATCH[2]}"; } || { echo 0; return; }
        case "${u}" in us) awk -v n="${n}" 'BEGIN{printf "%.4f", n/1000}';; ms) echo "${n}";; s) awk -v n="${n}" 'BEGIN{printf "%.4f", n*1000}';; *) echo 0;; esac
    }
    p50="$(echo "${raw}" | grep -E '^\s+50%' | head -1 | awk '{print $2}')"
    p99="$(echo "${raw}" | grep -E '^\s+99%' | head -1 | awk '{print $2}')"
    rps="$(echo "${raw}" | grep -E 'Requests/sec:' | head -1 | awk '{print $2}')"
    PARSED_MEDIAN_MS="$(_to_ms "${p50:-0ms}")"
    PARSED_P99_MS="$(_to_ms "${p99:-0ms}")"
    PARSED_RPS="${rps:-0}"
}

# ─── One measured run ────────────────────────────────────────────────────────
RUN_TS="$(date -u +%Y-%m-%dT%H-%M-%S)"
NDJSON="${RESULTS_DIR}/saturation-${RUN_TS}.ndjson"
SUMMARY="${RESULTS_DIR}/saturation-${RUN_TS}.summary.txt"
info "results: ${NDJSON}"

run_one() {
    local cfg="$1" round="$2" with_module interval
    case "${cfg}" in
        c1)     with_module=0; interval="" ;;
        c3_10s) with_module=1; interval="10s" ;;
        c3_1s)  with_module=1; interval="1s" ;;
    esac

    local prefix; prefix="$(mktemp -d /tmp/ngx-sat-"${cfg}".XXXXXX)"
    # shellcheck disable=SC2064
    trap "nginx_stop '${prefix}'; rm -rf '${prefix}'" RETURN
    make_conf "${prefix}" "${with_module}" "${interval}"
    nginx_start_pinned "${prefix}"

    local exp_pid="" exp_t0=0 exp_rss=0 recv_before=0
    if [[ "${with_module}" == "1" ]]; then
        local w
        for w in $(seq 1 10); do exp_pid="$(_exporter_pid)"; [[ -n "${exp_pid}" ]] && break; sleep 0.5; done
        [[ -n "${exp_pid}" ]] && exp_t0="$(_proc_cpu_ticks "${exp_pid}")"
        recv_before="$(collector_metric_count)"
    fi

    local cpu0; cpu0="$(_cpu_snapshot "${SERVER_CORES}")"
    local wall_start; wall_start="$(date +%s.%N)"
    local WRK_OUT; WRK_OUT="$(taskset -c "${LOAD_CORES}" wrk -t"${WRK_THREADS}" -c"${CONN}" -d"${DUR}s" --latency "${WRK_URL}" 2>&1)"
    local wall_end; wall_end="$(date +%s.%N)"
    local cpu1; cpu1="$(_cpu_snapshot "${SERVER_CORES}")"

    local exp_cpu_pct=0 exp_t1=0 nginx_rss=0
    if [[ "${with_module}" == "1" && -n "${exp_pid}" ]]; then
        exp_t1="$(_proc_cpu_ticks "${exp_pid}")"
        exp_rss="$(_proc_rss_kb "${exp_pid}")"
        exp_cpu_pct="$(awk -v d=$(( exp_t1 - exp_t0 )) -v clk="${CLK_TCK}" -v w0="${wall_start}" -v w1="${wall_end}" \
            'BEGIN{wall=w1-w0; if(wall<=0){print 0}else{printf "%.2f", 100.0*(d/clk)/wall}}')"
    fi
    nginx_rss="$(_nginx_total_rss_kb)"

    parse_wrk "${WRK_OUT}"
    local busy; busy="$(_cpu_busy_pct "${cpu0}" "${cpu1}")"
    local wall; wall="$(awk -v a="${wall_start}" -v b="${wall_end}" 'BEGIN{printf "%.2f", b-a}')"

    nginx_stop "${prefix}"

    local recv_delta=0
    if [[ "${with_module}" == "1" ]]; then
        sleep 2
        local after; after="$(collector_metric_count)"
        if (( after > recv_before )); then
            recv_delta=$(( after - recv_before ))
        elif (( after < recv_before )); then
            recv_delta=-1   # METRICS_LOG rotated (10MB cap) => heavy export confirmed
        else
            fail "C3 (${cfg} r${round}) exported NOTHING to the collector (count unchanged at ${after}). Comparison meaningless. STOP-AND-ASK."
            rm -rf "${prefix}"; trap - RETURN; exit 2
        fi
    fi

    printf '{"ts":"%s","round":%d,"config":"%s","interval":"%s","median_ms":%s,"p99_ms":%s,"req_per_sec":%s,"server_busy_pct":%s,"exporter_cpu_pct":%s,"exporter_rss_kb":%s,"nginx_total_rss_kb":%s,"recv_delta":%d,"wall_s":%s}\n' \
        "$(date -u +%FT%TZ)" "${round}" "${cfg}" "${interval:-none}" \
        "${PARSED_MEDIAN_MS:-0}" "${PARSED_P99_MS:-0}" "${PARSED_RPS:-0}" \
        "${busy}" "${exp_cpu_pct}" "${exp_rss:-0}" "${nginx_rss}" "${recv_delta}" "${wall}" \
        >> "${NDJSON}"

    info "  ${cfg} r${round}: rps=${PARSED_RPS} median=${PARSED_MEDIAN_MS}ms p99=${PARSED_P99_MS}ms server_busy=${busy}% exp_cpu=${exp_cpu_pct}% exp_rss=${exp_rss}KB recv+=${recv_delta}"
    trap - RETURN
    rm -rf "${prefix}"
}

# ─── Rolling summary ─────────────────────────────────────────────────────────
write_summary() {
    jq -s '
      def med(f): map(f) | sort | if length==0 then 0 else .[(length/2)|floor] end;
      def sel(c): map(select(.config==c));
      (sel("c1")) as $c1 | (sel("c3_10s")) as $a | (sel("c3_1s")) as $b |
      ($c1|med(.req_per_sec)) as $c1r |
      {
        rounds: (map(.round)|max // 0),
        samples: length,
        c1:     {n:($c1|length), rps_med:$c1r, busy_med:($c1|med(.server_busy_pct))},
        c3_10s: {n:($a|length), rps_med:($a|med(.req_per_sec)), busy_med:($a|med(.server_busy_pct)),
                 exporter_cpu_pct_med:($a|med(.exporter_cpu_pct)), exporter_rss_kb_med:($a|med(.exporter_rss_kb)),
                 rps_delta_vs_c1_pct: (if $c1r>0 then (100.0*(($a|med(.req_per_sec))-$c1r)/$c1r) else 0 end)},
        c3_1s:  {n:($b|length), rps_med:($b|med(.req_per_sec)), busy_med:($b|med(.server_busy_pct)),
                 exporter_cpu_pct_med:($b|med(.exporter_cpu_pct)), exporter_rss_kb_med:($b|med(.exporter_rss_kb)),
                 rps_delta_vs_c1_pct: (if $c1r>0 then (100.0*(($b|med(.req_per_sec))-$c1r)/$c1r) else 0 end)}
      }
    ' "${NDJSON}" > "${SUMMARY}.tmp" 2>/dev/null && mv "${SUMMARY}.tmp" "${SUMMARY}" || true
}

# ─── Main loop ───────────────────────────────────────────────────────────────
END_EPOCH=$(( $(date +%s) + DEADLINE_HOURS*3600 ))
CONFIGS="c1 c3_10s c3_1s"
round=0
step "Saturation bench start. Deadline in ${DEADLINE_HOURS}h ($(date -d "@${END_EPOCH}" 2>/dev/null || echo "+${DEADLINE_HOURS}h"))."
while : ; do
    round=$(( round + 1 ))
    SHUFFLED="$(echo "${CONFIGS}" | tr ' ' '\n' | awk 'BEGIN{srand()}{a[NR]=$0}END{for(i=NR;i>1;i--){j=int(rand()*i)+1;t=a[i];a[i]=a[j];a[j]=t}for(i=1;i<=NR;i++)print a[i]}' | tr '\n' ' ')"
    step "Round ${round} (order: ${SHUFFLED})"
    for cfg in ${SHUFFLED}; do
        run_one "${cfg}" "${round}"
        sleep "${COOLDOWN_S}"
    done
    write_summary
    info "Round ${round} done. Summary -> ${SUMMARY}"
    if (( $(date +%s) >= END_EPOCH )); then break; fi
done

write_summary
step "Saturation bench complete after ${round} round(s)."
echo "=== SUMMARY ($(date -u +%FT%TZ)) ==="
cat "${SUMMARY}" 2>/dev/null || true
echo "SATURATION_DONE=0"
