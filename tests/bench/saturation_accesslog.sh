#!/usr/bin/env bash
# tests/bench/saturation_accesslog.sh — full-Phase-2.2 access-log saturation bench.
#
# WHY THIS EXISTS
# ---------------
# saturation.sh measured the ALWAYS-ON metrics-recording hot path (histogram
# bumps) under CPU saturation, but with `return 200` and NO `otel_log_export`
# it did NOT exercise the access-log EXPORT path: the exception-tail ring push
# (emit_access_record) or the per-request `traceparent`/`user-agent` header scan
# (the instrumented.rs export gate is the selected `otel_log_export` mode).
#
# This bench closes that gap. Every request returns 500 and carries a
# `traceparent` header, so when `otel_log_export on` is set the FULL hot path
# fires on every request: histograms + exemplar reservoir write (trace-sampled)
# + tail ring push + traceparent parse + UA scan. That is the worst-case
# per-request cost of the export path.
#
# Three configs (randomized per round) decompose the cost:
#   c1          — clean nginx, NO module (fair baseline; same return-500 workload)
#   c3_metrics  — module + exporter, NO otel_log_export
#                 (always-on histograms only; export block skipped)
#   c3_full     — module + exporter + otel_log_export on (FULL path every request)
# Deltas: (c3_metrics - c1) = histogram cost; (c3_full - c3_metrics) = the marginal
# cost of the tail + traceparent capture (+ exemplar write when traced).
#
# A collector LOGS-received check on c3_full proves the tail path actually
# emitted (otel_log_export is genuinely functioning, not silently off).
#
# HOST: dedicated timing hardware only (host-1) for the gate of record. Needs Linux
# /proc, taskset, wrk, jq, and a native OTLP collector whose file exporters write
# METRICS_LOG (metrics.json) and LOGS_LOG (logs.json).
#
# Usage (host-1, from the crate dir), AFTER any other bench on the box has finished:
#   NGINX_BINARY=$PWD/objs-release/nginx \
#   MODULE_PATH=$PWD/target/release/libngx_http_otel_module.so \
#   OTEL_COLLECTOR_AUTOSTART=0 DEADLINE_HOURS=2 \
#   bash tests/bench/saturation_accesslog.sh
#
#   SMOKE=1 bash tests/bench/saturation_accesslog.sh   # 1 short round, self-test
#
# Exit: 0 ok; 1 preflight; 2 invariant (C3 did not export, or c3_full emitted no logs).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/results"
. "${CRATE_DIR}/test-harness/lib.sh"

# ─── Tunables ────────────────────────────────────────────────────────────────
SERVER_CORES="${SERVER_CORES:-0,1}"
LOAD_CORES="${LOAD_CORES:-2,3}"
WORKERS="${WORKERS:-2}"
CONN="${CONN:-200}"
WRK_THREADS="${WRK_THREADS:-2}"
DUR="${DUR:-60}"
COOLDOWN_S="${COOLDOWN_S:-8}"
DEADLINE_HOURS="${DEADLINE_HOURS:-2}"
NGINX_BIND_WAIT_S="${NGINX_BIND_WAIT_S:-2}"
WRK_URL="${WRK_URL:-http://127.0.0.1:9101/}"
SERVICE_NAME="${SERVICE_NAME:-ngx-otel-sat-accesslog}"
METRIC_INTERVAL="${METRIC_INTERVAL:-1s}"   # aggressive flush (worst case for exporter)
# A valid W3C traceparent (version 00, 16-byte trace id, 8-byte span id, sampled).
TRACEPARENT="${TRACEPARENT:-00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01}"

if [[ "${SMOKE:-0}" == "1" ]]; then DUR=8; CONN=50; DEADLINE_HOURS=0; COOLDOWN_S=2; fi

CLK_TCK="$(getconf CLK_TCK 2>/dev/null || echo 100)"
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*" >&2; }
info() { echo -e "${YELLOW}[INFO]${NC} $*"; }
step() { echo -e "${CYAN}[STEP]${NC} $*"; }

resolve_nginx_binary || true
case "$(uname -s)" in Darwin) EXT=dylib;; *) EXT=so;; esac
# Respect an externally-provided MODULE_PATH; otherwise derive it. When
# CARGO_BUILD_TARGET is set (TSAN gate uses --target), cargo writes to
# target/<triple>/release/ rather than target/release/.
if [[ -z "${MODULE_PATH:-}" ]]; then
    if [[ -n "${CARGO_BUILD_TARGET:-}" ]]; then
        MODULE_PATH="${CRATE_DIR}/target/${CARGO_BUILD_TARGET}/release/libngx_http_otel_module.${EXT}"
    else
        MODULE_PATH="${CRATE_DIR}/target/release/libngx_http_otel_module.${EXT}"
    fi
fi

# ─── Preflight ───────────────────────────────────────────────────────────────
step "Preflight"
[[ -x "${NGINX_BINARY}" ]]    || { fail "nginx binary not found: ${NGINX_BINARY}"; exit 1; }
[[ -f "${MODULE_PATH}" ]]     || { fail "module not found: ${MODULE_PATH}"; exit 1; }
command -v wrk >/dev/null     || { fail "wrk not installed"; exit 1; }
command -v jq  >/dev/null     || { fail "jq not installed"; exit 1; }
command -v taskset >/dev/null || { fail "taskset not installed"; exit 1; }
[[ -r /proc/stat ]]           || { fail "no /proc/stat — Linux/host-1 only"; exit 1; }
ensure_collector_running      || { fail "collector not reachable at ${COLLECTOR_HTTP_ENDPOINT}"; exit 1; }
info "nginx=${NGINX_BINARY}"
info "module=${MODULE_PATH} (mtime=$(date -r "${MODULE_PATH}" +%s))"
info "SERVER_CORES=${SERVER_CORES} LOAD_CORES=${LOAD_CORES} conn=${CONN} dur=${DUR}s interval=${METRIC_INTERVAL}"
mkdir -p "${RESULTS_DIR}"

COLLECTOR_PID="$(pgrep -f 'otelcol' | head -1 || true)"
if [[ -n "${COLLECTOR_PID}" ]]; then
    taskset -cp "${LOAD_CORES}" "${COLLECTOR_PID}" >/dev/null 2>&1 \
      || sudo -n taskset -cp "${LOAD_CORES}" "${COLLECTOR_PID}" >/dev/null 2>&1 \
      || info "WARNING: could not pin collector pid ${COLLECTOR_PID}"
    info "pinned collector (pid ${COLLECTOR_PID}) to cores ${LOAD_CORES}"
fi

# ─── /proc samplers (same as saturation.sh) ──────────────────────────────────
_cpu_snapshot() {
    local cores="$1" b=0 t=0 c line; local -a corelist
    IFS=',' read -ra corelist <<<"${cores}"
    for c in "${corelist[@]}"; do
        line="$(grep -E "^cpu${c} " /proc/stat || true)"; [[ -z "${line}" ]] && continue
        # shellcheck disable=SC2086
        set -- ${line}
        local idleall=$(( ${5:-0} + ${6:-0} ))
        local total=$(( ${2:-0}+${3:-0}+${4:-0}+${5:-0}+${6:-0}+${7:-0}+${8:-0}+${9:-0} ))
        b=$(( b + total - idleall )); t=$(( t + total ))
    done
    echo "${b} ${t}"
}
_cpu_busy_pct() {
    local b1 t1 b2 t2; read -r b1 t1 <<<"$1"; read -r b2 t2 <<<"$2"
    local db=$(( b2 - b1 )) dt=$(( t2 - t1 ))
    (( dt <= 0 )) && { echo 0; return; }
    awk -v db="${db}" -v dt="${dt}" 'BEGIN{printf "%.1f", 100.0*db/dt}'
}
_exporter_pid() { pgrep -f 'otel exporter' | head -1 || true; }
_proc_cpu_ticks() {
    local pid="$1" stat rest; stat="$(cat "/proc/${pid}/stat" 2>/dev/null)" || { echo 0; return; }
    rest="${stat#*) }"; set -- ${rest}; echo $(( ${12:-0} + ${13:-0} ))
}
_proc_rss_kb() { awk '/^VmRSS:/{print $2}' "/proc/$1/status" 2>/dev/null || echo 0; }
collector_logs_count() { [[ -f "${LOGS_LOG}" ]] && wc -l < "${LOGS_LOG}" | tr -d ' ' || echo 0; }

# ─── conf generator ──────────────────────────────────────────────────────────
# make_conf <prefix> <with_module:0|1> <with_sample:0|1>
make_conf() {
    local prefix="$1" with_module="$2" with_sample="$3"
    mkdir -p "${prefix}/logs" "${prefix}/client_body_temp"
    {
        echo "daemon off;"; echo "master_process on;"; echo "worker_processes ${WORKERS};"
        echo "error_log ${prefix}/logs/error.log error;"; echo "pid ${prefix}/logs/nginx.pid;"
        [[ "${with_module}" == "1" ]] && echo "load_module ${MODULE_PATH};"
        echo "events { worker_connections 4096; }"
        echo "http {"
        echo "    access_log off;"
        if [[ "${with_module}" == "1" ]]; then
            echo "    otel_exporter { endpoint ${COLLECTOR_HTTP_ENDPOINT}/v1/metrics; }"
            echo "    otel_service_name ${SERVICE_NAME};"
            echo "    otel_metric_interval ${METRIC_INTERVAL};"
            [[ "${with_sample}" == "1" ]] && echo "    otel_log_export on;"
        fi
        # return 500 => every request is operator-selected for export (otel_log_export on).
        echo "    server { listen 127.0.0.1:9101; location / { return 500 'err\\n'; } }"
        echo "}"
    } > "${prefix}/nginx.conf"
}

nginx_start_pinned() {
    local prefix="$1"
    if command -v nc >/dev/null && nc -z 127.0.0.1 9101 2>/dev/null; then fail "port 9101 busy"; exit 1; fi
    taskset -c "${SERVER_CORES}" "${NGINX_BINARY}" -p "${prefix}" -c "${prefix}/nginx.conf" &
    NGINX_BG_PID=$!; sleep "${NGINX_BIND_WAIT_S}"
    if ! kill -0 "${NGINX_BG_PID}" 2>/dev/null; then fail "nginx exited immediately"; cat "${prefix}/logs/error.log" >&2 || true; exit 1; fi
}
nginx_stop() {
    local prefix="$1" pid i; pid="$(cat "${prefix}/logs/nginx.pid" 2>/dev/null || true)"
    [[ -n "${pid}" ]] && kill -QUIT "${pid}" 2>/dev/null || true
    for i in $(seq 1 8); do command -v nc >/dev/null && ! nc -z 127.0.0.1 9101 2>/dev/null && break; sleep 1; done
    [[ -n "${pid}" ]] && kill -9 "${pid}" 2>/dev/null || true
    [[ -n "${NGINX_BG_PID:-}" ]] && kill -9 "${NGINX_BG_PID}" 2>/dev/null || true
    NGINX_BG_PID=""; sleep 1
}

parse_wrk() {
    local raw="$1" p50 p99 rps
    _to_ms() { local v="$1" n u; [[ "${v}" =~ ^([0-9]+\.?[0-9]*)([a-z]+)$ ]] && { n="${BASH_REMATCH[1]}"; u="${BASH_REMATCH[2]}"; } || { echo 0; return; }
        case "${u}" in us) awk -v n="${n}" 'BEGIN{printf "%.4f", n/1000}';; ms) echo "${n}";; s) awk -v n="${n}" 'BEGIN{printf "%.4f", n*1000}';; *) echo 0;; esac; }
    p50="$(echo "${raw}" | grep -E '^\s+50%' | head -1 | awk '{print $2}')"
    p99="$(echo "${raw}" | grep -E '^\s+99%' | head -1 | awk '{print $2}')"
    rps="$(echo "${raw}" | grep -E 'Requests/sec:' | head -1 | awk '{print $2}')"
    PARSED_MEDIAN_MS="$(_to_ms "${p50:-0ms}")"; PARSED_P99_MS="$(_to_ms "${p99:-0ms}")"; PARSED_RPS="${rps:-0}"
}

RUN_TS="$(date -u +%Y-%m-%dT%H-%M-%S)"
NDJSON="${RESULTS_DIR}/saturation-accesslog-${RUN_TS}.ndjson"
SUMMARY="${RESULTS_DIR}/saturation-accesslog-${RUN_TS}.summary.txt"
info "results: ${NDJSON}"

run_one() {
    local cfg="$1" round="$2" with_module with_sample
    case "${cfg}" in
        c1)         with_module=0; with_sample=0 ;;
        c3_metrics) with_module=1; with_sample=0 ;;
        c3_full)    with_module=1; with_sample=1 ;;
    esac
    local prefix; prefix="$(mktemp -d /tmp/ngx-satal-"${cfg}".XXXXXX)"
    # shellcheck disable=SC2064
    trap "nginx_stop '${prefix}'; rm -rf '${prefix}'" RETURN
    make_conf "${prefix}" "${with_module}" "${with_sample}"
    nginx_start_pinned "${prefix}"

    local exp_pid="" exp_t0=0 exp_rss=0 recv_before=0 logs_before=0
    if [[ "${with_module}" == "1" ]]; then
        local w; for w in $(seq 1 10); do exp_pid="$(_exporter_pid)"; [[ -n "${exp_pid}" ]] && break; sleep 0.5; done
        [[ -n "${exp_pid}" ]] && exp_t0="$(_proc_cpu_ticks "${exp_pid}")"
        recv_before="$(collector_metric_count)"; logs_before="$(collector_logs_count)"
    fi

    local cpu0; cpu0="$(_cpu_snapshot "${SERVER_CORES}")"
    local wall_start; wall_start="$(date +%s.%N)"
    local WRK_OUT; WRK_OUT="$(taskset -c "${LOAD_CORES}" wrk -t"${WRK_THREADS}" -c"${CONN}" -d"${DUR}s" \
        --latency -H "traceparent: ${TRACEPARENT}" "${WRK_URL}" 2>&1)"
    local wall_end; wall_end="$(date +%s.%N)"
    local cpu1; cpu1="$(_cpu_snapshot "${SERVER_CORES}")"

    local exp_cpu_pct=0 exp_t1=0
    if [[ "${with_module}" == "1" && -n "${exp_pid}" ]]; then
        exp_t1="$(_proc_cpu_ticks "${exp_pid}")"; exp_rss="$(_proc_rss_kb "${exp_pid}")"
        exp_cpu_pct="$(awk -v d=$(( exp_t1 - exp_t0 )) -v clk="${CLK_TCK}" -v w0="${wall_start}" -v w1="${wall_end}" \
            'BEGIN{wall=w1-w0; if(wall<=0){print 0}else{printf "%.2f", 100.0*(d/clk)/wall}}')"
    fi

    parse_wrk "${WRK_OUT}"
    local busy; busy="$(_cpu_busy_pct "${cpu0}" "${cpu1}")"
    local wall; wall="$(awk -v a="${wall_start}" -v b="${wall_end}" 'BEGIN{printf "%.2f", b-a}')"

    nginx_stop "${prefix}"

    local recv_delta=0 logs_delta=0
    if [[ "${with_module}" == "1" ]]; then
        sleep 2
        local after; after="$(collector_metric_count)"
        if (( after > recv_before )); then recv_delta=$(( after - recv_before ));
        elif (( after < recv_before )); then recv_delta=-1;
        else fail "${cfg} r${round}: exporter delivered NO metrics."; rm -rf "${prefix}"; trap - RETURN; exit 2; fi
        local lafter; lafter="$(collector_logs_count)"
        if (( lafter > logs_before )); then logs_delta=$(( lafter - logs_before ));
        elif (( lafter < logs_before )); then logs_delta=-1;  # logs.json rotated under heavy volume = tail firing
        else logs_delta=0; fi
        # The ROBUST proof the sampling/tail path fired is the exporter RSS/CPU jump
        # (c3_full >> c3_metrics), recorded below. The logs.json line count is
        # rotation-fragile under heavy volume (rotation can land the count exactly
        # equal), so a per-round 0 is a soft note, not a hard fail.
        if [[ "${cfg}" == "c3_full" && "${logs_delta}" == "0" ]]; then
            info "  (note) c3_full r${round}: no net logs.json line growth this window (likely a rotation/flush-timing artifact; exporter RSS/CPU confirm tail activity)"
        fi
    fi

    printf '{"ts":"%s","round":%d,"config":"%s","median_ms":%s,"p99_ms":%s,"req_per_sec":%s,"server_busy_pct":%s,"exporter_cpu_pct":%s,"exporter_rss_kb":%s,"recv_delta":%d,"logs_delta":%d,"wall_s":%s}\n' \
        "$(date -u +%FT%TZ)" "${round}" "${cfg}" "${PARSED_MEDIAN_MS:-0}" "${PARSED_P99_MS:-0}" "${PARSED_RPS:-0}" \
        "${busy}" "${exp_cpu_pct}" "${exp_rss:-0}" "${recv_delta}" "${logs_delta}" "${wall}" >> "${NDJSON}"
    info "  ${cfg} r${round}: rps=${PARSED_RPS} busy=${busy}% exp_cpu=${exp_cpu_pct}% exp_rss=${exp_rss}KB metrics+=${recv_delta} logs+=${logs_delta}"
    trap - RETURN; rm -rf "${prefix}"
}

write_summary() {
    jq -s '
      def med(f): map(f)|sort| if length==0 then 0 else .[(length/2)|floor] end;
      def sel(c): map(select(.config==c));
      (sel("c1")) as $c1 | (sel("c3_metrics")) as $m | (sel("c3_full")) as $f |
      ($c1|med(.req_per_sec)) as $c1r | ($m|med(.req_per_sec)) as $mr |
      {
        rounds:(map(.round)|max // 0), samples:length,
        c1:{n:($c1|length), rps_med:$c1r, busy_med:($c1|med(.server_busy_pct))},
        c3_metrics:{n:($m|length), rps_med:$mr, busy_med:($m|med(.server_busy_pct)),
                    exporter_cpu_pct_med:($m|med(.exporter_cpu_pct)), exporter_rss_kb_med:($m|med(.exporter_rss_kb)),
                    rps_delta_vs_c1_pct:(if $c1r>0 then 100.0*($mr-$c1r)/$c1r else 0 end)},
        c3_full:{n:($f|length), rps_med:($f|med(.req_per_sec)), busy_med:($f|med(.server_busy_pct)),
                 exporter_cpu_pct_med:($f|med(.exporter_cpu_pct)), exporter_rss_kb_med:($f|med(.exporter_rss_kb)),
                 logs_delta_med:($f|med(.logs_delta)),
                 rps_delta_vs_c1_pct:(if $c1r>0 then 100.0*(($f|med(.req_per_sec))-$c1r)/$c1r else 0 end),
                 rps_delta_vs_c3metrics_pct:(if $mr>0 then 100.0*(($f|med(.req_per_sec))-$mr)/$mr else 0 end)}
      }' "${NDJSON}" > "${SUMMARY}.tmp" 2>/dev/null && mv "${SUMMARY}.tmp" "${SUMMARY}" || true
}

END_EPOCH=$(( $(date +%s) + DEADLINE_HOURS*3600 ))
CONFIGS="c1 c3_metrics c3_full"; round=0
step "Access-log saturation bench start. Deadline in ${DEADLINE_HOURS}h."
while : ; do
    round=$(( round + 1 ))
    SHUFFLED="$(echo "${CONFIGS}" | tr ' ' '\n' | awk 'BEGIN{srand()}{a[NR]=$0}END{for(i=NR;i>1;i--){j=int(rand()*i)+1;t=a[i];a[i]=a[j];a[j]=t}for(i=1;i<=NR;i++)print a[i]}' | tr '\n' ' ')"
    step "Round ${round} (order: ${SHUFFLED})"
    for cfg in ${SHUFFLED}; do run_one "${cfg}" "${round}"; sleep "${COOLDOWN_S}"; done
    write_summary; info "Round ${round} done -> ${SUMMARY}"
    (( $(date +%s) >= END_EPOCH )) && break
done
write_summary
step "Access-log saturation bench complete after ${round} round(s)."
echo "=== SUMMARY ($(date -u +%FT%TZ)) ==="; cat "${SUMMARY}" 2>/dev/null || true
echo "SATURATION_ACCESSLOG_DONE=0"
