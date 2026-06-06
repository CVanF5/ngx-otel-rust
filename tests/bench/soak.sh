#!/usr/bin/env bash
# 24h soak driver — all telemetry features on, OTLP/gRPC. Run on host-1.
#   DURATION_S=60 CHUNK_S=30 bash soak.sh   # short smoke
#   bash soak.sh                            # full 24h (defaults)
set -u

SOAK=/home/admin/soak
NGINX=/home/admin/project-nginx-otel/ngx-otel-rust/objs-release/nginx
CONF=/home/admin/soak_grpc.conf
LUA=/home/admin/mix.lua
URL=http://127.0.0.1:9200/
LOGS=/home/admin/project-nginx-otel/ngx-otel-rust/test-harness/logs
REPORT=$SOAK/REPORT.txt

DURATION_S=${DURATION_S:-86400}   # 24h
CHUNK_S=${CHUNK_S:-900}           # 15-min wrk chunks between health snapshots
THREADS=${THREADS:-4}
CONNS=${CONNS:-100}

mkdir -p "$SOAK/logs"
log(){ echo "[$(date -u +%FT%TZ)] $*" | tee -a "$REPORT"; }
rss_sum(){ local t=0 r; for p in $1; do r=$(ps -o rss= -p "$p" 2>/dev/null | tr -d ' '); t=$((t + ${r:-0})); done; echo $t; }
mtr(){ wc -c < "$LOGS/metrics.json" 2>/dev/null || echo 0; }
lgs(){ wc -c < "$LOGS/logs.json" 2>/dev/null || echo 0; }
# Latest value of an ngx_otel self-metric from the metrics file (best-effort).
selfmetric(){ grep -o "\"$1\"[^}]*\"asInt\":\"[0-9]*\"" "$LOGS/metrics.json" 2>/dev/null | grep -oE '[0-9]+"$' | tr -d '"' | tail -1; }

pkill -f "objs-release/nginx" 2>/dev/null; sleep 1
: > "$REPORT"
log "SOAK START — OTLP/gRPC, all features (access tail+exemplars, error log+coalesce, metrics)."
log "params: duration=${DURATION_S}s chunk=${CHUNK_S}s threads=$THREADS conns=$CONNS"
log "baseline: metrics.json=$(mtr)B logs.json=$(lgs)B"

"$NGINX" -p "$SOAK" -c "$CONF" &
NGINX_PID=$!
sleep 4
if grep -q "protocol=otlp_grpc" "$SOAK/logs/error.log" 2>/dev/null; then
  log "exporter: 'export loop started ... protocol=otlp_grpc' CONFIRMED"
else
  log "WARN: protocol=otlp_grpc not yet in error.log:"; grep -i "export loop\|otel export" "$SOAK/logs/error.log" 2>/dev/null | tail -3 | tee -a "$REPORT"
fi

START=$(date +%s); END=$((START + DURATION_S)); i=0
while [ "$(date +%s)" -lt "$END" ]; do
  i=$((i + 1))
  remain=$((END - $(date +%s))); [ "$remain" -lt "$CHUNK_S" ] && CH=$remain || CH=$CHUNK_S
  [ "$CH" -lt 5 ] && break
  wrk -t"$THREADS" -c"$CONNS" -d"${CH}s" -s "$LUA" "$URL" > "$SOAK/wrk-$i.txt" 2>&1
  WK=$(pgrep -f "nginx: worker" | tr '\n' ' '); EX=$(pgrep -f "nginx: otel exporter" | tr '\n' ' ')
  reqs=$(grep -oE '[0-9]+ requests in' "$SOAK/wrk-$i.txt" | grep -oE '^[0-9]+' | tail -1)
  acc=$(grep -c 'url.path\|http.route' "$LOGS/logs.json" 2>/dev/null || echo 0)
  err=$(grep -c 'nginx.error' "$LOGS/logs.json" 2>/dev/null || echo 0)
  up=$(kill -0 "$NGINX_PID" 2>/dev/null && echo yes || echo NO)
  log "chunk $i: worker_rss=$(rss_sum "$WK")KB exporter_rss=$(rss_sum "$EX")KB metrics=$(mtr)B logs=$(lgs)B (acc~$acc err~$err) reqs=${reqs:-?} nginx_up=$up drops=$(selfmetric ngx_otel.dropped_records) logdrops_acc=$(selfmetric ngx_otel.logs.access.dropped_records) logdrops_err=$(selfmetric ngx_otel.logs.error.dropped_records) sendfail=$(selfmetric ngx_otel.send_failures)"
  if [ "$up" = NO ]; then log "FATAL: nginx exited at chunk $i — stopping."; break; fi
done

log "LOAD COMPLETE — graceful drain (SIGQUIT)."
kill -QUIT "$NGINX_PID" 2>/dev/null; sleep 6
log "post-drain: nginx_up=$(kill -0 "$NGINX_PID" 2>/dev/null && echo yes || echo no)"
log "panics/crashes in error.log: $(grep -ciE 'panic|SIGSEGV|SIGABRT|core dumped' "$SOAK/logs/error.log" 2>/dev/null)"
log "final self-metrics: dropped=$(selfmetric ngx_otel.dropped_records) acc_logdrops=$(selfmetric ngx_otel.logs.access.dropped_records) err_logdrops=$(selfmetric ngx_otel.logs.error.dropped_records) sendfail=$(selfmetric ngx_otel.send_failures)"
log "SOAK END."
