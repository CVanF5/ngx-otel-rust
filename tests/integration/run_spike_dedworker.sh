#!/usr/bin/env bash
# Spike driver: dedicated non-accepting otel worker.
# Arg1: "reuseport" or "noreuseport"  (socket mode)
# Runs checks 1-4 for that mode and prints EVIDENCE.
set -u

MODE="${1:-noreuseport}"
CRATE=~/project-nginx-otel/ngx-otel-rust
SCRATCH=~/project-nginx-otel/spike-dedworker-scratch
MODULE="$CRATE/objs-debug/ngx_http_otel_module.so"
NGINX="$CRATE/objs-debug/nginx"
TMPL="$SCRATCH/spike_conf.tmpl"
PREFIX="$SCRATCH/run-$MODE"
CONF="$PREFIX/nginx.conf"
PORT=9300

rm -rf "$PREFIX"; mkdir -p "$PREFIX/logs"
if [ "$MODE" = reuseport ]; then RP=reuseport; else RP=""; fi
sed -e "s#@MODULE_PATH@#$MODULE#g" -e "s#@PREFIX@#$PREFIX#g" -e "s#@REUSEPORT@#$RP#g" "$TMPL" > "$CONF"

echo "################################################################"
echo "## SOCKET MODE: $MODE  (listen 127.0.0.1:$PORT $RP)"
echo "################################################################"

# nginx needs an absolute prefix; -p sets it. logs/ exists.
"$NGINX" -p "$PREFIX" -c "$CONF" 2>&1 &
sleep 2

# Under daemon on, the launching process exits; read master from pidfile.
MASTER="$(cat "$PREFIX/nginx.pid" 2>/dev/null)"
echo "[INFO] master pid (from pidfile) = $MASTER"
if [ -z "$MASTER" ]; then echo "[FAIL] no master pid"; tail -20 "$PREFIX/error.log"; exit 2; fi

# List workers (children of master).
worker_pids() { ps -eo pid,ppid,args | awk -v m="$MASTER" '$2==m && /worker process/{print $1}'; }
echo "[INFO] worker pids:"; ps -eo pid,ppid,args | awk -v m="$MASTER" '$2==m {print "   "$0}'

# The dedicated otel worker is the LAST slot. Identify it from the error.log line.
grep "dedicated otel worker" "$PREFIX/error.log" | tail -3
DEDPID="$(grep -oE 'dedicated otel worker' "$PREFIX/error.log" >/dev/null && \
  ps -eo pid,ppid,args | awk -v m="$MASTER" '$2==m && /worker process/{print $1}' | tail -1)"
# Heuristic: the dedicated worker is the highest-PID worker (forked last = last slot).
# Confirm via accept evidence below regardless.
DEDPID="$(worker_pids | sort -n | tail -1)"
echo "[INFO] presumed dedicated otel worker (last slot, highest pid) = $DEDPID"

echo "=== accept-suppression evidence (error.log) ==="
grep -E "spike dedicated-worker|accept suppressed|removed accept|closed reuseport" "$PREFIX/error.log"

# ---- generate load ----
echo "=== CHECK 1: drive 300 requests, observe which workers serve ==="
for i in $(seq 1 300); do curl -s -o /dev/null "http://127.0.0.1:$PORT/" & done; wait
sleep 1

echo "=== listening sockets / ESTAB by PID (ss) ==="
ss -tlnp 2>/dev/null | grep ":$PORT " || echo "(ss -tlnp showed no :$PORT listener line)"
echo "--- per-worker listen fd ownership ---"
for w in $(worker_pids); do
  n=$(ls -l /proc/$w/fd 2>/dev/null | grep -c socket)
  echo "  worker $w: $n socket fds"
done

echo "=== CHECK 1b: per-worker accept counts via /proc fd -> socket inodes on :$PORT ==="
# Find listen socket inodes on :$PORT (hex port)
HEXPORT=$(printf '%04X' $PORT)
echo "  (port $PORT = hex $HEXPORT) listening entries in /proc/net/tcp:"
grep -i " 0100007F:$HEXPORT " /proc/net/tcp 2>/dev/null | awk '{print "    local="$2" st="$4" inode="$10}'

# Telemetry baseline + after (check 2)
echo "=== CHECK 2: telemetry to collector ==="
ML=$CRATE/test-harness/logs/metrics.json
echo "  metrics.json size before extra load: $(wc -l < "$ML" 2>/dev/null)"
for i in $(seq 1 200); do curl -s -o /dev/null "http://127.0.0.1:$PORT/" & done; wait
sleep 3
echo "  metrics.json size after: $(wc -l < "$ML" 2>/dev/null)"
echo "  newest metrics line mentions our service?"
tail -2 "$ML" 2>/dev/null | grep -o 'spike-dedworker' | head -1 || echo "   (service tag not in last lines; checking whole tail)"
tail -50 "$ML" 2>/dev/null | grep -c 'spike-dedworker'

echo "=== B2 / CHECK 3: PPID of dedicated worker, kill -9, respawn ==="
echo "  dedicated worker $DEDPID PPID = $(ps -o ppid= -p $DEDPID 2>/dev/null | tr -d ' ') (master=$MASTER)"
echo "  killing dedicated otel worker $DEDPID"
kill -9 "$DEDPID" 2>/dev/null
sleep 4
echo "  workers after kill:"; ps -eo pid,ppid,args | awk -v m="$MASTER" '$2==m && /worker process/{print "   "$0}'
NEWDED="$(worker_pids | sort -n | tail -1)"
echo "  new dedicated (last slot) worker pid = $NEWDED  PPID = $(ps -o ppid= -p $NEWDED 2>/dev/null | tr -d ' ')"
echo "  respawn accept-suppression re-applied?"
grep -E "accept suppressed|removed accept|closed reuseport" "$PREFIX/error.log" | tail -3
echo "  master log respawn line:"; grep -iE "respawn|exited on signal" "$PREFIX/error.log" | tail -3

echo "=== CHECK 4: reload re-establishes dedicated worker with accept suppressed ==="
"$NGINX" -p "$PREFIX" -c "$CONF" -s reload 2>&1
sleep 3
MASTER2="$(cat "$PREFIX/nginx.pid")"
echo "  master after reload = $MASTER2"
echo "  workers after reload:"; ps -eo pid,ppid,args | awk -v m="$MASTER2" '$2==m && /worker process/{print "   "$0}'
echo "  accept-suppression after reload (new lines):"
grep -E "accept suppressed|removed accept|closed reuseport" "$PREFIX/error.log" | tail -3
echo "  post-reload requests still 200 + no accept on ded worker:"
for i in $(seq 1 50); do curl -s -o /dev/null -w "%{http_code} " "http://127.0.0.1:$PORT/"; done | tr ' ' '\n' | sort | uniq -c

echo "=== shutdown ==="
"$NGINX" -p "$PREFIX" -c "$CONF" -s quit 2>&1
sleep 2
pkill -f "nginx.*run-$MODE" 2>/dev/null
echo "=== ERROR LOG TAIL ($MODE) ==="
tail -40 "$PREFIX/error.log"
echo "## DONE MODE $MODE"
