#!/usr/bin/env bash
# Spike driver: dual-role otel worker (serves requests AND runs export task).
# Arg1: "reuseport" or "noreuseport"  (socket mode)
# Runs checks 1-5 for that mode and prints EVIDENCE.
set -u

MODE="${1:-noreuseport}"
CRATE=~/project-nginx-otel/ngx-otel-rust
SCRATCH=~/project-nginx-otel/spike-dualrole-scratch
MODULE="$CRATE/objs-debug/ngx_http_otel_module.so"
NGINX="$CRATE/objs-debug/nginx"
TMPL="$CRATE/tests/integration/nginx_spike_dualrole.conf.tmpl"
PREFIX="$SCRATCH/run-$MODE"
CONF="$PREFIX/nginx.conf"
PORT=9301

rm -rf "$PREFIX"; mkdir -p "$PREFIX/logs"
if [ "$MODE" = reuseport ]; then RP=reuseport; else RP=""; fi
sed -e "s#@MODULE_PATH@#$MODULE#g" -e "s#@PREFIX@#$PREFIX#g" -e "s#@REUSEPORT@#$RP#g" "$TMPL" > "$CONF"

echo "################################################################"
echo "## DUAL-ROLE SOCKET MODE: $MODE  (listen 127.0.0.1:$PORT $RP)"
echo "################################################################"

"$NGINX" -p "$PREFIX" -c "$CONF" 2>&1 &
sleep 2

# Under daemon on, the launching process exits; read master from pidfile.
MASTER="$(cat "$PREFIX/nginx.pid" 2>/dev/null)"
echo "[INFO] master pid (from pidfile) = $MASTER"
if [ -z "$MASTER" ]; then echo "[FAIL] no master pid"; tail -20 "$PREFIX/error.log"; exit 2; fi

# List workers (children of master).
worker_pids() { ps -eo pid,ppid,args | awk -v m="$MASTER" '$2==m && /worker process/{print $1}'; }
echo "[INFO] worker pids (all should serve requests):"; ps -eo pid,ppid,args | awk -v m="$MASTER" '$2==m {print "   "$0}'

# Identify the dual-role worker (last slot = highest PID among workers).
DUALROLE_PID="$(worker_pids | sort -n | tail -1)"
echo "[INFO] presumed dual-role otel worker (last slot, highest pid) = $DUALROLE_PID"

echo "=== dual-role init evidence (error.log) ==="
grep -E "dual-role|export task spawned" "$PREFIX/error.log"

echo "=== KEY: no accept-suppression lines should appear ==="
if grep -qE "accept suppressed|removed accept|closed reuseport" "$PREFIX/error.log"; then
    echo "[FAIL] accept suppression found — this should NOT appear in dual-role mode:"
    grep -E "accept suppressed|removed accept|closed reuseport" "$PREFIX/error.log"
else
    echo "[OK] no accept suppression — dual-role worker keeps its accept events"
fi

# ---- generate load ----
echo ""
echo "=== CHECK 1: drive 300 requests, verify dual-role worker ALSO serves ==="
SERVED=0; FAIL=0
for i in $(seq 1 300); do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 "http://127.0.0.1:$PORT/")
    if [ "$CODE" = "200" ]; then SERVED=$((SERVED+1)); else FAIL=$((FAIL+1)); fi
done
echo "  [RESULT] served=$SERVED fail=$FAIL (expect: served=300, fail=0)"
if [ "$SERVED" -eq 300 ]; then
    echo "  [OK] all 300 requests served"
else
    echo "  [WARN] $FAIL requests failed"
fi

echo ""
echo "=== CHECK 2: telemetry to collector ==="
ML=$CRATE/test-harness/logs/metrics.json
echo "  metrics.json size before extra load: $(wc -l < "$ML" 2>/dev/null)"
for i in $(seq 1 200); do curl -s -o /dev/null "http://127.0.0.1:$PORT/" & done; wait
sleep 3
echo "  metrics.json size after: $(wc -l < "$ML" 2>/dev/null)"
TELEMETRY_LINES=$(tail -50 "$ML" 2>/dev/null | grep -c 'spike-dualrole' || true)
echo "  spike-dualrole lines in last 50 of metrics.json: $TELEMETRY_LINES"
if [ "$TELEMETRY_LINES" -gt 0 ]; then
    echo "  [OK] telemetry flowing to collector"
else
    echo "  [WARN] no spike-dualrole lines found — check collector"
fi

echo ""
echo "=== CHECK 3 / B2: PPID of dual-role worker, kill -9, respawn ==="
echo "  dual-role worker $DUALROLE_PID PPID = $(ps -o ppid= -p $DUALROLE_PID 2>/dev/null | tr -d ' ') (master=$MASTER)"
echo "  killing dual-role otel worker $DUALROLE_PID"
kill -9 "$DUALROLE_PID" 2>/dev/null
sleep 4
echo "  workers after kill:"; ps -eo pid,ppid,args | awk -v m="$MASTER" '$2==m && /worker process/{print "   "$0}'
NEWDUAL="$(worker_pids | sort -n | tail -1)"
NEW_PPID="$(ps -o ppid= -p $NEWDUAL 2>/dev/null | tr -d ' ')"
echo "  new dual-role worker pid = $NEWDUAL  PPID = $NEW_PPID  (expect PPID=$MASTER)"
if [ "$NEW_PPID" = "$MASTER" ]; then
    echo "  [OK] PPID == master — B2 supervision confirmed"
else
    echo "  [WARN] PPID mismatch"
fi
echo "  export task re-spawned after respawn?"
grep -E "dual-role.*export task spawned" "$PREFIX/error.log" | tail -3
echo "  master respawn log line:"; grep -iE "respawn|exited on signal" "$PREFIX/error.log" | tail -3

echo ""
echo "=== CHECK 4: reload re-establishes dual-role worker, all still serve 200 ==="
"$NGINX" -p "$PREFIX" -c "$CONF" -s reload 2>&1
sleep 3
MASTER2="$(cat "$PREFIX/nginx.pid")"
echo "  master after reload = $MASTER2"
echo "  workers after reload:"; ps -eo pid,ppid,args | awk -v m="$MASTER2" '$2==m && /worker process/{print "   "$0}'
echo "  post-reload: dual-role log in error.log?"
grep -E "dual-role" "$PREFIX/error.log" | tail -3
echo "  post-reload: no accept suppression?"
if grep -qE "accept suppressed|removed accept|closed reuseport" "$PREFIX/error.log"; then
    echo "  [FAIL] accept suppression appeared after reload"
else
    echo "  [OK] no accept suppression after reload"
fi
echo "  post-reload requests:"
RELOAD_SERVED=0; RELOAD_FAIL=0
for i in $(seq 1 50); do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 "http://127.0.0.1:$PORT/")
    if [ "$CODE" = "200" ]; then RELOAD_SERVED=$((RELOAD_SERVED+1)); else RELOAD_FAIL=$((RELOAD_FAIL+1)); fi
done
echo "  [RESULT] served=$RELOAD_SERVED fail=$RELOAD_FAIL (expect served=50, fail=0)"

echo ""
echo "=== CHECK 5: reuseport headline — served/total ratio ==="
echo "  (This check is most meaningful in reuseport mode)"
RUP_SERVED=0; RUP_FAIL=0
for i in $(seq 1 150); do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 "http://127.0.0.1:$PORT/")
    if [ "$CODE" = "200" ]; then RUP_SERVED=$((RUP_SERVED+1)); else RUP_FAIL=$((RUP_FAIL+1)); fi
done
echo "  [RESULT] mode=$MODE served=$RUP_SERVED / 150 total (fail=$RUP_FAIL)"
if [ "$RUP_FAIL" -eq 0 ]; then
    echo "  [OK] 0 failures — no blackhole"
else
    echo "  [WARN] $RUP_FAIL failures"
fi

echo ""
echo "=== shutdown ==="
"$NGINX" -p "$PREFIX" -c "$CONF" -s quit 2>&1
sleep 2
pkill -f "nginx.*run-$MODE" 2>/dev/null
echo "=== ERROR LOG TAIL ($MODE) ==="
tail -40 "$PREFIX/error.log"
echo "## DONE MODE $MODE"
