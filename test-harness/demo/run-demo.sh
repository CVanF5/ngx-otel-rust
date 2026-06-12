#!/usr/bin/env bash
# run-demo.sh — one-command Grafana demo for ngx-otel-rust.
#
#   ./run-demo.sh up      # build (if needed) + start stack + nginx + traffic
#   ./run-demo.sh down     # stop traffic + nginx + docker stack
#   ./run-demo.sh status   # show what's running
#
# Layout: nginx runs on the HOST loading the host-built module and ships
# OTLP/HTTP to the demo collector on 127.0.0.1:14318. The collector exposes
# a Prometheus endpoint scraped by Prometheus; Grafana reads Prometheus.
#
#   Grafana:    http://localhost:3000   (anonymous; lands on the dashboard)
#   Prometheus: http://localhost:19090
#   Collector /metrics: http://localhost:18889/metrics
#
# Everything binds 127.0.0.1 only and uses offset ports, so it never
# collides with the test harness collector (4317/4318).
set -euo pipefail

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "${DEMO_DIR}/../.." && pwd)"
PREFIX="${DEMO_DIR}/.run"
COMPOSE=(docker compose -f "${DEMO_DIR}/docker-compose.demo.yml")
COLLECTOR_HTTP="http://127.0.0.1:14318"
GRAFANA_URL="http://localhost:3000"

case "$(uname -s)" in
    Darwin) MODULE_EXT="dylib" ;;
    *)      MODULE_EXT="so"    ;;
esac
MODULE_PATH="${CRATE_DIR}/target/release/libngx_http_otel_module.${MODULE_EXT}"
NGINX_BIN="${NGINX_BINARY:-${CRATE_DIR}/objs-release/nginx}"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info() { echo -e "${YELLOW}[demo]${NC} $*"; }
ok()   { echo -e "${GREEN}[demo]${NC} $*"; }
err()  { echo -e "${RED}[demo]${NC} $*" >&2; }

ensure_built() {
    if [[ ! -f "${MODULE_PATH}" || ! -x "${NGINX_BIN}" ]]; then
        info "module or nginx missing — running 'make build-release'..."
        ( cd "${CRATE_DIR}" && make build-release )
    fi
    [[ -f "${MODULE_PATH}" ]] || { err "module not found: ${MODULE_PATH}"; exit 1; }
    [[ -x "${NGINX_BIN}" ]]   || { err "nginx not found: ${NGINX_BIN}"; exit 1; }
}

# Self-signed serving certs so the "Serving certificates" dashboard panel has
# data: one SHORT-lived cert (~1 h → sits below the panel's 7 d threshold and
# visibly counts down) and one LONG cert (90 d → green).
#
# A true 1-hour notAfter needs `openssl req -not_after` (OpenSSL >= 3.4).
# Stock macOS LibreSSL lacks it, so we prefer a Homebrew OpenSSL when present
# and fall back to `-days 1` (24 h — still well under the 7 d threshold).
gen_demo_certs() {
    local certs="${PREFIX}/certs"
    mkdir -p "${certs}"

    local ossl="openssl"
    local cand
    for cand in /opt/homebrew/opt/openssl*/bin/openssl /usr/local/opt/openssl*/bin/openssl; do
        [[ -x "${cand}" ]] && ossl="${cand}" && break
    done

    local short_args=(-days 1)
    if "${ossl}" req -help 2>&1 | grep -q -- '-not_after'; then
        # notAfter = now + 1 h (UTC), format YYYYMMDDHHMMSSZ.
        local not_after
        not_after="$(date -u -v+1H +%Y%m%d%H%M%SZ 2>/dev/null \
                     || date -u -d '+1 hour' +%Y%m%d%H%M%SZ)"
        short_args=(-not_after "${not_after}")
        info "generating demo serving certs (short: 1 h via ${ossl})..."
    else
        info "generating demo serving certs (short: 24 h fallback — ${ossl} lacks -not_after)..."
    fi

    "${ossl}" req -x509 -nodes -newkey rsa:2048 \
        -keyout "${certs}/short.key" -out "${certs}/short.crt" \
        -subj "/CN=demo-short.local" "${short_args[@]}" >/dev/null 2>&1
    "${ossl}" req -x509 -nodes -newkey rsa:2048 \
        -keyout "${certs}/long.key" -out "${certs}/long.crt" \
        -subj "/CN=demo-long.local" -days 90 >/dev/null 2>&1

    ok "serving certs: short=$("${ossl}" x509 -in "${certs}/short.crt" -noout -enddate), long=90d"
}

wait_for_collector() {
    local i
    for i in $(seq 1 30); do
        if curl -s --max-time 2 "${COLLECTOR_HTTP}/" >/dev/null 2>&1; then return 0; fi
        sleep 1
    done
    return 1
}

start_traffic() {
    # Light, varied background load so every histogram populates.
    #
    # Each request carries a UNIQUE W3C `traceparent` so the trace_id propagates
    # to BOTH the request-duration histogram exemplar (Phase 2.2.4) and the
    # access tail LogRecord — that shared trace_id is the join key behind the
    # Grafana exemplar→Loki drill-down (click an exemplar diamond → its tail log).
    (
      # 00-<16-byte trace-id>-<8-byte span-id>-01 (01 = sampled).
      tp() { printf '00-%s-%s-01' "$(openssl rand -hex 16)" "$(openssl rand -hex 8)"; }
      req() { curl -s -o /dev/null -H "traceparent: $(tp)" "$@" || true; }
      while true; do
        req "http://127.0.0.1:9400/"
        req "http://127.0.0.1:9400/big"
        req "http://127.0.0.1:9400/api/"
        req "http://127.0.0.1:9400/api/"
        req -X POST "http://127.0.0.1:9400/"                      # method=POST
        req "http://127.0.0.1:9400/client-error"                 # 4xx
        # 5xx less often, so the breakdown shows a realistic error mix
        [ $((RANDOM % 4)) -eq 0 ] && req "http://127.0.0.1:9400/server-error"
        # Periodic BURST of dead-upstream hits: many identical "connect() failed"
        # error lines inside one ~250ms log-drain window → a single coalesced
        # nginx.error LogRecord with coalesced_count >> 1 (showcases producer-side
        # error coalescing; a sparse 1-per-window hit would always show x1).
        if [ $((RANDOM % 8)) -eq 0 ]; then
          # ONE curl process firing ~30 identical dead-upstream requests, packed
          # into a single ~250ms log-drain window → coalesced_count well above 1.
          curl -s -o /dev/null $(yes "http://127.0.0.1:9400/backend-down" | head -n 30) 2>/dev/null || true
        fi
        sleep 0.05
      done ) >/dev/null 2>&1 &
    echo $! > "${PREFIX}/traffic.pid"
}

cmd_up() {
    ensure_built
    info "starting docker stack (collector + prometheus + grafana + loki + tempo)..."
    "${COMPOSE[@]}" --profile traces up -d

    info "waiting for collector on ${COLLECTOR_HTTP} ..."
    wait_for_collector || { err "collector did not come up; see: ${COMPOSE[*]} logs collector"; exit 1; }

    # Fresh sandbox prefix for nginx.
    rm -rf "${PREFIX}"; mkdir -p "${PREFIX}/logs"
    gen_demo_certs
    sed -e "s|@MODULE_PATH@|${MODULE_PATH}|g" \
        -e "s|@PREFIX@|${PREFIX}|g" \
        "${DEMO_DIR}/nginx-demo.conf.template" > "${PREFIX}/nginx.conf"

    # Raise the fd soft limit so worker_connections (1024) doesn't warn against
    # the macOS default of 256 (harmless cap, but noisy for a demo). Best-effort.
    ulimit -n 4096 2>/dev/null || true

    # Validate then launch nginx (daemon off → background it ourselves).
    "${NGINX_BIN}" -t -p "${PREFIX}" -c "${PREFIX}/nginx.conf"
    "${NGINX_BIN}" -p "${PREFIX}" -c "${PREFIX}/nginx.conf" &
    echo $! > "${PREFIX}/nginx.pid"
    sleep 1

    info "starting background traffic generator..."
    start_traffic

    ok "demo is up."
    echo "  Grafana:            ${GRAFANA_URL}   (opens on the ngx-otel-rust dashboard)"
    echo "  Prometheus:         http://localhost:19090"
    echo "  Collector /metrics: http://localhost:18889/metrics"
    echo "  Loki:               http://localhost:13100  (logs → Grafana 'Logs' section)"
    echo "  nginx front:        http://127.0.0.1:9400/  (also /big, /api/, /client-error, /server-error)"
    echo "  export interval: 2s — allow ~10s for metrics; the Logs section needs a few 4xx/5xx (traffic gen drives them)."
    echo "  stop with: ${BASH_SOURCE[0]} down"
}

cmd_down() {
    if [[ -f "${PREFIX}/traffic.pid" ]]; then
        kill "$(cat "${PREFIX}/traffic.pid")" 2>/dev/null || true
        rm -f "${PREFIX}/traffic.pid"
    fi
    if [[ -f "${PREFIX}/nginx.pid" ]]; then
        "${NGINX_BIN}" -p "${PREFIX}" -c "${PREFIX}/nginx.conf" -s quit 2>/dev/null \
            || kill "$(cat "${PREFIX}/nginx.pid")" 2>/dev/null || true
        rm -f "${PREFIX}/nginx.pid"
    fi
    # Belt-and-braces: any stray demo nginx workers.
    pgrep -f "nginx.*${PREFIX}" 2>/dev/null | while read -r p; do kill "$p" 2>/dev/null || true; done
    info "stopping docker stack..."
    "${COMPOSE[@]}" --profile logs --profile traces down
    ok "demo stopped."
}

cmd_status() {
    "${COMPOSE[@]}" ps || true
    echo "---"
    if [[ -f "${PREFIX}/nginx.pid" ]] && kill -0 "$(cat "${PREFIX}/nginx.pid")" 2>/dev/null; then
        ok "nginx running (pid $(cat "${PREFIX}/nginx.pid"))"
    else
        info "nginx not running"
    fi
}

case "${1:-up}" in
    up)     cmd_up ;;
    down)   cmd_down ;;
    status) cmd_status ;;
    *)      err "usage: $0 {up|down|status}"; exit 2 ;;
esac
