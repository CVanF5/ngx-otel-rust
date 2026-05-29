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
    ( while true; do
        curl -s -o /dev/null "http://127.0.0.1:9400/"      || true
        curl -s -o /dev/null "http://127.0.0.1:9400/big"   || true
        curl -s -o /dev/null "http://127.0.0.1:9400/api/"  || true
        curl -s -o /dev/null "http://127.0.0.1:9400/api/"  || true
        sleep 0.05
      done ) >/dev/null 2>&1 &
    echo $! > "${PREFIX}/traffic.pid"
}

cmd_up() {
    ensure_built
    info "starting docker stack (collector + prometheus + grafana)..."
    "${COMPOSE[@]}" up -d

    info "waiting for collector on ${COLLECTOR_HTTP} ..."
    wait_for_collector || { err "collector did not come up; see: ${COMPOSE[*]} logs collector"; exit 1; }

    # Fresh sandbox prefix for nginx.
    rm -rf "${PREFIX}"; mkdir -p "${PREFIX}/logs"
    sed -e "s|@MODULE_PATH@|${MODULE_PATH}|g" \
        -e "s|@PREFIX@|${PREFIX}|g" \
        "${DEMO_DIR}/nginx-demo.conf.template" > "${PREFIX}/nginx.conf"

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
    echo "  nginx front:        http://127.0.0.1:9400/  (also /big, /api/)"
    echo "  metric export interval: 2s — allow ~10s for the dashboard to fill."
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
