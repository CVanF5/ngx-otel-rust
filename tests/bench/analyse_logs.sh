#!/usr/bin/env bash
# tests/bench/analyse_logs.sh — re-derive zero-cost-logs tolerance from saved JSON
#
# Reads the raw per-run RPS numbers from a results/<timestamp>.txt file
# produced by zero_cost_logs.sh and recomputes the regression percentages.
#
# Usage:
#   bash tests/bench/analyse_logs.sh tests/bench/results/logs_bench_YYYYMMDD_HHMMSS.txt

set -euo pipefail

LOGFILE="${1:-}"
if [[ -z "${LOGFILE}" || ! -f "${LOGFILE}" ]]; then
    echo "Usage: $0 <results/logs_bench_*.txt>" >&2
    exit 1
fi

CYAN='\033[0;36m'; NC='\033[0m'
section() { echo -e "${CYAN}=== $* ===${NC}"; }

section "Re-analysis of $(basename "${LOGFILE}")"

get_median() {
    local label="$1"
    grep "^${label} median=" "${LOGFILE}" | tail -1 | sed 's/.*median=\([^ ]*\).*/\1/'
}

BL=$(get_median BL)
TA=$(get_median TA)
TB=$(get_median TB)

echo "BL = ${BL} req/s"
echo "TA = ${TA} req/s"
echo "TB = ${TB} req/s"

REG_TA=$(awk "BEGIN { printf \"%.2f\", (${BL} - ${TA}) / ${BL} * 100 }")
REG_TB=$(awk "BEGIN { printf \"%.2f\", (${BL} - ${TB}) / ${BL} * 100 }")

echo "BL vs TA: ${REG_TA}% regression"
echo "BL vs TB: ${REG_TB}% regression (informational)"

# Use awk float comparison so the gate is exactly 2.0%, not a rounded integer
# boundary (rounding 1.5->2 or 2.49->2 would produce a fuzzy ~1.5% threshold).
if awk "BEGIN { exit (${REG_TA} < 2.0) ? 0 : 1 }"; then
    echo "PASS: BL vs TA regression ${REG_TA}% < 2% (zero-cost gate)"
elif awk "BEGIN { exit (${REG_TA} < 5.0) ? 0 : 1 }"; then
    echo "INFO: BL vs TA regression ${REG_TA}% < 5% (acceptable on dev hardware)"
else
    echo "WARN: BL vs TA regression ${REG_TA}% >= 5% — check on isolated hardware" >&2
fi
