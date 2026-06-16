#!/usr/bin/env bash
# tests/bench/analyse.sh — analyse a wrk benchmark run JSON and assert
# the zero-cost-when-disabled tolerance check.
#
# Usage:
#   bash tests/bench/analyse.sh [path-to-run-*.json]
#
# If no path is given, picks the most recent results/run-*.json.
#
# Tolerance (overridable via TOLERANCE_PCT env var; default 3.0):
#   - C1 run-to-run variance must be < TOLERANCE_PCT (machine-stability check)
#   - |C1 - C2| / C1 must be < TOLERANCE_PCT on median latency, p99 latency,
#     and throughput (the headline zero-cost assertion)
#
# C3 operational cost (C3 vs C1) is reported but not asserted — that number
# gets quoted in the proposal and characterised properly on production hardware.
#
# Exit codes:
#   0  all checks pass
#   2  one or more checks fail
#   3  input file missing, malformed, or has unequal iteration counts
#
# Designed to be re-runnable on any committed run-*.json file so re-analysis
# is reproducible without re-executing the benchmark itself.  A follow-on soak
# run can reuse this for its own tolerance check (with a per-run threshold).

set -euo pipefail

# ─── Resolve JSON path ───────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JSON="${1:-}"
if [[ -z "${JSON}" ]]; then
    # shellcheck disable=SC2012  # ls -t is intentional here for recency sort
    JSON="$(ls -t "${SCRIPT_DIR}/results/"run-*.json 2>/dev/null | head -1 || true)"
fi
if [[ -z "${JSON}" || ! -f "${JSON}" ]]; then
    echo "ERROR: results JSON not found: ${JSON:-(none); pass a path or place a run-*.json under ${SCRIPT_DIR}/results/}" >&2
    exit 3
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq is required and not installed." >&2
    exit 3
fi

TOLERANCE_PCT="${TOLERANCE_PCT:-3.0}"

# ─── Extract per-config stats via jq ─────────────────────────────────────────

STATS="$(jq -c '
  def median:
    sort as $a | ($a | length) as $n |
    if $n == 0 then null
    elif $n % 2 == 1 then $a[($n / 2 | floor)]
    else ($a[$n / 2 - 1] + $a[$n / 2]) / 2
    end;

  group_by(.config) | map({
    config: .[0].config,
    n: length,
    median_ms: ([.[].median_ms] | median),
    p99_ms: ([.[].p99_ms] | median),
    req_per_sec: ([.[].req_per_sec] | median),
    median_ms_min: ([.[].median_ms] | min),
    median_ms_max: ([.[].median_ms] | max),
    req_per_sec_min: ([.[].req_per_sec] | min),
    req_per_sec_max: ([.[].req_per_sec] | max)
  })
' "${JSON}")"

# Helper: extract one field for one config from $STATS.  Renamed from
# the obvious "stat" to avoid collision with the stat(1) shell builtin
# used elsewhere in the harness.
field() {
    local cfg="$1" key="$2"
    jq -r --arg cfg "$cfg" --arg key "$key" \
        '.[] | select(.config == $cfg) | .[$key]' <<<"${STATS}"
}

# Helper: |a - b| / a * 100 as a percentage with 2 decimals.
abs_pct() {
    awk -v a="$1" -v b="$2" '
        BEGIN {
            if (a == 0) { print "INF"; exit }
            d = b - a; if (d < 0) d = -d
            printf "%.2f", d / a * 100
        }'
}

# Helper: signed (b - a) / a * 100 percentage (for operational cost).
signed_pct() {
    awk -v a="$1" -v b="$2" '
        BEGIN {
            if (a == 0) { print "INF"; exit }
            printf "%+.2f", (b - a) / a * 100
        }'
}

# Helper: assert numeric value < threshold.  Updates FAILED on failure.
assert_lt() {
    local label="$1" value="$2" threshold="$3"
    if awk -v v="$value" -v t="$threshold" 'BEGIN { exit !(v < t) }'; then
        printf "  [PASS] %-40s %6s%% < %s%%\n" "$label" "$value" "$threshold"
    else
        printf "  [FAIL] %-40s %6s%% >= %s%%\n" "$label" "$value" "$threshold"
        FAILED=1
    fi
}

# ─── Sanity check: equal iteration counts ────────────────────────────────────

N_C1="$(field c1 n)"
N_C2="$(field c2 n)"
N_C3="$(field c3 n)"

if [[ "${N_C1}" != "${N_C2}" || "${N_C1}" != "${N_C3}" ]]; then
    echo "ERROR: unequal iteration counts across configs (c1=${N_C1}, c2=${N_C2}, c3=${N_C3})" >&2
    echo "       Tolerance comparison is only valid when all configs have the same N." >&2
    exit 3
fi

if (( N_C1 < 5 )); then
    echo "WARNING: only ${N_C1} iterations per config; ≥ 5 recommended for stable medians." >&2
fi

# ─── Per-config medians ──────────────────────────────────────────────────────

echo "Analyzing: ${JSON}"
echo ""
echo "=== Per-config medians (N=${N_C1} iterations each) ==="
printf "  %-10s %14s %14s %14s\n" "config" "median (ms)" "p99 (ms)" "req/sec"
for cfg in c1 c2 c3; do
    printf "  %-10s %14s %14s %14s\n" \
        "${cfg}" \
        "$(field "$cfg" median_ms)" \
        "$(field "$cfg" p99_ms)" \
        "$(field "$cfg" req_per_sec)"
done

# ─── Capture stat values once for delta math ─────────────────────────────────

C1_MED="$(field c1 median_ms)";    C2_MED="$(field c2 median_ms)";    C3_MED="$(field c3 median_ms)"
C1_P99="$(field c1 p99_ms)";       C2_P99="$(field c2 p99_ms)";       C3_P99="$(field c3 p99_ms)"
C1_RPS="$(field c1 req_per_sec)";  C2_RPS="$(field c2 req_per_sec)";  C3_RPS="$(field c3 req_per_sec)"
C1_MED_MIN="$(field c1 median_ms_min)";    C1_MED_MAX="$(field c1 median_ms_max)"
C1_RPS_MIN="$(field c1 req_per_sec_min)";  C1_RPS_MAX="$(field c1 req_per_sec_max)"

FAILED=0

# ─── C1 run-to-run variance (machine stability) ──────────────────────────────

echo ""
echo "=== C1 run-to-run variance (machine-stability check; must be < ${TOLERANCE_PCT}%) ==="
C1_MED_VAR="$(awk -v lo="$C1_MED_MIN" -v hi="$C1_MED_MAX" -v m="$C1_MED" \
    'BEGIN { printf "%.2f", (hi - lo) / m * 100 }')"
C1_RPS_VAR="$(awk -v lo="$C1_RPS_MIN" -v hi="$C1_RPS_MAX" -v m="$C1_RPS" \
    'BEGIN { printf "%.2f", (hi - lo) / m * 100 }')"
assert_lt "C1 median latency variance" "$C1_MED_VAR" "$TOLERANCE_PCT"
assert_lt "C1 throughput variance"     "$C1_RPS_VAR" "$TOLERANCE_PCT"

# ─── C1-vs-C2 (the zero-cost assertion) ──────────────────────────────────────

echo ""
echo "=== C1-vs-C2 tolerance (zero-cost-when-disabled; |C2-C1|/C1 < ${TOLERANCE_PCT}%) ==="
assert_lt "median latency delta" "$(abs_pct "$C1_MED" "$C2_MED")" "$TOLERANCE_PCT"
assert_lt "p99 latency delta"    "$(abs_pct "$C1_P99" "$C2_P99")" "$TOLERANCE_PCT"
assert_lt "throughput delta"     "$(abs_pct "$C1_RPS" "$C2_RPS")" "$TOLERANCE_PCT"

# ─── C3 operational cost (informational) ─────────────────────────────────────

echo ""
echo "=== C3 operational cost vs C1 (informational, NOT asserted) ==="
printf "  %-40s %s%%\n" "median latency (C3 vs C1)" "$(signed_pct "$C1_MED" "$C3_MED")"
printf "  %-40s %s%%\n" "p99 latency (C3 vs C1)"    "$(signed_pct "$C1_P99" "$C3_P99")"
printf "  %-40s %s%%\n" "throughput (C3 vs C1)"     "$(signed_pct "$C1_RPS" "$C3_RPS")"
echo ""
echo "(Signed deltas; throughput negative = C3 slower than C1.  C3 numbers"
echo " from a local laptop are a sanity check, not the definitive"
echo " operational characterisation — run on production-shape hardware for that.)"

# ─── Summary ─────────────────────────────────────────────────────────────────

echo ""
if [[ "${FAILED}" -eq 0 ]]; then
    echo "RESULT: all tolerance checks PASS at ${TOLERANCE_PCT}% threshold."
    exit 0
else
    echo "RESULT: one or more tolerance checks FAILED at ${TOLERANCE_PCT}% threshold." >&2
    exit 2
fi
