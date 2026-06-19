# Metrics OTel-correctness regression bench — paired Δ (host-1, AMD EPYC 9R14)

## Question

Did the metrics OTel-correctness rework regress per-request cost? The rework changed the
metric *wire shape* (`nginx.*` counters → real OTLP Sums; request-duration exp-histogram
→ seconds via a spec-exact `ceil(log2(v_s)*8)-1` bucketing over a precomputed integer-µs
threshold table; `http.response.status_code` int → `http.response.status_class` string)
and was expected to be hot-path-cost-neutral (the per-request bump is unchanged; the
seconds conversion happens exporter-side). This bench tests that expectation directly.

## Provenance

- **Arms (3):** `baseline` (no module) · `ours_base` = commit `4de43cc` (pre-rework) ·
  `ours_now` = commit `c691331` (post-rework, current `main`-line; `origin/main = 889d152`,
  +2 demo-dashboard-only commits since).
- **Run:** launched 2026-06-18 18:16:20Z, completed `ALL-CELLS-DONE` 2026-06-19 06:19:18Z
  (≈12 h unattended). Zero failures; every cell held 8000 rps at 100 % success.
- **Host:** host-1, c7a EPYC 9R14, 4 cores (the designated bench host; debian-vm/macOS are
  unfit for timing — see memory `dev-host-unfit-for-timing-benchmarks`).
- **Design:** 4 signal-config windows — `m` metrics-only · `ms` metrics+spans ·
  `ml` metrics+logs · `mls` metrics+logs+spans — each 3 h, run sequentially, **40 rounds /
  arm / window** with the 3 arms round-robin-interleaved *within* each round so host drift
  cancels in the paired Δ. **480 cells** total (4 × 40 × 3).
- **Metric:** worker CPU-µs/req = `worker_cpu_pct * 1e4 / offered_rps`. Headline = paired
  Δ(`ours_now` − `ours_base`) within each round, 95 % CI.
- **Artifacts:** host-1 `~/regbench-20260618-181620/{cells.jsonl,timeseries-host.csv,STATUS}`
  (cleaned up after harvest); local copy `~/project-nginx-otel/regbench-results/`. Scripts
  `regression_bench.sh` + `analyse_regression.py` (workspace root, not in repo).

## Result — paired Δ (now − base), n = 40 per window

| Window | Δ cpu-µs/req | % of base | 95 % CI clears 0? | Δ p99 (µs) | Verdict |
|---|---|---|---|---|---|
| `m`  metrics-only       | +0.032 ± 0.037 | +0.37 % | no (spans 0) | +0.7 ± 5.1 | no change |
| `ms` metrics+spans      | +0.022 ± 0.019 | +0.24 % | barely (LB +0.003) | −1.1 ± 5.8 | noise-floor |
| `ml` metrics+logs       | +0.012 ± 0.034 | +0.13 % | no (spans 0) | −3.9 ± 6.0 | no change |
| `mls` all three         | +0.023 ± 0.029 | +0.26 % | no (spans 0) | +1.8 ± 5.1 | no change |

### Absolute per-arm means (cpu-µs/req)

| Window | baseline | ours_base | ours_now | marginal now−baseline |
|---|---|---|---|---|
| `m`   | 8.498 | 8.607 | 8.639 | +0.141 |
| `ms`  | 8.576 | 8.962 | 8.983 | +0.407 |
| `ml`  | 8.482 | 8.671 | 8.683 | +0.200 |
| `mls` | 8.502 | 8.979 | 9.003 | +0.501 |

Exporter CPU scales sensibly with signal count (0 % → 1.5 % → 2.4 % → 4.0 % across the
windows); worker RSS flat ~7–8 MB across all arms; p50 = 60 µs everywhere.

## Interpretation

**No meaningful regression.** Three of four windows show paired Δ with a 95 % CI that
spans zero — i.e. statistically indistinguishable from no change. The lone window whose CI
clears zero (`ms`) does so by a hair: +0.24 % of base with a lower bound of just
**+0.003 µs/req**, right at the noise floor, and it is **not reproduced in the heavier
`ml`/`mls` windows** — the signature of host jitter, not a real cost change.

Decisively: if the rework had added per-request work it would show **most clearly in the
metrics-only `m` window** (that is exactly where the Sums / seconds-bucketing / status_class
changes live), and `m` shows no change (CI spans 0). The marginal cost vs the no-module
baseline (+0.14 to +0.50 µs/req depending on signal mix) is consistent with the prior
authoritative micro-bench (`RESULTS.md`, `88dd57d`) and well under the C++ `nginx-otel`
+1.2 µs/req.

## Bottom line

The metrics OTel-correctness rework (`4de43cc → c691331`) is **per-request-cost-neutral**.
The deliberate wire-shape changes (µs→s bucketing, real Sums, status_class string) cost
nothing measurable on the worker hot path, as designed — the bucketing is the same
per-request integer bump and the seconds conversion is lossless exporter-side work. No
host or disk issues (17 G free at end, /tmp tmpfs 19 %).
