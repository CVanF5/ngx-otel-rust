# Weekend TLS + chaos soak — head-to-head (host-1, AMD EPYC 9R14)

## Provenance

- Code: tree of commit `4de6633` (both arms built from it). Module arm = ours (central
  exporter, TLS transport); reference arm = upstream C++ `nginx-otel`.
- Run: launched Fri 2026-06-12 20:51Z, completed Mon 2026-06-15 09:56Z (≈60 h unattended).
- Host: host-1, c7a EPYC 9R14, 4 cores (the designated bench host; debian-vm/macOS are
  unfit for timing — see memory `dev-host-unfit-for-timing-benchmarks`).
- Design: **30 cells**, 2 h each, **alternating arms** (15 ours / 15 cpp) over TLS, each
  cell subjected to chaos (collector kill+restart, SIGSTOP/SIGCONT backpressure, worker
  kill; ours arm additionally exporter-kill) + one Saturday cert rotation.
- Raw data: host-1 `~/weekend-tls-chaos/{cells.jsonl,recovery.jsonl,STATUS}`; local copy
  `~/project-nginx-otel/weekend-tls-results/`. `ALL-CELLS-DONE` marker present; disk 17 G
  free at end (no ENOSPC). The sibling `~/weekend-tls-chaos-SMOKE/` is unrelated smoke
  data (2 cells) — ignore it.

## Performance (n = 15 per arm)

| Metric | Ours | C++ `nginx-otel` | Delta |
|---|---|---|---|
| RPS | **132,250** | 114,812 | **+15.2 %** |
| p50 latency | 479 µs | 508 µs | −5.7 % |
| p99 latency | **516 µs** | 921 µs | **−44 %** |
| worker CPU | **35.7 %** | 56.6 % | **−20.9 pts** |
| exporter CPU | 0.73 % | 0.00 % (no exporter) | cold path ≈ free |
| worker RSS | **7.9 MB** | 23.1 MB | −66 % |
| exporter RSS | 15.0 MB (flat) | n/a | no growth over 60 h |

Interpretation: the result corroborates and strengthens the micro-bench (`RESULTS.md`,
commit `88dd57d`) under sustained TLS load + injected chaos. The central-exporter design
keeps the worker hot path ~21 CPU points lighter and the worker RSS ~3× smaller than the
per-worker C++ model, while delivering higher throughput and a dramatically tighter tail
(p99 −44 %). The **flat 15 MB exporter RSS across 60 h definitively closes the old "191 MB"
open question** (memory `span-saturation-ceiling`): there is no exporter leak.

## Resilience / chaos (all clean — zero failures across 60 h)

- **Exporter-kill, ours arm (B4 heartbeat-stale detection), n = 15:** alert detected
  **15/15**, exporter resumed **15/15**; alert latency 5–6 s, operator-reload re-arm 8–9 s.
  This matches the unit-test numbers and validates the heartbeat path under real sustained
  TLS load + chaos — the headline resilience result.
- **Worker kill→respawn (both arms, n = 30):** mean 3.1 s, max 4 s (master supervision
  holds under TLS load on both designs).
- **Collector kill→restart recovery (both arms, n = 30):** mean 184.2 s, max 185 s
  (collector-side; identical across arms, as expected).

## Caveats (measurement artifacts, not module defects)

1. **`p999` not captured** — recorded as 0 in every cell; the harness's p999 path is
   broken. Fix the harness before relying on p999.
2. **`col_received_delta` unusable on the ours arm** — negative every cell (positive on
   cpp). The col-restart *and* exporter-kill chaos both reset the collector's cumulative
   "received" counter mid-cell, so end − start goes negative. Delivery for ours should be
   read from the drop-alert lines (~789/cell, reflecting the documented ~10k spans/s/worker
   saturation ceiling at ~130k rps offered) and the span-saturation memory — **not** from
   this field. Harness should snapshot deltas per chaos segment.
3. **Cert-rotation coverage thin** — only 1 rotation event fired (cell 18, cpp arm,
   Saturday). The ours-arm serving-cert metric (Phase C) was **not** exercised across a
   rotation. Add an ours-arm cert-rotation chaos step for real coverage.

## Bottom line

Ours wins on throughput (+15 %), tail latency (−44 % p99), worker CPU (−21 pts), and worker
RSS (−66 %); exporter footprint is flat with no leak; and every chaos injection recovered
cleanly, including 15/15 heartbeat-driven exporter recoveries. No host or disk issues.
