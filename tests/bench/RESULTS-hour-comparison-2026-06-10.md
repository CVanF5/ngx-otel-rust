# 1-hour 4-arm comparison bench — 2026-06-10 (host-1)

**Purpose:** same-day comparison numbers for architect discussion (compressed variant of the
planned overnight run). **Characterization, not a gate** — single run, 240s cells, no ±1% claim.

- **Host:** host-1 (c7a EPYG 9R14, 4 cores, no SMT, isolated). Worker pinned core 3, exporter +
  otelcol core 2, loadgen cores 0–1.
- **Code under test:** `dc89fb1` — A1–E2 fixes landed (shm sizing/alignment,
  exporter lifecycle B1–B3, sentinel + url.path fixes, D1 traceparent-gate reorder, transport E1–E2).
  **Sanitizer batch (loop part H) NOT yet run on these commits.** F1–F5 landed after the bench build.
- **Arms:** `baseline` (no module) · `cpp` (C++ nginx-otel, traces only) · `ours_ml` (metrics+logs,
  no traces) · `ours_all` (metrics+logs+traces). C++ exports from worker threads (cost in worker
  CPU); ours exports from the dedicated child (cost in exporter CPU) → **ours fair-total =
  worker + exporter**.
- **Phases:** A = vegeta 8k rps, 100% sampling · B = wrk saturating, 10% · C = wrk saturating, 100%.
- **Sink:** otelcol-contrib `nop`, OTLP/gRPC (ours), OTLP (cpp).
- Raw: host-1 `~/overnight/cells.jsonl`, `~/overnight/timeseries-host.csv`, `~/recell2*` (run
  13:36–14:28 UTC + re-measure 14:41–14:46).

## Results

### Phase A — moderate load (8,000 rps offered, 100% sampling)

| arm | worker CPU | exporter CPU | p50 µs | p99 µs | spans/s | RSS wkr | RSS exp |
|---|---|---|---|---|---|---|---|
| baseline | 6.8% | — | 62 | 377 | — | 5.7 MB | — |
| cpp | 8.4% | (in worker) | 61 | 394 | 8,001 | 16.6 MB | — |
| ours_ml | 6.8% | n/m† | 61 | 349 | — | 6.1 MB | n/m† |
| ours_all | 6.9%‡ | **1.5%**‡ | 59‡ | **299–314**‡ | 8,009 | 6.5 MB | **10.0 MB flat**‡ |

† not measured — PID-picker miss, see "Measurement notes".
‡ from the pinned re-measure cells (the main run's ours_all/A p99=673µs is an artifact: the
undetected exporter ran unpinned and contended with the worker core; re-measured twice pinned:
p99 314µs and 299µs).

**Marginal trace cost at 8k spans/s (A):**
- cpp − baseline = **+1.6pp worker CPU** (≈ 2.0 µs-cpu/req), all on the request path.
- ours_all − ours_ml = **+0.1pp worker** (≈ 0.13 µs-cpu/req) **+1.5pp exporter** (off-path)
  ≈ 1.9 µs-cpu/span total.
- **Total CPU is comparable (~2 µs/span); the difference is *where* it is spent.** Ours keeps the
  request path at ≈ baseline cost (consistent with the earlier §3.8 characterization: +0.10 vs
  +1.21 µs-cpu/req worker marginal); the cold cost moves to the dedicated core.

### Phase B — saturating, 10% sampling

| arm | rps | Δ vs own base* | p99 µs | spans/s | exporter CPU |
|---|---|---|---|---|---|
| baseline | 138,666 | — | 493 | — | — |
| cpp | 127,635 | **−8.0%** | 850 | 12,766 | (in worker) |
| ours_ml | 142,370 | (base) | 480 | — | n/m† |
| ours_all | 137,256 | **−3.6%** | 504 | 9,677 | 2.2% |

### Phase C — saturating, 100% sampling

| arm | rps | Δ vs own base* | p99 µs | spans/s | exporter CPU |
|---|---|---|---|---|---|
| baseline | 138,753 | — | 496 | — | — |
| cpp | 116,729 | **−15.9%** | 833 | **116,744** | (in worker) |
| ours_ml | 142,985 | (base) | 501 | — | n/m† |
| ours_all | 137,806 | **−3.6%** | 582 | 9,688 | 2.0% |

\* trace marginal: cpp vs baseline; ours_all vs ours_ml (isolates trace cost — ours_ml carries
metrics+logs in both).

## Honest read

1. **The deferred-export thesis holds on current code.** At 100% sampling under saturation, C++
   pays **−16% throughput and ~70% worse p99** in the request path; ours pays **−3.6% / +16% p99**
   with a pegged worker.
2. **The trade is delivery, not magic.** C++ delivers *all* ~116.7k spans/s from that pegged
   worker; ours delivers **~9.7k spans/s** — the known drain-budget ceiling
   (`span-saturation-ceiling`: 250ms drain × 2,500 budget; raise budget+ring+send-chunking
   together to move it). Identical 9.7k in B and C confirms ceiling, not load-dependence.
   At 2% exporter CPU, the ceiling is budget-bound, not resource-bound.
3. **Headline for architects:** *keep the worker fast and cap trace delivery* (ours) vs
   *deliver everything and pay in the request path* (C++). At moderate load (phase A) the total
   CPU cost per span is comparable (~2 µs); the architectural difference shows up only at
   saturation — in tail latency, throughput, and what gets dropped.
4. **Exporter RSS question RESOLVED (for this load): ~10 MB, flat.** 17-sample timeline over
   240s at 8k spans/s + tails + exemplars + metrics: 8.8–10.7 MB, settled 10.0 MB, no trend. The
   ~191 MB seen in the 06-09 smoke was most plausibly the **stale leftover second master's
   days-old exporter** picked up by the old global PID-matcher (that leftover is documented in
   the smoke caveats; current picker + clean box can't repeat the reading). A leak verdict still
   needs the long soak, but there is no 191 MB footprint on current code.
5. **ours_ml measures ≥ baseline throughput (+2.7%)** consistently across B and C. Do not read
   metrics+logs as "negative cost": same binary, module loaded vs not — this is within
   code-layout/run variance for single runs. Claim "≈ baseline", nothing more.
6. **Worker RSS:** ours_all 6.5–6.8 MB vs cpp 14.8–17.8 MB (cpp batches in-worker). Master RSS
   ours 1.7–3.3 MB vs cpp 2.5–4.2 MB.

## Caveats

- **Code is mid-hardening-loop** (`dc89fb1`): includes the D1 span-gate reorder on the hot path;
  TSAN/ASan batch for these commits had not run at bench time. Single 240s cell per condition —
  use the overnight run (relaunch pending) for anything gate-grade or leak-grade.
- vegeta drives phase A (wrk2 panics on host-1); plain wrk B/C. 1 worker; `return 200` (no
  upstream); null sink.
- Run produced one **new latent-bug finding** (not loop-introduced, now loop item **B4**):
  on a daemonized initial start the exporter is spawned pre-`ngx_daemon()` → PPID 1 → the master
  can never reap it → **crash-respawn is dead for the gen-1 exporter** (works post-reload; chaos
  suite ran `daemon off` and missed it). Live-reproduced on host-1 (`exporter_ppid=1`).

## Measurement notes (for the next run)

- `exporter_pid()` was `--ppid <master>`-scoped (Jun-9 anti-aliasing hardening) and therefore
  missed the PPID-1 gen-1 exporter for `ours_ml` (all phases) and `ours_all/A`; that also left
  the exporter **unpinned** in those cells (the 673µs p99 artifact) and zeroed its CPU/RSS
  columns. Script fixed 2026-06-10 (global proctitle match, newest PID) and shipped to host-1.
- ours_all/A exporter CPU/RSS/latency re-measured in two dedicated pinned cells (14:33, 14:41 UTC),
  same conf/load; values above are from those.
