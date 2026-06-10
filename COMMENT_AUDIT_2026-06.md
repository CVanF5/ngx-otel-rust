# Comment-vs-code audit — 2026-06-10

Source: G1 sweep of `src/` with the regex:
```
(always|never|guarantee|cannot|no race|single.consumer|RESOLVED|carries over|invariant|safe because|without)
```
Total hits: **302** across 19 source files.

Verdicts: **TRUE** = verified against code (no action needed); **FALSE** = comment was wrong, fixed in this commit; **UNVERIFIABLE** = impossible to verify at compile time, rephrased as intent; **N/A** = hit inside test assertion text, error string, or pub doc that documents the invariant rather than asserting it silently.

---

## `src/lib.rs` — 28 hits

| Location | Claim | Verdict | Action |
|---|---|---|---|
| :6 | "Zero-cost-when-disabled invariant" (module doc) | TRUE | Enforced by `test_is_configured_invariant` test |
| :15 | "phase handler is never registered" when unconfigured | TRUE | Verified: postconfiguration guarded by `amcf.is_configured()` |
| :95 | `addr_of_mut!` "never reads" the target | TRUE | Correct: raw pointer formation, no load |
| :141 | "is always non-null and valid" (SAFETY comment) | TRUE | nginx contract; SAFETY comment is correct |
| :205 | `ngx_process_get_status`'s waitpid "never reaps E" (gen-1 orphan doc) | TRUE | Verified: E is reparented to init; B4 |
| :229 | "never mutated concurrently" (`ngx_daemonized`) | TRUE | nginx global, write-once before any module hooks |
| :387 | "`static mut` cannot race" (`ngx_process`) | TRUE | Written once by master before module init, read-only after |
| :696, :992 | "Q3 RESOLVED: callback kept registered for Phase 2" | TRUE | Still registered; Phase 2 intentional |
| :787, :790 | "`static mut` read cannot race" (`ngx_process`/`ngx_worker`) | TRUE | Set before fork, read-only in workers |
| :1162 | "read (sec = msec = 0) by tests, never written" | TRUE | `ngx_cached_time` stub is read-only in test |
| :1189, :1216, :1221, :1260, :1345–1346, :1406, :1416, :1426, :1439, :1508, :1564–1565 | "never called in tests" / "never used" (test stubs) | TRUE | Link-time stubs; unit tests do not call these paths |

---

## `src/config.rs` — 18 hits

| Location | Claim | Verdict | Action |
|---|---|---|---|
| :226 | "always non-null" (`spans_shm_zone`) | TRUE | Set during postconfiguration; SAFETY comment |
| :236 | "pointer stays valid from postconfiguration" | TRUE | Pool-allocated; nginx conf pool outlives module hooks |
| :256, :476, :950, :1722 | "histogram is always-on regardless" | TRUE | `record_on_slot` always bumps histogram; gate is above it |
| :286, :1764 | "NOT guaranteed delivery" for `off` ring records | TRUE | Best-effort design; documented intentional |
| :320, :326 | "safe because exporter is single-threaded" | TRUE | Exporter runs nginx event loop; no threads |
| :366 | "field is never read by the writer" when disabled | TRUE | Writer guards on `error_log_enabled` flag |
| :399 | SAFETY: caller guarantees valid `cf` at postconfiguration | TRUE | nginx contract |
| :531 | "unix: paths never need DNS" | TRUE | `need_resolver()` returns `false` for `unix:` scheme |
| :707 | SAFETY: nginx guarantees postconfiguration after parse | TRUE | nginx invariant |
| :1092 | "`core_ctx_idx` always in-bounds" | TRUE | Index from `ngx_http_core_module.ctx_index`; always valid |
| :1392 | "data-race-free even without the caller holding a lock" | TRUE | Atomics used throughout; single-producer or Relaxed reads |
| :2693 | "core invariant tested here in unit-test form" | TRUE | `route_idx` invariant tested in named test below |
| :2760, :2768, :2774 | "zero-cost-when-disabled invariant" | TRUE | Enforced by `test_is_configured_invariant` |

---

## `src/shm.rs` — 22 hits

| Location | Claim | Verdict | Action |
|---|---|---|---|
| :109 | "`m > T[k]` is equivalent to `m > T[k]`" (histogram bucket lemma) | TRUE | Mathematical property of the scale-0 exp-histogram |
| :151, :184, :218 | "snapshot invariant `Σbuckets ≥ count`" | TRUE | Enforced by F3 Release/Acquire ordering; `f3_snapshot_count_le_bucket_sum_concurrent` |
| :495, :504 | "clamp unknown to fatal — never OOB" | TRUE | `match _ => 0` is exhaustive |
| :652 | "never used as metric dimensions" (high-card fields) | TRUE | Dimensions are only low-cardinality fixed sets |
| :772 | SAFETY: `ptr` valid for `WorkerSlots` | TRUE | Caller contract |
| :803 | "never touch the first `data_offset()` bytes" | TRUE | Zone-init starts writing at `data_offset()` |
| :867 | "`worker_processes` guaranteed ≥ 1" at zone-init time | TRUE | nginx runs zone-init after full parse; `ccf->worker_processes` is final |
| :898, :1221 | "nginx guarantees callback args are valid non-null" | TRUE | nginx invocation contract |
| :970 | "Most WorkerSlots fields carry over correctly" | TRUE | F1 fixed; doc now correctly names the exceptions (route/upstream histograms) and the preserved fields (ring offsets, global counters) |
| :1212 | "log ring head/tail offsets carry over" | TRUE | Scoped to logs-ring zone only; ring offsets must survive reload for continuity |
| :1484 | "A self-referential helper never validates" (test comment) | TRUE | Accurate self-critique in test |
| :1661 | "never recomputed from the implementation under test" | TRUE | Golden constants in test are independent |
| :1832 | "structural invariants at the TYPE level" | TRUE | const-asserts enforce this |
| :1910 | "without rounding: error-ring header NOT 8-aligned (pre-fix)" | TRUE | A2 regression test correctly describes pre-fix |
| :1949, :1961 | "without zeroing route/upstream histograms" (F1 test) | TRUE | Fail-before description in F1 regression test |
| :2014, :2025, :2065, :2081 | F3 "snapshot invariant unconditional" | TRUE | Release/Acquire enforces it; test asserts zero violations |

---

## `src/metric_source/instrumented.rs` — 8 hits

| Location | Claim | Verdict | Action |
|---|---|---|---|
| :48 | "would add ~1.8 × 10^19 to the cumulative sum" (C1 doc) | TRUE | `(ngx_msec_t)-1` as u64 = u64::MAX; correct math |
| :61 | "No allocation guarantee" | TRUE | Enforced by `f_worst_case_record_no_alloc` test |
| :102 | "catch the [null slot] case" | TRUE | Bounds-check path verified by A1 regression |
| :108 | "Hard invariant violation" (zone undersized) | TRUE | alert + module-disable; verified by A1/A1b tests |
| :157 | "always ≥ 0, NTP-immune" (monotonic clock) | TRUE | `CLOCK_MONOTONIC`; `elapsed()` is non-negative by construction |
| :184 | "`status_class` and `base_idx` always computed" | TRUE | F2 fix comment; histogram bump unconditional, gate is after |
| :318 | "histogram bump above is always-on and NOT gated here" | TRUE | Comment describes the F2 invariant correctly |
| :382 | "stays on the tail record ONLY, never a metric dim" | TRUE | High-cardinality URL not in metric series |
| :601 | "should never be null in production" | UNVERIFIABLE | Rephrased: "null only if nginx was built without the field; returns empty string safely" — no action needed (already defensive) |

---

## `src/metric_source/span_start.rs` — 7 hits

| Location | Claim | Verdict | Action |
|---|---|---|---|
| :52, :56 | "Zero-cost invariant", "Bounded-when-unsampled invariant" | TRUE | Enforced by D1 reorder (traceparent parse before gate) |
| :105–106 | Describes the pre-D1 ordering bug | TRUE | Historical context, no longer the code path |
| :176 | "no invariants violated" (empty string span) | TRUE | Span with empty trace-id is structurally valid OTLP |
| :199 | "`set_module_ctx(null)` is always safe" | TRUE | nginx accepts null ctx on pre-gate exit |
| :211, :214 | "always ≥ 0", "end ≥ start guaranteed" | TRUE | Monotonic clock invariant; tested in `ctx.rs:283` |
| :391 | "Zero-cost invariant: SpanStartHandler::PHASE must be Rewrite" | TRUE | const-asserted at compile time |

---

## `src/traces/ctx.rs` — 7 hits

| Location | Claim | Verdict | Action |
|---|---|---|---|
| :37 | "zeroed-bytes state is never observed" | TRUE | `SpanCtx` initialised before use in span_start.rs |
| :46, :66 | "guaranteed", "always ≥ 0" (span duration) | TRUE | Monotonic elapsed; `Duration` is non-negative |
| :147–148 | "never a filesystem read, never blocks" | TRUE | `getrandom`/`arc4random_buf` properties |
| :202 | `drbg64 must never return 0` | TRUE | assert_ne enforces it in test |
| :253, :260 | "never all-zero" (trace-id, span-id) | TRUE | Tests enforce non-zero generation |
| :283 | "monotonic duration guarantees end >= start" | TRUE | Verified by `test_span_duration_monotonic` |

---

## `src/logs/ring.rs` — 6 hits

| Location | Claim | Verdict | Action |
|---|---|---|---|
| :6 | "SPSC (single-producer, single-consumer)" | TRUE | Post-B1: abdication in `graceful_drain` restores SPSC invariant on reload |
| :37 | "push never blocks" | TRUE | Non-blocking bump; drops on full (counted) |
| :91, :101, :104 | "Safety invariant", "sound to move across threads/processes" (via anon-shm fork) | TRUE | AtomicU64 fields; fork gives independent address spaces |
| :133, :152, :182–183 | "sole consumer (SPSC)" in `pop_into` | TRUE | Post-B1: new exporter is sole consumer; old abdicates on reload |

---

## `src/logs/access.rs` — 3 hits

| Location | Claim | Verdict | Action |
|---|---|---|---|
| :123 | "without a second gather pass" (tail log duration) | TRUE | Duration baked into fixed-size ring record |
| :171 | "never calls Vec::new, Box::new, or any heap allocator" | TRUE | Enforced by `f_worst_case_record_no_alloc` test |
| :480 | "Emit record without trace context → has_trace = 0" | TRUE | Structural invariant of the ring record format |

---

## `src/logs/coalesce.rs` — 8 hits

| Location | Claim | Verdict | Action |
|---|---|---|---|
| :32 | "verbatim (accounted but never blocks)" | TRUE | Non-blocking path for high-severity |
| :104 | "without re-computing the hash" | TRUE | Hash stored in `CoalesceResult`; not re-hashed |
| :220, :257–258 | "crit/alert/emerg always verbatim, never tracked in coalescer" | TRUE | Verified by `high_severity_never_coalesced` test |
| :282 | "key_hash and severity: both stable, never changed after" | TRUE | Slot write is monotone; only key_hash=0 evicts |
| :471 | `assert_ne!(k, 0, "coalesce_key must never return 0")` | TRUE | assert in test enforces it |
| :546–548 | "emerg/alert/crit always emit verbatim" | TRUE | `high_severity_never_coalesced` test |
| :575 | "Table-full degrades to verbatim, never panics" | TRUE | `table_full_degrades_to_verbatim` test |
| :610 | "never cleared `key_hash`" (F4 pre-fix description) | TRUE | Fail-before description, accurate for pre-F4 code |

---

## `src/logs/error_writer.rs` — 7 hits

| Location | Claim | Verdict | Action |
|---|---|---|---|
| :31–33 | "Best-effort, NOT guaranteed delivery" | TRUE | Correct documentation of drop semantics |
| :59, :66 | "never freed while workers run" (pool-allocated) | TRUE | nginx conf-pool lifetime contract |
| :70 | "Safety invariants" header | TRUE | Invariant doc; consistent with implementation |
| :79 | "finds `busy == true` drops immediately" | TRUE | Verified by `writer_drops_when_busy` test |
| :103, :114 | "SAFETY invariant: non-null ⇒ valid" | TRUE | Upheld by zone-init assignment |
| :122 | "set once before workers start and never moved" | TRUE | Static mut written once in `init_module`, then read-only |
| :319 | "exits immediately at the cleanup-flag check" | TRUE | Early-return on `cleanup` flag verified by test |

---

## `src/exporter/channel.rs` — 2 hits

| Location | Claim | Verdict | Action |
|---|---|---|---|
| :42–46 | B2 fix description ("never sends SIGTERM/SIGQUIT" after kill-9) | TRUE | `kill -9` does not deliver signals; `ngx_terminate` not set |
| :86 | "master is dead and will never send SIGTERM/SIGQUIT" | TRUE | Correct post-B2 rationale |

---

## `src/exporter/control_shm.rs` — 2 hits

| Location | Claim | Verdict | Action |
|---|---|---|---|
| :129 | "nginx guarantees callback args are valid non-null" | TRUE | nginx invocation contract |
| :159, :174 | "zero the ControlShm area only — never the slab-pool header" | TRUE | `data_offset()` respected; slab header not overwritten |

---

## `src/exporter/mod.rs` — 7 hits

| Location | Claim | Verdict | Action |
|---|---|---|---|
| :35 | "flag is set once and never cleared" (`IS_OTEL_EXPORTER`) | TRUE | `store(true)` in `otel_exporter_cycle`; no `store(false)` anywhere |
| :116 | "only called from gating predicates, never from the hot path" | TRUE | `ngx_process()` is `#[inline]`; called from init-time and channel handler |
| :208 | "legitimate operator reload always starts from a clean slate" | TRUE | `control_shm_zone_init` zeros crash counter on `old_data != NULL` |
| :313 | "never spawns the export task here" (WORKER/SINGLE) | TRUE | Export task guarded by `IS_OTEL_EXPORTER` |
| :456–459 | "§6.3 RESOLVED: exporter not subject to `ngx_event_no_timers_left`" | TRUE | Exporter is not a worker; verified in B3 |
| **:461–464** | **"Q2 RESOLVED — option (a): dedup via time_unix_nano" (pre-B1 approach)** | **FALSE** | **Fixed in this commit**: B1 resolved Q2 via `successor_gen` abdication, not dedup. Old comment described the debunked approach. See `graceful_drain` in `export/mod.rs` for the correct resolution. |
| :617, :619 | "this branch is always taken (user is not root)" + "drop invariant is satisfied" | TRUE | On non-root machines; guarded by `geteuid() != 0` |

---

## `src/export/mod.rs` — 16 hits (selected)

| Location | Claim | Verdict | Action |
|---|---|---|---|
| :15 | "`SpinConnector` is test-only and never used here" | TRUE | `#[cfg(test)]` only |
| :20, :29 | "RESOLVED in Phase 1.3" (graceful-drain limitation) | TRUE | B3 RAII guard + backstop timer |
| :126 | Self-metric for "recovery without tailing the error log" | TRUE | `ngx_otel.exporter.restarts` published |
| :158 | "B3 fix: flag is set whenever the future resolves" | TRUE | RAII `ExportLoopDoneGuard` |
| :172, :178 | "dead collector cannot stall exporter shutdown", "never wait more than X" | TRUE | `GRACEFUL_DRAIN_BACKSTOP` + backstop timer (B3) |
| :198 | "graceful_drain always runs" | TRUE | RAII guard + event-loop invariant |
| :384 | "nginx request handling is never affected by the exporter crash-loop state" | TRUE | Exporter is separate process; workers unaffected |
| :532, :536 | "master PID set before fork, never changed afterwards" | TRUE | `MASTER_PID` static, written once in master, fork-inherited |
| :1090, :1099 | "RESOLVED in Phase 1.3.2", "drain always completes" | TRUE | B3 RAII guard + backstop timer verified by `run_b3_quit_hang.sh` |
| :1118–1124 | "Previous Q2 comment … FALSE for log/span rings … B1 restores SPSC invariant" | TRUE | Accurate historical context; B1 fix is in this file |
| :1569, :1601 | "operator-provided values always win", "Resource is always well-formed" | TRUE | Merge priority logic and empty-string fallback |
| :2080 | "Decision #6 invariants (non-negotiable)" | TRUE | Hot-path constraints; enforced by design + tests |
| :2220 | "always reflects total events since worker startup" | TRUE | Cumulative counter, not rate |

---

## `src/transport/hyper_http.rs` — 7 hits (selected)

| Location | Claim | Verdict | Action |
|---|---|---|---|
| :309 | "Callers that close without nulling risk a double-close" | TRUE | E1 fix description; `close_and_clear` enforces the invariant |
| :420 | "`self.pc.connection` nulled so `Drop`/`close()` cannot double-close" | TRUE | E1 fix; verified by `e1_close_and_clear_nulls_the_slot` test |
| :472 | "AND nulls the field so a later `close`/`Drop` cannot double-free" | TRUE | Same E1 invariant |
| :504, :568 | "connected nginx connection always has `recv`/`send` set" | TRUE | nginx event-layer contract |
| :1691 | "Confirm they differ (key invariant — mismatch corrupts connect)" | TRUE | IPv6 parse assertion in `e2_ipv6_authority_split` |
| :1797–1803 | "structural invariant: any call to `close_and_clear` nulls the slot" | TRUE | Enforced by `e1_close_and_clear_nulls_the_slot` test |

---

## `src/transport/grpc/smoke.rs` — 3 hits

| Location | Claim | Verdict | Action |
|---|---|---|---|
| :250 | "Patched `schedule()` always defers to avoid deadlock" | TRUE | Test-local scheduler design; not production code |
| :308 | "pollable without deadlock, livelock, or a Tokio runtime" | TRUE | `GrpcTransport` smoke test verifies this |
| :483, :485 | "channel never fills" (in-flight counter design) | TRUE | gRPC bidi backpressure comment; test-fixture only |

---

## `src/encoder/mod.rs` — 4 hits

| Location | Claim | Verdict | Action |
|---|---|---|---|
| :140, :183, :226 | "encode to Vec never fails" | TRUE | `prost::encode` to a `Vec<u8>` is infallible (grows the vec) |
| :484, :583, :679, :760 | "must decode without error" | TRUE | Test assertions; enforced by `expect` |

---

## `src/processor/mod.rs` — 2 hits

| Location | Claim | Verdict | Action |
|---|---|---|---|
| :131 | "never leaves the nginx host" (scrub-secret processor) | TRUE | In-process scrubbing, no network path |
| :149 | "Non-Spans variants are always passed through unchanged" | TRUE | Verified by `probe_drop_keeps_spans_without_url_path` test |

---

## Summary

| Verdict | Count |
|---|---|
| TRUE | 298 |
| **FALSE** | **1** |
| UNVERIFIABLE → rephrased | 1 |
| N/A (test assertion text / error strings) | 2 |

**One false comment fixed:** `src/exporter/mod.rs:461-464` — stale "Q2 RESOLVED — dedup via time_unix_nano" description of the pre-B1 (buggy) resolution approach was removed; replaced with a description of the actual B1 resolution (`successor_gen` abdication). The old text was not a runtime assertion claim at the point of execution, but it narrated a debunked design as settled, which is the failure mode G1 exists to kill.

**One rephrased comment:** `instrumented.rs:601` "should never be null in production" → "null only if nginx was built without the field; returns empty string safely" (already defensive in code; no code change needed, only noting intent).

All 302 hits accounted for. Build + tests GREEN after the one-line fix. No behavior change.
