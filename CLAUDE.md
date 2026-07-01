# ngx-otel-rust — project instructions

## Code style (enforced)

Comments carry **rationale and invariants, not restatement** — sparse, never
narrating self-evident code. Full convention:
[`docs/DEVELOPING.md`](docs/DEVELOPING.md#comment-style). In short:

- `///` = one-line summary; rationale in `# Safety`/`# Errors`/`# Panics`.
- `//!` = one paragraph; design narrative goes in `docs/ARCHITECTURE.md`.
- Constants get one line; no "why this value" essays. Inline `//` only for
  non-obvious intent — never narrate self-evident code.
- **Always keep**: `// SAFETY:` per unsafe block, FFI/bindgen-bitfield notes,
  memory-ordering proofs, metric unit/semconv contracts, spec citations,
  test mutation-evidence.
- Do **not** chase a density percentage — FFI-heavy files sit at 25–45% on
  mandatory SAFETY/FFI content. The goal is zero *removable* narrative.

Code conventions (full text in
[`docs/DEVELOPING.md`](docs/DEVELOPING.md#code-conventions)):

- Errors that are logged/displayed derive `thiserror::Error` + `#[error("…")]`;
  a purely internal `match`-ed enum needs no `Display`.
- Propagate with `?` in `Result` fns; `extern "C"` callbacks and the no-alloc
  hot path handle failures inline (no `Result` to propagate).
- Concise `snake_case`; `pub(crate)` for internal API, `pub` only for the real
  public surface; split pure logic out of FFI glue so it stays unit-testable.

Apply by default when writing or reviewing so no bulk cleanup is ever needed.

## Verification

`make check` (fmt + clippy `-D warnings`, both default and `--features
test-support` compile), `make doc-check`, `make unittest`. See
`docs/DEVELOPING.md` for the full command set and cross-host rules.
