# ngx-otel-rust — project instructions

## Comment style (enforced)

Comments carry **rationale and invariants, not restatement**. Keep the
sparsity of nginx / nginx-acme. Full convention: [`docs/DEVELOPING.md` →
Comment style](docs/DEVELOPING.md#comment-style). In short:

- `///` = one-line summary; rationale in `# Safety`/`# Errors`/`# Panics`.
- `//!` = one paragraph; design narrative goes in `docs/ARCHITECTURE.md`.
- Constants get one line; no "why this value" essays. Inline `//` only for
  non-obvious intent — never narrate self-evident code.
- **Always keep**: `// SAFETY:` per unsafe block, FFI/bindgen-bitfield notes,
  memory-ordering proofs, metric unit/semconv contracts, spec citations,
  test mutation-evidence.
- Do **not** chase a density percentage — FFI-heavy files sit at 25–45% on
  mandatory SAFETY/FFI content. The goal is zero *removable* narrative.

When writing or reviewing code, apply this by default so a bulk
comment-density cleanup is never needed again.

## Verification

`make check` (fmt + clippy `-D warnings`, both default and `--features
test-support` compile), `make doc-check`, `make unittest`. See
`docs/DEVELOPING.md` for the full command set and cross-host rules.
