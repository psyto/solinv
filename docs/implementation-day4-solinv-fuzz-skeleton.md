# Phase 1 Day 4 — solinv-fuzz Skeleton Implementation

Date: 2026-05-25
Status: ✅ `solinv-fuzz` compiles. Crucible integration mechanically working.

## Outcomes

| Day 4 goal | Status | Evidence |
|---|---|---|
| Add Crucible deps to workspace Cargo.toml | ✅ | crucible-fuzzer + crucible-test-context pinned to `tag = "v0.1.0"` |
| Add Solana split-crate deps | ✅ | anchor-lang 1.0.1, solana-keypair 3, solana-pubkey 3, solana-instruction 3.1 |
| Write `solinv-fuzz/src/lib.rs` re-exports | ✅ | `crucible_fuzzer::*` + 8 missing re-exports (Day 3 finding) + prelude |
| Write `solinv-fuzz/src/capability.rs` | ✅ | `HasContext` (with `program_ids`), `HasInstructionSet`, `InstructionSpec` (with `signers` field) |
| `cargo check --workspace` passes | ✅ | 50.70s build, all 6 solinv crates + 8 Crucible crates + LiteSVM 0.9.1 |

## What was built

### Workspace Cargo.toml additions

```toml
[workspace.dependencies]
# ... existing ...

# Solana ecosystem — pinned to match Crucible v0.1.0 workspace
anchor-lang = "1.0.1"
solana-keypair = "3"
solana-pubkey = "3"
solana-instruction = "3.1"

# Crucible — solinv runs as plugin layer
crucible-fuzzer = { git = "https://github.com/asymmetric-research/crucible", tag = "v0.1.0" }
crucible-test-context = { git = "https://github.com/asymmetric-research/crucible", tag = "v0.1.0" }
```

### `crates/solinv-fuzz/src/lib.rs` (44 lines)

Three responsibilities:
1. `pub use crucible_fuzzer::*` — full Crucible surface to downstream users
2. Add 8 missing re-exports from `crucible_test_context`:
   - `record_violation`, `has_violation`, `take_violation`
   - `set_violation_action_index`, `get_violation_action_index`, `clear_violation_tracking`
   - `TxOutcome`, `TxError`
   - (`fuzz_assert_approx_eq` deferred — exists in crucible-test-context lib.rs:1056 but requires further re-export work)
3. `pub mod capability` + `pub mod prelude` for harness convenience

### `crates/solinv-fuzz/src/capability.rs` (130 lines)

Three exports per Day 3 design:

**`HasContext` trait** (3 methods):
```rust
pub trait HasContext {
    fn ctx(&self) -> &TestContext;
    fn ctx_mut(&mut self) -> &mut TestContext;
    fn program_ids(&self) -> Vec<Pubkey>;  // Day 3: TestContext.programs is private
}
```

**`HasInstructionSet` trait** (1 method):
```rust
pub trait HasInstructionSet {
    fn instructions(&self) -> Vec<InstructionSpec>;
}
```

**`InstructionSpec` struct** (12 fields, all per 5 Critical specs):
- `program_id`, `name`, `accounts`
- `signer_indices`, `optional_signer_indices` (signer-skip)
- `expected_owners` (owner-skip)
- `expected_discriminators` (discriminator-skip)
- `expected_pda_seeds`, `creates_indices` (pda-forge)
- `swap_alternates` (account-swap)
- `data_sample`
- `signers: Vec<Rc<Keypair>>` (Day 3 addition — needed for `raw_call(ix).signers(&...).send()`)

Plus `InstructionSpec::to_instruction() -> Instruction` for `raw_call` lowering.

Module doc-comment captures both Day 3 hard requirements (`pub ctx`
field mandatory; `raw_call` not Anchor `ProgramBuilder.accounts()`).

## Build results

```
$ cargo check --workspace
   Compiling crucible-fuzz-macro v0.1.0 (https://github.com/asymmetric-research/crucible?tag=v0.1.0#689e63a2)
   Compiling crucible-invariant-macro v0.1.0 (https://github.com/asymmetric-research/crucible?tag=v0.1.0#689e63a2)
   ...
    Checking crucible-test-context v0.1.0 (https://github.com/asymmetric-research/crucible?tag=v0.1.0#689e63a2)
    Checking crucible-fuzz-runtime v0.1.0 (https://github.com/asymmetric-research/crucible?tag=v0.1.0#689e63a2)
    Checking crucible-fuzzer v0.1.0 (https://github.com/asymmetric-research/crucible?tag=v0.1.0#689e63a2)
    Checking solinv-fuzz v0.0.1 (~/src/solinv/crates/solinv-fuzz)
    Checking solinv-cli v0.0.1 (~/src/solinv/crates/solinv-cli)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 50.70s
```

All 6 solinv crates + 8 Crucible crates compile. Dep tree includes:
- Anchor 1.0.1 (with all anchor-* sub-crates)
- LiteSVM 0.9.1 (with `register-tracing` feature transitively)
- Solana SDK 3.1.14 ecosystem (~80 transitive crates)
- LibAFL transitively via crucible-fuzz-runtime
- mimalloc, tokio, serde_json

## What this proves

1. **Crucible-on-top integration is mechanically working** — type-level
   composition succeeds. No version mismatches.
2. **Capability trait surface is API-compatible** with both Crucible's
   `TestContext` and Solana 3.0 split-crate ecosystem.
3. **Day 3 corrections are integrated** at the lowest level (capability
   module). Subsequent invariant implementations will use this as their
   contract.
4. **Workspace cargo build time** is acceptable (~50s first compile,
   incremental will be much faster).

## Risks discovered (Day 4)

None new. All Day 3 corrections successfully integrated. Build was
clean on first attempt — no Cargo resolution conflicts, no missing
re-exports beyond Day 3 known list.

`fuzz_assert_approx_eq` re-export was deferred — it requires deeper
investigation of how the macro is exported from crucible-test-context.
Not a blocker for Day 5.

## Day 5 plan

- Create `crates/solinv-core/src/invariants/mod.rs` module structure
- Create `crates/solinv-core/src/invariants/signer_skip.rs` (~80 lines)
  per `docs/implementation-day3-crucible-internals.md` §7 revised template
- Add `solinv-core` Cargo.toml deps on `solinv-fuzz` (capability traits) +
  Solana types
- `cargo check` should still pass
- Optional: write a trivial fixture in `examples/openhl-solana/fuzz/` to
  validate end-to-end compilation (would require building openhl-solana
  program with Crucible-compatible deps — Day 6+ scope)

Day 5 deliverable: `solinv_core::invariants::signer_skip::check::<F>(fixture)`
compiles, generic over `F: HasContext + HasInstructionSet`.

## Day 1-4 cumulative

- Day 1: Crucible CLI install + escrow fuzz + planted bug found + LCOV bytecode
- Day 2: Source-level LCOV with DWARF + 3-binary workflow
- Day 3: Internals deep-read + 7 critical design corrections
- Day 4: solinv-fuzz capability layer compiling against Crucible

Commit chain: `3ce0fdf` → `7217257` → `0dd5f3b` → (this commit)

By end of Day 5, the first concrete solinv invariant function exists
and the Crucible plugin pattern is end-to-end exercised in Rust code.
