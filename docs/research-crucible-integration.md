# Crucible Integration — Architecture Decision

Date: 2026-05-24
Status: Week 1 validation item #3

## Verdict

**Pattern A (Crucible-as-library)** with capability traits + free invariant functions. No fork required, no plugin API needed — Crucible's macro/re-export design makes library composition the natural seam.

## Crucible architecture summary

Workspace = 8 crates (v0.1.0, MIT, 2026-04-30):
- `crucible-fuzzer` — umbrella facade (`pub use` everything)
- `crucible-test-context` — SVM wrapper (`TestContext`, `fuzz_assert_*!` macros, violation TLS)
- `crucible-fuzz-macro` — `#[crucible_fuzz]` simple-fuzz harness
- `crucible-invariant-macro` — `#[fuzz_fixture]` + `#[invariant_test]` stateful API
- `crucible-fuzz-runtime` — LibAFL mutators, `FuzzAction` trait, `FuzzInput`
- `crucible-macro-utils` — shared macro helpers
- `crucible-idl-gen` — Anchor/Codama/Shank → typed bindings
- `crucible-fuzz-cli` — `crucible` binary

## How a Crucible fuzz target works

Two macros (both in `crates/crucible-invariant-macro/src/lib.rs`):

1. **`#[fuzz_fixture]`** on `impl MyFixture` — auto-discovers `pub fn action_*` methods and codegens `MyFixtureActions` enum implementing `FuzzAction` (variant_count, variant_index, action_name, constrain_in_place, to_json_params) + `__dispatch_action` + `__auto_flush`.

2. **`#[invariant_test]`** (lines 1270-1434) — wraps `fn(&mut Fixture)` body in a `#[crucible_fuzz(structured)]` driver loop:
   ```
   for action in actions {
       fixture.__dispatch_action(action);
       <user_body>;
       if has_violation() break;
   }
   ```

**Invariant checking happens BETWEEN actions** inside the generated loop. Violation reporting via thread-local sentinels (`VIOLATION`, `has_violation()`, `set_violation_action_index`) set by `fuzz_assert_*!` macros.

**No `Invariant` trait exists.** The entire invariant is the function body.

## Public API surface (`crucible-fuzzer/src/lib.rs`)

```rust
pub use crucible_fuzz_macro::crucible_fuzz;
pub use crucible_invariant_macro::{fuzz_fixture, invariant_test};
pub use crucible_test_context::{TestContext, AccountBuilderBase,
    fuzz_assert, fuzz_assert_eq, fuzz_assert_ge, fuzz_assert_gt,
    fuzz_assert_le, fuzz_assert_lt, fuzz_assert_ne};
pub use crucible_fuzz_runtime::{FuzzAction, FuzzInput, ActionGenerator,
    SequenceMutator, ParamMutator, CrossoverMutator, ...};
pub use anchor_lang; pub use anchor_spl;
pub use mimalloc::MiMalloc; pub extern crate libc;
```

`TestContext` is the stateful surface: `program(..).call(..).accounts(..).signers(..).send()`, `read_anchor_account`, `read_zero_copy_account`, `update_account`, `token_balance`, `warp_to_slot`, `slot()`, `dirty_tracker`. Plus re-exports: `litesvm`, `TxOutcome`, `MockPythOracleBuilder`. Coverage/snapshot machinery also `pub`.

## solinv integration pattern

solinv provides invariants as **free functions parametrized over capability traits** that user fixtures implement. No forking, no upstream PRs needed.

```rust
// solinv-fuzz/src/lib.rs
pub use crucible_fuzzer as crucible;
pub mod traits;        // HasTokenVaults, HasLendingPool, HasOracle, ...
pub mod invariants;    // token_conservation, solvency, monotonic_supply, ...

pub mod prelude {
    pub use crate::invariants::*;
    pub use crate::traits::*;
    pub use crucible_fuzzer::*;
}
```

User harness:

```rust
use solinv_fuzz::prelude::*;

#[derive(Clone)]
struct MyFixture { ctx: TestContext, vault_a: Pubkey, vault_b: Pubkey }

impl HasTokenVaults for MyFixture {
    fn ctx(&self) -> &TestContext { &self.ctx }
    fn vaults(&self) -> &[Pubkey] { &[self.vault_a, self.vault_b] }
    fn expected_total(&self) -> u64 { self.deposits.saturating_sub(self.withdrawals) }
}

#[fuzz_fixture]
impl MyFixture {
    pub fn setup() -> Self { /* ... */ }
    pub fn action_deposit(&mut self, amount: u64) -> bool { /* ... */ }
}

#[invariant_test]
fn invariant_all(f: &mut MyFixture) {
    solinv_fuzz::invariants::token_conservation(f);
    solinv_fuzz::invariants::solvency(f);
    // ... 15-20 invariants ...
}
```

`solinv check <program> <test>` CLI shells out to `crucible run <program> <test> --release`, passing through `--cores`, `--timeout`, `--coverage`. `solinv init <protocol>` scaffolds fixture with pre-wired trait impls.

## Critical decisions

| Decision | Choice | Reason |
|---|---|---|
| Cargo dep style | `git = "...", tag = "v0.1.0"` | Tag pinning (not `branch = "main"`) — Crucible explicitly says "API may change before 1.0" |
| solinv license | MIT or Apache-2.0 | Crucible MIT + LiteSVM Apache-2.0 = no copyleft contamination |
| Solana version | `solana-* = "3.0"`, `anchor-lang = "1.0.1"`, `litesvm = "0.9.0"` | Must match Crucible workspace |
| Harness mode | invariant-mode only (skip `#[crucible_fuzz]` simple-mode) | Invariants run only between actions in `#[invariant_test]` loop |
| Solinv invariant pattern | Free functions over capability traits | No plugin API exists; this is the natural seam |

## Risks

1. **API instability** — v0.1.0 disclaimer: "API may change before 1.0." Budget for refactor per Crucible minor bump.
2. **Macro coupling** — solinv-provided macros could break if Asymmetric changes `__dispatch_action` / `FuzzAction` shape. Stick to capability-trait approach (decoupled from macro internals).
3. **Solana version lock** — User's program types must match Crucible's pinned solana-*/anchor versions. Document in `solinv init`.
4. **fuzz-up CLI is opaque** — closed-source release-only repo (README + cosign.pub only). Treat as black box. Use Crucible's in-repo `crucible init` scaffold instead.
5. **litesvm-tracing fork** — now historical (last push 2025-11-05). Crucible moved to upstream `litesvm = "0.9.0"` with `register-tracing` feature. No action needed from solinv.

## Day 1 code pointers

Files to read and mirror:
- `crucible/crates/crucible-fuzzer/src/lib.rs` — public re-export set (mirror in solinv-fuzz)
- `crucible/crates/crucible-invariant-macro/src/lib.rs` (lines 1270-1434) — `#[invariant_test]` injection point
- `crucible/crates/crucible-test-context/src/lib.rs` — `TestContext`, `fuzz_assert_*!`, `has_violation()`, `read_anchor_account`, `read_zero_copy_account`, `token_balance`
- `crucible/examples/escrow/fuzz/escrow/src/main.rs` — minimal harness skeleton
- `crucible/crates/crucible-fuzz-cli/src/templates.rs` — init scaffold (mirror for `solinv init`)
- `crucible/docs/writing-tests.md` + `harness-guide.md` — behavioral contract

Cargo target:
```toml
[dependencies]
crucible-fuzzer = { git = "https://github.com/asymmetric-research/crucible", tag = "v0.1.0" }
crucible-test-context = { git = "https://github.com/asymmetric-research/crucible", tag = "v0.1.0" }
```

## Sources

- [asymmetric-research/crucible](https://github.com/asymmetric-research/crucible) (v0.1.0, MIT, 2026-04-30)
- [Introducing Crucible — Asymmetric blog](https://blog.asymmetric.re/introducing-crucible-an-invariant-fuzzing-framework-for-solana/)
- [asymmetric-research/litesvm-tracing](https://github.com/asymmetric-research/litesvm-tracing) (historical fork, superseded)
- [asymmetric-research/fuzz-up](https://github.com/asymmetric-research/fuzz-up) (opaque release-only)
