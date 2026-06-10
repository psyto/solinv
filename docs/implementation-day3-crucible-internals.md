# Phase 1 Day 3 — Crucible Internals + Design Corrections

Date: 2026-05-25
Status: ✅ Internals read; **7 critical design corrections identified** for solinv-fuzz + invariant specs.

## Outcomes

| Day 3 goal | Status | Evidence |
|---|---|---|
| Read `crucible-fuzzer/lib.rs` (re-export set) | ✅ | All 48 lines + missing re-exports identified |
| Read `crucible-invariant-macro` (lines 1270-1434) | ✅ | Exact invariant_test loop structure documented |
| Read `crucible-test-context` API surface | ✅ | TestContext methods cataloged (lines 1392-2278) |
| Read `coverage.rs` bitmap shape | ✅ | MAP_SIZE=64K, SHARED_EDGE=2M bits, 13 hitcount buckets |
| Identify solinv-fuzz integration points | ✅ | See §10 for Day 4-5 starting code |
| Confirm/refute capability trait design | ✅ | Modifications required — see §3 |

## 1. THE 7 CRITICAL DESIGN CORRECTIONS

These supersede assumptions baked into the 5 Critical invariant specs
(signer-skip / owner-skip / discriminator-skip / pda-forge / account-swap)
and parts of CLAUDE.md / research-crucible-integration.md.

### Correction #1: `pub ctx: TestContext` is a HARD field requirement

The `#[fuzz_fixture]` macro hard-codes `fixture.ctx.send_batch()` in
`__auto_flush` (`crucible-invariant-macro/src/lib.rs:1209`) and accesses
`fixture.ctx.svm` / `fixture.ctx.dirty_tracker` (lines 1391-1394).

**HasContext trait does NOT substitute for this field — both required.**

```rust
#[derive(Clone)]
struct MyFixture {
    pub ctx: TestContext,  // ← MANDATORY field name, exact spelling
    // ... user state ...
}

impl HasContext for MyFixture {  // ADDITIONAL, not substitute
    fn ctx(&self) -> &TestContext { &self.ctx }
    fn ctx_mut(&mut self) -> &mut TestContext { &mut self.ctx }
}
```

### Correction #2: Must use `raw_call(Instruction)`, NOT Anchor `ProgramBuilder.accounts()`

The Anchor typed builder path always overwrites the AccountMeta vec from
a `ToAccountMetas`-derived value (`program_builder.rs:26-32`). This
destroys any AccountMeta flags solinv mutates for signer-skip detection.

**solinv MUST lower `InstructionSpec` → `Instruction` and use
`ctx.raw_call(Instruction)`** (line 2147 of test-context lib.rs), not
the typed `program(pid).call(...).accounts(...)` path.

```rust
// WRONG (used in original spec drafts):
ctx.program(spec.program_id).call(...).accounts(...).send()

// CORRECT (Day 3 finding):
let ix = Instruction {
    program_id: spec.program_id,
    accounts: mutated_metas,  // signer_idx flipped here
    data: spec.data_sample.clone(),
};
ctx.raw_call(ix).signers(&signers).send()
```

### Correction #3: First-violation-wins TLS

`record_violation()` (test-context lib.rs:908) only writes if `VIOLATION`
is `None` (lines 911-915). 5 chained solinv invariants in one
`#[invariant_test]` body will all run, but **only the first to trip
records its message**. The loop then breaks after current action's body.

**Quintuple-bug fixture contract MUST be reframed:**

- ❌ "5 bugs planted → 5 violations in 1 iteration"
- ✅ "5 bugs planted → 5 distinct violation messages observed **across a fuzz campaign**"

This still validates orthogonality (each invariant catches its bug
independently), just over multiple iterations, not in a single shot.

### Correction #4: Snapshot is iteration-scoped, NOT nestable

`take_snapshot()` (line 1730) snapshots ALL SVM accounts + Clock once
per iteration. `restore_snapshot()` (line 1760) restores ALL dirty
accounts to post-snapshot state — **including ones other actions
modified before the invariant ran**.

Calling `restore_snapshot()` inside an invariant body would undo prior
actions' state. **WRONG.**

**solinv invariants must do MANUAL per-account save/restore:**

```rust
// CORRECT pattern (Day 3 finding):
let saves: Vec<_> = spec.accounts.iter()
    .filter_map(|m| fixture.ctx().get_account(&m.pubkey).ok()
        .map(|a| (m.pubkey, a)))
    .collect();

// ... mutate accounts, send ix, check ...

// Manual restore (only touched accounts, O(5-10) writes)
for (pk, acct) in saves {
    let _ = fixture.ctx_mut().write_account(&pk, acct);
}
```

### Correction #5: No feedback extension API

`SharedBitmapFeedback::is_interesting` (line 687 of coverage.rs) returns
`Ok(true)` only on internal coverage signals. **`mark_new_coverage()`
is private to the generated module.**

solinv cannot signal "this input is interesting because invariant X
tripped" back to LibAFL's scheduler.

**Workaround: offline corpus replay.** solinv-corpus maintains a
sidecar directory of "interesting inputs" (ones that exercised
specific code paths or near-violations), and seeds them back via
Crucible's `--corpus-in` between fuzz campaigns. No runtime hook
needed.

### Correction #6: InstructionSpec must hold `signers: Vec<Rc<Keypair>>`

To call `raw_call(ix).signers(&signers).send()`, solinv needs the
keypair list. Fixtures hold keypairs as `Rc<Keypair>` (per escrow
example line 16-17). Add to InstructionSpec:

```rust
pub struct InstructionSpec {
    // ... existing 10 fields ...
    pub signers: Vec<Rc<Keypair>>,  // NEW
}
```

solinv signer-skip detection drops the target signer from this list
when sending: `signers.iter().enumerate().filter(|(i,_)| i != sig_idx)`.

### Correction #7: HasContext needs `program_ids()` method

`TestContext.programs` field is private (line 1332). Owner-skip
invariant needs to know which programs are registered. Add to
HasContext trait:

```rust
pub trait HasContext {
    fn ctx(&self) -> &TestContext;
    fn ctx_mut(&mut self) -> &mut TestContext;
    fn program_ids(&self) -> Vec<Pubkey>;  // NEW
}
```

User fixture implements this from its own knowledge:
```rust
impl HasContext for MyFixture {
    fn program_ids(&self) -> Vec<Pubkey> {
        vec![self.program_id, anchor_spl::token::ID, /* etc. */]
    }
}
```

## 2. Public API surface (validated)

### crucible_fuzzer re-export set (full)

From `crates/crucible-fuzzer/src/lib.rs` (48 lines):

- Macros: `crucible_fuzz`, `fuzz_fixture`, `invariant_test`
- Core types: `TestContext`, `AccountBuilderBase`
- Assertions: `fuzz_assert{,_eq,_ne,_lt,_le,_gt,_ge}` (7)
- Direct deps: `anchor_lang`, `anchor_spl`
- Mutation traits: `ActionGenerator`, `CrossoverMutator`, `FuzzAction`,
  `FuzzInput`, `FuzzRand`, `ParamMutator`, `SequenceMutator`, `StdRand`
- Mutators: `gen_i128/i64/range_u64/range_usize/u128/u64/usize`,
  `mutate_bool/i64/u64/usize`, `rand_below`
- Corpus: `cmin`, `SuccessPatternMetadata`, `SuccessTrimStage`
- Other: `serde_json`, `MiMalloc`, `libc`

### Missing re-exports — solinv-fuzz must add explicitly

- `crucible_test_context::record_violation`
- `crucible_test_context::has_violation` / `take_violation`
- `crucible_test_context::TxOutcome`, `TxError`
- `crucible_test_context::set_violation_action_index`
- `crucible_test_context::fuzz_assert_approx_eq` (exists at line 1056
  but not re-exported)

### TestContext key methods (grouped, with line refs)

**Construction**: `new()` (1393), `with_invocation_callback<C>()` (1425),
`from_svm()` (1605), `into_svm()` (1619)

**Program loading**: `add_program(&Pubkey, &str)` (1535),
`add_program_from_bytes()` (1553), `get_program_binary(&Pubkey)` (1717)

**Snapshot (iteration-scoped)**: `take_snapshot()` (1730),
`begin_iteration()` (1751), `restore_snapshot() -> usize` (1760),
`has_snapshot() -> bool` (1769), `dirty_tracker()` (1774)

**Account read**: `get_account(&Pubkey) -> Result<Account>` (1945),
`read_account()` (1950), `read_anchor_account<T>()` (1958),
`read_zero_copy_account<T>()` (2049), `token_balance(&Pubkey)` (1998)

**Account write**: `write_account(&Pubkey, Account)` (2009),
`write_anchor_account<T>()` (2017), `update_account<F>()` (2135),
`create_account() -> GenericAccountBuilder` (1781)

**Sysvar / time**: `set_sysvar<T>()` (1895), `slot()` (1904),
`warp_to_slot(u64)` (1883), `advance_slots(u64)` (1888)

**Instruction execution**:
- `raw_call(Instruction) -> InstructionBuilder` (2147) ← use for solinv
- `program(Pubkey) -> ProgramBuilder` (2157) ← Anchor typed, avoid for solinv
- `transaction() -> TransactionBuilder` (2171)
- `send_batch() -> Result<Option<TxOutcome>>` (2179)

**InstructionBuilder chain**: `.signers(&[&Keypair])` (18),
`.fee_payer(&Keypair)` (23), `.send() -> Result<TxOutcome>` (28)

## 3. Coverage feedback contract

| Constant | Value | File line |
|---|---|---|
| `MAP_SIZE` | `1 << 16` = 64K | coverage.rs:8 |
| `SHARED_EDGE_BITMAP_SIZE` | `1 << 18` = 2M bits | coverage.rs:17 |
| `SHARED_BRANCH_BITMAP_SIZE` | `1 << 18` = 2M branch bits | coverage.rs:18 |
| Hitcount buckets | 13 (vs AFL's 9) | coverage.rs:36-52 |

Edge hash: `(cur_loc ^ prev_loc) % MAP_SIZE` (line 436), mixed via
xxhash finalizer (`mix_hash`, lines 23-30) into shared bitmap.

**No extension hook for solinv.** See Correction #5.

`CMIN_EDGE_SET` (line 175) is exact-edge HashSet for corpus
minimization. Useful reference for solinv-corpus design.

## 4. `#[invariant_test]` loop structure (exact)

From `crucible-invariant-macro/src/lib.rs:1337-1430`:

```rust
#[crucible_fuzz(structured)]
fn invariant_x(fixture: &mut F, actions: Vec<__f_fuzz::FActions>) {
    clear_iteration_state();
    set_total_actions(actions.len());
    set_current_test_name("invariant_x");
    let mut __executed = Vec::with_capacity(actions.len());

    for (i, mut action) in actions.into_iter().enumerate() {
        action.constrain_in_place();                       // 1365
        let variant_idx = FuzzAction::variant_index(&action);
        let success = fixture.__dispatch_action(action.clone());  // 1374
        push_action_record_lite(action.action_name(), success);
        __executed.push(action);

        <USER BODY HERE — runs after every action>         // 1386

        if has_violation() {                                // 1402
            for (j, a) in __executed.iter().enumerate() {
                backfill_action_params(j, a.to_json_params());
            }
            set_violation_action_index(i);
            break;
        }
        if !success && is_stateful_chain_mode() { break; } // 1413
    }
    fixture.__auto_flush();                                // 1429
}
```

**Confirmed**: invariant body runs **after every action**, not just at
end. Early break on `has_violation()`.

## 5. Escrow harness skeleton (solinv init template)

From `examples/escrow/fuzz/escrow/src/main.rs` (145 lines). solinv
init should generate this exact shape:

```rust
use crucible_fuzzer::*;
use crucible_fuzzer::anchor_lang::system_program;
use my_program::*;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use std::rc::Rc;

#[derive(Clone)]
struct MyFixture {
    pub ctx: TestContext,                  // mandatory field
    pub program_id: Pubkey,
    pub authority: Rc<Keypair>,
}

#[fuzz_fixture]
impl MyFixture {
    pub fn setup() -> Self {
        let mut ctx = TestContext::new();
        ctx.add_program(&PROGRAM_ID, "../../target/deploy/my_program.so").unwrap();
        let authority = Rc::new(Keypair::new());
        // ... initialize accounts, run init ix ...
        Self { ctx, program_id: PROGRAM_ID, authority }
    }

    pub fn action_foo(&mut self, #[range(1..1_000_000)] amount: u64) -> bool {
        // Domain action — uses ctx.program() typed builder is fine here
        // since this is the canonical (untampered) call path
        self.ctx.program(self.program_id)
            .call(instruction::Foo { amount })
            .accounts(accounts::Foo { /* ... */ })
            .signers(&[&*self.authority])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }
}

// solinv capability impls (Day 4-5 will add these as trait helpers)
impl HasContext for MyFixture {
    fn ctx(&self) -> &TestContext { &self.ctx }
    fn ctx_mut(&mut self) -> &mut TestContext { &mut self.ctx }
    fn program_ids(&self) -> Vec<Pubkey> { vec![self.program_id] }
}

impl HasInstructionSet for MyFixture {
    fn instructions(&self) -> Vec<InstructionSpec> {
        // Lower domain actions to InstructionSpec for solinv
        // (this is the manual surface users write)
        vec![/* ... */]
    }
}

#[invariant_test]
fn invariant_all(fixture: &mut MyFixture) {
    solinv_core::invariants::signer_skip::check(fixture);
    solinv_core::invariants::owner_skip::check(fixture);
    solinv_core::invariants::discriminator_skip::check(fixture);
    solinv_core::invariants::pda_forge::check(fixture);
    solinv_core::invariants::account_swap::check(fixture);
    // user-written domain invariants below
}
```

## 6. Revised solinv-fuzz integration pattern

```rust
// solinv-fuzz/src/lib.rs

pub use crucible_fuzzer::*;

// Add missing re-exports
pub use crucible_test_context::{
    record_violation, has_violation, take_violation,
    set_violation_action_index, get_violation_action_index,
    clear_violation_tracking, TxOutcome, TxError,
    fuzz_assert_approx_eq,
};

pub mod capability;
pub use capability::{HasContext, HasInstructionSet, InstructionSpec};

pub mod prelude {
    pub use crate::*;
}
```

```rust
// solinv-fuzz/src/capability.rs

use anchor_lang::solana_program::{instruction::AccountMeta, pubkey::Pubkey};
use crucible_test_context::TestContext;
use solana_keypair::Keypair;
use std::rc::Rc;

pub trait HasContext {
    fn ctx(&self) -> &TestContext;
    fn ctx_mut(&mut self) -> &mut TestContext;
    fn program_ids(&self) -> Vec<Pubkey>;
}

pub trait HasInstructionSet {
    fn instructions(&self) -> Vec<InstructionSpec>;
}

pub struct InstructionSpec {
    pub program_id: Pubkey,
    pub name: String,
    pub accounts: Vec<AccountMeta>,
    pub signer_indices: Vec<usize>,
    pub optional_signer_indices: Vec<usize>,
    pub expected_owners: Vec<Option<Pubkey>>,
    pub expected_discriminators: Vec<Option<[u8; 8]>>,
    pub expected_pda_seeds: Vec<Option<Vec<Vec<u8>>>>,
    pub creates_indices: Vec<usize>,
    pub swap_alternates: Vec<Vec<Pubkey>>,
    pub data_sample: Vec<u8>,
    pub signers: Vec<Rc<Keypair>>,  // NEW from Day 3
}

impl InstructionSpec {
    pub fn to_instruction(&self) -> anchor_lang::solana_program::instruction::Instruction {
        anchor_lang::solana_program::instruction::Instruction {
            program_id: self.program_id,
            accounts: self.accounts.clone(),
            data: self.data_sample.clone(),
        }
    }
}
```

## 7. Revised signer-skip implementation (template)

Apply Corrections #2, #4, #6 to the canonical detection pattern:

```rust
// solinv-core/src/invariants/signer_skip.rs

pub fn check<F: HasContext + HasInstructionSet>(fixture: &mut F) {
    for spec in fixture.instructions() {
        for &sig_idx in &spec.signer_indices {
            if spec.optional_signer_indices.contains(&sig_idx) {
                continue;
            }

            // Manual save (Correction #4 — don't use restore_snapshot)
            let saves: Vec<_> = spec.accounts.iter()
                .filter_map(|m| fixture.ctx().get_account(&m.pubkey).ok()
                    .map(|a| (m.pubkey, a)))
                .collect();
            let pre_hash = hash_accounts(&saves);

            // Build mutated ix (Correction #2 — raw_call only)
            let mut metas = spec.accounts.clone();
            metas[sig_idx].is_signer = false;
            let ix = Instruction {
                program_id: spec.program_id,
                accounts: metas,
                data: spec.data_sample.clone(),
            };

            // Send with dropped signer (Correction #6 — Rc<Keypair> list)
            let signers: Vec<&Keypair> = spec.signers.iter().enumerate()
                .filter(|(i, _)| *i != sig_idx)
                .map(|(_, k)| &**k)
                .collect();
            let result = fixture.ctx_mut().raw_call(ix).signers(&signers).send();

            // Compare post-state
            let post_hash = hash_accounts_now(
                fixture.ctx(),
                saves.iter().map(|(k, _)| *k)
            );

            if matches!(result, Ok(o) if o.is_success()) && pre_hash != post_hash {
                fuzz_assert!(false, "[signer-skip:{}:{}] ix succeeded without required signer at index {}",
                             spec.name, sig_idx, sig_idx);
            }

            // Manual restore (Correction #4)
            for (pk, acct) in saves {
                let _ = fixture.ctx_mut().write_account(&pk, acct);
            }
        }
    }
}

fn hash_accounts(saves: &[(Pubkey, solana_sdk::account::Account)]) -> u64 {
    use std::hash::Hasher;
    let mut h = std::collections::hash_map::DefaultHasher::new();
    for (pk, acct) in saves {
        h.write(pk.as_ref());
        h.write(&acct.data);
        h.write_u64(acct.lamports);
        h.write(acct.owner.as_ref());
    }
    h.finish()
}

fn hash_accounts_now<I: IntoIterator<Item = Pubkey>>(
    ctx: &TestContext, pubkeys: I,
) -> u64 {
    let saves: Vec<_> = pubkeys.into_iter()
        .filter_map(|pk| ctx.get_account(&pk).ok().map(|a| (pk, a)))
        .collect();
    hash_accounts(&saves)
}
```

Apply same corrections to owner-skip / discriminator-skip / pda-forge /
account-swap implementations.

## 8. Specs needing revision

These 5 spec files have detection pseudocode that uses
`snapshot`/`revert_to` and conceptually assumes "5 violations in 1
iteration" — both need Day 3 corrections applied:

- `docs/invariants/signer-skip.md`
- `docs/invariants/owner-skip.md`
- `docs/invariants/discriminator-skip.md`
- `docs/invariants/pda-forge.md`
- `docs/invariants/account-swap.md`

Revision scope per spec:
- Replace `ctx.snapshot()` / `ctx.revert_to(snapshot)` with manual
  `get_account` save + `write_account` restore
- Replace `ctx.send(program_id, data, accounts)` pseudocode with
  `ctx.raw_call(Instruction { ... }).signers(&...).send()`
- Add `signers: Vec<Rc<Keypair>>` to InstructionSpec usage examples
- Reframe quintuple-bug fixture: "5 bugs → 5 violations **across
  campaign**, not single iteration"
- Add `program_ids()` to HasContext implementations shown

**Deferred revision**: marking as TODO rather than rewriting now —
implementation will surface any remaining gaps in Day 11-20. Better
to revise specs DURING Critical-tier implementation when actual API
constraints are felt, rather than speculatively now.

## 9. Day 3 strategic learnings

1. **Crucible-on-top strategy is viable** but with concrete API constraints
   (raw_call only, manual save/restore, ctx field required)
2. **Reading internals before implementing saved significant rework cost**
   — without Day 3, would have written invariants against wrong API
3. **First-violation-wins TLS** changes the orthogonality contract but
   doesn't invalidate it — solinv just measures over campaign, not iteration
4. **No feedback hook = offline corpus workflow** for solinv-corpus —
   already aligned with Medusa-pattern research (replayable artifacts)
5. **5 of the 7 corrections** are implementation-detail (raw_call,
   manual restore, signers field, program_ids, missing re-exports);
   **2 corrections are conceptual** (ctx field requirement, first-
   violation TLS) and warrant CLAUDE.md updates

## 10. Day 4-5 implementation start

Files to create:

1. **`crates/solinv-fuzz/src/lib.rs`** — re-export Crucible + missing
   items + capability module
2. **`crates/solinv-fuzz/src/capability.rs`** — HasContext +
   HasInstructionSet + InstructionSpec
3. **`crates/solinv-core/src/invariants/mod.rs`** — module list
4. **`crates/solinv-core/src/invariants/signer_skip.rs`** — first
   invariant per §7 template (~80 lines)
5. **`examples/openhl-solana/fuzz/openhl-fuzz/src/main.rs`** —
   first user harness; copies escrow pattern but targets openhl-solana
6. **`examples/openhl-solana/fuzz/openhl-fuzz/Cargo.toml`** — depends
   on solinv-fuzz + solinv-core

Reference files (from Crucible repo) to mirror:
- `crates/crucible-fuzzer/src/lib.rs` — re-export structure
- `examples/escrow/fuzz/escrow/src/main.rs` — harness skeleton
- `examples/escrow/fuzz/escrow/Cargo.toml` — Cargo deps shape

Day 4 deliverable: `solinv-fuzz` compiles, re-exports work. Day 5
deliverable: `solinv-core::invariants::signer_skip::check` compiles
and runs against trivial planted bug in openhl-solana.

## 11. Risks discovered

| Risk | Severity | Action |
|---|---|---|
| ctx field name hard-coded | Low (well-documented constraint) | Document in CLAUDE.md |
| raw_call complicates spec impls | Medium (more verbose code) | Document + accept |
| First-violation-wins per iteration | Medium (acceptance test reframing) | Update CLAUDE.md acceptance contract |
| Snapshot non-nestable | Medium (manual save/restore overhead) | Document pattern; verify implementation cost |
| No feedback extension API | Low (offline workflow already planned) | Confirm solinv-corpus design assumption |
| Solana version pins (3.0 / 1.0.1 / 0.9.0) | Low (already documented) | Ensure solinv Cargo.toml matches |
| `fuzz_assert_approx_eq` missing | Trivial | Re-export from solinv-fuzz |

None are show-stoppers. All 7 corrections are accommodatable in the
existing architecture without redesign.

## Sources

- `research/crucible/crates/crucible-fuzzer/src/lib.rs` (48 lines, full read)
- `research/crucible/crates/crucible-invariant-macro/src/lib.rs` (lines 736-1434)
- `research/crucible/crates/crucible-test-context/src/lib.rs` (lines 1392-2278 + macro defs)
- `research/crucible/crates/crucible-fuzz-macro/src/coverage.rs` (constants + feedback)
- `research/crucible/crates/crucible-test-context/src/instruction_builder.rs` (raw_call chain)
- `research/crucible/crates/crucible-test-context/src/program_builder.rs` (typed Anchor path — what to avoid)
- `research/crucible/examples/escrow/fuzz/escrow/src/main.rs` (harness template)
- `research/crucible/docs/harness-guide.md`, `writing-tests.md`
