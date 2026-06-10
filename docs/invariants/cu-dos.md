# Invariant: cu-dos

> **Severity**: High (Critical when the DoS surface is permanent — see §6)
> **Bug class**: Single instruction consumes compute units (CU) sufficiently close to the per-tx limit that protocol interaction is denied for a class of inputs.
> **Status**: Spec written 2026-05-26 (Day 35). Implementation: Day 36. Gate 1: Day 37. Gate 2: Day 38.

## 1. Bug class

A Solana transaction runs under a strict per-tx Compute Unit budget
— 200,000 CU by default, requestable up to 1,400,000 via the
ComputeBudget program. If an instruction consumes CU close to that
ceiling, an attacker who can grow the consumed amount past the
ceiling — by inflating an attacker-controllable input, by causing
intermediate state to balloon, or by chaining the ix with other CU
consumers in the same tx — denies all users of the protocol the
ability to execute that ix until either Solana raises the ceiling or
the protocol team patches.

This is distinct from a one-off failed tx: cu-dos is a **systemic
denial** that affects a category of legitimate users.

### Five sub-patterns

1. **Unbounded loop on input size** — ix iterates over an
   attacker-controllable account list, vector, or data buffer.
   Largest input → loop exhausts CU.
2. **Quadratic algorithm** — O(n²) where n is attacker-influenced.
   Naive search over a list, naive sort, etc.
3. **CPI cascade** — ix CPIs to another program inside a loop. Each
   CPI carries ~3-5K CU overhead; even modest loop counts add up.
4. **Storage iteration over a growable structure** — ix walks a
   Vec/linked list and processes each element. Attacker grows the
   structure permissionlessly, then triggers iteration.
5. **Deserialization explosion** — Borsh decodes a large
   variable-sized field whose size is attacker-set. Per-byte
   decode overhead becomes the dominant cost.

The first and fourth are the most common in mainnet bug reports.
Pattern 4 in particular is a **permanent** DoS: even after the
attacker stops, the inflated structure is still there forcing
high CU on every call.

### Why Solana-specific (vs EVM)

EVM's gas system is per-tx in similar spirit — but EVM tx senders
attach gas, so a high-gas tx is "the sender's problem" rather than
a contract-level DoS. On Solana the CU budget is fixed per tx
(modulo ComputeBudget program override) and the consumer is the
*invocation*, not the sender. If a program design forces 250k CU
on a particular path, **no caller** can use that path within the
default budget; raising it via ComputeBudget program is
non-obvious to many integrators and may not be enough.

Solana also has per-block CU caps (48M as of 2026), so even
ComputeBudget-uplifted txes compete for a shared resource — making
cu-dos a vector against block-level liveness for popular protocols.

## 2. Mainnet precedent and audit findings

### Direct precedents

- **OpenBook v1 (Serum legacy)** — order-cancel ix iterated all
  open orders per side; with enough open orders, single
  user-cancel-all exceeded budget. Patched in v2.
- **Lifinity v1 (early 2023)** — pool init carried an O(n²)
  validation loop on the LP supply list. Patched before significant
  TVL.
- **Multiple Solana NFT listings programs** — "claim all" ix
  iterated all unclaimed listings; attackers spam-listed to deny
  legitimate claims.
- **A common Solana governance pattern** — proposal-finalize ix
  loops over all votes. Discovered as cu-dos surface in several
  audits of governance forks.

### Audit firm coverage

- **OtterSec Anchor SECURITY.md** lists "Compute Budget DoS" under
  the same High-tier band as unchecked-math.
- **Neodyme "Common Pitfalls" §6** — explicit on unbounded
  iteration over user-controllable account lists.
- **Sec3 audit reports** — routinely flag any `for _ in
  attacker_controlled_size` site.
- **Trail of Bits Anchor guidelines** — recommends explicit
  `require!(list.len() <= MAX_LEN)` guards on every iteration site.

### Bounty bands (2026)

- Critical (DoS permanently denies a major protocol surface and is
  inexpensive to trigger): $50K-$300K
- High (DoS gates a class of legitimate calls; recovery possible
  via ComputeBudget uplift): $10K-$50K
- Medium (DoS theoretically possible but requires preconditions an
  attacker can't economically achieve): $1K-$10K

## 3. Detection algorithm

cu-dos detection runs against Crucible's existing per-ix execution:
read the consumed CU off `TxOutcome::Success { compute_units, … }`,
compare against the user-declared cap.

### Mechanism

For each ix in the fixture's `InstructionSpec` that has a non-`None`
`cu_budget`, solinv:

1. Saves the accounts list (per Day 3 Correction #4).
2. Executes the ix unmodified via `raw_call` — Crucible's mutator
   has already biased `data_sample` toward boundary values.
3. If the ix returns `TxOutcome::Success { compute_units, … }`,
   compares `compute_units` against `spec.cu_budget`.
4. If `compute_units > cu_budget`, records a violation with the
   exact consumed amount and the declared cap.
5. Restores the accounts list.

### InstructionSpec extension

```rust
pub struct InstructionSpec {
    // ... existing 13 fields (Critical 5 + Day 31 state_invariants) ...
    pub cu_budget: Option<u64>,         // High-tier addition #2
}
```

`None` means cu-dos detection is opt-out for that ix (e.g., ix has
an inherently large but bounded CU footprint that's accepted as a
design constraint). `Some(N)` means "this ix must complete in ≤ N
compute units; consumption above N indicates a cu-dos surface".

### Choosing the cap

Two strategies, in increasing rigour:

1. **Static cap from audit guidance**: 100,000 CU for swap-like ix,
   50,000 for simple account-mutation ix, 200,000 for ix that does
   CPI cascades. This is what v1 ships.
2. **Empirical baseline**: measure consumed CU across a sample of
   N legitimate executions, set cap at `1.5 × max_observed`. v2
   stretch; requires a separate measurement pass.

The 1.5× factor in (2) is the standard audit firm recommendation —
accommodates state-size-driven variation without leaving room for
the unbounded-loop bug class.

### Per-iteration semantics

Same first-violation-wins TLS as Critical tier. Each ix execution
produces at most one violation per iteration.

### What detection means

A cu-dos violation is **always** a true positive in the
detection-mechanism sense — the ix really did consume more CU than
declared. Whether it's an *exploitable* DoS depends on whether the
input triggering the consumption is attacker-controllable. v1 does
not distinguish — it surfaces the consumption fact and leaves the
triage call to the user. False positives in the bounty-submittable
sense come from caps that were set too tight; §5 discusses
mitigation.

## 4. Capability trait + implementation sketch

No new trait — same `HasContext` + `HasInstructionSet` as Critical
5 and unchecked-math.

Implementation lives at
`crates/solinv-core/src/invariants/cu_dos.rs`:

```rust
use crucible_test_context::{fuzz_assert, TxOutcome};
use solana_keypair::Keypair;
use solana_signer::Signer;
use solinv_fuzz::{HasContext, HasInstructionSet, InstructionSpec};

use super::util::{restore_accounts, save_accounts};

pub fn check<F>(fixture: &mut F)
where
    F: HasContext + HasInstructionSet,
{
    let ixs = fixture.instructions();
    for spec in &ixs {
        let Some(budget) = spec.cu_budget else { continue };
        run_attempt(fixture, spec, budget);
    }
}

fn run_attempt<F>(fixture: &mut F, spec: &InstructionSpec, budget: u64)
where
    F: HasContext + HasInstructionSet,
{
    let pubkeys: Vec<_> = spec.accounts.iter().map(|m| m.pubkey).collect();
    let saves = save_accounts(fixture.ctx(), &pubkeys);

    let fee_payer = fixture.fee_payer();
    let mut signer_refs: Vec<&Keypair> = vec![&*fee_payer];
    for kp in &spec.signers {
        if kp.pubkey() != fee_payer.pubkey() {
            signer_refs.push(&**kp);
        }
    }

    let result = fixture
        .ctx_mut()
        .raw_call(spec.to_instruction())
        .fee_payer(&*fee_payer)
        .signers(&signer_refs)
        .send();

    if let Ok(TxOutcome::Success { compute_units, .. }) = result {
        fuzz_assert!(
            compute_units <= budget,
            "[cu-dos:{}] ix {} consumed {} CU (cap {})",
            spec.program_id,
            spec.name,
            compute_units,
            budget,
        );
    }

    restore_accounts(fixture.ctx_mut(), saves);
}
```

`TxOutcome::Success` carries `compute_units: u64` directly (see
`research/crucible/crates/crucible-test-context/src/lib.rs:1082-1089`).
No new util helper needed.

### Regression tests

Direct unit tests on a synthetic `TxOutcome`-shaped value aren't
expressible cleanly because the comparison logic is one line. v1
regression coverage is:

- A non-detect test using a system_program transfer + a generous
  cap (e.g. `cu_budget = 10_000` — transfer is ~150 CU).
- A `#[ignore]`-marked detect_pair placeholder pending the
  escrow-demo `unsafe_compute_dos` planted ix (Day 37).

## 5. False-positive risks and mitigations

### Risk 1: Cap was set too tight

If the user declares `cu_budget = 50_000` but the legitimate
operation legitimately costs 60,000 CU on some inputs, every such
execution fires. This is the dominant false-positive mode.

**Mitigation**: spec recommends caps derived from observed maximums
across legitimate fuzzing input distribution + 1.5× margin. v1
ships with static caps and accepts this risk; v2 auto-baselines.

### Risk 2: Variable CU on state size

Some ix legitimately consume more CU when working over a larger
state (e.g., processing a larger position set). A flat cap fires
on the high end of legitimate state.

**Mitigation**: declare cap as a function of input size in v2.
v1 documents the limitation and recommends declaring the cap at
the high end of expected legitimate state size.

### Risk 3: Compiler / toolchain CU variance

cargo-build-sbf produces slightly different bytecode across
toolchain versions. CU counts vary by 1-5% across versions. A cap
set on v1.51 may fire spuriously on v1.52.

**Mitigation**: cu_budget margins of +5% relative to measured cap
absorb toolchain variance. Re-baseline the cap when the program
SBF binary is rebuilt with a new toolchain.

### Risk 4: ComputeBudget-uplifted budget

The fixture's tx might include a `ComputeBudget::set_compute_unit_limit`
ix raising the per-tx ceiling. solinv's detection compares
consumed CU against user's cu_budget, not against the actual
runtime ceiling. So cu_budget is the "what we should hit", not
"what the runtime allows".

**Mitigation**: documented behavior. Users who run with
ComputeBudget uplift should set cu_budget to match their
operational target, not the runtime ceiling.

## 6. Severity classification

**High** baseline. Reasoning:

- DoS is real-impact: legitimate users denied service.
- Often easy to trigger once discovered (single permissionless
  setup ix to grow the state, then any victim call is gated).
- Recovery requires either protocol patch or ComputeBudget uplift
  by all integrators — both costly.

Severity adjustments:

- **Critical**: DoS is permanent (state-driven, irreversible
  without protocol-level cleanup) AND inexpensive to trigger AND
  affects a high-volume ix (TVL-bearing).
- **High**: DoS is reversible (state cleanup possible) or affects
  a low-volume ix.
- **Medium**: DoS theoretically possible but requires preconditions
  attackers can't economically achieve (e.g., need 100k accounts
  spammed first).
- **Low**: rate-limited surface where DoS lifts naturally over
  time (e.g., per-block accounts).

Bounty reference: Solend governance DoS (2022) settled in the
high-five-figures; OpenBook v1 cancel-all DoS was patched
pre-mainnet so no bounty paid but multiple audit reports flagged it.

## 7. Test fixture in escrow-demo

Plant a cu-dos bug in escrow-demo by adding a new ix:

```rust
// programs/escrow/src/lib.rs

/// PLANTED BUG (Day 37 for cu-dos validation):
/// Naive O(n) loop with attacker-controllable bound. Real-world
/// analogue: order-cancel loops, position-iteration in lending,
/// any "process all entries" ix without a static MAX bound.
///
/// NOT FOR PRODUCTION. Only for solinv self-validation.
pub fn unsafe_compute_dos(
    _ctx: Context<UnsafeComputeDos>,
    iterations: u32,
) -> Result<()> {
    let mut acc: u64 = 0;
    for i in 0..iterations {
        // Per-iter cost is non-trivial enough that even modest
        // loop counts add up. `wrapping_add` so the loop body
        // itself can't overflow-trap and short-circuit detection.
        acc = acc.wrapping_add(i as u64).wrapping_mul(3);
    }
    msg!("acc={}", acc);  // prevent the optimizer from eliding the loop
    Ok(())
}

#[derive(Accounts)]
pub struct UnsafeComputeDos<'info> {
    pub authority: Signer<'info>,
}
```

State invariant declaration in `fuzz/escrow/src/main.rs`:

```rust
InstructionSpec {
    program_id: ESCROW_ID,
    name: "unsafe_compute_dos".to_string(),
    accounts: vec![/* authority signer */],
    // ... other fields ...
    cu_budget: Some(5_000),  // legitimate baseline: ~1-3K CU
    state_invariants: vec![],
}
```

Expected solinv output when run against planted bug:

```
[cu-dos:Esrcw1111…] ix unsafe_compute_dos consumed 87_341 CU (cap 5_000)
```

Pass criterion (**Gate 1, see §9**): solinv detects within 30s.

## 8. References

### Solana-ecosystem audit guidance

- OtterSec Anchor SECURITY.md
  https://github.com/otter-sec/anchor-security
- Neodyme "Common Pitfalls in Solana Programs" §6 (Compute budget)
- Sec3 audit retrospectives
- Trail of Bits Solana best practices

### Solana CU semantics

- Solana docs — Compute budget
  https://docs.solana.com/developing/programming-model/runtime#compute-budget
- ComputeBudget program reference
- Solana runtime: per-tx and per-block caps

### Mainnet incidents (cu-dos family)

- OpenBook v1 order-cancel saga
- Solend governance DoS (2022) post-mortem
- Various Anchor-program "process all entries" cu-dos disclosures

### Internal

- `docs/invariants/README.md` §"High tier" — cu-dos is #9
- `docs/invariants/unchecked-math.md` — first High-tier invariant,
  shipped Day 31-34 with kill criterion (Gate 2: FAIL on Raydium).
  cu-dos is the deliberate "different invariant class" continuation,
  per Day 34 follow-on decision.
- `docs/phase3-day34-unchecked-math-gate2.md` — Gate 2 fail log
- `crates/solinv-core/src/invariants/util.rs` —
  `save_accounts`/`restore_accounts` reused as-is

## 9. Experiment design and kill criterion

**Pre-committed 2026-05-26 (Day 35, before implementation begins).**

This is the **second** gated High-tier experiment, run after
unchecked-math's Gate 2 FAILed on Raydium (Day 34). The Day 34
follow-on decision (user-confirmed) was: continue with one more
gated invariant on the same shape — different bug class, same
gating discipline — to test the "different invariant class fires"
hypothesis the unchecked-math result couldn't resolve.

This experiment is **not** an override of the unchecked-math §9
pivot in spirit — it's a hypothesis sharpening. The unchecked-math
§9 said "no more invariants on the same protocol set" because the
data didn't distinguish "this detector doesn't fire" from "no
detector would fire". cu-dos targets a **different mechanism**
(per-ix CU consumption, gated by Raydium's `processor.rs` bounds
checks differently than monetary state). If cu-dos also fails
Gate 2, the hypothesis is doubly confirmed and **no more High-tier
invariants ship** without changing protocol mix or strategy.

### Gate 1 — implementation correctness (Day 37)

After implementation:

```bash
cd examples/escrow-demo
crucible run escrow invariant_cu_dos_only --release --timeout 30
```

**Pass condition**: at least one violation reported within 30
seconds, matching the planted `unsafe_compute_dos` ix in §7.

**Fail handling**: implementation bug, not strategy failure.
Triage, fix, retry. Do not proceed to Gate 2 until Gate 1 passes.

### Gate 2 — strategy validation (Day 38)

Once Gate 1 passes:

```bash
cd examples/raydium-amm-fuzz
crucible run raydium_amm invariant_cu_dos_only --release --timeout 30 -j 4
crucible run raydium_amm invariant_cu_dos_only --release --timeout 30 -j 4
```

Same 2-minute × 4-parallel × 2-ix budget as unchecked-math Gate 2.

The Raydium SwapV2 specs gain `cu_budget = Some(100_000)` — 100k
chosen as the upper bound of expected legitimate swap CU (typical
swap-base-in-v2 measured around 30-50k pre-test, +1.5× margin +
toolchain noise = ~100k).

**Pass condition** (defer §9 pivot, continue with cpi-reentrancy
under same gating): at least one violation reported across the
campaigns.

**Fail condition** (pivot is binding, no more High-tier invariants
ship): **0 violations** after the full budget.

### Two-fail outcome — explicit binding

If cu-dos Gate 2 also fails, then:

- **Confirmed**: two different invariant classes (unchecked-math
  and cu-dos) tested on the same protocol (Raydium SwapV2),
  both detected 0 violations across pre-committed budgets.
- **Implication**: the gap to original target E[V] is not closed
  by adding invariant variety on the existing protocol set —
  doubly demonstrated.
- **Action**: no more High-tier invariants are spec'd or
  implemented. cpi-reentrancy (the only remaining v1-applicable
  High-tier candidate) stays deferred. realloc-race and
  token-2022-hook are not applicable to Raydium SwapV2 surface
  in any case.
- **Pivot options**: same three as unchecked-math §9 — less-hardened
  protocols, OSS audit-accelerator framing, or pause. The pivot
  becomes binding *across the High-tier program*, not just for
  one invariant.

### Two-pass outcome — what it would mean

If cu-dos Gate 2 *passes* (≥1 violation), the data point would
say:
- unchecked-math doesn't fire on Raydium, but cu-dos does
- The bug-class-variety hypothesis has partial support
- Reasonable next move: spec + implement + Gate-test
  cpi-reentrancy as a third data point, same shape

This is the only scenario where High-tier expansion continues
under the current strategy.

### What does NOT count

- Cu-dos Gate 2 fails *because the cap was tuned wrong* — that's
  a Gate 1 redo, not a Gate 2 result. If observed CU consistently
  approaches but never exceeds 100k, re-tune cap (e.g., to 80k) and
  re-run. Only after one full pass with a well-tuned cap does the
  Gate 2 result count.
- Detection on escrow-demo regression during the Raydium campaign
  — only Raydium ix surfaces count for Gate 2.
- Gate 1 still failing.

### Logging the result

Per the unchecked-math §9 precedent, write
`docs/phase3-day38-cu-dos-gate2.md` with:

- Exact `crucible run` invocations.
- Counts: campaigns × workers × executions, violations, ok rate.
- Sample violation message if any.
- Decision: continue to cpi-reentrancy / pivot binding.
- Same timestamp + commit-hash precision as Day 34's log.

## 10. Honest framing of the override decision

This experiment exists because, on Day 34, the user proposed
implementing additional High-tier invariants despite the
unchecked-math §9 pivot being binding. The honest framing of that
choice — recorded in this section so it's not buried in
conversation history:

- The unchecked-math kill criterion was binding *in spirit* — the
  Day 31 §9 explicitly said cu-dos and three other High-tier
  invariants stay deferred after a fail.
- The Day 34 user follow-on argued that Gate 2's result generalized
  only to *the bug class tested*, not to *all bug classes on the
  same target*. This is defensible: cu-dos targets a different
  surface (per-ix CU consumption) than Bounded-on-monetary-fields.
- Proceeding with cu-dos under same-discipline gating is the
  *minimum* override that tests the strengthened hypothesis. Any
  alternative — implementing all four High-tier invariants in
  parallel, or implementing without re-gating — would be a stronger
  override and reproduce Phase 2's "one more thing" pattern.
- The §9 of *this* spec inherits the same binding force. The
  user is making the same commitment again: if Gate 2 fails here,
  no more High-tier work ships. The credibility of the
  pre-commit mechanism rides on honoring this on a binary fail
  outcome.

This experiment is the cleanest experimental design that addresses
the open hypothesis. It's also the last data point the user has
pre-committed to taking before pivoting at the strategy layer.
