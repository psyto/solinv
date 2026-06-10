# Invariant: unchecked-math

> **Severity**: High (Critical when overflow enables direct fund loss)
> **Bug class**: Arithmetic overflow / underflow / precision loss reaching protocol-tracked state
> **Status**: Spec written 2026-05-26 (Day 31). Implementation: Day 32-34. Detection validation: Day 35-36. Strategy gate: Day 37.

## 1. Bug class

A Solana program performs arithmetic on protocol-tracked monetary
state (balances, share counts, prices, fees, accrued interest) using
Rust primitives that wrap silently in release builds rather than
`checked_*` / `saturating_*` / explicit bounds checks. An attacker
crafts ix arguments or chains ix calls so the arithmetic wraps, and
the post-state holds a value that violates the protocol's intended
accounting (negative balance represented as `u64::MAX`-near, share
inflation, fee underflow).

### Rust arithmetic semantics, release builds

In standard release builds (default `overflow-checks = false`):

- `u64 + u64`, `u64 - u64`, `u64 * u64` **wrap** silently
- `u128` same
- `i64 / i128` wrap on `iX::MIN / -1` (the only signed-wrap case)
- `a / 0`, `a % 0` panic and abort the transaction
- `u64::pow` wraps

Anchor + the broader Solana ecosystem recommend `checked_*` (returns
`Option<T>` → `Err` on overflow) or `saturating_*` (clamps to bounds)
for all arithmetic on token amounts. Several mature projects set
`overflow-checks = true` in their release profile, which converts
wraps to runtime aborts; but this is opt-in and many programs don't.

`cargo build-sbf` honors the program's `Cargo.toml` profile settings —
solinv's unchecked-math detection must work on programs *without*
`overflow-checks = true` (the common case) and report cleanly on
programs *with* it (no false positives — overflow aborts are visible
as ix failures, no state mutation).

### Why Solana-specific (vs EVM)

Solidity uses `unchecked { … }` blocks for opt-in wrap arithmetic
since 0.8 (`SafeMath` was the prior idiom). The default is checked. In
Rust on Solana the default is the opposite: wrap unless the developer
opts in. So while the bug class exists in both ecosystems, the *base
rate* is meaningfully higher on Solana — the language defaults push
toward the bug rather than away from it.

### Three sub-patterns

1. **Pure overflow / underflow**: `balance -= amount` wraps when
   `amount > balance` → huge synthetic balance → attacker withdraws
   the synthetic amount. Most common pattern.
2. **Precision loss in multiply-then-divide**: `share = amount * total_supply / total_assets` truncates intermediate; with carefully
   crafted small `amount`, rounds to 0 shares but charges full asset.
   Inflation attack precursor. (Distinct from pure overflow — fits
   here because the fix is `mul_div_floor` / `mul_div_ceil` rather
   than `checked_mul + checked_div`.)
3. **Sign flip on cast**: `let amount_i64: i64 = amount_u64 as i64`
   where `amount_u64 > i64::MAX` produces a negative i64. PnL math
   then treats withdraw as deposit.

This spec covers all three under "unchecked-math" as a single
invariant family — detection mechanism is the same (state-transition
sanity check), just with different declarations.

## 2. Mainnet precedent and audit findings

### Direct precedents

- **Saber Stable Swap precision-loss (2021)** — multiply-then-divide
  ordering in `swap_to` allowed extracting more from the pool than
  the curve invariant should permit. ~$5M lost across operators
  before patch.
- **Wormhole token bridge (multiple)** — pre-the-$326M-exploit
  internal audits flagged several unchecked-math sites in token
  amount conversion across decimals.
- **Drift v1 collateral calc** — i64 cast bug allowed negative
  collateral to register as positive in PnL accounting; patched
  pre-v2 launch.
- **Marinade liquid staking (early 2022)** — share inflation via
  precision-loss in MSOL mint math.
- **Various Solana DeFi forks of OpenZeppelin patterns** that didn't
  translate `SafeMath` idioms to Rust `checked_*`.

### Audit firm coverage

- **OtterSec Anchor SECURITY.md** lists unchecked arithmetic under
  "High severity" — second tier behind account validation.
- **Neodyme "Common Pitfalls"** §3 — uses `vault.balance -= amount`
  as the canonical underflow example.
- **Sec3 audit reports** routinely flag missing `checked_*` calls.
- **Trail of Bits "Solana smart contract security best practices"** —
  recommends `overflow-checks = true` as a profile setting + manual
  `checked_*` audit.

### Audit firm bounty bands (2026)

- Critical (direct fund loss via overflow): $50K-$500K depending on
  protocol TVL
- High (state corruption via overflow without direct fund loss):
  $10K-$100K
- Medium (precision loss visible but bounded): $1K-$25K

## 3. Detection algorithm

Solinv's Critical 5 detect by mutating ix *inputs* and observing
*account validation failures*. Unchecked-math is fundamentally
different — the ix is well-formed; the bug is in how the program's
*arithmetic on state* responds to extreme but legal inputs. So
detection is by **state-transition invariant checking** rather than
input mutation alone.

### Mechanism

For each ix in the fixture's `InstructionSpec`, the user declares one
or more **state invariants** that the protocol's accounting requires
to hold. Solinv:

1. Captures the pre-image of each declared invariant (reads the
   referenced account fields).
2. Executes the ix (Crucible's fuzzer biases args toward boundary
   values — `0`, `1`, `u64::MAX`, `u64::MAX-1`, halves — using its
   existing mutator).
3. If the ix succeeded, captures the post-image and checks each
   invariant.
4. If any invariant is violated, records a violation with the field
   delta and the implicated invariant name.

### State invariant kinds

```rust
pub enum StateInvariantKind {
    /// Sum of (field) across (accounts) is unchanged by the ix
    /// (modulo `tolerance` for rounding / fee dust).
    SumConservation {
        field_offset: usize,
        field_size: usize,    // 8 for u64, 16 for u128
        tolerance: u64,
    },
    /// Field at (offset, size) in each declared account is non-
    /// decreasing (or non-increasing) over this ix. Catches
    /// monotonic counters that wrap.
    Monotonic {
        field_offset: usize,
        field_size: usize,
        direction: MonotonicDir,    // NonDecreasing | NonIncreasing
    },
    /// Field at (offset, size) stays within [min, max] post-ix.
    /// Catches wrap-to-near-MAX after underflow.
    Bounded {
        field_offset: usize,
        field_size: usize,
        min: u128,
        max: u128,
    },
}
```

### InstructionSpec extension

```rust
pub struct InstructionSpec {
    // ... existing 12 fields (Day 3 + Day 15) ...
    pub state_invariants: Vec<StateInvariant>,   // High-tier addition
}

pub struct StateInvariant {
    pub name: String,
    pub kind: StateInvariantKind,
    pub accounts: Vec<usize>,        // indices into spec.accounts
}
```

A program with `vault.amount` to be monotonic on a `compound_yield`
ix declares one StateInvariant; the bound check is automatic.

### Auto-fill story

- Anchor IDL doesn't provide enough information to auto-derive
  these — there's no metadata on which field is "balance" vs which
  is "config".
- Heuristic auto-fill (v2 stretch): scan `#[account]` structs for
  fields named `balance`, `amount`, `supply`, `total_*` and emit
  `Bounded` invariants with `[0, u64::MAX/2]` as the default range.
  Suppresses wrap signature (`u64::MAX-something`) without false-
  flagging legitimate near-MAX values. Not v1 scope.
- v1: user declaration, ~3-5 lines per ix.

### Per-iteration semantics

Same first-violation-wins TLS as Critical tier
(`crucible_test_context::record_violation`). Each ix execution
captures one violation message at most per iteration. Across a fuzz
campaign of N iterations targeting one ix with multiple declared
invariants, expect distinct violation messages as different code
paths fire.

## 4. Capability trait + implementation sketch

No new trait — `HasContext` + `HasInstructionSet` from Critical tier
suffice, since state-invariant data is carried inside
`InstructionSpec`.

Implementation lives at
`crates/solinv-core/src/invariants/unchecked_math.rs`:

```rust
use super::util::{hash_field, read_field_u128};
use solana_account::Account;

pub fn check<F>(fixture: &mut F)
where
    F: HasContext + HasInstructionSet,
{
    for spec in fixture.instructions() {
        for inv in &spec.state_invariants {
            run_attempt(fixture, &spec, inv);
        }
    }
}

fn run_attempt<F>(fixture: &mut F, spec: &InstructionSpec, inv: &StateInvariant)
where F: HasContext + HasInstructionSet
{
    // 1. Pre-image
    let pre: Vec<u128> = inv.accounts.iter()
        .map(|&i| read_field_u128(fixture.ctx(), &spec.accounts[i].pubkey, inv))
        .collect();

    // 2. Save accounts for restore
    let saves = save_accounts(fixture.ctx(), &spec.accounts);

    // 3. Execute ix via raw_call (mutator picks args; boundary biased)
    let result = exec_ix(fixture.ctx_mut(), spec);

    // 4. Post-image (only meaningful if ix succeeded)
    if result.is_ok() {
        let post: Vec<u128> = inv.accounts.iter()
            .map(|&i| read_field_u128(fixture.ctx(), &spec.accounts[i].pubkey, inv))
            .collect();

        if let Some(viol) = check_invariant(&inv.kind, &pre, &post) {
            record_violation(format!(
                "[unchecked-math:{}] ix {} violated state invariant '{}': {}",
                spec.program_id, spec.name, inv.name, viol));
        }
    }

    // 5. Restore
    restore_accounts(fixture.ctx_mut(), saves);
}

fn check_invariant(kind: &StateInvariantKind, pre: &[u128], post: &[u128])
    -> Option<String>
{
    match kind {
        StateInvariantKind::SumConservation { tolerance, .. } => {
            let pre_sum: u128 = pre.iter().sum();
            let post_sum: u128 = post.iter().sum();
            let drift = pre_sum.abs_diff(post_sum);
            (drift > *tolerance as u128).then(|| format!(
                "sum drifted by {} (pre {}, post {}, tolerance {})",
                drift, pre_sum, post_sum, tolerance))
        }
        StateInvariantKind::Monotonic { direction, .. } => {
            for (i, (p, q)) in pre.iter().zip(post.iter()).enumerate() {
                let bad = match direction {
                    MonotonicDir::NonDecreasing => q < p,
                    MonotonicDir::NonIncreasing => q > p,
                };
                if bad {
                    return Some(format!(
                        "account {} field {} {} (pre {}, post {})",
                        i, /* offset */ "?", direction.adverb(), p, q));
                }
            }
            None
        }
        StateInvariantKind::Bounded { min, max, .. } => {
            for (i, q) in post.iter().enumerate() {
                if q < min || q > max {
                    return Some(format!(
                        "account {} field out of bounds [{}, {}]: {}",
                        i, min, max, q));
                }
            }
            None
        }
    }
}
```

### Util additions

`crates/solinv-core/src/invariants/util.rs` gains:

```rust
pub(crate) fn read_field_u128(ctx: &TestContext, pk: &Pubkey,
    inv: &StateInvariant) -> u128 { /* read & widen */ }
```

Use the existing `save_accounts` / `restore_accounts` from Critical
tier — no new save/restore mechanics needed.

## 5. False-positive risks and mitigations

### Risk 1: Intentional wrapping arithmetic

Some programs use `wrapping_add` / `wrapping_mul` intentionally for
hash functions, RNG mixers, slot-modular indexing. State-invariant
declarations are per-account-field, so this is not a false-positive
risk in practice — solinv only checks fields the user declared as
monetary state, not arbitrary u64 fields.

**Mitigation**: documented in the declaration API docs — "declare
state invariants only on monetary fields, not on hash / RNG state".

### Risk 2: Legitimate fee accrual

`SumConservation` will fire when fees are deducted on transfer. Two
mitigations:

- `tolerance` parameter accommodates expected fee dust per call (set
  to max fee per ix).
- Add a third "fee_sink" account to the `accounts` list so the
  fee accumulates within the conserved sum.

### Risk 3: Rounding (precision loss)

Multiply-then-divide rounds toward zero. `SumConservation` with
`tolerance = 0` will fire on legitimate rounding. **This is correct
v1 behavior** — rounding loss IS a bug class we want to catch. v2
extension: distinguish "constant 1-wei drift per call" (legitimate
rounding) from "huge drift on edge inputs" (overflow signature) using
the rate of drift across iterations.

### Risk 4: Ix that legitimately mutates the declared field

A withdraw ix legitimately decreases `vault.amount`. Declaring
`Monotonic { direction: NonDecreasing }` on `vault.amount` for
*all* ix would false-positive on withdraw.

**Mitigation**: state invariants are per-ix, declared in each
`InstructionSpec`. The fixture author declares Monotonic on
`compound_yield` but Bounded on `withdraw`.

## 6. Severity classification

**High** baseline. Reasoning:

- Direct path to fund loss when the wrapped field is a balance.
- Routinely caught in audit; mainnet history shows multi-million-
  dollar precedents.
- Exploit complexity: low (single ix with crafted args), but requires
  knowing which field/op is vulnerable.

Severity adjustments:

- Wrapped field is a counter / metadata only → **Medium**.
- Wrapped field is a balance + ix is permissionless → **Critical**.
- Wrapped field is a balance but ix gated by admin → **High** with
  privilege-confused-deputy escalation noted.
- Precision-loss only (no overflow path, just rounding drift) → **Medium-Low**.

Bug bounty reference: when wraparound enables fund loss, this is
Critical-tier on Immunefi's Smart Contract scale ($50K-$500K). Pure
precision-loss without exploitable path is often dismissed as
"informational" by triage.

## 7. Test fixture in escrow-demo

Plant an unchecked-math bug in escrow-demo by adding a new ix:

```rust
// programs/escrow/src/lib.rs

/// PLANTED BUG (Day 32+ for unchecked-math validation):
/// Compound interest with naive arithmetic — wraps on overflow,
/// silently corrupting vault.amount.
///
/// NOT FOR PRODUCTION. Only for solinv self-validation.
pub fn unsafe_accumulate_yield(
    ctx: Context<UnsafeAccumulateYield>,
    rate_bps: u64,
) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    // BUG: u64 multiplication wraps; rate_bps near u64::MAX overflows.
    // Should use checked_mul + checked_div + explicit rate_bps bounds.
    let yield_amount = vault.amount * rate_bps / 10_000;
    vault.amount = vault.amount + yield_amount;       // ← also unchecked
    Ok(())
}

#[derive(Accounts)]
pub struct UnsafeAccumulateYield<'info> {
    #[account(mut, seeds = [b"vault", depositor.key().as_ref()], bump,
              has_one = depositor)]
    pub vault: Account<'info, Vault>,
    pub depositor: Signer<'info>,
}
```

State invariant declaration in `fuzz/escrow/src/main.rs`:

```rust
InstructionSpec {
    program_id: ESCROW_ID,
    name: "unsafe_accumulate_yield".to_string(),
    accounts: vec![/* vault, depositor */],
    // ... other fields ...
    state_invariants: vec![StateInvariant {
        name: "vault_amount_monotonic_on_yield".to_string(),
        kind: StateInvariantKind::Monotonic {
            field_offset: 8 /* disc */ + 32 /* depositor */ + 8 /* unlock_slot */,
            field_size: 8,
            direction: MonotonicDir::NonDecreasing,
        },
        accounts: vec![0],  // vault
    }],
}
```

Expected solinv output when run against planted bug:

```
[unchecked-math:Esrcw1111…] ix unsafe_accumulate_yield violated state
invariant 'vault_amount_monotonic_on_yield': account 0 field
non-decreased (pre 18446744073709551500, post 99)
```

Pass criterion (**Gate 1, see §9**): solinv detects within 30s.

## 8. References

### Solana-ecosystem audit guidance

- OtterSec Anchor SECURITY.md
  https://github.com/otter-sec/anchor-security
- Neodyme "Common Pitfalls in Solana Programs" §3 (Arithmetic)
  https://neodyme.io/blog/common-pitfalls/
- Sec3 audit retrospectives
  https://www.sec3.dev/
- Trail of Bits "Solana smart contract security best practices"
  https://github.com/trailofbits/publications

### Rust arithmetic semantics

- The Rust Reference, "Overflow"
  https://doc.rust-lang.org/reference/expressions/operator-expr.html
- `cargo` profile reference (`overflow-checks`)
  https://doc.rust-lang.org/cargo/reference/profiles.html#overflow-checks
- `std::primitive::u64` — checked / wrapping / saturating
  https://doc.rust-lang.org/std/primitive.u64.html

### Mainnet incidents (math family)

- Saber Stable Swap precision-loss post-mortem (2021)
- Wormhole bridge audits — unchecked arithmetic mentions across
  Trail of Bits / Neodyme audits
- Drift v1 → v2 migration notes on collateral i64 cast
- Marinade share inflation patch

### Internal

- `docs/invariants/README.md` §"High tier" — unchecked-math is #10
- `crates/solinv-core/src/invariants/util.rs` —
  `save_accounts`/`restore_accounts`/`hash_accounts` are reused as-is

## 9. Experiment design and kill criterion

**Pre-committed 2026-05-26 (Day 31, before implementation begins) to
reduce sunk-cost bias when results come in.**

This invariant is the first High-tier ship — also the test of whether
High-tier as a *strategy* moves Phase 3 E[V]. The Phase 2
retrospective revised E[V] from $140K to $60-80K and flagged that
"current scope is below threshold for the high-bounty extraction
strategy". This experiment tests one specific hypothesis: that the
gap is closed by *invariant variety* (more bug-class coverage on the
same protocols), not by *protocol variety* (more protocols with the
same invariants).

### Gate 1 — implementation correctness (Day 35-36)

After implementation lands:

```bash
cd examples/escrow-demo
crucible run escrow invariant_unchecked_math_only --release --timeout 30
```

**Pass condition**: at least one violation reported within 30 seconds
matching the escrow-demo planted bug from §7.

**If fail**: implementation bug, not strategy failure. Triage,
fix, retry. Do **not** roll forward to Gate 2 until Gate 1 passes —
moving on with a broken implementation would invalidate the strategy
data from Gate 2.

### Gate 2 — strategy validation (Day 37)

Once Gate 1 passes, run against Raydium AMM:

```bash
cd examples/raydium-amm-fuzz
crucible run raydium_amm invariant_unchecked_math_only --release --timeout 30 -j 4
crucible run raydium_amm invariant_unchecked_math_only \
    --release --timeout 30 -j 4   # second campaign for the second ix
```

Total budget: 2 minutes wall time across SwapBaseInV2 + SwapBaseOutV2,
4-way parallel.

**Pass condition** (continue High-tier expansion): at least one
violation reported. Even one finding on a hardened production target
is meaningful signal that High-tier invariants close the E[V] gap.

**Fail condition** (pivot, do not continue High-tier expansion):
**0 violations** after the full 2-minute budget across both ix.

### What "pivot" means concretely

If Gate 2 fails, do **not** proceed to spec/implement cu-dos,
realloc-race, token-2022-hook, cpi-reentrancy, or any other
High-tier invariant. The data from Gate 2 says additional invariants
on the existing protocol set don't move the needle. Instead choose
from:

1. **Less-hardened protocol targets**: scaffold one or two newer /
   smaller-TVL protocols (recent Solana DeFi launches, post-audit
   but not heavily bug-bountied yet) and rerun the existing
   Critical 5 + unchecked-math on those. Tests the protocol-variety
   hypothesis.
2. **OSS audit-accelerator framing**: pivot solinv from private
   the strategy framing from extraction-yield to OSS catalog
   completion — different success criteria, different gating.
3. **Pause and reassess**: Phase 1 + 2 outputs are durable.
   Reassess in 3-6 months after observable changes in Solana
   tooling landscape (Crucible roadmap, Trident upgrades, new
   protocol launches).

### What does NOT count as a successful Gate 2

- A violation that turns out to be a false positive after triage
  (e.g., legitimate rounding within tolerance). If the violation is
  a false positive, treat Gate 2 as fail and pivot.
- A violation on a non-Raydium target (e.g., escrow-demo regression
  during the Raydium campaign). Only Raydium ix surfaces count for
  Gate 2.
- Gate 1 still failing. Without Gate 1, Gate 2 results are noise.

### Logging the result

Whatever happens — Gate 1 pass, Gate 1 fail, Gate 2 pass, Gate 2
fail — write `docs/phase3-day37-unchecked-math-gate2.md` with:

- The exact `crucible run` invocations used
- The exact violation messages observed (or "none")
- The decision taken (continue / pivot / pause) with one-paragraph
  rationale
- A timestamp

Phase 3 must not slip into the same daily-shipping rhythm without
gate-checked decision points that Phase 2 partially did. This
section is the gate.
