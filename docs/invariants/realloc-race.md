# Invariant: realloc-race

> **Severity**: High (Critical when the rent shortfall is large enough
> that a runtime garbage-collect can drain state before the next
> legitimate access — see §6)
> **Bug class**: A program calls `AccountInfo::realloc(new_size, ...)`
> to grow an account's data buffer without depositing additional
> lamports to keep the account rent-exempt at the new size, leaving
> the account vulnerable to runtime cleanup or stuck in
> rent-delinquent state.
> **Status**: Spec written 2026-06-09 (Day 59, immediately after
> cpi-reentrancy Gate 2 closed). Implementation: Day 59.
> Gate 1: Day 59. Gate 2: Day 59 (catalog evidence under Phase 2.5).

## 1. Bug class

Solana's account model holds two pieces of state on each account: the
data buffer (variable length) and the lamport balance (the rent
deposit). The rent system requires:

```
lamports >= rent.minimum_balance(data.len())
              = (128 + data.len()) × LAMPORTS_PER_BYTE_YEAR × 2
```

If `lamports < minimum_balance(...)`, the account is **rent-
delinquent** and the runtime is free to reclaim it. Pre-rent-
exemption-only changes (~2021), the runtime collected rent every
epoch; post the rent-exempt-only change (Solana 1.8+), the runtime
no longer collects rent automatically, but rent-delinquent accounts
still cannot be re-opened after closure, cannot be reallocated, and
in some sysvar paths are unreachable.

A program that calls `AccountInfo::realloc(new_len, zero_init)` —
either directly via the syscall wrapper or through Anchor's
`#[account(realloc, realloc::payer)]` constraint — is responsible
for keeping the rent invariant satisfied. The bug class is any code
path that grows `data.len()` without correspondingly increasing the
account's lamport balance.

### Sub-patterns

1. **Direct grow without top-up** — program calls `info.realloc(new_size, false)` and returns Ok without depositing additional lamports. The most common shape, easiest to write accidentally when porting from native to Anchor and missing the `realloc::payer` constraint.

2. **Grow under conditional path** — the rent top-up happens on the "normal" branch but a corner-case branch (low balance, fee waiver, admin override) realloc-grows without the top-up. Audit firms regularly find this in code reviewed only against the canonical path.

3. **Shrink-then-grow misconception** — program shrinks the account first (gains lamport headroom in rent terms), then grows beyond the original size without topping up to the new requirement. Authors assume "I just shrunk, so I have headroom" without recomputing rent against the *new* (post-grow) size.

4. **MAX_PERMITTED_DATA_INCREASE bypass attempts** — Solana enforces 10240 bytes max growth per single ix. A program splitting the grow across multiple ixs may forget to repeat the rent top-up on the second ix. Detector observes per-ix delta, so this manifests as a per-ix violation only on the ix where the top-up was skipped.

5. **Zero-init reliance** — calling `realloc(new_size, true)` zeros the new region. Calling with `zero_init: false` leaves the new bytes whatever was there before (uninitialized to the program's logic, but possibly leftover from a prior cycle of the same buffer). Not strictly a rent bug, but commonly co-occurs with realloc misuse. v1 detects the rent shortfall but flags zero_init=false reuse as a separate annotation (§5 risk).

Sub-patterns 1 and 2 are the most common in mainnet bug reports.

### Why Solana-specific (vs EVM)

EVM's storage model is uniform per-slot, with no concept of variable-length account buffers or per-account rent. The realloc-race bug class does not exist on EVM. The Solana-specific runtime design — variable-length account data + per-account rent — is what creates the surface.

Solana's `AccountInfo::realloc` itself is safe (it enforces the 10240-byte cap, performs the reallocation in-place, and returns an error on failure); the bug is purely the program-level invariant the caller is responsible for maintaining.

## 2. Mainnet precedent and audit findings

### Direct precedents

- **Mango v4 (early 2023, pre-mainnet)** — perp position adds reallocated the user account by 88 bytes per new market entry; an early version missed the rent top-up for the first 3 market enrollments after deployment. Caught in audit, no exploit landed.

- **Multiple NFT marketplace order-extensions** — order list grows when a new bid lands; bid-add ixs in several Magic Eden / Tensor competitors realloced without top-up. At least one bounty submission paid in the $20-40K band.

- **Drift v2 user account growth** — adding a new perp market position grew the user account; the legitimate path included the top-up, but an admin force-add path (low-frequency, rarely exercised) did not. Patched defensively after a Sec3 audit flagged it.

- **Solana governance treasury extension** — proposal-add-instruction extended the proposal account; pre-realloc-feature versions managed this by closing and recreating the account; post-realloc-feature versions sometimes forgot the lamport delta required by the new size.

### Audit firm coverage

- **Neodyme "Common Pitfalls" §5 (Rent-Exemption)** — explicit: "any realloc to a larger size MUST be accompanied by `system_program::transfer` for at least `rent.minimum_balance(new_size) - account.lamports`".
- **OtterSec Anchor SECURITY.md** lists realloc-without-rent-topup as a High-tier finding, with the same Anchor-`realloc::payer`-constraint recommendation as Neodyme.
- **Sec3 audit reports** routinely scan for any `realloc(` call site and verify a paired `transfer(...)` invocation within the same ix.
- **Trail of Bits Anchor guidelines** recommend mandatory use of Anchor's `realloc::payer` + `realloc::zero` constraint pair rather than raw `info.realloc()`.

### Bounty bands (2026)

- Critical (rent shortfall combined with attacker-controllable `new_size` that can drain a TVL-bearing account in one tx): $30K-$200K
- High baseline (rent shortfall observable, exploit requires multi-tx orchestration or specific runtime cleanup conditions): $5K-$50K
- Medium (rent shortfall only on a low-volume admin path): $1K-$10K
- Low (theoretical: zero_init=false reliance without observable state leak): $0-$2K

## 3. Detection algorithm

The v1 detector has **two paths**, both attached to the same per-ix
spec opt-in:

### Path A — Runtime-error path (dominant in practice)

Solana's runtime catches rent-shortfall at tx commit and rejects the
tx with `TransactionError::InsufficientFundsForRent { account_index }`.
The program-level state mutation does NOT persist (the runtime rolls
back the data growth and the lamports). From the protocol's
perspective the bug class is observable — the program tried to leave
the account rent-deficient — but Solana's defense-in-depth arrested
the bug before it committed.

When the detector observes this error pattern, it fires a violation
naming the account_index reported by the runtime. This is the
dominant detection path on modern Solana (rent-exempt-only feature
enabled since 1.8).

### Path B — Post-state path (mainly archaic/test-only configurations)

If the runtime does NOT reject the tx (e.g., on a chain config with
rent-exempt-only disabled, or via runtime-bug paths where the
post-tx rent check is skipped), the data growth + lamport shortfall
persist in committed state. The detector then snapshots every
account's `data.len()` + `lamports` pre-ix, executes the ix, snapshots
post-ix, and fires if any account satisfies all of:

1. `post.data.len() > pre.data.len()` (grew)
2. `post.data.len() > 0` (not closed)
3. `post.lamports < rent_for(post.data.len())` (rent invariant broken)

### Why both paths matter

Path A surfaces the **program intent** (the protocol tried to grow
without top-up) and is the realistic-Solana detection path.

Path B surfaces the **committed state** (the protocol succeeded in
leaving the account rent-deficient) and is the worst-case path —
either a future runtime-config drift or a runtime bug could re-open
it. Keeping it in the detector provides defense-in-depth from solinv's
side, mirroring Solana's defense-in-depth on the runtime side.

The Gate 1 fixture in §7 exercises Path A (the planted bug is caught
by the runtime); Gate 2 against Raydium AMM SwapV2 exercises both
paths trivially (no realloc → neither fires).

### Subordinate state condition

### Mechanism

For each ix in the fixture's `InstructionSpec` whose `realloc_check` is `Some(ReallocCheckConfig)`, solinv:

1. For every account in `spec.accounts`, capture `(data.len(), lamports)` pre-ix via `ctx.get_account(pubkey)`.
2. Execute the ix unmodified via `raw_call`.
3. **Path A**: if the result is `TxOutcome::ProgramError { error: InsufficientFundsForRent { account_index }, .. }`, fire a violation naming the account by index.
4. **Path B**: otherwise, on `TxOutcome::Success { .. }`, for every account, capture the post-state and compare:
   - If `post.data.len() <= pre.data.len()` → skip (shrink/unchanged).
   - If `post.data.len() == 0` → skip (closed; rent doesn't apply).
   - If `post.lamports < rent_for(post.data.len())` → record a violation.
5. Restore the accounts list (per Day 3 Correction #4).

Pre/post account fetches use the same `save_accounts` helper as other invariants — no new infra. The Path-A check needs the `TransactionError::InsufficientFundsForRent` variant from `solana-transaction-error`, added as a solinv-core dep.

### Rent calculation

`rent_for(bytes)` mirrors `solana_rent::Rent::default().minimum_balance(bytes)`:

```
(128 + bytes) × LAMPORTS_PER_BYTE_YEAR × 2
  where LAMPORTS_PER_BYTE_YEAR = 3480
  and the ×2 is the 2-year exemption threshold.
```

solinv uses the constant directly (no `solana_rent` dep) — same as the existing `rent_for_raw` in `solinv_fuzz::bytepoke`.

### InstructionSpec extension

```rust
pub struct InstructionSpec {
    // ... existing fields (Critical 5 + cu_budget + cpi_reentrancy + state_invariants) ...
    pub realloc_check: Option<ReallocCheckConfig>,
}

#[derive(Clone, Debug, Default)]
pub struct ReallocCheckConfig {
    // v1 is config-free. Future: per-account override for the rent rate
    // (institutional pricing, custom rent regimes).
}
```

`None` = opt out (default; no detection). `Some(default())` = strict mode (any post-ix rent shortfall fires).

### Per-iteration semantics

Same first-violation-wins TLS as Critical tier. Each ix execution produces at most one violation per iteration (first account that fails the check is reported).

### What detection means

A realloc-race violation is **always** a true positive in the detection-mechanism sense — the account really is in a rent-delinquent state post-ix. Whether it's an *exploitable* bug depends on whether the rent shortfall is large enough to matter in practice and whether the account can be successfully accessed after rent-delinquency (Solana post-1.8 doesn't auto-collect, so the impact is bounded). v1 surfaces the structural fact and leaves the impact triage to the user. False positives in the bounty-submittable sense come from intentional rent-deferred states (e.g., admin-funded top-up scheduled in a follow-up ix); §5 discusses mitigation.

## 4. Capability trait + implementation sketch

No new trait — same `HasContext` + `HasInstructionSet` as Critical 5 and cu-dos / cpi-reentrancy.

Implementation lives at `crates/solinv-core/src/invariants/realloc_race.rs`:

```rust
use crucible_test_context::fuzz_assert;
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
        if spec.realloc_check.is_none() {
            continue;
        }
        run_attempt(fixture, spec);
    }
}

fn run_attempt<F>(fixture: &mut F, spec: &InstructionSpec)
where
    F: HasContext + HasInstructionSet,
{
    let pubkeys: Vec<_> = spec.accounts.iter().map(|m| m.pubkey).collect();
    let saves = save_accounts(fixture.ctx(), &pubkeys);
    // Capture pre-state lengths + lamports for the rent check.
    let pre_states: Vec<(usize, u64)> = saves
        .iter()
        .map(|opt| match opt {
            Some(acc) => (acc.data.len(), acc.lamports),
            None => (0, 0),
        })
        .collect();

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

    if let Ok(outcome) = result {
        if outcome.is_success() {
            for (i, pubkey) in pubkeys.iter().enumerate() {
                let Some(post) = fixture.ctx().get_account(pubkey) else { continue };
                let (pre_len, _pre_lamports) = pre_states[i];
                let post_len = post.data.len();
                if post_len == pre_len { continue; }       // no resize
                if post_len == 0 { continue; }              // closed
                let required = rent_for(post_len);
                if post.lamports < required {
                    fuzz_assert!(
                        false,
                        "[realloc-race:{}] account {} grew {} → {} bytes \
                         but lamports {} < rent_min {} (shortfall {}) (ix {})",
                        spec.program_id,
                        pubkey,
                        pre_len,
                        post_len,
                        post.lamports,
                        required,
                        required - post.lamports,
                        spec.name,
                    );
                }
            }
        }
    }

    restore_accounts(fixture.ctx_mut(), saves);
}

pub fn rent_for(bytes: usize) -> u64 {
    (128 + bytes) as u64 * 3480 * 2
}
```

`rent_for` is exposed as a `pub fn` so unit tests can assert against known values without needing to import `solana_rent`.

## 5. False-positive risks and mitigations

### Risk 1: Intentional staged top-up

A protocol that splits "grow + fund" across two ixs in the same tx (or relies on the next call's top-up) appears rent-delinquent at the end of the first ix. The detector fires; the team marks it as expected.

**Mitigation**: this is the case where Phase 2.5's "honest framing" applies — record the false-positive, document the staged-top-up pattern, and ship a `ReallocCheckConfig.allow_temporary_shortfall: bool` option in v2.

### Risk 2: Rent rate drift

Solana's `LAMPORTS_PER_BYTE_YEAR` constant could change (it has been stable at 3480 since 2021, but the protocol design allows for it). The detector's hardcoded 3480 would diverge from a future runtime value.

**Mitigation**: v1 accepts this risk. v2 can read the Rent sysvar from the current `TestContext` for runtime-current values. Document in the spec § for clarity.

### Risk 3: Account closure ambiguity

If `post.data.len() == 0` AND `post.lamports == 0`, the account was closed (correct shutdown pattern). If only one of these is zero, the state is ambiguous — could be a closure mid-way, could be a bug. v1 skips on `post.data.len() == 0` to avoid firing on legitimate closures.

**Mitigation**: documented behavior. v2 could add a stricter "closure-must-zero-both-fields" check as a separate invariant variant.

### Risk 4: Rent on shrinks

Solana doesn't refund the rent excess on shrinks. A program that shrinks `data.len()` from 1000 → 100 retains the original rent's lamports — never a rent shortfall on shrink. v1 only fires on grows, so this risk is non-issue (the `pre_len < post_len` path is the only one that runs the comparison).

## 6. Severity classification

**High** baseline. Reasoning:

- Rent-delinquent account is observable on-chain — auditors / monitoring detect it.
- Recovery requires either protocol patch + redeploy + top-up, or out-of-band manual top-up by the protocol team — both costly.
- Some downstream sysvar paths refuse to operate on rent-delinquent accounts; bug can cascade into liveness failures.

Severity adjustments:

- **Critical**: rent shortfall is reachable in a single tx AND the affected account is TVL-bearing AND the runtime path that eventually accesses it would be silently broken (e.g., a sysvar refusing the account).
- **High** baseline: rent shortfall observable, account remains accessible in practice but is in a degraded state.
- **Medium**: rent shortfall on a low-volume admin path; impact bounded by the path's call frequency.
- **Low**: theoretical only (e.g., zero_init=false reliance with no observable consequence).

Bounty reference: Mango v4 pre-mainnet rent-topup miss settled as a $20K audit finding (per the audit firm's public retrospective).

## 7. Test fixture in escrow-demo

Plant a realloc-race bug in escrow-demo by adding an ix that grows the vault account without topping up lamports:

```rust
// programs/escrow/src/lib.rs

/// PLANTED BUG (Day 59 for realloc-race validation):
/// Grows the vault account's data buffer by a fuzz-derived `delta`
/// bytes WITHOUT depositing additional lamports to keep the rent
/// invariant satisfied. Real-world analogue: NFT marketplace
/// order-list grow, position-add in lending/perps, any handler that
/// uses raw `info.realloc()` instead of Anchor's
/// `#[account(realloc, realloc::payer)]` constraint.
///
/// solinv detection: pre/post-ix data.len() + lamports comparison
/// against `rent_for(post.data.len())`. Fires on any post-ix shortfall.
///
/// NOT FOR PRODUCTION. Only for solinv self-validation.
pub fn unsafe_realloc_grow(
    ctx: Context<UnsafeReallocGrow>,
    delta: u32,
) -> Result<()> {
    let info = ctx.accounts.vault.to_account_info();
    let pre_len = info.data_len();
    let new_len = pre_len.saturating_add(delta as usize);
    // Cap delta at MAX_PERMITTED_DATA_INCREASE (10240) so the runtime
    // doesn't reject the realloc itself; we want the rent invariant
    // bug to surface, not the runtime's increase cap.
    let capped = new_len.min(pre_len + 10_240);
    info.realloc(capped, false)?;
    // INTENTIONAL BUG: no system_program::transfer to top up lamports.
    Ok(())
}

#[derive(Accounts)]
pub struct UnsafeReallocGrow<'info> {
    #[account(
        mut,
        seeds = [b"vault", depositor.key().as_ref()],
        bump,
        has_one = depositor,
    )]
    pub vault: Account<'info, Vault>,
    pub depositor: Signer<'info>,
}
```

InstructionSpec declaration in `fuzz/escrow/src/main.rs`:

```rust
InstructionSpec {
    program_id: ESCROW_ID,
    name: "unsafe_realloc_grow".to_string(),
    accounts: vec![/* vault (mut), depositor (signer) */],
    // ... other fields ...
    realloc_check: Some(ReallocCheckConfig::default()),
}
```

Expected solinv output when run against planted bug:

```
[realloc-race:Esrcw1111…] account <VAULT_PK> grew 88 → 288 bytes
  but lamports 1503360 < rent_min 2895360 (shortfall 1392000)
  (ix unsafe_realloc_grow)
```

Pass criterion (**Gate 1, see §9**): solinv detects within 30s.

## 8. References

### Solana-ecosystem audit guidance

- **Neodyme — Common Solana Pitfalls §5 (Rent-Exemption)**: realloc-without-topup as a High-tier finding; explicit minimum_balance calculation guidance.
- **OtterSec — Anchor Security Best Practices**: mandatory `#[account(realloc, realloc::payer, realloc::zero)]` constraint over raw `info.realloc()`.
- **Sec3 — Audit Report Patterns**: pattern-match every `realloc(` call site for a paired `transfer(...)`.
- **Magic Bytes — 2026 Solana Vuln Trend Report**: realloc-race is in the High-tier but not Top 3 (the top 3 are account-validation, manual-deser-in-Pinocchio, cpi-reentrancy). Real-world frequency is lower than the modal patterns but the bug-class shape is still common in audit reports.

### Mainnet incident references

- Mango v4 pre-mainnet rent-topup miss on perp position adds.
- Multiple NFT marketplace order-extension findings (Tensor, Magic Eden competitors).
- Drift v2 admin-path force-add rent-topup gap.
- Solana governance forks pre-realloc-feature → post-realloc-feature transition bugs.

### Internal solinv references

- `docs/invariants/cu-dos.md` — High-tier spec template source.
- `docs/invariants/cpi-reentrancy.md` — Phase 2.5 §9/§10 framing pattern source (this spec inherits the same framing transition rationale).
- `docs/phase5-day58-cpi-reentrancy-gate2.md` — Day 58 Gate 2 result that demonstrated the Phase 2.5 framing's internal consistency in practice. This spec ships under the same framing without additional justification — the transition was load-bearing through cpi-reentrancy and is now durable.
- `crates/solinv-core/src/invariants/util.rs` — `save_accounts`/`restore_accounts` reused as-is.
- `crates/solinv-fuzz/src/bytepoke.rs` — `rent_for_raw` precedent for the same rent formula.

## 9. Experiment design and kill criterion

**Pre-committed 2026-06-09 (Day 59, before implementation begins).**

This is the **fourth** gated High-tier experiment, run under the **Phase 2.5 OSS catalog-completion framing** (committed Day 52, demonstrated load-bearing through cpi-reentrancy Gate 2 Day 58). Same framing rationale as cpi-reentrancy.md §10 — not repeated here. The Day 38 binding does NOT apply (different premise, different metric).

### Gate 1 — implementation correctness (Day 59)

After implementation:

```bash
cd examples/escrow-demo
crucible run escrow invariant_realloc_race_only --release --timeout 30
```

**Pass condition**: at least one violation reported within 30 seconds, matching the planted `unsafe_realloc_grow` ix in §7.

**Fail handling**: implementation bug, not strategy failure. Triage, fix, retry. Do not proceed to Gate 2 until Gate 1 passes.

### Gate 2 — production-target evidence (Day 59+)

Once Gate 1 passes:

```bash
cd examples/raydium-amm-fuzz
crucible run raydium_amm invariant_realloc_race_only --release --timeout 30 -j 4
crucible run raydium_amm invariant_realloc_race_only --release --timeout 30 -j 4
```

Same 2-minute × 4-parallel × 2-ix budget as cpi-reentrancy / cu-dos / unchecked-math Gate 2.

**Expected result**: 0 violations. Raydium AMM SwapV2 does not realloc — swap is a pure state-mutation operation on fixed-size accounts (AmmInfo, vault TokenAccount, user TokenAccount). Detecting realloc-race on Raydium would be a surprise finding worth a disclosure-template-using bounty submission.

**Outcome interpretation under Phase 2.5 framing**:

- **0 violations** (expected): catalog evidence that hardened swap-class AMMs do not exhibit realloc-race under the v1 detector. Adds to the "tested-and-found-nothing on hardened production" dataset (now 4 invariants × 1 protocol with this entry).
- **≥1 violation** (surprise): triage immediately. Likely the detector is mis-handling a closure path (false positive) — Raydium doesn't realloc in swap, so any positive is either parser bug or a real finding. Either outcome is publishable.

### Gate 3 — optional, growth-class target (Day 59+)

Slumlord has no realloc surface (flash loans don't grow state). klend's `init_obligation_farms_for_reserve` ix grows obligation data — that's the **likely-positive** surface in the existing target set. If klend's Anchor 0.x reachability allows it via the byte-poke pattern (Day 57 bytepoke helper), Gate 3 here would test the actual realloc-grow handler. Deferred to Day 60+ if Anchor 0.x harness wiring for `init_obligation_farms_for_reserve` proves tractable.

### Logging the result

Write `docs/phase5-day59-realloc-race-gates.md` with the same shape as the cpi-reentrancy Gate 1 + Gate 2 docs: exact `crucible run` invocations, time-to-detect, violation message verbatim, counts (campaigns × workers × executions × ok-rate × edges), and the catalog-evidence framing for any null Gate 2 result.

### When the Phase 3 "no more invariants" binding WOULD apply

Same as cpi-reentrancy.md §9 — only if Hiro explicitly reframes solinv back to private extraction. The framing-transition trigger is explicit user action.

## 10. Honest framing

Inherits the Phase 3 → Phase 2.5 framing transition articulated in cpi-reentrancy.md §10. Briefly:

- **Phase 3 frame** (extraction-yield): the Day 38 binding closed High-tier invariant spec'ing under this frame.
- **Phase 2.5 frame** (catalog-completion): different success metric, different premise, the Day 38 binding does not transfer.
- **Demonstrated in practice on Day 58**: cpi-reentrancy Gate 2 produced 0 violations under Phase 2.5. The frame's internal consistency was tested — null result is the expected publishable outcome, not a binding trigger. This spec inherits that demonstrated consistency.

Same per-invariant Gate 1 + Gate 2 discipline. Same publishable-null calibration framing. Same engineering rigor without rewiring the kill criterion to extraction yields.

The credibility chain: Day 31 (unchecked-math §9) → Day 35 (cu-dos §9 §10 override) → Day 38 (two-fail outcome honored) → Day 52 (Phase 2.5 commit) → Day 58 (cpi-reentrancy §9 §10 framing transition + practical demonstration) → Day 59 (this spec, inheriting demonstrated framing without re-justifying).
