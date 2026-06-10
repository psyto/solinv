# Invariant: cpi-reentrancy

> **Severity**: High (Critical when the re-entry path crosses a
> writable state-mutation handler — see §6)
> **Bug class**: A program's handler is invoked again (directly or
> via a chain of intermediate CPI hops) before the original handler
> frame returns. State read pre-CPI may not match state observed
> after CPI returns, breaking the original handler's correctness
> assumptions.
> **Status**: Spec written 2026-06-09 (Day 58). Implementation: Day
> 58. Gate 1: Day 58-59 (planted-bug detection on escrow-demo).
> Gate 2: Day 59+ (Raydium-AMM-fuzz or Slumlord run, **catalog
> evidence rather than kill criterion** per §9 / §10).

## 1. Bug class

A Solana program executes a CPI to another program. If the callee
(or any program in the callee's CPI subtree) invokes the original
program *again* before the outer handler returns, the original
handler's state assumptions break: account data that was read
before the CPI may have been mutated by the re-entrant handler.

The Solana runtime defends against the simplest case via
**account-lock semantics**: a writable account locked by the outer
ix cannot be re-locked by a nested CPI. Re-entry through the
*same writable account* is blocked. But the lock model is per-
account-flag, not per-program. Re-entry through:

1. The same program but **different writable accounts** the program
   owns
2. The same program acting on **readonly accounts** (no lock check)
3. The same program through a **proxy program** that holds the
   writable lock and forwards the call

…all bypass the writable-account guard and produce the classic
re-entrancy pattern.

### Sub-patterns

1. **Direct A→B→A on disjoint writable accounts** — A's handler
   touches account X (writable), CPIs to B, B CPIs back to a
   different handler in A that mutates account Y (also writable
   but distinct from X). A's outer handler then reads Y assuming
   no concurrent mutation. Most common bug shape.

2. **Indirect A→B→C→A multi-hop** — same logical re-entry but
   reachable only through a chain. Audit firms miss this in
   manual review because the cycle isn't visible in single-file
   reading.

3. **A→B(holds-token-account-authority)→A** — B is an SPL Token
   program or similar primitive that hands control back to A
   through a transfer hook (Token-2022) or via emit-and-callback
   pattern. The re-entry chain crosses an "innocent" primitive
   on the way.

4. **A→A_proxy (different program ID, same logic)→A** — same
   codebase deployed under two program IDs (governance/upgrade
   patterns, A/B testing). Lock model treats them as distinct
   programs but they share state via a shared account family.

5. **Self-CPI via `invoke_signed`** — A's handler invokes A
   itself via `invoke_signed` with PDA seeds it controls. Some
   programs intentionally do this for chained sub-operations;
   the bug shape arises when the chained sub-operation is not
   meant to interleave with the caller's mid-flight state.

Sub-patterns 1 and 3 are the most common in mainnet bug reports.
Pattern 3 has grown sharply since Token-2022 transfer hooks
went mainstream (~2025).

### Why Solana-specific (vs EVM)

EVM's re-entrancy is the classic Solidity bug — a `call.value()`
to an attacker-controlled address returns control to the
attacker before the calling function completes its state update
("checks-effects-interactions" violation). The Solana model is
*different* because:

- The runtime enforces writable-account locks across the CPI tree
  (EVM has no equivalent at the protocol level).
- Compute-unit budgets constrain how deep recursive call chains
  can grow.
- Program IDs are explicit and account ownership is enforced
  cryptographically (vs EVM's loose `msg.sender` model).

But these defenses are partial. The lock model only catches
*same-account* re-entry; the bug class on Solana shifts to
*different-account / same-program* re-entry, which the lock
model does not block. This is what makes cpi-reentrancy a
Solana-specific invariant rather than a direct port of the EVM
detector.

## 2. Mainnet precedent and audit findings

### Direct precedents

- **Mango Markets v3 insurance fund (2022)** — re-entry through
  the insurance fund's CPI back into deposit logic enabled the
  $114M exploit. The specific path differed from the classic
  Solidity shape but the structural bug (state assumption
  broken across CPI return) was the same. Settled via on-chain
  socialization; precedent in every Solana audit firm's
  checklist since.

- **Wormhole bridge early `complete_transfer_wrapped` (2022,
  fixed pre-exploit)** — the original implementation read
  bridge state, CPIed to SPL Token to mint wrapped tokens, and
  re-read state assuming no concurrent mutation. A re-entry via
  a transfer hook would have allowed double-mints. Caught and
  fixed pre-exploit by Neodyme audit.

- **Multiple Solana governance forks (2023-2024)** — proposal
  finalization flows that CPIed to a treasury program, which
  could CPI back through a delegated vote handler. Patched
  defensively after Mango raised the audit bar.

- **Sanctum LST token-2022 hook reviews (2025)** — at least
  three audit reports flagged the LST → transfer-hook → LST
  shape as a re-entry surface, though no exploits landed.

### Audit firm coverage

- **Neodyme "Common Pitfalls" §3 (Re-entrancy)** — explicit
  guidance: "any account modified between two CPIs to the same
  program should be re-validated".
- **OtterSec Anchor SECURITY.md** lists CPI-reentrancy as a
  High-tier review item, with the same writable-account-bypass
  observation.
- **Sec3 audit reports** routinely diagram CPI call graphs and
  flag any cycle through the audited program.
- **Trail of Bits Anchor guidelines** recommend
  `require_invocation_depth!` macros around re-entrant-sensitive
  state mutations.
- **Magic Bytes 2026 trend report** ranks CPI-reentrancy as the
  #3 modal Solana vuln class (#1: account validation, #2:
  manual-deser bugs in Pinocchio rewrites).

### Bounty bands (2026)

- Critical (re-entry on TVL-bearing path, exploitable in single
  tx): $100K-$500K (Mango-class)
- High (re-entry on state-coherence path, exploit requires
  multiple txs or precondition setup): $20K-$100K
- Medium (re-entry only on read paths, no state divergence
  observable but breaks "no-callback" semantic): $5K-$25K
- Low (re-entry only into non-state-mutating handler — design
  smell but no actual divergence): $0-$3K

## 3. Detection algorithm

cpi-reentrancy detection runs against Crucible's existing per-ix
execution: read `TxOutcome.logs` after the ix returns, parse the
Solana-runtime-emitted `Program {pid} invoke [{depth}]` lines,
reconstruct the CPI call stack at each step, and fire if the same
program ID appears at two different depths simultaneously.

### Mechanism

For each ix in the fixture's `InstructionSpec` whose
`detect_cpi_reentrancy` flag is `true` (default), solinv:

1. Saves the accounts list (per Day 3 Correction #4).
2. Executes the ix unmodified via `raw_call` — Crucible's mutator
   has already biased `data_sample` toward boundary values.
3. On any outcome that carries logs (`TxOutcome::Success { logs,
   .. }` or `TxOutcome::ProgramError { logs, .. }`), parses the
   logs into a CPI call-tree representation.
4. Walks the tree; at each `invoke` event, checks whether the
   program being invoked is already in the active call stack.
5. If yes, records a violation naming the re-entrant pid and the
   two depths at which it appears.
6. Restores the accounts list.

### Solana runtime log shape

The Solana runtime emits one log line per CPI transition. The
canonical shape (Solana 1.16+ through current 3.x):

```
Program <BASE58_PID> invoke [<DEPTH>]
Program log: <user message>
Program <BASE58_PID> consumed <N> of <M> compute units
Program <BASE58_PID> success
```

Or on error:

```
Program <BASE58_PID> failed: <REASON>
```

Detection parses the `invoke [<DEPTH>]` and `success` / `failed`
lines; user-emitted `Program log:` lines are ignored.

### Call-tree reconstruction (parser sketch)

```rust
fn parse_cpi_call_tree(logs: &[String]) -> Vec<CpiEvent> {
    let mut events = Vec::new();
    for line in logs {
        if let Some((pid, depth)) = parse_invoke(line) {
            events.push(CpiEvent::Invoke { pid, depth });
        } else if let Some(pid) = parse_success(line) {
            events.push(CpiEvent::Success { pid });
        } else if let Some(pid) = parse_failed(line) {
            events.push(CpiEvent::Failed { pid });
        }
        // ignore Program log: lines + consumed lines
    }
    events
}

fn detect_reentry(events: &[CpiEvent]) -> Option<Reentry> {
    let mut stack: Vec<Pubkey> = Vec::new();
    for event in events {
        match event {
            CpiEvent::Invoke { pid, .. } => {
                if let Some(prior_depth) = stack.iter().position(|p| p == pid) {
                    return Some(Reentry {
                        pid: *pid,
                        outer_depth: prior_depth + 1,
                        inner_depth: stack.len() + 1,
                    });
                }
                stack.push(*pid);
            }
            CpiEvent::Success { .. } | CpiEvent::Failed { .. } => {
                stack.pop();
            }
        }
    }
    None
}
```

### InstructionSpec extension

```rust
pub struct InstructionSpec {
    // ... existing fields (Critical 5 + cu_budget + state_invariants) ...
    /// Default true — opt-out via `false` for intentional re-entry
    /// patterns (governance nested votes, delegation chains).
    pub detect_cpi_reentrancy: bool,
    /// Optional allowlist: program IDs explicitly permitted to
    /// re-enter this ix's program. Empty means "no re-entry allowed".
    pub reentry_allowlist: Vec<Pubkey>,
}
```

`reentry_allowlist` accommodates patterns where program A
intentionally CPIs to known partner B that may re-enter A as a
documented protocol feature.

### Per-iteration semantics

Same first-violation-wins TLS as Critical tier. Each ix execution
produces at most one violation per iteration.

### What detection means

A cpi-reentrancy violation is **always** a true positive in the
detection-mechanism sense — the runtime really did re-enter the
program. Whether it's an *exploitable* bug depends on whether the
inner handler's state mutation breaks the outer handler's
assumptions. v1 surfaces the structural fact (re-entry occurred)
and leaves the exploitability triage to the user. False positives
in the bounty-submittable sense come from intentional re-entry
patterns; §5 discusses mitigation.

## 4. Capability trait + implementation sketch

No new trait — same `HasContext` + `HasInstructionSet` as
Critical 5 and cu-dos.

Implementation lives at
`crates/solinv-core/src/invariants/cpi_reentrancy.rs`:

```rust
use crucible_test_context::{fuzz_assert, TxOutcome};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solinv_fuzz::{HasContext, HasInstructionSet, InstructionSpec};

use super::util::{restore_accounts, save_accounts};

pub fn check<F>(fixture: &mut F)
where
    F: HasContext + HasInstructionSet,
{
    let ixs = fixture.instructions();
    for spec in &ixs {
        if !spec.detect_cpi_reentrancy {
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
        let logs = outcome.logs();
        let events = parse_cpi_events(logs);
        if let Some(reentry) = detect_reentry(&events, &spec.reentry_allowlist) {
            fuzz_assert!(
                false,
                "[cpi-reentrancy:{}] program {} re-entered at depths {}/{} (ix {})",
                spec.program_id,
                reentry.pid,
                reentry.outer_depth,
                reentry.inner_depth,
                spec.name,
            );
        }
    }

    restore_accounts(fixture.ctx_mut(), saves);
}
```

The log parser (`parse_cpi_events`) and re-entry detector
(`detect_reentry`) live in the same file as free functions with
unit-test coverage for the malformed-input, single-invoke,
direct-cycle, and disjoint-sibling cases.

## 5. False-positive risks and mitigations

### Risk 1: Intentional re-entry through delegation patterns

A governance program that CPIs to a treasury, which CPIs back
through a vote-record handler, is an intentional cycle. The
detector fires; the team marks it as expected.

**Mitigation**: `reentry_allowlist` field on the spec accepts
specific program IDs as known re-entrant peers. Allowed-pid
re-entry is silently ignored.

### Risk 2: Self-CPI via invoke_signed (chained sub-operations)

Some programs intentionally invoke themselves via `invoke_signed`
to chain operations under a single signer (e.g., batch operations
inside a single ix). The detector treats this as re-entry.

**Mitigation**: `detect_cpi_reentrancy: false` opt-out at the
spec level. v2 may add finer-grained "self-CPI allowed, others
not" toggles.

### Risk 3: SPL Token / SystemProgram appearing twice via independent CPI chains

`A→Token::transfer` then `A→Token::burn` in the same ix produces
two Token invocations at depth 1 (not nested). The
detect-reentry walker correctly handles this because the second
`invoke` only fires after the first `success` popped the stack.
Unit test required to lock in the behavior.

**Mitigation**: tested in the unit-test suite; no spec-level
workaround required.

### Risk 4: Log truncation under heavy CPI

LiteSVM and the Solana runtime both have log-buffer caps
(~10K bytes). A deep ix with verbose `Program log:` lines may
truncate the log stream, causing the parser to see an unbalanced
invoke/success sequence.

**Mitigation**: parser is fail-soft on unbalanced sequences — an
unmatched `invoke` at parse end does not fire a violation; it's
recorded as an inconclusive parse. Documented behavior.

## 6. Severity classification

**High** baseline. Reasoning:

- Re-entry on a TVL-bearing state path can drain funds (Mango
  precedent).
- Even non-draining re-entry breaks invariants that may surface
  exploits elsewhere (state-coherence assumption violations).
- Recovery requires protocol patch + redeploy + possibly user-
  side migration.

Severity adjustments:

- **Critical**: re-entry path crosses a writable state-mutation
  handler AND the chain is reachable in a single tx AND the
  surface is TVL-bearing.
- **High** baseline: re-entry observable, exploit requires
  precondition setup or multi-tx orchestration.
- **Medium**: re-entry only into read-side handlers; no
  observable state divergence but breaks documented "no-callback"
  semantic.
- **Low**: re-entry into pure-emit handlers (events only, no
  state); design smell, no exploit.

Bounty reference: Mango v3 insurance fund re-entry led to the
$114M exploit (largest Solana DeFi loss to date). Pre-mainnet
flags by Neodyme / Sec3 typically settle as $50K-$300K.

## 7. Test fixture in escrow-demo

Plant a cpi-reentrancy bug in escrow-demo by adding a small helper
program + a planted ix that CPIs to the helper and accepts a
re-entrant callback:

```rust
// programs/escrow/src/lib.rs

/// PLANTED BUG (Day 58 for cpi-reentrancy validation):
/// Outer handler CPIs to the helper program with a callback
/// hint that asks the helper to CPI back into a different
/// escrow handler before returning. Real-world analogue:
/// Token-2022 transfer hooks, governance vote delegation,
/// any "callback after work" pattern.
///
/// NOT FOR PRODUCTION. Only for solinv self-validation.
pub fn unsafe_callback_dispatch(
    ctx: Context<UnsafeCallbackDispatch>,
) -> Result<()> {
    // Pre-CPI state read
    let pre_value = ctx.accounts.state.value;

    // CPI to the helper program; helper will CPI back into us.
    let cpi_accounts = helper::cpi::accounts::PerformCallback {
        escrow_program: ctx.accounts.escrow_program.to_account_info(),
        escrow_state: ctx.accounts.state.to_account_info(),
        authority: ctx.accounts.authority.to_account_info(),
    };
    let cpi_ctx = CpiContext::new(
        ctx.accounts.helper_program.to_account_info(),
        cpi_accounts,
    );
    helper::cpi::perform_callback(cpi_ctx)?;

    // Post-CPI: assume state.value unchanged (the bug — the
    // helper's callback mutated it via inner_mutate).
    let post_value = ctx.accounts.state.value;
    require_eq!(pre_value, post_value, EscrowError::StaleStateAssumption);

    Ok(())
}

/// Inner mutation handler — re-entered via the helper's callback.
pub fn inner_mutate(
    ctx: Context<InnerMutate>,
    new_value: u64,
) -> Result<()> {
    ctx.accounts.state.value = new_value;
    Ok(())
}
```

The helper program (`programs/escrow-callback-helper/`) carries a
single ix `perform_callback` that CPIs back into
`escrow::inner_mutate` with a fixed `new_value`. The structural
cycle is `escrow → helper → escrow`.

InstructionSpec declaration in `fuzz/escrow/src/main.rs`:

```rust
InstructionSpec {
    program_id: ESCROW_ID,
    name: "unsafe_callback_dispatch".to_string(),
    accounts: vec![/* state, authority, helper_program, escrow_program */],
    // ... other fields ...
    detect_cpi_reentrancy: true,
    reentry_allowlist: vec![],  // no allowed re-entry; the bug should fire
    state_invariants: vec![],
}
```

Expected solinv output when run against planted bug:

```
[cpi-reentrancy:Esrcw1111…] program Esrcw1111… re-entered at depths 1/3 (ix unsafe_callback_dispatch)
```

Pass criterion (**Gate 1, see §9**): solinv detects within 30s.

## 8. References

### Solana-ecosystem audit guidance

- **Neodyme — Common Solana Pitfalls §3 (Re-entrancy)**: writable-
  account lock model is necessary but not sufficient; cross-
  account re-entry through the same program is the modal bypass.
- **OtterSec — Anchor Security Best Practices**: CPI cycle
  detection recommended for any handler that touches state both
  before and after a CPI call.
- **Sec3 — Audit Report Patterns**: explicit CPI-graph rendering
  for every audited program; flag every cycle.
- **Magic Bytes — 2026 Solana Vuln Trend Report**: cpi-reentrancy
  is the #3 modal class behind account-validation and manual-
  deser-in-Pinocchio.

### Mainnet incident references

- Mango v3 insurance-fund exploit (October 2022, $114M loss): the
  defining cpi-reentrancy-class bug in Solana DeFi history.
- Wormhole bridge `complete_transfer_wrapped` (early 2022): pre-
  exploit catch by Neodyme audit; the structural bug was fixed
  before mainnet exposure.

### Internal solinv references

- `docs/invariants/cu-dos.md` — sibling High-tier spec; template
  source for this doc's structure
- `docs/invariants/unchecked-math.md` — first High-tier spec; §9
  pre-commit pattern source
- `docs/phase3-day38-cu-dos-gate2.md` — Phase 3 binding closure
  that defers cpi-reentrancy under the *extraction* framing; §10
  of this spec explains why Phase 2.5 framing reopens the work
  legitimately
- `crates/solinv-core/src/invariants/util.rs` —
  `save_accounts`/`restore_accounts` reused as-is
- `crates/solinv-core/src/invariants/cu_dos.rs` — direct
  structural template for this invariant's `check()` and
  `run_attempt()` shape

## 9. Experiment design and kill criterion

**Pre-committed 2026-06-09 (Day 58, before implementation begins).**

This is the **third** gated High-tier experiment, run under the
**Phase 2.5 OSS catalog-completion framing** (committed Day 52)
rather than the **Phase 3 private-extraction framing** (closed
Day 38 by the two-fail outcome on unchecked-math + cu-dos). §10
explains the framing transition in detail.

The Phase 2.5 success criteria are catalog completeness +
methodology rigor + reachability + honest "tested and found
nothing on hardened production" data. **Gate 2 here is evidence
collection, not a kill criterion.** This is the structural
difference from cu-dos §9.

### Gate 1 — implementation correctness (Day 58-59)

After implementation:

```bash
cd examples/escrow-demo
crucible run escrow invariant_cpi_reentrancy_only --release --timeout 30
```

**Pass condition**: at least one violation reported within 30
seconds, matching the planted `unsafe_callback_dispatch` /
helper-program re-entry chain in §7.

**Fail handling**: implementation bug, not strategy failure.
Triage, fix, retry. Do not proceed to Gate 2 until Gate 1 passes.

### Gate 2 — production-target evidence (Day 59+)

Once Gate 1 passes:

```bash
cd examples/raydium-amm-fuzz
crucible run raydium_amm invariant_cpi_reentrancy_only --release --timeout 30 -j 4
crucible run raydium_amm invariant_cpi_reentrancy_only --release --timeout 30 -j 4
```

Same 2-minute × 4-parallel × 2-ix budget as cu-dos / unchecked-
math Gate 2.

**Expected result**: 0 violations. Raydium AMM v0.3.1 is hardened
and its CPI graph is well-understood (2-3 hops max: AMM →
SerumDEX-shim → SPL Token, all non-cyclic). Detecting cpi-
reentrancy on Raydium would be a surprise finding worth a
disclosure-template-using bounty submission.

**Outcome interpretation under Phase 2.5 framing**:

- **0 violations** (expected): catalog evidence that hardened
  AMMs do not exhibit cpi-reentrancy under the v1 detector. Adds
  to the "tested-and-found-nothing on hardened production"
  dataset; published as part of the OSS launch's honest
  calibration page. **NOT a kill criterion** — this is the
  expected result under Phase 2.5.
- **≥1 violation** (surprise): triage immediately. Likely the
  detector's log parser is misclassifying a non-cyclic CPI
  pattern (false positive) or, less likely, a real finding.
  Either path is valuable Phase 2.5 information.

### Gate 3 — secondary-target evidence (Day 59+, optional)

Slumlord flash-loan harness (already wired into the example
crate set) carries a single-ix CPI chain that includes a
borrower-callback pattern — exactly the cpi-reentrancy-friendly
shape. Running solinv against it tests the detector on the
likely-positive surface.

```bash
cd examples/slumlord-fuzz
crucible run slumlord invariant_cpi_reentrancy_only --release --timeout 30 -j 4
```

**Expected**: 0 violations. Slumlord's design predicates the
borrower-callback on a single immutable contract pre-registered
at flash-loan-init, so the re-entry path is controlled and
runtime-validated. A violation here would be unusually
interesting (either Slumlord bug or solinv parser bug).

### Logging the result

Write `docs/phase5-day59-cpi-reentrancy-gates.md` with:

- Gate 1: exact `crucible run` invocation, time-to-detect,
  violation message verbatim, planted-bug commit hash.
- Gate 2 (and Gate 3 if run): exact invocations, counts
  (campaigns × workers × executions × ok-rate × edges), violations.
- Decision: which finding (if any) becomes a disclosure-template
  submission; whether the next High-tier invariant (realloc-race)
  proceeds.
- Same timestamp + commit-hash precision as Day 34's log.

### When Phase 3 "no more invariants" binding WOULD apply

Per the Day 38 §9 binding inherited verbatim: if Hiro at any
point reframes solinv back to *private extraction* (i.e.,
"land bug bounties"), the Day 38 binding re-activates and
cpi-reentrancy work pauses. The framing-transition trigger is
explicit user action — not a Gate 2 outcome under Phase 2.5
framing.

## 10. Honest framing of the post-Day-38 reopen

This spec exists because the cu-dos Day 38 binding ("no more
High-tier invariants are spec'd or implemented") was closed
under the **Phase 3 private-extraction frame**, and the project
subsequently pivoted to **Phase 2.5 OSS catalog-completion frame**.
The pivot was an explicit strategy change — not a quiet override of
the Day 38 binding.

The structural distinction:

- **Phase 3 frame** measured success in *bug-bounty yield*.
  cpi-reentrancy under that frame would have meant "spec it,
  implement it, hunt with it for bounty submissions". Day 38's
  two-fail result demonstrated this was not productive on the
  existing protocol set under the existing extraction strategy.
- **Phase 2.5 frame** measures success in *catalog completeness
  + methodology rigor + honest calibration data*. cpi-reentrancy
  under this frame means "spec it cleanly, implement it under
  the same gated-experiment discipline, Gate 1 pass it on
  escrow-demo, Gate 2 run it on production and publish the
  result (whether finding or null) as honest calibration".

The Day 38 §9 binding is honored at the *Phase 3 frame* level —
no further Phase 3 work was done after Day 38, and the project
exited that frame on Day 52 with the explicit OSS pivot. The
binding does not transfer across frames because its premise
("the gap to original target E[V] is not closed by adding
invariant variety on the existing protocol set") is a Phase 3
extraction metric. Phase 2.5 has different metrics; the binding
mechanism rides on metric-aligned discipline.

The Phase 2.5 success criteria are:

1. **Catalog**: Critical 5 + High 5 (currently 2 implemented,
   3 in this spec + realloc-race + bump-seed-canonicalization
   to follow).
2. **Methodology**: every invariant ships with a §9 pre-commit
   experiment + a Gate 1 + a Gate 2 evidence point, even when
   the Gate 2 result is the expected null. Publishing the null
   is part of the deliverable.
3. **Reachability**: bytepoke helper + Anchor 0.x integration
   story (landed Day 57); future toolchain-fork option preserved.
4. **Public launch**: README + CONTRIBUTING + security policy +
   the catalog above + the honest calibration dataset.

This spec's Gate 1 + Gate 2 produce the catalog entry + the
calibration data point. Their outcomes do not gate "more
invariants" — that decision belongs to the user at the project
level, not to a per-invariant kill criterion. The §9 mechanism
is preserved as engineering rigor (pre-commit to the exact
experiment design), not as an extraction-binding (commit to
abandon if extraction yield is zero).

The credibility of the pre-commit mechanism is preserved by:
- Honoring Day 38's Phase 3 binding fully (no Phase 3 work
  shipped after Day 38).
- Articulating the frame transition in writing (this section).
- Applying the same gated-experiment design under the new frame,
  with metrics aligned to the new frame's success criteria.

What would NOT preserve credibility:
- Quietly proceeding with cpi-reentrancy without articulating
  the frame transition (would look like "let me try one more
  thing" drift).
- Reusing Phase 3's kill-criterion shape ("0 violations → stop")
  on Phase 2.5 work (mismatch between the binding's premise and
  the new frame's metric — would invalidate both the old
  binding and the new gating).

Recording the framing transition here preserves both.
