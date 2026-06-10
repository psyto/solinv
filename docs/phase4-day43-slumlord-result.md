# Phase 4 Day 43 — Slumlord N=1 result

Date: 2026-05-26
Spec: Phase 4 protocol-variety stopping rule (2 protocol-size negatives close the axis).
Inventory: [docs/slumlord-ix-inventory.md](slumlord-ix-inventory.md)
Pre-fuzz estimate (Day 40): 0 violations across all 5 applicable invariants.
**Actual result: 0 violations across 5 invariants × 30s × 84,864 executions.**

## Result — clean negative

| Invariant | Executions | Crashes | exec/sec | ok rate | Edges |
|---|---|---|---|---|---|
| signer-skip | 15,611 | **0** | 518 | 49.4% | 444/2458 (18.1%) |
| owner-skip | 1,603 | **0** | 53 | 14.0% | 456/2458 (18.6%) |
| pda-forge | 4,349 | **0** | 145 | 24.6% | 456/2458 (18.6%) |
| unchecked-math | 47,808 | **0** | 1,593 | 99.1% | 356/2458 (14.5%) |
| cu-dos | 15,493 | **0** | 515 | 74.8% | 356/2458 (14.5%) |
| **Total** | **84,864** | **0** | — | — | — |

Plus the Day 42 combined smoke variant: 1,527 executions / 0 crashes.

Total Phase 4 N=1 budget consumed: 5 × 30s isolated + 30s smoke = **3 minutes wall time, 86,391 executions**.

## Invocations (per the Phase 4 plan §"Per-protocol contract")

```bash
cd examples/slumlord-fuzz
crucible run slumlord invariant_signer_skip_only    --release --timeout 30
crucible run slumlord invariant_owner_skip_only     --release --timeout 30
crucible run slumlord invariant_pda_forge_only      --release --timeout 30
crucible run slumlord invariant_unchecked_math_only --release --timeout 30
crucible run slumlord invariant_cu_dos_only         --release --timeout 30
```

discriminator-skip and account-swap omitted per the Day 40
inventory's N/A determination (Native 1-byte disc; single-PDA
program — no alternate-context concept).

## Why this matched the pre-fuzz estimate

Slumlord's per-ix validation is via solores-generated helpers:

| Helper | What it checks |
|---|---|
| `*_verify_account_keys` | Strict pubkey equality against the canonical resolved addresses (program-resolvable for the PDA, caller-provided for `dst` / `src`) |
| `*_verify_account_privileges` | `is_signer` flags and `is_writable` flags against the IDL declaration |

These two helpers are functionally equivalent to Anchor's
`Account<'info, T>` constraint for the account-validation invariant
family:

- **signer-skip** (drops `src` signer in Repay): `*_verify_account_privileges` fails before handler body runs.
- **owner-skip** (substitutes fake slumlord with wrong owner): `*_verify_account_keys` fails on pubkey mismatch — wrong-owner account can't be at the canonical slumlord PDA address.
- **pda-forge** (substitutes random pubkey at slumlord position): same — pubkey mismatch.

For the High-tier 2:

- **unchecked-math**: declared `Bounded { 0, 10^18 }` on `slumlord.old_lamports` (field at data offset 0). Field is u64 ≈ 10M lamports throughout the campaign — never approaches 10^18. Lamport-level invariants on `slumlord.lamports` itself (the field that actually moves during Borrow/Repay) are not expressible in v1's `read_field_widened` (account.data-only). v2 extension to read from `account.lamports` would be the right surface here.
- **cu-dos**: declared `cu_budget = 20K` for Init/Repay, 10K for CheckRepaid. Slumlord ix consume ~3-5K CU. Comfortable margin; no fire.

Slumlord is **competently-coded simple code**, not less-hardened code. This is documented honestly in the Day 40 inventory and confirmed by the actual fuzz result.

## What this tests, what this doesn't

**Does test**: the *protocol-size / TVL* axis of "less-hardened". Slumlord is a tiny program (115KB .so, ~200 lines of handler logic, single PDA, 4 ix) by experienced developers. Even at this minimal-surface scale, solinv's invariants don't find anything.

**Doesn't test**: the *code-quality* axis. Slumlord's developers (Igneous Labs / Sanctum team) have written production-grade Solana infrastructure for years. The validation discipline shows. To test the code-quality axis, N=2 needs to be something written under different conditions — hackathon-grade code is the canonical example.

## Decision — N=1 alone insufficient, continue to N=2

Per Phase 4 plan §"Stopping rule":

> - **N=1, 0 violations** → 1 data point, continue to N=2 (don't
>   pivot on a single trial).

This is the **continue** branch. The two-fail outcome (N=2 also 0) would bind the protocol-variety pivot. The single-trial result is not strong enough to do that yet — the next data point is what closes the loop.

N=2 target selection should pivot **toward the code-quality axis** explicitly:

- Slumlord's clean negative is information about *protocol-size*. N=2 needs to be a different axis to test.
- Candidate A from the Day 39 plan (Colosseum Nov 2025 winner) is the cleanest "hackathon-grade code" test. Picking a specific project is the Day 44 sub-decision.
- Alternative: a younger / smaller indie protocol whose team is solo / first-time-on-Solana.

C and D from the Day 39 shortlist (Phoenix v1, Sanctum unstake) would reproduce Slumlord's shape — both are heavily-audited production code by experienced teams. Picking them for N=2 would burn 5-7 days for the same outcome.

## Sub-decision for N=2

Three options for the user:

1. **A — Colosseum Nov 2025 winner**: hackathon-grade code = different axis. Need specific project pick (user has more context on the 2025 cohort).
2. **A' — Recent Solana indie project**: similar to A but not hackathon-specific. Smaller team, less audit history, real mainnet deployment.
3. **C / D from Day 39 shortlist**: same axis as Slumlord. Likely 0 again. Would burn 5-7 days for a confirming-but-not-conclusive data point.

User picks the axis. The Phase 4 sequential design is preserved
regardless — N=2 ships under the same Gate criteria as N=1.

## What's durable from this trial

- `examples/slumlord-fuzz/` harness — 546-line scaffold + 88-line
  Day 42 wiring. Reusable as a Native-program harness template
  for future targets with similar shape (single-PDA, helper-based
  validation).
- The `InstructionBuilder::add_transaction` + `send_batch` multi-ix
  pattern (Day 42 discovery) — solves the "ix requires another ix
  in the same tx" problem (Solana flash loans, Anchor multi-step
  setups, sysvar-dependent ix chains).
- Honest framing in the per-protocol README and the Day 40
  inventory — pre-fuzz estimate matched outcome, no narrative
  shift mid-experiment.
- Confirmation that solores's `*_verify_account_keys` +
  `*_verify_account_privileges` pattern is competent against the
  Critical 5 — this is a useful catalog entry for future
  target-selection decisions (programs using this pattern are
  unlikely to surface account-validation bugs).

## Files added/changed today

- `docs/phase4-day43-slumlord-result.md` (this doc).

Existing harness unchanged from Day 42. No code changes today —
campaigns ran against the already-built `slumlord_fuzz` binary
from Day 42.

## Cumulative Phase 4 schedule actuals

| Day | Theme | Commit |
|---|---|---|
| 39 | Phase 4 plan + sequential kill criterion | `78d74df` |
| 39a | Lifinity eliminated, refreshed shortlist | `ba3cc97` |
| 40 | Slumlord target + .so build + ix inventory | `e90a229` |
| 41 | Harness scaffold | `58e9777` |
| 42 | Borrow multi-ix + state invariants + smoke | `564e240` |
| 43 | Isolated 5-invariant campaigns + N=1 log (this doc) | (pending) |

Phase 4 N=1 completed in 5 working days vs Day 39 plan's 5-day
estimate — exactly on schedule. N=2 budget: ≤7 days (Day 44-50)
if a Native target, ≤8-9 days if Anchor zero-copy.

## Status of the kill criterion

Per Phase 4 plan §"Stopping rule" (Day 39):

> - N=1 with 0 violations → 1 data point, continue to N=2.

Actual N=1: 0 violations across 84,864 executions.

**Status: 1 negative data point. N=2 ships under same gating to resolve.**
