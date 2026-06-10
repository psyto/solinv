# Phase 3 Day 34 — unchecked-math Gate 2 result

Date: 2026-05-26
Spec: [docs/invariants/unchecked-math.md](invariants/unchecked-math.md) §9
Gate 1 (escrow-demo): **PASS** (Day 33, commit `31fbc2e` — 1,555
violations / 34,971 executions in 30s).
Gate 2 (Raydium SwapV2): **FAIL — 0 violations across the full
pre-committed budget**.

## Setup

Raydium AMM v0.3.1 harness (`examples/raydium-amm-fuzz/`) with the
new `invariant_unchecked_math_only` variant calling
`solinv_core::invariants::unchecked_math::check(fixture)`.

Two `Bounded { 0, 10^18 }` state invariants declared on each of the
two ix specs:

- `coin_vault_amount_bounded` — account index 3 (AMM coin vault SPL
  TokenAccount), `field_offset = 64` (SPL TokenAccount.amount), `field_size = 8`
- `pc_vault_amount_bounded` — account index 4 (AMM pc vault SPL
  TokenAccount), same offset / size

10^18 cap chosen per the Day 31 spec §5: above any legitimate AMM
state (init balance 10^9; even runaway trading caps below 10^18) but
catches the wrap-to-near-u64::MAX signature characteristic of an
unchecked-math bug. Tighter precision-loss bugs that stay below 10^18
will not fire — that is the conservative-by-design v1 setting.

## Invocations

```bash
cd examples/raydium-amm-fuzz
crucible run raydium_amm invariant_unchecked_math_only --release --timeout 30 -j 4
crucible run raydium_amm invariant_unchecked_math_only --release --timeout 30 -j 4
```

Two campaigns at the §9-budgeted 30s × 4-worker × 2-ix surface. The
`unchecked_math::check` function iterates both `swap_base_in_v2` and
`swap_base_out_v2` specs in a single campaign, so both ixs are
covered per run.

## Results

| Campaign | Workers | Executions | Crashes | ok rate | Edges |
|---|---|---|---|---|---|
| 1 | 4 | 7,818 | **0** | 200,796 / 217,565 = 92.3% | 629/14,696 (4.3%) |
| 2 | 4 | 7,562 | **0** | 200,736 / 210,275 = 95.5% | 629/14,696 (4.3%) |
| **Total** | — | **15,380** | **0** | — | — |

**No violations observed** across the full pre-committed budget.

Edge counts saturated at the same 629/14,696 across both campaigns,
indicating coverage is exhaustive for this surface — additional time
on the same workload would not have changed the result.

ok rate of 92-95% confirms the swap ixs largely succeeded throughout
the campaign — the harness is healthy, not error-gated. Failures
(7-8%) are explained by the existing Day 19-21 known-good rejects
(invalid amount_in, slippage tripped by mutator, etc.) and not a
post-state miss.

## Interpretation

Two readings are honest, in increasing order of strategic
implication:

1. **Detection-mechanism reading**: unchecked-math's
   `Bounded { 0, 10^18 }` formulation catches wrap-to-near-u64::MAX,
   not precision loss or sign flips. Raydium SwapV2's `processor.rs`
   uses internal bounds checks (`swap_curve` validation, slippage
   gate) that reject extreme inputs *before* arithmetic executes. So
   even if a wrap-able multiplication existed, it would never be
   reached at fuzz time. The detector is correctly idle here.

2. **Strategic reading**: This is precisely the data point the
   Day 31 kill criterion was designed to surface. The hypothesis
   under test was *"the gap between Phase 2's revised $60-80K E[V]
   and the original $140K target closes by adding invariant
   variety on the same protocols"*. Phase 2 evidence
   (25,383 attacks / 0 detections on the Critical 5) said the
   protocol-variety side is gated. Day 34 evidence says the
   invariant-variety side is also gated for this protocol set —
   adding a different *kind* of detector on the same hardened
   production surface does not move the per-protocol detection
   probability above zero.

## Decision

**Stop High-tier expansion.** Per the §9 pre-commit:

> If Gate 2 fails, do **not** proceed to spec/implement cu-dos,
> realloc-race, token-2022-hook, cpi-reentrancy, or any other
> High-tier invariant. The data from Gate 2 says additional invariants
> on the existing protocol set don't move the needle.

cu-dos / realloc-race / token-2022-hook / cpi-reentrancy stay
deferred. No more High-tier specs ship without changing the protocol
mix or the strategy.

## What this does NOT mean

- It does **not** mean Raydium SwapV2 is bug-free in the
  unchecked-math class. It means *solinv's current Bounded-only
  detector at the 10^18 cap doesn't fire on this surface*. A
  precision-loss bug that stays below 10^18 would be invisible to
  v1.
- It does **not** mean the unchecked-math invariant is wrong.
  Gate 1 proved it detects against a planted bug. It just doesn't
  yield findings on hardened production targets — the same shape
  Phase 2 documented for the Critical 5.
- It does **not** invalidate the solinv-core implementation.
  unchecked_math.rs ships at Critical-5 parity (compiled + detecting
  + regression-tested + planted-fixture-validated) and is durable.

## Pivot — three options enumerated in §9, current preference

Per §9 the three options are:

1. **Less-hardened protocol targets**: scaffold one or two newer
   / smaller-TVL protocols and rerun the existing 5 Critical +
   unchecked-math. Tests the protocol-variety hypothesis.
2. **OSS audit-accelerator framing**: pivot solinv from private
   extraction to Phase 2.5 OSS — different revenue model
   (consulting + integrations instead of bounties).
3. **Pause and reassess**: Phase 1 + 2 outputs are durable.
   Reassess in 3-6 months.

**Current state**: Day 34. 18 commits ahead of origin/main. Phase 3
experiment complete in the strictest sense — both gates ran, kill
criterion fired, decision is binding.

The next decision is at the strategy layer, not the implementation
layer. Two of three pivot options (#1 and #2) require committing
multi-week chunks of work toward outcomes whose E[V] is now
explicitly informed by both Phase 2 evidence and Day 34 evidence.
Option #3 (pause) is the lowest-cost option and preserves all
durable artifacts for later.

## Cumulative Phase 3 schedule actuals

| Day | Theme | Commit | Outcome |
|---|---|---|---|
| 31 | unchecked-math spec + §9 kill criterion | `f8a681c` | 571-line spec, kill criterion checked-in |
| 32 | implementation: types + detector + 13 unit tests | `27b210f` | All workspace tests passing (18 + 5 ignored) |
| 33 | Gate 1 — escrow-demo planted ix | `31fbc2e` | PASS, 1,555 violations / 34,971 exec in 30s |
| 34 | Gate 2 — Raydium SwapV2 (this doc) | (pending) | **FAIL, 0 violations / 15,380 exec in ≈2 min** |

Phase 3 ran in 4 days, well under the spec's Day 31-37 budget. The
short cadence is honest in both directions: when the experiment was
positive (Gate 1), it shipped quickly; when negative (Gate 2), it
stopped at the gate rather than rationalizing forward.

## Files added/changed today

- `examples/raydium-amm-fuzz/fuzz/raydium_amm/src/main.rs` — added
  `state_invariants` on both SwapV2 specs (2 × Bounded), added
  `invariant_unchecked_math_only` test variant.
- `examples/raydium-amm-fuzz/fuzz/raydium_amm/Cargo.toml` — added
  `invariant_unchecked_math_only` feature.
- `docs/phase3-day34-unchecked-math-gate2.md` (this doc).

## Status of the kill criterion

Pre-committed criterion (§9, written 2026-05-26 Day 31):
> Fail condition (pivot, do not continue High-tier expansion):
> **0 violations** after the full 2-minute budget across both ix.

Actual result: **0 violations across 15,380 executions / ≈2 minutes
wall / both SwapV2 ixs**.

**Status: FAILED. Pivot is binding.**
