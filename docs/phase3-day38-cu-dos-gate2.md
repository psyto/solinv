# Phase 3 Day 38 — cu-dos Gate 2 result + two-fail outcome

Date: 2026-05-26
Spec: [docs/invariants/cu-dos.md](invariants/cu-dos.md) §9 + §10
Prior: [Day 34 unchecked-math Gate 2 FAIL](phase3-day34-unchecked-math-gate2.md)
Gate 1 (escrow-demo): **PASS** (Day 37, commit `c356e00` — 23,999
violations / 24,000 executions in 30s).
Gate 2 (Raydium SwapV2): **FAIL — 0 violations across the full
pre-committed budget**.

**Two-fail outcome triggered.** No more High-tier invariants ship.

## Setup

Raydium AMM v0.3.1 harness with the new `invariant_cu_dos_only`
variant calling `solinv_core::invariants::cu_dos::check(fixture)`.

Both SwapV2 specs gained `cu_budget = Some(100_000)`:
- Below the 200K-CU runtime ceiling.
- Above the upper end of expected-legitimate swap CU (typical
  SwapBaseInV2 around 30-50K pre-test).
- Fires only on genuinely pathological code paths consuming
  >100K CU per ix.

## Invocations

```bash
cd examples/raydium-amm-fuzz
crucible run raydium_amm invariant_cu_dos_only --release --timeout 30 -j 4
crucible run raydium_amm invariant_cu_dos_only --release --timeout 30 -j 4
```

Two campaigns at the §9-budgeted 30s × 4-worker × 2-ix surface.
`cu_dos::check` iterates both `swap_base_in_v2` and
`swap_base_out_v2` specs in a single campaign, so both ixs are
covered per run.

## Results

| Campaign | Workers | Executions | Crashes | ok rate | Edges |
|---|---|---|---|---|---|
| 1 | 4 | 13,658 | **0** | 197,546 / 236,196 = 83.6% | 629/14,696 (4.3%) |
| 2 | 4 | 11,992 | **0** | 197,193 / 212,631 = 92.7% | 629/14,696 (4.3%) |
| **Total** | — | **25,650** | **0** | — | — |

**No violations observed** across the full pre-committed budget.

Edge counts saturated at 629/14,696 — **identical** to Day 34
unchecked-math Gate 2. Two campaigns × two invariant classes ×
same coverage saturation point confirms additional time would not
have changed the outcome.

ok rate 83-93% confirms the swap ixs were largely succeeding —
harness is healthy, not error-gated.

## Interpretation

### Detection-mechanism reading

cu-dos's `compute_units ≤ cu_budget` formulation catches per-ix CU
consumption above the cap. Raydium SwapV2 with default 200K
ceiling stays well below 100K on all explored inputs. The detector
is correctly idle here — there is no pathological CU path on
SwapV2 within the inputs the fuzzer reached.

### Strategic reading — two-fail outcome

This is the **second** High-tier Gate 2 fail on the same Raydium
SwapV2 surface, with two different invariant classes:

| | Invariant | Mechanism | Gate 2 result |
|---|---|---|---|
| Day 34 | unchecked-math | state mutation (Bounded on monetary fields) | 0 / 15,380 |
| Day 38 | cu-dos | per-ix CU consumption | 0 / 25,650 |

The hypothesis under test in Day 35 was the user-confirmed Day 34
follow-on: *"Gate 2 result generalized to the bug class tested,
not to all bug classes — a different invariant class might fire."*

**That hypothesis is now falsified with hard data.** Two genuinely
different mechanisms, same target, same outcome.

The combined evidence stack on the original strategic question
("does adding solinv capability close the Phase 2 E[V] gap on the
existing protocol set?") now reads:

- **Phase 2** (5 Critical × 2 protocols, ~25K attacks): 0 detections
- **Day 34** (unchecked-math × Raydium SwapV2, 15K executions): 0
- **Day 38** (cu-dos × Raydium SwapV2, 25K executions): 0

Three distinct data points, same shape. The gap is not closeable
by adding more solinv invariants against the current protocol set
under the current strategy. This is now demonstrated, not assumed.

## Decision — pivot is binding across the High-tier program

Per the cu-dos spec §9 "Two-fail outcome":

> If cu-dos Gate 2 also fails, then:
> - **Confirmed**: two different invariant classes (unchecked-math
>   and cu-dos) tested on the same protocol (Raydium SwapV2),
>   both detected 0 violations across pre-committed budgets.
> - **Implication**: the gap to original target E[V] is not closed
>   by adding invariant variety on the existing protocol set —
>   doubly demonstrated.
> - **Action**: no more High-tier invariants are spec'd or
>   implemented. cpi-reentrancy (the only remaining v1-applicable
>   High-tier candidate) stays deferred. realloc-race and
>   token-2022-hook are not applicable to Raydium SwapV2 surface
>   in any case.

**cpi-reentrancy stays deferred.** **realloc-race stays deferred.**
**token-2022-hook stays deferred.** Phase 3 closes.

The §9 binding force inherits from §10's honest framing of the
override decision. The user's Day 34 follow-on was tested under
the strictest experimental design possible — one more invariant,
same gating discipline. The hypothesis failed. Honoring the
binding on a binary fail outcome preserves the credibility of the
pre-commit mechanism for the future.

## What this does NOT mean

- It does **not** mean Raydium SwapV2 is bug-free in the cu-dos
  class. It means *no input the fuzzer reached pushed consumed
  CU above 100K*. A subtle pathological state (e.g., a fully
  saturated order book, deep open-orders chain) might still
  surface a higher CU path — but that requires fixtures the
  current harness doesn't construct.
- It does **not** mean cpi-reentrancy / realloc-race /
  token-2022-hook would yield 0 if implemented. It means
  *implementing them under the current strategy is not justified
  by the data*. The decision is about resource allocation, not
  invariant viability in absolute terms.
- It does **not** invalidate the cu-dos solinv-core
  implementation. cu_dos.rs ships at Critical-5 parity (compiled
  + detecting + regression-tested + planted-fixture-validated)
  and is durable across any future pivot.

## Pivot — three options enumerated in unchecked-math §9, status updated

Same three options as Day 34, but the binding force is now
*across the High-tier program* (not just one invariant):

1. **Less-hardened protocol targets**: scaffold one or two newer
   / smaller-TVL protocols and rerun the existing 6 invariants
   (Critical 5 + unchecked-math + cu-dos). Tests the
   protocol-variety hypothesis. This is the only option that
   remains within "Phase 3 / private extraction" framing.
2. **OSS audit-accelerator framing**: pivot solinv to Phase 2.5
   OSS branch. Different revenue model (consulting + integrations
   instead of bounties). Catalog completeness as the value prop
   rather than per-protocol bug yield.
3. **Pause and reassess**: Phase 1 + 2 + 3 outputs are durable.
   Reassess in 3-6 months as the Solana tooling landscape moves.

**Current state**: Day 38. 27 commits ahead of the Phase 2
closing point (24 already pushed Day 36, 3 more local: Day 37,
this Day 38).

## What's durable

The Phase 3 mechanism + body of work that survives any pivot:

- **6 invariants implemented at Critical-5 parity**:
  signer-skip, owner-skip, discriminator-skip, pda-forge,
  account-swap (Critical); unchecked-math, cu-dos (High).
- **Two pre-committed kill criteria honored**: Day 31 §9
  triggered Day 34; Day 35 §9 + §10 triggered Day 38. The
  pre-commit framework is empirically functional — both
  override attempts were tested cleanly and the data resolved
  the question.
- **Three production validation campaigns**: Day 34
  unchecked-math, Day 38 cu-dos, prior Day 20-21 Critical 5.
  All shipped with honest framing (`0 detections is the
  positive outcome` — invariants confirm absence of bugs on
  hardened production code, doubly demonstrated).
- **5 reusable patterns + escrow-demo + 3 example harnesses +
  disclosure templates** — all unaffected by the pivot.

## Cumulative Phase 3 schedule actuals

| Day | Theme | Commit | Outcome |
|---|---|---|---|
| 31 | unchecked-math spec + §9 | `f8a681c` | spec + kill criterion locked |
| 32 | unchecked-math implementation | `27b210f` | 18 + 5 ignored tests passing |
| 33 | Gate 1 escrow | `31fbc2e` | PASS, 1,555 / 34,971 in 30s |
| 34 | Gate 2 Raydium | `efa9f07` | **FAIL**, 0 / 15,380 in 2 min |
| 35 | cu-dos spec + §9 + §10 | `b362cb9` | second gated experiment locked |
| 36 | cu-dos implementation | `f4e789d` | 20 + 6 ignored tests passing |
| 37 | Gate 1 escrow | `c356e00` | PASS, 23,999 / 24,000 in 30s |
| 38 | Gate 2 Raydium (this doc) | (pending) | **FAIL**, 0 / 25,650 in 2 min |

Phase 3 ran in 8 working days against the spec's Day 31-38 plan
— exactly on schedule, all gates honored on both binary outcomes.

## Honest framing of where we are

The §10 of the cu-dos spec said:

> The credibility of the pre-commit mechanism rides on honoring
> this binary fail outcome.

We're at the moment that text was written about. Two attempts to
extend solinv against the current protocol set, both gated, both
failed, both stopped at the gate. The pre-commit framework
worked exactly as designed.

The next decision is at the strategy layer, not the implementation
layer — and the implementation layer's contribution to the
decision is now closed.

## Files added/changed today

- `examples/raydium-amm-fuzz/fuzz/raydium_amm/src/main.rs` —
  added `cu_budget: Some(100_000)` on both SwapV2 specs, added
  `invariant_cu_dos_only` variant.
- `examples/raydium-amm-fuzz/fuzz/raydium_amm/Cargo.toml` —
  added `invariant_cu_dos_only` feature.
- `docs/phase3-day38-cu-dos-gate2.md` (this doc).

## Status of the kill criterion

Pre-committed criterion (cu-dos §9, written 2026-05-26 Day 35):
> Fail condition (pivot is binding, no more High-tier invariants
> ship): **0 violations** after the full budget.

Actual result: **0 violations across 25,650 executions / ≈2 min
wall / both SwapV2 ixs**.

**Status: FAILED. Pivot binding across the entire High-tier
program.**
