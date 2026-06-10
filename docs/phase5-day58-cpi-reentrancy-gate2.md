# Phase 5 Day 58 — cpi-reentrancy Gate 2 result (Raydium AMM SwapV2)

Date: 2026-06-09
Spec: [docs/invariants/cpi-reentrancy.md](invariants/cpi-reentrancy.md) §9 + §10
Prior: [Gate 1 PASS](phase5-day58-cpi-reentrancy-gate1.md) (planted-bug detection, 18,999 / 30s)
Framing: **Phase 2.5 OSS catalog-completion** — 0 violations on
hardened production is the **expected** result; this is catalog
evidence, NOT a kill criterion. The Phase 3 §9 "stop spec'ing more
invariants" binding does NOT apply (spec §10).

## Result — 0 violations across 27,573 executions

Two campaigns × 4 workers × 30s each. Combined null result confirms
Raydium AMM SwapV2 + SwapBaseOutV2 do not exhibit CPI re-entry
under the v1 detector. Adds to the "tested-and-found-nothing on
hardened production" calibration dataset (now spans 3 invariants ×
1 protocol: unchecked-math Day 34, cu-dos Day 38, cpi-reentrancy
Day 58).

## Setup

Both Raydium SwapV2 specs now declare
`cpi_reentrancy: Some(CpiReentrancyConfig { allowlist: vec![] })`
(strict mode — no allowed re-entry). `cpi_reentrancy::check` runs
each ix unmodified, parses `TxOutcome.logs`, walks the CPI call
tree. Raydium's actual CPI graph (per static analysis of
amm-program v0.3.1):

```
swap_base_in_v2:
  AMM → SerumDEX-shim (`MarketState::load_from_account_info`)
      → SPL Token (`SplTokenTransfer` for vault outflow + user inflow)

swap_base_out_v2: same shape, reverse direction
```

2-3 hops, non-cyclic. The detector's expected behavior is to see
each program at exactly one depth and produce no violation.

## Invocations

```bash
cd ~/src/solinv/examples/raydium-amm-fuzz
crucible run raydium_amm invariant_cpi_reentrancy_only --release --timeout 30 -j 4
crucible run raydium_amm invariant_cpi_reentrancy_only --release --timeout 30 -j 4
```

Same 2-campaign × 30s × 4-worker × 2-ix budget as cu-dos /
unchecked-math Gate 2 — apples-to-apples comparison across the
three High-tier invariants tested on this surface.

## Results

| Campaign | Workers | Executions | Crashes | ok rate | Edges |
|---|---|---:|---:|---:|---|
| 1 | 4 | 14,029 | **0** | 205,738 / 229,704 = 89.6% | 629/14,696 (4.3%) |
| 2 | 4 | 13,544 | **0** | 200,588 / 232,101 = 86.4% | 629/14,696 (4.3%) |
| **Total** | — | **27,573** | **0** | — | — |

**No violations observed across either campaign.**

Edge counts saturated at **629/14,696 — identical** to cu-dos Day
38 and unchecked-math Day 34. Three different High-tier invariants
× same protocol × same coverage saturation confirms additional
time would not have changed the outcome (the fuzzer hit the same
reachable surface in each campaign).

ok rate 86-90% confirms the swap ixs are largely succeeding —
harness is healthy, not error-gated.

## Interpretation

### Detection-mechanism reading

The detector correctly idled: zero CPI cycles observed across
27K successful swap executions. Raydium SwapV2's CPI graph is
exactly the shape spec §9 predicted — 2-3 hops through SerumDEX-
shim and SPL Token, no path back to the AMM program.

The unit-test-validated parser ran on real LiteSVM-emitted logs
without parse errors (no spurious violations from malformed
sequences). Gate 1's planted-bug fixture had previously confirmed
the **detector fires correctly when re-entry is present**; Gate 2
confirms it **does not fire spuriously when re-entry is absent**.

### Phase 2.5 framing reading

This is the **expected and publishable** Gate 2 outcome under the
catalog-completion frame. Spec §9 explicitly states:

> Expected result: 0 violations. Raydium AMM v0.3.1 is hardened
> and its CPI graph is well-understood (2-3 hops max: AMM →
> SerumDEX-shim → SPL Token, all non-cyclic).

> NOT a kill criterion — this is the expected result under Phase
> 2.5.

The result becomes catalog evidence in the OSS launch's honest
calibration page: "cpi-reentrancy invariant ran 27,573 executions
against Raydium AMM SwapV2/SwapBaseOutV2 surface, detected 0
violations". Identical methodology to the cu-dos Day 38 and
unchecked-math Day 34 datasets.

### What this does NOT mean

- It does **not** mean Raydium SwapV2 is bug-free in the
  cpi-reentrancy class. It means *no input the fuzzer reached
  through the SwapV2 surface produced a CPI cycle*. A subtle
  pathological state (e.g., a malicious serum market with a
  callback that re-enters Raydium) might still surface a higher-
  depth path — but that requires fixtures the current harness
  doesn't construct.
- It does **not** invalidate the cpi_reentrancy solinv-core
  implementation. cpi_reentrancy.rs ships at Critical-5 parity
  (compiled + detecting + regression-tested + planted-fixture-
  validated + production-clean) and is durable through Phase 2.5
  launch.
- It does **not** trigger any Day-38-style binding. The Phase 3
  binding was about *extraction yield justification*; this Phase
  2.5 dataset is about *catalog calibration* — distinct premises,
  distinct decisions.

## Cross-invariant Phase 2.5 calibration dataset (cumulative)

All three High-tier invariants tested under the same shape on
Raydium SwapV2:

| Day | Invariant | Mechanism | Executions | Violations |
|---|---|---|---:|---:|
| 34 | unchecked-math | state mutation (Bounded) | 15,380 | 0 |
| 38 | cu-dos | per-ix CU consumption | 25,650 | 0 |
| **58** | **cpi-reentrancy** | **CPI call-tree logs** | **27,573** | **0** |

Three distinct detection mechanisms, same hardened-production
surface, three null results. This dataset is the empirical
backbone of solinv's "honest calibration" framing — the detectors
are sensitive (Gate 1 catches planted bugs in all three cases) and
silent (Gate 2 produces 0 on hardened production). Publishable as
solinv's catalog-completeness deliverable under Phase 2.5.

## Next

- **Optional Gate 3** (Slumlord flash-loan harness) — the most-
  likely-positive production surface per spec §9. Slumlord's
  borrower-callback shape (`borrow → callback → repay`) is exactly
  the cpi-reentrancy-friendly path. If run, expected 0 violations
  because Slumlord's design predicates the borrower on a single
  immutable contract pre-registered at flash-loan-init — but the
  result becomes another catalog data point.
- **Continue catalog completion** per [[project-solinv]] Phase 2.5
  plan: realloc-race + bump-seed-canonicalization specs + impls.
  Each follows the same template: spec → impl with logs/state
  parser → Gate 1 planted-bug detection → Gate 2 production
  evidence.
- **Public launch prep** (Day 79-83 per CLAUDE.md "Next session
  priorities") — the cpi-reentrancy catalog entry + this Gate 2
  data point lock in additional public-facing material for the
  launch.

## Files changed Day 58 (Gate 2)

- `examples/raydium-amm-fuzz/fuzz/raydium_amm/src/main.rs` — both
  SwapV2 specs now carry `cpi_reentrancy: Some(CpiReentrancyConfig
  { allowlist: vec![] })`. Added `invariant_cpi_reentrancy_only`
  `#[invariant_test]` fn.
- `examples/raydium-amm-fuzz/fuzz/raydium_amm/Cargo.toml` — added
  `invariant_cpi_reentrancy_only` cargo feature.
- `docs/phase5-day58-cpi-reentrancy-gate2.md` (this doc).
