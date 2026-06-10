# Phase 2 Day 25 — klend deposit_reserve_liquidity InstructionSpec + first campaign

Date: 2026-05-25
Status: ✅ First klend ix wired end-to-end. ⚠️ Fuzz depth limited — ix fails at internal lending logic, attacks don't reach account-validation surface.
Schedule: 3-4 days ahead of Day 14 baseline. **Day 26 decision required**.

## Goal

Per Day 24 plan: implement first real klend ix +
InstructionSpec + campaign + triage. Day 25 actual:

1. ✅ `build_deposit_reserve_liquidity_ix` raw_call constructor (12 accounts)
2. ✅ `action_deposit_reserve_liquidity` method on KlendFixture
3. ✅ `deposit_reserve_liquidity_spec` in `instructions()` with full
   metadata (expected_owners/disc/pda_seeds/swap_alternates per Day 17
   inventory + Day 20 lesson applied)
4. ✅ First real klend campaign ran (combined + isolated invariants)
5. ⚠️ **0 detections, but `ok: 0/N (0.0%)` — every ix call fails**
6. Triage finding: depth limited (see below)

## Campaign results

| Variant | Wall | Executions | Crashes | ok ratio |
|---|---|---|---|---|
| combined (5 inv) | ~2m | 929 | **0** | **0/150434 (0%)** |
| account_swap isolated | 19s | 1543 | **0** | **0/47354 (0%)** |

**0 crashes is honest, NOT proof of "klend bug-free"** — the
attacks all fail at the SAME upstream check that the legitimate
baseline ix also fails at. Solinv invariants record violations only
when MUTATED ix succeeds + state changes; if attacks fail at upstream,
nothing to record.

## Root cause of 0% ok ratio

Reading `handler_deposit_reserve_liquidity.rs:20-89`, the ix execution
order is:

1. `lending_checks::deposit_reserve_liquidity_checks(...)` — passes
   with zero ReserveConfig (status=0=Active, emergency_mode=0)
2. `lending_market.check_permissions(DEPOSIT, ...)` — passes if
   `permissioned_ops == 0` (zero LendingMarket → no perms required)
3. `refresh_reserve(reserve, &clock, None, ...)` — **likely fails
   here** due to:
   - `reserve.accrue_interest(slot, referral_fee_bps)?` — math on
     all-zero borrowed_amount_sf / cumulative_borrow_rate
   - `reserve.distribute_rewards(slot, ...)?` — similar
4. `lending_operations::deposit_reserve_liquidity(reserve, &clock,
   amount)` — has `deposit_limit` check; zero limit blocks deposits

Either step 3 or 4 returns an error before the actual SPL Token
transfer (account-validation surface that solinv targets).

## Implication for solinv detection depth

Solinv attacks substitute accounts (account_swap) or flip signer
flags (signer_skip) or use wrong owner (owner_skip) etc. These
mutations are designed to test what happens AT the account-validation
checkpoints in Anchor + the program's `if` statements.

If the ix returns early at internal-logic checks BEFORE reaching
those checkpoints, solinv can't observe whether the checkpoints
work correctly.

So Day 25 result is: **infrastructure proven (harness compiles, runs,
reaches klend processor, fixture init valid). Test depth limited
(zero-config Reserve fails internal lending math before reaching
account-validation surface)**.

## Day 26 decision required (3 options)

### (A) Build full ReserveConfig defaults

- Populate ~50 ReserveConfig fields with sensible defaults (deposit_limit,
  borrow_limit, fees, oracle setup, etc.)
- Mirror ReserveConfig struct + offset_of! for each field setter
- ~1.5-2 days
- Outcome: baseline ix succeeds → account-validation attacks reach
  intended surface
- Could yield real findings or confirm clean
- Risk: oracle config (Scope/Pyth) might require external account
  setup beyond fixture scope

### (B) Pivot to init_reserve via raw_call

- Use Anchor's init_reserve ix with pre-created accounts
- Anchor populates ReserveConfig correctly
- Need to pass `is_allowed_signer_to_init_reserve` (probably checks
  lending_market_owner = signer)
- Need to pre-create reserve_liquidity_supply (PDA seed
  `[seeds::RESERVE_LIQ_SUPPLY, reserve.key()]`) and fee_receiver
  (PDA seed `[seeds::FEE_RECEIVER, reserve.key()]`)
- ~1.5 days
- Outcome: closer-to-mainnet Reserve state, all fields set per Anchor's
  init logic

### (C) Accept current depth, document + declare klend MVP done

- Honest Phase 2 outcome: klend infrastructure proven, account-validation
  surface partially tested (any attack that succeeds AT the upstream
  failure point would still be detected — solinv didn't miss any
  successful mutated attack)
- Day 26-27 → write Phase 2 retrospective + disclosure templates
  for Phase 1 wrap-up
- Day 28-30 → Phase 1 OSS prep if pivoting

Realistic value comparison:
- (A) and (B) extend depth but bounty yield still uncertain
- (C) acknowledges Phase 2 MVP scope was 5-7 days originally; we're
  at 4 days with infrastructure done, depth limited
- Day 21 user decision was Option B (accelerate klend). User wanted
  klend coverage. **(A) or (B) honors that signal**; (C) doesn't

## Recommendation: **(B) init_reserve via raw_call**

Reasons:
- Anchor handles ReserveConfig correctness (no manual field-by-field
  setup of 50 config params)
- Closer to mainnet-realistic state (better fuzz fidelity)
- Pre-creating PDAs is annoying but well-understood pattern
- 1.5 days budget fits remaining lead

If `is_allowed_signer_to_init_reserve` requires more than just being
lending_market_owner (e.g., needs init_global_config setup), pivot
to (A) at that point.

## Files changed Day 25

- `examples/klend-fuzz/fuzz/klend/src/main.rs` — build_deposit_reserve_liquidity_ix
  (~40 LOC) + action_deposit_reserve_liquidity (~25 LOC) + InstructionSpec
  (~70 LOC). Total ~135 LOC delta.
- `docs/phase2-day25-klend-first-ix.md` (this log)

## Honest framing for Phase 2 retrospective

Phase 2 Raydium AMM coverage was clean (Day 18-21): 4 invariants × 2
ix surfaces, 0 detections, full chain validated. Phase 2 klend
coverage is **infrastructure proven, depth gated by fixture
completeness**. This is a valuable finding even without bugs —
documents the cost-of-entry for Anchor-based zero-copy programs vs
Native programs, and validates that solinv invariants don't false-
positive on legitimate code paths that fail upstream.

For OSS branch (Phase 2.5), the klend harness should ship with a
note: "Reserve fixture is byte-poked minimum-viable; full coverage
requires either (a) populating ReserveConfig defaults or (b) using
init_reserve raw_call. Contributors welcome to extend."

## Schedule status

Cumulative **3-4 days ahead** of Day 14 baseline. Day 26 decision
allocates remaining lead time.
