# Phase 2 Day 21 — Raydium SwapBaseOutV2 + Deposit feasibility analysis

Date: 2026-05-25
Status: ✅ SwapBaseOutV2 added (4/4 invariants × 2 ix = 0 crashes). Deposit/Withdraw feasibility analyzed → recommend defer to focus on klend (Day 22+).
Schedule: 3-4 days ahead of Day 14 baseline.

## Goal

Day 20 plan: extend to Deposit / Withdraw / SwapBaseOutV2 + re-run
regression. Day 21 outcome:

1. ✅ Added SwapBaseOutV2 ix constructor + action + InstructionSpec
2. ✅ Sequential regression 4 invariants × 2 ix = **0 crashes**
3. ⏸️ Investigated Deposit/Withdraw — feasible but high-cost; recommend defer
4. → Day 22 should accelerate to klend (Day 23+ → Day 22 now)

## SwapBaseOutV2 (tag 17) — trivial mirror of InV2

Implementation (~50 LOC delta in `main.rs`):

- `build_swap_base_out_v2_ix(...)` — identical 8 AccountMeta layout,
  tag=17, args swapped: max_amount_in (cap) + amount_out (target)
- `action_swap_base_out_v2(max_amount_in, amount_out)` — raw_call
- `swap_base_out_v2_spec` InstructionSpec — identical to InV2's
  expected_owners/discriminators/pda_seeds/swap_alternates; only
  name + data_sample differ

`instructions()` now returns `vec![swap_base_in_v2_spec, swap_base_out_v2_spec]`.
Each invariant check iterates both, attacking each.

## Regression matrix — 4 invariants × 2 ix (sequential)

| Invariant | Crashes | Executions | Wall |
|---|---|---|---|
| signer_skip | **0** | 9,199 | 30s |
| owner_skip | **0** | 1,784 | 51s |
| pda_forge | **0** | 11,222 | 30s |
| account_swap | **0** | 3,178 | 45s |

**Total: 0 violations across 25,383 attacks** spanning both ix
surfaces. SwapBaseOutV2 confirmed clean — symmetric to InV2 as
expected (same processor validation pattern at `processor.rs:`
just with args reordered).

## Deposit / Withdraw feasibility — analysis

### Deposit (tag 3, 14 accounts)

**Per `processor.rs:1225-1373` (process_deposit)**:

Strict validation requires (in addition to SwapBaseInV2's checks):
- `amm.lp_mint` must match `amm_lp_mint_info.key` — need to set in
  AmmInfoMirror AND create an SPL Mint owned by amm_authority
- `amm.target_orders` must match `amm_target_orders_info.key`
  — need to set in AmmInfoMirror AND create a TargetOrders account
  (zero-copy, 2208 bytes, owner=program_id)
- `target_orders.owner` must equal `amm_info.key` (per
  `TargetOrders::load_mut_checked` at `state.rs:185-201`)
- LP destination user_dest_lp account must exist (SPL TokenAccount
  with mint=lp_mint)

**Good news**: `enable_orderbook = AmmStatus::orderbook_permission()`.
With `SwapOnly (=6)`, orderbook is disabled → skips
`load_serum_market_order` → **no OpenBook market needed**. The 
`market` account at idx 8 + `market_event_queue` at idx 13 are passed
but not validated when orderbook disabled.

### Withdraw (tag 4, 20 accounts)

Same pattern as Deposit but includes Market bids/asks/event_queue/
coin_vault/pc_vault/vault_signer in the AccountMeta list. With
orderbook disabled, these are presumably also passthrough — but the
account count is large enough that fixture setup is more brittle.

### Implementation cost estimate

| Component | LOC | Complexity |
|---|---|---|
| `TargetOrdersMirror` struct (2208 bytes) | ~50 | mechanical, with size assertion |
| `lp_mint` SPL Mint + `user_lp` SPL TokenAccount | ~30 | trivial (ctx.create_mint/token_account) |
| `user_b_lp` for swap_alternates | ~10 | trivial |
| AmmInfoMirror update (set lp_mint, target_orders fields) | ~10 | trivial |
| `build_deposit_ix` + InstructionSpec (14 accounts) | ~80 | careful with isMut/isSigner per Day 16 |
| `build_withdraw_ix` + InstructionSpec (20 accounts) | ~120 | larger, more account_swap surface to enumerate |
| Add `action_deposit` + `action_withdraw` | ~40 | mirror SwapV2 pattern |
| Cargo feature gates | ~5 | trivial |

**Total: ~345 LOC + ~1.5 days** to implement and validate (regression
sweep on 4 inv × 4 ix combinations).

### Expected yield

| Ix | Expected detections | Reasoning |
|---|---|---|
| Deposit | 0 | Same validation pattern as swaps (vault-key + signer + PDA + load_mut_checked) |
| Withdraw | 0 | Same pattern, larger surface = marginally higher false-positive risk, no new bug-class exposure |

The 4 invariants target the SAME 4 attack patterns regardless of ix.
If Raydium correctly validates these on SwapBaseInV2/OutV2 (proven Day
20), they're validated on Deposit/Withdraw too — same processor
infrastructure (`AmmInfo::load_mut_checked`, vault-key equality,
SPL Token CPI, `authority_id` PDA check).

**Expected outcome: 0 crashes on Deposit/Withdraw.** Same as
SwapBaseInV2/OutV2.

## Day 22 decision (recommend acceleration to klend)

### Option A: Continue Raydium (Day 21-22 implementing Deposit+Withdraw)

- Cost: ~1.5 days
- Yield: ~0 new findings (per above analysis)
- Confidence: high (mature audited code, same patterns)
- Value: marginal — extends coverage but unlikely to find Critical bugs

### Option B: Accelerate to klend (Day 22 → Day 23 → ... renumbered)

- Cost: same Day 22-27 budget as original
- Yield: **higher expected**:
  - Anchor 0.29 protections leave cross-account relationships exposed
    (Day 17 hit-rate analysis: account-swap = HIGH on klend)
  - $1.5M bounty ceiling (vs Raydium's $505K)
  - Historic precedent: Mango v3, Solend, Cypher, Drift v1 — all
    cross-account / has_one bypass / obligation-collateral misuse
- Confidence: medium (klend is also well-audited but surface is richer)

### Recommendation: **Option B**

- Day 22: Begin klend harness scaffold (analogous to Day 18 Raydium scaffold)
- Day 23-27: Reserve fixture + 5 critical ix InstructionSpec + regression
- Day 28-30: Triage + disclosure for any klend findings + final Raydium pass
  (Deposit/Withdraw if time permits)

This reallocates ~1.5 days from low-yield Raydium extension to higher-
yield klend MVP.

## Files changed Day 21

- `examples/raydium-amm-fuzz/fuzz/raydium_amm/src/main.rs` —
  build_swap_base_out_v2_ix + action_swap_base_out_v2 +
  swap_base_out_v2_spec (~110 LOC delta)
- `examples/raydium-amm-fuzz/fuzz/raydium_amm/Cargo.toml` — no
  new features (existing isolated invariants test both ix)
- `docs/phase2-day21-raydium-extension.md` (this log)

## Schedule status

Day 21 = 1 session (~1 hour). Cumulative **3-4 days ahead** of
Day 14 baseline. Day 22 = klend acceleration (per recommendation).

## Open questions (for Day 22 user decision)

User has 3 choices:

- **(A)** Continue Raydium Deposit/Withdraw Day 22 (low yield, complete coverage)
- **(B)** Accelerate to klend Day 22 (higher yield, defer Raydium completion)
- **(C)** Hybrid — quick Deposit (1 day) + klend Day 23 (skip Withdraw for now)
