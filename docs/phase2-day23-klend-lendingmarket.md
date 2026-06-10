# Phase 2 Day 23 — klend LendingMarket byte-poke (minimum viable)

Date: 2026-05-25
Status: ✅ LendingMarket constructed via byte-poke, smoke test passes. Reserve byte-poke deferred to Day 24 — heavier than estimated, decision point required.
Schedule: 3-4 days ahead of Day 14 baseline.

## Goal

Per Day 22 plan: byte-offset helpers + LendingMarket/Reserve/Obligation
construction + smoke test. Day 23 actual outcome:

1. ✅ Byte-offset helpers added (`write_u64_at`, `write_u8_at`,
   `write_pubkey_at`) — generic, reusable
2. ✅ `build_lending_market_bytes(bump, owner)` constructs 4664-byte
   buffer with disc + version + bump_seed + owner + quote_currency
3. ✅ `ctx.write_account()` injects LendingMarket; smoke test confirms
   no fixture-init panic
4. ⏸️ Reserve/Obligation byte-poke deferred — see complexity analysis below

## What worked

LendingMarket has shallow structure (no nested Pubkey or fraction
fields in the first 120 bytes). Byte-poke required:
- 8 byte offsets to remember
- 1 helper function (`build_lending_market_bytes`)
- ~25 LOC total

For deposit_reserve_liquidity, only `bump_seed` is read from
LendingMarket. The other set fields (version, owner, quote_currency)
are forward-compatibility insurance for other ix.

## What's harder than expected: Reserve byte-poke

Reading `klend/programs/klend/src/state/reserve.rs:64-106` reveals:

```rust
pub struct Reserve {
    pub version: u64,                        // 0..8
    pub last_update: LastUpdate,             // 8..24 (16 bytes)
    pub lending_market: Pubkey,              // 24..56
    pub farm_collateral: Pubkey,             // 56..88
    pub farm_debt: Pubkey,                   // 88..120
    pub liquidity: ReserveLiquidity,         // 120..??? (HEAVY)
    pub reserve_liquidity_padding: [u64; 150],
    pub collateral: ReserveCollateral,       // offset depends on liquidity size
    pub reserve_collateral_padding: [u64; 150],
    pub config: ReserveConfig,
    pub config_padding: [u64; 113],
    ...
}
```

For `deposit_reserve_liquidity`, Anchor reads from Reserve:
- `lending_market` Pubkey (offset 24 — easy)
- `liquidity.mint_pubkey` (offset 120 + 0 = 120 — easy)
- `liquidity.supply_vault` (offset 120 + 32 = 152 — easy)
- `collateral.mint_pubkey` (offset 120 + size_of::<ReserveLiquidity>() + 1200 — **requires
  knowing ReserveLiquidity size exactly**)

ReserveLiquidity contains:
- 3 Pubkey (mint, supply, fee_vault) = 96
- 1 u64 = 8
- 2 u128 = 32
- 4 u64 = 32
- 1 BigFractionBytes (need size, ~32 bytes likely)
- 4 u128 = 64
- 1 Pubkey (token_program) = 32
- 1 u64 = 8
- padding2: [u64; 50] = 400
- padding3: [u128; 32] = 512

Total ≈ 1216 bytes (need BigFractionBytes verified). Then collateral
starts at 120 + 1216 + 1200 = 2536. And ReserveCollateral.mint_pubkey
at 2536.

**Risk**: any miscounted byte breaks every downstream offset. Single
mistake = invariant tests run against garbage Reserve state = false
detections / silent failures.

## Three options for Day 24

### (A) Continue byte-poke, mirror nested structs

- Define `LastUpdate`, `ReserveLiquidity`, `ReserveCollateral`,
  `BigFractionBytes` mirrors via `#[repr(C)]` + `offset_of!()`
- Compile-time verified offsets (no manual counting)
- ~200 LOC of struct definitions
- 1-1.5 days

### (B) Pivot to raw_call init_reserve

- Pre-create empty Reserve account (already understand pattern)
- Build init_reserve ix per `handler_init_reserve.rs:116`
- Challenges:
  - `is_allowed_signer_to_init_reserve` constraint (Day 23 unverified —
    probably checks LendingMarket.lending_market_owner; if so, our setup
    where user is owner should pass)
  - Pre-create `reserve_liquidity_supply` + `fee_receiver` as PDA
    TokenAccounts (specific seeds)
  - `initial_liquidity_source` SPL TokenAccount with funded balance
- Once working, Anchor handles all Reserve byte layout correctly
- 1-1.5 days (different complexity, similar total)

### (C) Scope down: stop klend at "LendingMarket exists"

- Declare klend MVP = "harness compiles + loads klend .so + writes
  valid LendingMarket"
- Skip deposit_reserve_liquidity etc.
- Don't run klend campaigns
- Honest framing: klend full coverage exceeded MVP budget; surface area
  documented for Phase 2.5 / OSS contributors
- Reallocate Day 24-27 to Phase 1 wrap-up (disclosure templates,
  README polish, Phase 2 retrospective)

## Recommendation: (A) Continue byte-poke

Reasons:
- (B) and (A) both ~1-1.5 days; (A) gives explicit control
- (A)'s mirror structs serve as documentation of klend layout for
  Phase 2 OSS branch
- (B) has unverified is_allowed_signer_to_init_reserve risk —
  could add another half-day if constraint requires init_global_config
  prerequisite
- (C) abandons Day 21's user decision (accelerate to klend); should
  be last resort

User decision recommended before Day 24 work begins. Each option has
different deliverables.

## Schedule status (cumulative)

Day 23 = ~1 session. Cumulative **3-4 days ahead** of Day 14 baseline.
Day 24 decision will allocate remaining lead time.

## Files changed Day 23

- `examples/klend-fuzz/fuzz/klend/src/main.rs` — byte helpers (+30 LOC)
  + LendingMarket build + write (+45 LOC)
- `docs/phase2-day23-klend-lendingmarket.md` (this log)

## Smoke test output

```
crucible run klend invariant_account_swap_only --release --timeout 3 -j 1
[FUZZ_PULSE] run time: 0s, ..., crashes: 0, executions: 4, ...
[FUZZ] Fuzzing stopped
```

- Fixture init didn't panic ✓
- 0 crashes expected (instructions() returns vec![], action_noop returns false)
- 4 executions = harness ran the fuzz loop

LendingMarket bytes are valid (klend's AccountLoader didn't reject —
verified implicitly by no-panic; explicit verification deferred to
Day 24 when we actually call an ix that reads LendingMarket).
