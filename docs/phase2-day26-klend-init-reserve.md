# Phase 2 Day 26 — klend init_reserve raw_call pivot

Date: 2026-05-25
Status: ✅ init_reserve raw_call succeeds end-to-end. ⚠️ Baseline deposit_reserve_liquidity STILL fails — ReserveConfig defaults (status=Hidden, deposit_limit=0) block normal flow.
Schedule: 3-4 days ahead of Day 14 baseline. **Day 27 decision required**.

## Goal (Day 25 Option B)

Replace Day 24 Reserve byte-poke with Anchor's `init_reserve` ix via
raw_call. Expected outcome: Reserve struct populated correctly by
Anchor → baseline deposit_reserve_liquidity succeeds → solinv attacks
reach account-validation surface.

## What worked

### Permission check is simple

`is_allowed_signer_to_init_reserve` (per `lending_operations.rs:4216`):
```rust
signer == lending_market.lending_market_owner ||
signer == lending_market.proposer_authority
```

Our LendingMarket byte-poke (Day 23) sets `lending_market_owner =
user.pubkey()`. User passes. No `init_global_config` prerequisite.

### Pre-creation footprint smaller than expected

Reading `handler_init_reserve.rs:23-113` reveals:
- **`reserve_liquidity_supply`**: handler calls `account_ops::
  initialize_pda_token_account` (lines 39-47). Pass empty PDA pubkey.
- **`fee_receiver`**: same handler call (lines 49-57). Pass empty PDA
  pubkey.
- **`reserve_collateral_mint`**: Anchor `#[account(init,...)]` creates
  during ix dispatch. Pass empty PDA pubkey.
- **`reserve_collateral_supply`**: same Anchor `init`. Pass empty PDA
  pubkey.

So 4 of the 12 accounts are constructed BY init_reserve itself. No
pre-creation needed beyond their derived PDA addresses.

### Pre-create the Reserve account itself (Anchor `#[account(zero)]`)

`reserve` is `#[account(zero)] AccountLoader<Reserve>`. Anchor requires:
- owner == program_id
- data == all zeros (including disc bytes 0..8)
- rent-exempt lamports

`ctx.write_account()` with `Account { data: vec![0; 8 + RESERVE_SIZE],
owner: program_id, lamports: rent_for(8632), ... }` does the job.

### init_reserve raw_call invocation

13-account `Instruction` (counted right per handler_init_reserve.rs:
116-184): signer, lending_market, lma, reserve, liquidity_mint,
liquidity_supply, fee_receiver, collateral_mint, collateral_supply,
initial_liquidity_source (= user_source_liquidity), rent_sysvar,
liquidity_token_program, collateral_token_program, system_program.

Dispatched via:
```rust
ctx.raw_call(init_ix)
    .fee_payer(&*fee_payer)
    .signers(&[&*user])
    .send()
    .expect("init_reserve failed");
```

## What proved insufficient

Smoke test (10s combined invariant variant):
- 977 executions over 1m22s wall time
- 0 crashes (no solinv violations)
- 0 panics in setup (init_reserve raw_call succeeded across all
  iterations — `.expect()` never fired)
- **ok ratio: 0/106528 (0%)** — baseline `deposit_reserve_liquidity`
  STILL fails

## Root cause of continued 0% ok

`handler_init_reserve.rs:95-99` sets:
```rust
config: Box::new(ReserveConfig {
    status: ReserveStatus::Hidden.into(),  // = 2
    ..Default::default()                    // deposit_limit=0, etc.
}),
```

Newly-initialized reserves are in **Hidden status with zero
deposit_limit**. By Kamino design, admin must call `update_reserve_config`
to set `status=Active` + `deposit_limit>0` before users can deposit.

`deposit_reserve_liquidity_checks` passes Hidden status (only rejects
Obsolete), but downstream `lending_operations::deposit_reserve_liquidity`
likely rejects deposits when `deposit_limit == 0` (or amount check
against total deposits).

## So init_reserve alone wasn't enough — but the pattern is proven

Day 26 milestones:
- ✅ init_reserve raw_call works end-to-end (signer perm + PDA setup +
  Anchor init + handler logic all succeed)
- ✅ Reserve is structurally correct (Anchor wrote disc + populated
  ReserveLiquidity + ReserveCollateral + ReserveConfig + lending_market
  binding)
- ✅ 4 PDA accounts created (liquidity_supply + fee_receiver +
  collateral_mint + collateral_supply)
- ✅ Pattern transferable to any other Anchor `#[account(zero)]` init
  flow

## Day 27 decision required (3 options)

### (A) Add update_reserve_config raw_call to setup()

- Check `is_allowed_signer_to_update_reserve_config` — needs
  `initialization_phase` flag, mode-specific permission
  (proposer_authority_locked == false, reserve_is_used == false,
  reserve_is_usage_blocked == true)
- Set `status` mode → Active
- Set `deposit_limit` mode → e.g., 100_000_000
- Possibly set `borrow_limit` mode → similar
- Possibly set `max_age_price_seconds` mode → 600 (else `refresh_reserve`
  rejects stale prices)
- 0.5-1 day investigation; might hit oracle-config requirement

### (B) Byte-poke ReserveConfig.status + deposit_limit post-init

- After init_reserve writes Reserve, manually patch 2 bytes:
  - status byte: 2 (Hidden) → 0 (Active)
  - deposit_limit u64: 0 → 100_000_000
- Need to find byte offsets within ReserveConfig. Two ways:
  - Extend ReserveMirror with ReserveConfig sub-mirror (~30+ field
    declarations)
  - Read Reserve account back after init_reserve, find `2u8` byte
    pattern, set to 0 (fragile, exact byte search)
- 1 day

### (C) Accept current state, document, declare Phase 2 done

- klend infrastructure validated: harness loads .so, fixture passes
  Anchor init checks, raw_call ix dispatched correctly, no panics
- Depth gated by ReserveConfig defaults (Hidden + 0 limits) — same
  outcome as Day 25
- Day 27-30 → Phase 1 wrap-up / retrospective / disclosure templates

## Recommendation: **(B) byte-poke 2 fields**

Reasons:
- (A) requires understanding update_reserve_config's permission tree
  per mode + likely oracle-config dependency = high uncertainty
- (B) is bounded scope: find 2 byte offsets via ReserveMirror extension
  (already have offset_of! infrastructure), patch 2 bytes
- (C) feels premature — we have momentum and the next step is small
- Combined Day 26+27 spend: 2 days for both init_reserve + 2-field
  patch = ~complete depth coverage

Note: even with depth unblocked, solinv may still find 0 detections
(Raydium SwapBaseInV2 outcome). The value is **confirming** klend
account-validation surface is clean, not finding bugs.

## Files changed Day 26

- `examples/klend-fuzz/fuzz/klend/src/main.rs`:
  - Removed: Day 24 manual collateral_mint + reserve vault creations
    + build_reserve_bytes call
  - Added: 4 PDA seed constants (RESERVE_LIQ_SUPPLY / FEE_RECEIVER /
    RESERVE_COLL_MINT / RESERVE_COLL_SUPPLY)
  - Added: build_init_reserve_ix (13-account constructor)
  - Refactored: setup() to derive 4 PDAs + pre-create empty reserve +
    init_reserve raw_call + post-init user_destination_collateral
    creation
  - Total ~85 LOC delta
- `docs/phase2-day26-klend-init-reserve.md` (this log)

## Schedule

Cumulative **3-4 days ahead** of Day 14 baseline. Day 27 decision
allocates remaining lead time.
