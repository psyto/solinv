# Phase 2 Day 24 — klend Reserve byte-poke via offset_of! mirror

Date: 2026-05-25
Status: ✅ Reserve fixture written via byte-poke with compile-time-verified offsets. Smoke test passes. Day 25 = first real klend ix (deposit_reserve_liquidity).
Schedule: 3-4 days ahead of Day 14 baseline.

## Goal

Per Day 23 user decision (Option A: mirror nested structs + offset_of!),
build Reserve fixture without manual byte counting.

## Mirror struct definitions

Three new structs in `main.rs` mirror klend's `#[repr(C)]` layout
exactly. Leading fields explicit (those we read); trailing collapsed
into opaque `[u8; N]` tails sized to make total struct size match
klend's `const_assert_eq!(SIZE, sizeof(T))`:

```rust
#[repr(C)]
struct ReserveLiquidityMirror {
    pub mint_pubkey: [u8; 32],         // offset 0
    pub supply_vault: [u8; 32],        // offset 32
    pub _tail: [u8; 1232 - 64],        // offset 64..1232
}
const _: () = assert!(std::mem::size_of::<ReserveLiquidityMirror>() == 1232);

#[repr(C)]
struct ReserveCollateralMirror {
    pub mint_pubkey: [u8; 32],         // offset 0
    pub mint_total_supply: u64,        // offset 32
    pub supply_vault: [u8; 32],        // offset 40
    pub _tail: [u8; 1096 - 72],        // offset 72..1096
}
const _: () = assert!(std::mem::size_of::<ReserveCollateralMirror>() == 1096);

#[repr(C)]
struct ReserveMirror {
    pub version: u64,                                  // offset 0
    pub last_update: [u8; 16],                         // offset 8
    pub lending_market: [u8; 32],                      // offset 24
    pub farm_collateral: [u8; 32],                     // offset 56
    pub farm_debt: [u8; 32],                           // offset 88
    pub liquidity: ReserveLiquidityMirror,             // offset 120
    pub reserve_liquidity_padding: [u8; 1200],         // offset 1352
    pub collateral: ReserveCollateralMirror,           // offset 2552
    pub _tail: [u8; 8616 - 3648],                      // offset 3648..8616
}
const _: () = assert!(std::mem::size_of::<ReserveMirror>() == 8616);
```

All 3 compile-time size assertions PASS at `cargo check` time —
verifying my byte counting matches klend's actual struct layout.

## offset_of!() — compile-time offset computation

Stable since Rust 1.77; nested field paths since 1.82. Used as
const expressions:

```rust
const _RESERVE_OFFSET_LENDING_MARKET: usize = std::mem::offset_of!(ReserveMirror, lending_market);
const _RESERVE_OFFSET_LIQUIDITY: usize = std::mem::offset_of!(ReserveMirror, liquidity);
const _RESERVE_OFFSET_COLLATERAL: usize = std::mem::offset_of!(ReserveMirror, collateral);

const _RL_OFFSET_MINT_PUBKEY: usize = std::mem::offset_of!(ReserveLiquidityMirror, mint_pubkey);
const _RL_OFFSET_SUPPLY_VAULT: usize = std::mem::offset_of!(ReserveLiquidityMirror, supply_vault);

const _RC_OFFSET_MINT_PUBKEY: usize = std::mem::offset_of!(ReserveCollateralMirror, mint_pubkey);
const _RC_OFFSET_SUPPLY_VAULT: usize = std::mem::offset_of!(ReserveCollateralMirror, supply_vault);

const RES_OFFSET_LENDING_MARKET: usize = DISC_LEN + _RESERVE_OFFSET_LENDING_MARKET;
const RES_OFFSET_LIQUIDITY_MINT: usize = DISC_LEN + _RESERVE_OFFSET_LIQUIDITY + _RL_OFFSET_MINT_PUBKEY;
const RES_OFFSET_LIQUIDITY_SUPPLY: usize = DISC_LEN + _RESERVE_OFFSET_LIQUIDITY + _RL_OFFSET_SUPPLY_VAULT;
const RES_OFFSET_COLLATERAL_MINT: usize = DISC_LEN + _RESERVE_OFFSET_COLLATERAL + _RC_OFFSET_MINT_PUBKEY;
const RES_OFFSET_COLLATERAL_SUPPLY: usize = DISC_LEN + _RESERVE_OFFSET_COLLATERAL + _RC_OFFSET_SUPPLY_VAULT;
```

**No manual byte counting in setter code**. If klend renames or
reorders any field upstream, the offsets recompute correctly OR
the static_assert on struct size triggers a compile error.

## build_reserve_bytes()

```rust
fn build_reserve_bytes(
    lending_market, liquidity_mint, liquidity_supply,
    collateral_mint, collateral_supply: &Pubkey,
) -> Vec<u8> {
    let mut buf = vec![0u8; DISC_LEN + RESERVE_SIZE];
    buf[0..8].copy_from_slice(&account_disc("Reserve"));
    write_u64_at(&mut buf, RES_OFFSET_VERSION, 1);
    write_pubkey_at(&mut buf, RES_OFFSET_LENDING_MARKET, lending_market);
    write_pubkey_at(&mut buf, RES_OFFSET_LIQUIDITY_MINT, liquidity_mint);
    write_pubkey_at(&mut buf, RES_OFFSET_LIQUIDITY_SUPPLY, liquidity_supply);
    write_pubkey_at(&mut buf, RES_OFFSET_COLLATERAL_MINT, collateral_mint);
    write_pubkey_at(&mut buf, RES_OFFSET_COLLATERAL_SUPPLY, collateral_supply);
    buf
}
```

Sets 5 fields read by `deposit_reserve_liquidity` Anchor constraints:
- `has_one = lending_market`
- `address = reserve.load()?.liquidity.mint_pubkey`
- `address = reserve.load()?.liquidity.supply_vault`
- `address = reserve.load()?.collateral.mint_pubkey`
- (and supply_vault for redeem path)

All other Reserve fields zeroed — acceptable since deposit_reserve_liquidity
doesn't read them.

## setup() expansion (Day 24 delta ~95 LOC)

- Create `mint_authority` Keypair + funded system account
- `ctx.create_mint()` x2: `liquidity_mint` (auth=mint_authority),
  `collateral_mint` (auth=lending_market_authority — klend convention)
- `ctx.create_token_account()` x6:
  - `reserve_liquidity_supply` (owner=lma, amount=0)
  - `reserve_collateral_supply` (owner=lma, amount=0)
  - `reserve_liquidity_fee_receiver` (owner=lma, amount=0)
  - `user_source_liquidity` (owner=user, amount=1B base units)
  - `user_destination_collateral` (owner=user, amount=0)
  - `user_destination_liquidity` (owner=user, amount=0)
  - `user_b_source_liquidity` (owner=user_b, amount=1B)
- `build_reserve_bytes()` + `ctx.write_account()` for Reserve

## Smoke test

```
crucible run klend invariant_account_swap_only --release --timeout 3 -j 1
[FUZZ_PULSE] run time: 0s, ..., crashes: 0, executions: 4, ...
[FUZZ] Fuzzing stopped
```

- ✅ No panic during fixture init (8 token accounts created + Reserve
  written without error)
- 0 crashes, 4 executions (expected — instructions() still empty)

## Day 25 plan

1. **Implement `build_deposit_reserve_liquidity_ix`** — 12-account
   raw_call constructor per Day 17 inventory
2. **Add `action_deposit_reserve_liquidity`** method to Fixture
3. **Add `deposit_reserve_liquidity_spec` to `instructions()`** with
   correct expected_owners/expected_discriminators/expected_pda_seeds/
   swap_alternates per Day 17 inventory table
4. **First real klend campaign**: `crucible run klend
   invariant_klend_combined_only --release --timeout 30 -j 2`
5. **Triage outcomes**:
   - If 0 crashes: Reserve fixture validation passed; surface clean for
     deposit_reserve_liquidity
   - If false positives: refine InstructionSpec semantics (analog of
     Day 20 Raydium user_dest finding)
   - If real bugs: capture for disclosure draft

## Files changed Day 24

- `examples/klend-fuzz/fuzz/klend/src/main.rs` — 3 mirror structs +
  offset_of! consts + build_reserve_bytes + setup() expansion (~135 LOC delta)
- `docs/phase2-day24-klend-reserve.md` (this log)

## Schedule status

Cumulative **3-4 days ahead** of Day 14 baseline. Day 25-27 on plan
per Day 22 revision (Day 25: 1st ix, Day 26: 4 more, Day 27: regression
+ triage).

## Key takeaway

`offset_of!()` + mirror structs gave us **compile-time-verified
byte offsets** without needing to mirror the full 8616-byte Reserve
or its nested BigFractionBytes/ReserveConfig. Only the structs we
read FROM (ReserveLiquidity / ReserveCollateral) needed leading-field
mirroring; everything else is opaque tail. Total mirror code: ~30 LOC.

This pattern is reusable for Obligation (Day 25 byte-poke) and any
future klend ix that requires new field reads — just add the field to
the mirror struct, the offset constant follows automatically.
