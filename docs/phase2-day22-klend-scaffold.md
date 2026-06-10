# Phase 2 Day 22 — Kamino klend Harness Scaffold

Date: 2026-05-25
Status: ✅ Scaffold compiles. Day 23 = fixture init strategy decision + Reserve/LendingMarket byte construction.
Schedule: continues 3-4 days ahead of Day 14 baseline.

## Goal

Per Day 21 user decision (Option B: accelerate to klend), Day 22
mirrors Day 18's Raydium AMM scaffold pattern. Deliverables:

1. ✅ Directory scaffold at `examples/klend-fuzz/`
2. ✅ Cargo.toml — workspace opt-out, deps mirror raydium-amm-fuzz
3. ✅ Constants, helpers (ix_sighash, account_disc, rent_for)
4. ✅ KlendFixture struct + setup() stub + HasContext/HasInstructionSet
5. ✅ 5 isolated invariant variants (Anchor klend = 5/5 applicable
   vs Raydium Native's 4/5; discriminator-skip is back)
6. ✅ `cargo check` passes (0.59s, 11 warnings — all dead-code Day 23+)

## Key differences from Raydium AMM scaffold (Day 18)

| Aspect | Raydium AMM (Day 18) | klend (Day 22) |
|---|---|---|
| Account framework | Native (`#[repr(C, packed)]`) | Anchor zero-copy (`#[account(zero_copy)] #[repr(C)]`) |
| Wire data prefix | u8 enum tag | 8-byte sha256 sighash |
| Account data prefix | none | 8-byte sha256 disc |
| Applicable invariants | 4 (no discriminator-skip) | **5** (discriminator-skip active) |
| Struct mirror approach | Full bytemuck::Pod for AmmInfo (752 bytes) | **Skip full mirrors** — byte-poke selected offsets (Day 23) |
| State sizes | 752 bytes | LendingMarket=4656, Reserve=8616, Obligation=3336 |
| Best expected invariant | (all 4 equally low after Day 20) | **account-swap (Day 17 finding)** |

## Strategic deviation: skip bytemuck struct mirrors

Day 18 Raydium AMM = `AmmInfoMirror` with `#[repr(C, packed)]` +
bytemuck Pod + compile-time `assert!(size_of == 752)`. Worked
cleanly because:
- AmmInfo is small (752 bytes)
- `#[repr(C, packed)]` = no alignment ambiguity
- Only ~15 fields mattered for swap validation; others zero-init OK

klend = `Reserve` (8616 bytes), `LendingMarket` (4656 bytes),
`Obligation` (3336 bytes). Each has:
- Many u128 / embedded struct fields
- `#[repr(C)]` (NOT packed) = compiler-determined alignment padding
- 30+ ReserveConfig fields
- Anchor zero-copy = 8-byte discriminator prefix

**Decision**: skip full struct mirrors. Use byte-level writes:
```rust
let mut bytes = vec![0u8; RESERVE_SIZE + 8];  // +8 for disc
bytes[0..8].copy_from_slice(&account_disc("Reserve"));
// Set specific u64/Pubkey fields at known offsets via byte_field_at()
// helpers — Day 23 implementation
```

Trade-off:
- ✅ Avoid ~600 LOC of mirror struct definitions (3 large structs)
- ✅ More resilient to klend layout updates (only fail when accessed
  fields move, not when ANY field moves)
- ❌ No compile-time size assertion (must trust `RESERVE_SIZE` const
  matches klend upstream; Day 23 will add runtime assertion via
  reading actual on-chain account if needed)
- ❌ Byte-offset helpers fragile if Anchor adds padding; mitigated
  by setting only fields whose offset is unambiguous (first few fields
  + Pubkey fields which Anchor places adjacently)

## Stack confirmed (Day 17 carries forward)

| Component | Value |
|---|---|
| anchor-lang | 0.29.0 |
| solana-program | 1.17.18 |
| borsh | 0.10.3 |
| Rust toolchain | 1.74.1 (rust-toolchain.toml) |
| Build incantation | `SDKROOT=$(xcrun --show-sdk-path) CFLAGS=... cargo build-sbf --tools-version v1.39` |
| Binary location | `~/src/klend/target/deploy/kamino_lending.so` |

## Constants seeded in main.rs

| Const | Value | Source |
|---|---|---|
| `KLEND_SO_PATH` | absolute path to .so | hardcoded (Day 22 portability TODO) |
| Program ID | `KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD` | klend Anchor.toml |
| `LENDING_MARKET_AUTH` | `b"lma"` | klend utils/seeds.rs:1 (Day 17) |
| `LENDING_MARKET_SIZE` | 4656 | klend utils/consts.rs |
| `RESERVE_SIZE` | 8616 | klend utils/consts.rs |
| `OBLIGATION_SIZE` | 3336 | klend utils/consts.rs |

## Fixture struct layout

```rust
struct KlendFixture {
    pub ctx: TestContext,
    program_id: Pubkey,
    fee_payer: Arc<Keypair>,

    // Pool-level (Day 23 populates via write_account on SIZE-byte buffers)
    lending_market: Pubkey,
    lending_market_authority: Pubkey,  // PDA: [b"lma", lending_market]
    lending_market_bump: u8,
    reserve: Pubkey,
    obligation: Pubkey,                 // user A's obligation

    // Mints + supplies
    liquidity_mint, collateral_mint,
    reserve_liquidity_supply, reserve_collateral_supply,
    reserve_liquidity_fee_receiver: Pubkey,

    // User A (primary)
    user: Arc<Keypair>,
    user_source_liquidity, user_destination_collateral,
    user_destination_liquidity: Pubkey,

    // User B (account-swap detection — Day 17 finding)
    user_b: Arc<Keypair>,
    obligation_b: Pubkey,
    user_b_source_liquidity: Pubkey,
}
```

Currently all Pubkey fields are `Pubkey::new_unique()` placeholders.
Day 23 populates via:
- `ctx.create_mint()` for the 2 mints
- `ctx.create_token_account()` for the 5 token accounts (supply,
  fee receiver, 3 user accounts; +1 for user_b)
- `ctx.write_account()` for LendingMarket / Reserve / Obligation /
  obligation_b with `data = vec![0; SIZE + 8]` + disc prefix + selected
  field bytes set

## 5 invariant variants (all applicable)

Cargo features:
- `invariant_klend_combined_only` (all 5 chained, first-violation-wins)
- `invariant_signer_skip_only`
- `invariant_owner_skip_only`
- `invariant_discriminator_skip_only` (active — klend is Anchor)
- `invariant_pda_forge_only`
- `invariant_account_swap_only` (expected best per Day 17)

## Day 23 plan

1. **Fixture init strategy decision** (parallel to Day 18 strategy
   decision for Raydium):
   - **(A) Byte-poke + write_account** (chosen direction per "skip
     bytemuck mirrors" above): set discriminator + 5-10 key fields
     at known byte offsets in each struct's zero-buffer
   - (B) Full init via on-chain ix chain (`init_global_config`,
     `init_lending_market`, `init_reserve`, `init_obligation`) — too
     heavy, 100+ accounts to set up
   - (C) Mainnet snapshot via RPC fetch + LiteSVM raw inject — adds
     RPC dep, snapshot freshness concern
2. **Implement byte-offset helpers** (~50 LOC):
   ```rust
   fn write_u64_at(buf: &mut [u8], offset: usize, val: u64) { ... }
   fn write_pubkey_at(buf: &mut [u8], offset: usize, pk: &Pubkey) { ... }
   fn write_u8_at(buf: &mut [u8], offset: usize, val: u8) { ... }
   ```
3. **Construct LendingMarket bytes**:
   - disc[0..8] = `account_disc("LendingMarket")`
   - version (u64 at offset 8)
   - bump_seed (u64 at offset 16) = `lending_market_bump`
   - lending_market_owner Pubkey at offset 24
   - lending_market_owner_cached Pubkey at offset 56
   - quote_currency [u8; 32] at offset 88 — set to "USDC" padded
   - rest = zero (acceptable — many u8 flags default to 0)
4. **Construct Reserve bytes** — largest, ~30 fields to set:
   - disc, version, last_update, lending_market binding, liquidity_mint,
     liquidity_supply, collateral_mint, collateral_supply, fee_receiver
5. **Construct Obligation bytes** (lighter):
   - disc, owner = user.pubkey(), lending_market binding,
     deposits/borrows = empty
6. **Validation step**: run `crucible run klend invariant_klend_combined_only
   --release --timeout 5 -j 1` to verify ix dispatches reach the
   processor (similar to Day 19 smoke test for Raydium).

## Day 24+ plan (revised post-Day 22)

Original Day 17 plan said Days 23-27 for klend MVP. Day 22 scaffold
ahead of plan; revised:

- Day 23: Byte-poke fixture init + smoke test
- Day 24: `deposit_reserve_liquidity` InstructionSpec + isolated regression
- Day 25: 4 more ix InstructionSpecs (redeem / borrow / repay / liquidate)
- Day 26: Sequential regression all 5 inv × 5 ix = 25 combinations + triage
- Day 27: If detections, prepare disclosure draft
- Day 28-30: Buffer for triage / disclosure / final Raydium pass

## Files added Day 22

- `examples/klend-fuzz/README.md`
- `examples/klend-fuzz/fuzz/klend/Cargo.toml`
- `examples/klend-fuzz/fuzz/klend/src/main.rs`
- `docs/phase2-day22-klend-scaffold.md` (this log)

No external klend code committed to solinv repo.

## Schedule status

Cumulative **3-4 days ahead** of Day 14 baseline. Day 23+ on plan.
