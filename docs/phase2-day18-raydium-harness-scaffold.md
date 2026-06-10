# Phase 2 Day 18 — Raydium AMM Harness Scaffold

Date: 2026-05-25
Status: ✅ Scaffold compiles. Day 19 = real pool init via write_account. Day 20 = first fuzz campaign.
Schedule: continues 3-4 days ahead of Day 14 baseline.

## Goal

Establish the harness skeleton so Day 19 can focus on `write_account`-
based pool init and Day 20 can run the first fuzz campaign. Day 18
deliverables:

1. ✅ Directory scaffold at `examples/raydium-amm-fuzz/`
2. ✅ Cargo.toml with workspace opt-out + mirrored deps from escrow-demo
3. ✅ AmmInfo wire mirror (`AmmInfoMirror`) with compile-time 752-byte
   size assertion
4. ✅ `build_swap_base_in_v2_ix` raw_call constructor
5. ✅ `RaydiumAmmFixture` + setup() stub + action_swap_base_in_v2 +
   HasContext/HasInstructionSet impls
6. ✅ `cargo check` passes (29.61s, 13 warnings — all future-use
   constants or proc-macro-consumed methods, matches escrow-demo
   pattern)

## Fixture strategy decision: (C) Hand-craft AmmInfo

**Three options considered** (per Day 16 open question):
- (A) Full Initialize2 in fixture — 21 accounts, needs OpenBook market = ~3-5 days
- (B) Snapshot mainnet pool via LiteSVM raw inject — needs RPC fetch +
  snapshot refresh logic = ~2 days
- (C) Hand-craft AmmInfo bytes via `ctx.write_account()` — local-only,
  no RPC = ~1 day

**Chose (C)** because:
- TestContext exposes `write_account(address, Account)` which accepts
  raw bytes (verified in crucible v0.1.0 source at line 2009)
- Forces understanding of AmmInfo wire layout (~750 bytes) — beneficial
  for triaging fuzz violations later
- No external dependency on mainnet RPC freshness or program-ID match
- Easy to extend to (B) later if snapshot becomes valuable

## AmmInfo wire mirror

Defined as `AmmInfoMirror` in `fuzz/raydium_amm/src/main.rs`. Layout:

```
#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
struct AmmInfoMirror {
    // 16 u64 head (status, nonce, ..., sys_decimal_value) = 128 bytes
    status: u64, nonce: u64, ...,
    // Fees: 8 u64 = 64 bytes
    fees: FeesMirror,
    // StateData: 7 u64 + [u64;2] + u64 + 3 u128 + 2 u64 + 2 u128 = 144 bytes
    state_data: StateDataMirror,
    // 9 Pubkey ([u8; 32]) = 288 bytes
    coin_vault, pc_vault, ..., target_orders: [u8; 32],
    // padding1 [u64; 8] = 64 bytes
    // amm_owner [u8; 32] = 32 bytes
    // 4 u64 tail = 32 bytes
}
// Total: 128 + 64 + 144 + 288 + 64 + 32 + 32 = 752 bytes
```

Compile-time check via:
```rust
const _: () = {
    let actual = std::mem::size_of::<AmmInfoMirror>();
    assert!(actual == 752, "AmmInfoMirror size mismatch ...");
};
```

If Raydium upstream changes the layout, this assertion fires at
`cargo check` time. **Re-verified each rebuild**.

**Note on Pubkey storage**: solana-pubkey 3.0 does NOT implement
bytemuck::Pod (checked: no `impl Pod` in src/lib.rs). Stored as raw
`[u8; 32]` in mirror; convert via `Pubkey::to_bytes()` /
`Pubkey::new_from_array` at boundaries.

## raw_call ix constructor for SwapBaseInV2

```rust
fn build_swap_base_in_v2_ix(
    program_id, spl_token, amm_pool, amm_authority,
    coin_vault, pc_vault, user_source, user_dest, user_owner: Pubkey,
    amount_in: u64,
    minimum_amount_out: u64,
) -> Instruction {
    let mut data = Vec::with_capacity(17);
    data.push(16);  // IX_TAG_SWAP_BASE_IN_V2
    data.extend_from_slice(&amount_in.to_le_bytes());
    data.extend_from_slice(&minimum_amount_out.to_le_bytes());

    Instruction {
        program_id,
        accounts: vec![ /* 8 AccountMeta per Day 16 inventory */ ],
        data,
    }
}
```

Wire format: `[tag(1), amount_in(8), min_amount_out(8)]` = 17 bytes.
Confirms Day 16 inventory mapping.

## RaydiumAmmFixture struct

Mirrors escrow-demo's EscrowFixture Day 11/12 pattern:
- `ctx: TestContext` (public, hard requirement for `#[fuzz_fixture]`)
- `program_id: Pubkey`
- `fee_payer: Arc<Keypair>` (separated from business signer, Day 11 lesson)
- Pool keys: `amm_pool`, `amm_authority`, `amm_nonce`, `coin_vault`,
  `pc_vault`, `coin_mint`, `pc_mint`
- User A keys (primary): `user`, `user_source`, `user_dest`
- User B keys (alternate for account_swap detection, Day 12 lesson):
  `user_b`, `user_b_source`, `user_b_dest`

## setup() stub (Day 19 fills in)

Currently:
1. Loads Raydium AMM .so via `ctx.add_program(&id, RAYDIUM_AMM_SO_PATH)`
2. Creates fee_payer, user, user_b system accounts (lamports only, no data)
3. Derives AMM authority PDA = `find_program_address([b"amm authority"], program_id)`
4. **Pool/vault/mint pubkeys are `Pubkey::new_unique()` placeholders**
   — no on-chain accounts created yet (Day 19 writes them)

Calling `action_swap_base_in_v2` on this fixture would fail at the
Raydium program's first `load_mut_checked` because `amm_pool` doesn't
exist on-chain. **This is expected for Day 18 — the scaffold compiles
but isn't yet runnable**.

## Day 19 work (next session, ~1 session)

1. **Build minimal AmmInfo via AmmInfoMirror::zeroed()**:
   - Set `status = AMM_STATUS_SWAP_ONLY` (6) so `load_mut_checked`
     passes the "not Uninitialized" assertion
   - Set `nonce = amm_nonce` (from PDA derivation)
   - Set `coin_vault` / `pc_vault` to created token account pubkeys
   - Set `coin_vault_mint` / `pc_vault_mint` to created mint pubkeys
   - Set `coin_decimals` / `pc_decimals` / `sys_decimal_value`
   - Set `fees` to reasonable defaults (per Fees::initialize)
   - Leave other fields zeroed (open_orders, market, etc. — V2 ix bypasses orderbook)

2. **Write AmmInfo via ctx.write_account()**:
   ```rust
   let mut amm_info = AmmInfoMirror::zeroed();
   amm_info.status = AMM_STATUS_SWAP_ONLY;
   // ... set other fields
   let bytes = bytemuck::bytes_of(&amm_info).to_vec();
   ctx.write_account(&amm_pool, Account {
       lamports: rent_exempt_for(752),
       data: bytes,
       owner: program_id,
       executable: false,
       rent_epoch: 0,
   }).unwrap();
   ```

3. **Create SPL Token mints + accounts**:
   - 2 mints (coin_mint, pc_mint) — via SPL Token initialize_mint ix
     OR hand-crafted Mint account bytes
   - 2 vaults (coin_vault, pc_vault) — TokenAccounts owned by amm_authority
   - 4 user token accounts (user_source/dest, user_b_source/dest) —
     owned by respective users
   - Seed vaults + user_source with token balances

4. **Verify action_swap_base_in_v2 with naive params executes** (not
   necessarily successfully — just reaches the program's swap logic
   rather than failing at AmmInfo load).

## Day 20 work (Day 19+1)

1. Run `crucible run raydium_amm invariant_swap_base_in_v2_only
   --release --timeout 30 -j 2`
2. Iterate on InstructionSpec metadata + swap_alternates as fuzz
   reveals which violations fire
3. Capture first detection counts vs escrow-demo Day 13 baselines
4. Triage any unexpected non-detection (likely pda-forge on
   create_program_address vs find_program_address style — Day 16
   open question #3)

## Validation: Day 18 scaffold compiles cleanly

```
cd examples/raydium-amm-fuzz/fuzz/raydium_amm
cargo check
→ Finished `dev` profile [unoptimized + debuginfo] target(s) in 29.61s
  13 warnings (all dead-code / proc-macro-consumed methods)
  0 errors
```

Warnings match escrow-demo's pattern post-Day-15 refactor.

## Files added

- `examples/raydium-amm-fuzz/README.md`
- `examples/raydium-amm-fuzz/fuzz/raydium_amm/Cargo.toml`
- `examples/raydium-amm-fuzz/fuzz/raydium_amm/src/main.rs`
- `docs/phase2-day18-raydium-harness-scaffold.md` (this log)

No external Raydium AMM code committed to solinv repo.

## Schedule status (cumulative)

| Day | Plan | Actual | Status |
|---|---|---|---|
| 15 | 3 days | 1 day | +2 |
| 16 | 1 day | 1 session | +1 |
| 17 | 1 day | 1 session | +1 |
| 18 | (Day 18-22 = 5 days planned for Raydium MVP) | 1 session = scaffold | on track |

Cumulative: **still 3-4 days ahead** of Day 14 baseline. Day 19-20
will continue the Raydium MVP on plan.
