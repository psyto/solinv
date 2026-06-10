# Phase 2 Day 19 — Raydium AMM Fixture Init (write_account)

Date: 2026-05-25
Status: ✅ Fixture init complete; harness reaches Raydium swap logic; **account-swap invariant already fires** (likely false positive, Day 20 triage).
Schedule: 3-4 days ahead of Day 14 baseline; Day 19+20 collapsing.

## Goal

Day 18 left a compiling scaffold with stubbed pool state. Day 19 wires
in real SPL Token mints + accounts + hand-crafted AmmInfo via the
`write_account` strategy chosen Day 18. Acceptance: `action_swap_base_in_v2`
reaches Raydium's swap logic (past `AmmInfo::load_mut_checked` + signer
+ PDA + vault checks).

## API discoveries (crucible v0.1.0 TestContext)

Found in `crates/crucible-test-context/src/lib.rs:1796-1881` +
`crates/crucible-test-context/src/account_builders.rs`:

| API | Use |
|---|---|
| `ctx.create_mint().pubkey().mint_authority().decimals().create()` | SPL Mint with proper rent + layout |
| `ctx.create_token_account().pubkey().mint().token_owner().amount().create()` | SPL TokenAccount with seed balance |
| `ctx.write_account(addr, Account{...})` | Raw byte inject (for AmmInfo) |
| `ctx.mint_to(mint, dest, amount, &authority)` | CPI to SPL Token mint_to |
| `ctx.transfer_tokens(from, to, &owner, amount)` | CPI to SPL Token transfer |

Builders use `AccountBuilderBase` trait — methods `.pubkey()`, `.owner()`,
`.lamports()` etc. shared across all builder types. Must import via
`use crucible_fuzzer::AccountBuilderBase;` to bring trait methods into
scope.

## Rent computation (no anchor / solana-rent dep)

Inline `rent_for(bytes)` helper:
```rust
const fn rent_for(bytes: usize) -> u64 {
    ((128 + bytes) as u64) * 3480 * 2
}
```
Matches `solana_rent::Rent::default().minimum_balance(bytes)` formula.
Anchor-version-independent — no need to pull anchor_lang into harness.

For AmmInfo (752 bytes): `rent_for(752) = 6_124_800` lamports.

## Critical processor validation chain (SwapBaseInV2)

Per `raydium-amm/program/src/processor.rs:3032-3145`:

1. `AmmInfo::load_mut_checked(amm_info, program_id)`:
   - `account.owner == program_id` ← Day 19 set via `write_account.owner`
   - `account.data_len() == size_of::<AmmInfo>() == 752` ← bytemuck struct
   - `data.status != Uninitialized` ← set to `SwapOnly(6)`
2. `user_source_owner.is_signer` ← user_owner at idx 7, AccountMeta signer=true
3. `token_program == spl_token::id()` ← idx 0
4. `amm_authority_info.key == create_program_address([AUTHORITY_AMM, [nonce]])` ← derived via `find_program_address`, nonce stored in `AmmInfo.nonce`
5. `amm_coin_vault.key == amm.coin_vault` ← set in AmmInfo bytes
6. `amm_pc_vault.key == amm.pc_vault` ← set in AmmInfo bytes
7. `user_source != amm.pc_vault/coin_vault` (anti-self-swap)
8. `AmmStatus::from_u64(amm.status).swap_permission()` — `SwapOnly = true`
9. NOT `orderbook_permission()` (for V2 ix) — `SwapOnly = false` ✓
10. `Calculator::calc_total_without_take_pnl_no_orderbook(pc_vault.amount, coin_vault.amount, &amm)` — needs valid Fees
11. user_source/dest mints match vault mints (Coin2PC or PC2Coin direction)
12. user_source.amount >= amount_in

Day 19 AmmInfo populated to satisfy 1, 4-6, 8-9, 10 (Fees defaults
per state.rs:508-521). Skipped open_orders / market / target_orders
(zeroed, V2 ix doesn't read them).

## Smoke test outcome (HARNESS WORKS)

```
crucible run raydium_amm invariant_swap_base_in_v2_only --release \
            --timeout 5 -j 1
```

Result: **999 violations in 9s wall-clock** at 109 exec/sec.

Sample violation report:
```
[FUZZ_FINDING] summary:[account-swap:675kPX9MHTjS2zt1qfr...] ix
swap_base_in_v2 succeeded with account 6 swapped from
111JV6iBiRLoJUtNieRJ9QmcpE2KPE3gLpDzAUkbNW to
111Q7zKqw7vEw6U5Mf3qDU1UrV3MRubjPcCrT1QftA (different context,
same shape)
```

Account 6 = `user_destination_token` per InstructionSpec layout.
Solinv substituted user A's dest with user B's dest (from
`swap_alternates[6] = vec![self.user_b_dest]`). The ix succeeded
AND state changed → flagged as account-swap violation.

**This confirms the entire harness stack works end-to-end**:
- ✅ Cargo build (debug + release) succeeds
- ✅ Raydium .so loads via add_program
- ✅ AmmInfo write_account produces program-readable bytes
- ✅ SPL Token mints + accounts created correctly
- ✅ AMM authority PDA derivation matches processor's create_program_address
- ✅ action_swap_base_in_v2 + raw_call reaches Raydium swap logic
- ✅ solinv account-swap invariant attacks + detects (1000 violations)

## First detection triage (Day 20 scope, preview)

The reported account-swap on `user_destination` is **likely a false
positive**:

- DEX swap semantics: user signs the ix, output goes to whatever
  `user_destination_token` the user specified (could be their own, a
  receiver's, a router contract, etc.)
- Raydium doesn't validate that `user_destination.owner == user_source_owner`
- This is **intentional permissive design**, not a bug
- Same pattern in Uniswap V2/V3, Orca, Meteora — DEX outputs go to
  any spec'd token account with correct mint

**Day 20 action**: Refine InstructionSpec `swap_alternates` for Raydium:
- account 6 (user_dest): `vec![]` — user-controlled, not context-bound
- account 5 (user_source): keep alternate (substituting source to user_b
  WOULD be unauthorized — user A signs but user B's tokens get debited)
- account 3 (coin_vault): keep alternate (substituting AMM vault is
  the real attack vector — drain other pool's vault into current pool)
- account 4 (pc_vault): keep alternate (same)

After refinement, account-swap should still fire on accounts 3-5 if
the real bug class exists; account 6 false positive eliminated.

## Open questions advanced

Day 16 question #3 ("pda-forge invariant compatibility with non-canonical
`create_program_address` style"): not yet observed firing in this smoke
test. Day 20 isolated `invariant_pda_forge_only` variant will test
explicitly.

Day 18 question (sys_decimal_value choice): 1e9 worked for AmmInfo
validation but actual swap math may produce overflow/underflow. Day 20
will observe.

## Schedule status (cumulative)

| Day | Plan | Actual | Status |
|---|---|---|---|
| 15 | 3 days | 1 day | +2 |
| 16 | 1 day | 1 session | +1 |
| 17 | 1 day | 1 session | +1 |
| 18 | scaffold | 1 session | on track |
| 19 | fixture init | 1 session = init + 1000 detections | **ahead, Day 20 partly done** |

**Cumulative: 3-4 days ahead** of Day 14 baseline. Day 19's outcome
collapses some of Day 20's scope.

## Day 20 plan (refined)

1. **Refine InstructionSpec** swap_alternates per false-positive analysis
2. **Add isolated invariant variants** (signer_skip_only, owner_skip_only,
   pda_forge_only, account_swap_only) like Day 12 pattern
3. **Run sequential regression** for each of 4 applicable invariants
4. **Triage all detections** — categorize as true positive / false
   positive / inconclusive
5. **Document first real Raydium AMM finding** (if any survive triage)

## Files changed Day 19

- `examples/raydium-amm-fuzz/fuzz/raydium_amm/src/main.rs` (setup() expansion ~140 LOC)
- `docs/phase2-day19-raydium-fixture-init.md` (this log)

No new external deps needed (used solana_account::Account already in
crate's transitive). cargo build --release succeeds (verified via
crucible run completing).
