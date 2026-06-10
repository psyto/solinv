# Kamino klend — Instruction Inventory (5 Critical for solinv MVP)

Date: 2026-05-25 (Day 17)
Source: `github.com/Kamino-Finance/klend` @ HEAD (cloned 2026-05-25, BUSL-1.1)
Program ID (mainnet): `KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD`
Program ID (staging): `SLendK7ySfcEzyaFqy93gDnD3RtrpXJcnRwb6zFHJSh`

## Wire format — Anchor 0.29

Standard Anchor convention:
- `data[0..8]` = `sha256("global:<ix_name>")[..8]` (snake_case ix name)
- `data[8..]` = Borsh-encoded args in declaration order

Solinv harness `ix_sighash()` helper (Day 15 raw_call pattern) applies
**directly without modification**. This is the canonical use case for
the raw_call refactor.

## Stack

- **anchor-lang**: 0.29.0
- **solana-program**: ~1.17.18 (so platform-tools v1.39 required for build)
- **borsh**: 0.10.3 with `const-generics` feature
- **rust-toolchain**: 1.74.1 (per `rust-toolchain.toml`)

## License

BUSL-1.1 with parameters:
- Licensor: StroudGlobal S.A.
- Licensed Work: Kamino Lending smart contract (©2025)
- Additional Use Grant: None
- Change Date: 2027-11-17 (becomes GPL-2.0)

**Permitted under BUSL**: copy, modify, derivative works, redistribute,
**non-production use**. Solinv private bug bounty research = local
fuzz against built binary + disclose via Kamino's bounty program =
clear non-production use, **compliant**.

## Handler surface

- `programs/klend/src/handlers/handler_*.rs`: 55 files
- `programs/klend/src/lib.rs`: `#[program]` mod with 63 `pub fn` ix
- 5 chosen for solinv MVP (core lending business logic) below

## 5 ix selected (with V2 variants noted)

| Sighash basis | Args | Accounts | V2 exists? |
|---|---|---|---|
| `deposit_reserve_liquidity` | u64 | 12 | (combined w/ `_and_obligation_collateral_v2`) |
| `redeem_reserve_collateral` | u64 | 12 | — |
| `borrow_obligation_liquidity` | u64 | 12 (1 Option) | `borrow_obligation_liquidity_v2` |
| `repay_obligation_liquidity` | u64 | 8 | `repay_obligation_liquidity_v2` |
| `liquidate_obligation_and_redeem_reserve_collateral` | u64 + u64 + u64 | 20 | `_v2` |

V2 variants add farms_accounts wrappers — defer for MVP, target v1
first.

## Per-ix detail

### deposit_reserve_liquidity (12 accounts)

**Sighash**: `sha256("global:deposit_reserve_liquidity")[..8]` — computed
at harness build via `ix_sighash("deposit_reserve_liquidity")`.

**Args**: `liquidity_amount: u64` (8 bytes LE).

**Wire**: 16 bytes total = 8 sighash + 8 amount.

**AccountMeta order** (per `handler_deposit_reserve_liquidity.rs:100-146`):

| idx | Account | Mut | Signer | Anchor constraint |
|---|---|---|---|---|
| 0 | owner | R | **S** | `Signer` |
| 1 | reserve | W | — | `AccountLoader<Reserve>` + `has_one = lending_market` |
| 2 | lending_market | R | — | `AccountLoader<LendingMarket>` |
| 3 | lending_market_authority | R | — | **PDA** `[b"lma", lending_market]` |
| 4 | reserve_liquidity_mint | R | — | `Mint` + `address = constraint` |
| 5 | reserve_liquidity_supply | W | — | `TokenAccount` + `address = constraint` |
| 6 | reserve_collateral_mint | W | — | `Mint` + `address = constraint` |
| 7 | user_source_liquidity | W | — | `TokenAccount` |
| 8 | user_destination_collateral | W | — | `TokenAccount` |
| 9 | collateral_token_program | R | — | `Program<Token>` |
| 10 | liquidity_token_program | R | — | `Interface<TokenInterface>` |
| 11 | instruction_sysvar_account | R | — | `address = SysInstructions::id()` |

**Solinv invariant applicability**:
- **signer-skip**: account 0 (owner) — Anchor `Signer<>` auto-checks, but
  invariant tests by flipping is_signer flag → high chance of false-
  positive immunity. Still test.
- **owner-skip**: accounts 1-2 (program-owned via `AccountLoader`), 5,
  7, 8 (SPL Token owned via `TokenAccount`)
- **discriminator-skip**: accounts 1, 2 (Anchor account discs on
  `Reserve`, `LendingMarket`)
- **pda-forge**: account 3 (`lending_market_authority`, PDA `[b"lma",
  lending_market_pk]`)
- **account-swap**: accounts 1/2 (reserve/lending_market binding via
  `has_one`), 5/6/7/8 (user-controlled vs reserve-controlled mixup)

### redeem_reserve_collateral (12 accounts)

**Sighash**: `ix_sighash("redeem_reserve_collateral")`.

**Args**: `collateral_amount: u64` (8 bytes LE).

**AccountMeta order** (per `handler_redeem_reserve_collateral.rs:96-143`):

| idx | Account | Mut | Signer | Notes |
|---|---|---|---|---|
| 0 | owner | R | **S** | |
| 1 | lending_market | R | — | |
| 2 | reserve | W | — | `has_one = lending_market` |
| 3 | lending_market_authority | R | — | PDA `[b"lma", lending_market]` |
| 4 | reserve_liquidity_mint | R | — | |
| 5 | reserve_collateral_mint | W | — | |
| 6 | reserve_liquidity_supply | W | — | |
| 7 | user_source_collateral | W | — | |
| 8 | user_destination_liquidity | W | — | `token::authority = owner` |
| 9 | collateral_token_program | R | — | |
| 10 | liquidity_token_program | R | — | |
| 11 | instruction_sysvar_account | R | — | |

Note **account order differs from deposit_reserve_liquidity** —
`lending_market` is idx 1 vs idx 2. Harness must construct each ix
independently, not assume shared layout.

### borrow_obligation_liquidity (11-12 accounts, 1 Option)

**Sighash**: `ix_sighash("borrow_obligation_liquidity")`.

**Args**: `liquidity_amount: u64`.

**AccountMeta order** (per `handler_borrow_obligation_liquidity.rs:171-224`):

| idx | Account | Mut | Signer | Notes |
|---|---|---|---|---|
| 0 | owner | R | **S** | |
| 1 | obligation | W | — | `has_one = lending_market` + `has_one = owner` |
| 2 | lending_market | R | — | |
| 3 | lending_market_authority | R | — | PDA |
| 4 | borrow_reserve | W | — | `has_one = lending_market` |
| 5 | borrow_reserve_liquidity_mint | R | — | |
| 6 | reserve_source_liquidity | W | — | |
| 7 | borrow_reserve_liquidity_fee_receiver | W | — | |
| 8 | user_destination_liquidity | W | — | `token::authority = owner` |
| 9 | referrer_token_state | W | — | **OPTIONAL** — include None as System Program ID |
| 10 | token_program | R | — | |
| 11 | instruction_sysvar_account | R | — | |

`referrer_token_state` is `Option<AccountLoader<ReferrerTokenState>>`.
For MVP, pass system program ID at idx 9 to indicate None per Anchor's
optional account convention.

**Solinv attack surface**:
- account-swap on accounts 1 (obligation) — has_one constraint critical
- has_one bypass test: provide attacker's obligation but with same
  lending_market = test whether owner constraint catches it

### repay_obligation_liquidity (8 accounts)

**Sighash**: `ix_sighash("repay_obligation_liquidity")`.

**Args**: `liquidity_amount: u64`.

**AccountMeta order** (per `handler_repay_obligation_liquidity.rs:113-156`):

| idx | Account | Mut | Signer | Notes |
|---|---|---|---|---|
| 0 | owner | R | **S** | |
| 1 | obligation | W | — | `has_one = lending_market` + cross-check w/ repay_reserve |
| 2 | lending_market | R | — | |
| 3 | repay_reserve | W | — | `has_one = lending_market` |
| 4 | reserve_liquidity_mint | R | — | |
| 5 | reserve_destination_liquidity | W | — | reserve's supply vault |
| 6 | user_source_liquidity | W | — | |
| 7 | token_program | R | — | |
| 8 | instruction_sysvar_account | R | — | `no_restricted_programs_within_tx` check |

Note: **9 accounts total** (idx 0-8). Smallest surface among the 5.

### liquidate_obligation_and_redeem_reserve_collateral (19 accounts)

**Sighash**: `ix_sighash("liquidate_obligation_and_redeem_reserve_collateral")`
(long name, important).

**Args**: 3× u64 = 24 bytes LE concatenated:
- `liquidity_amount: u64`
- `min_acceptable_received_liquidity_amount: u64`
- `max_allowed_ltv_override_percent: u64`

**Wire**: 32 bytes total (8 sighash + 24 args).

**AccountMeta order** (per `handler_liquidate_obligation_and_redeem_reserve_collateral.rs:274-345`):

| idx | Account | Mut | Signer | Notes |
|---|---|---|---|---|
| 0 | liquidator | R | **S** | Note: `liquidator` not `owner` |
| 1 | obligation | W | — | `has_one = lending_market` |
| 2 | lending_market | R | — | |
| 3 | lending_market_authority | R | — | PDA |
| 4 | repay_reserve | W | — | `has_one = lending_market` |
| 5 | repay_reserve_liquidity_mint | R | — | |
| 6 | repay_reserve_liquidity_supply | W | — | |
| 7 | withdraw_reserve | W | — | `has_one = lending_market` |
| 8 | withdraw_reserve_liquidity_mint | R | — | |
| 9 | withdraw_reserve_collateral_mint | W | — | |
| 10 | withdraw_reserve_collateral_supply | W | — | |
| 11 | withdraw_reserve_liquidity_supply | W | — | |
| 12 | withdraw_reserve_liquidity_fee_receiver | W | — | |
| 13 | user_source_liquidity | W | — | |
| 14 | user_destination_collateral | W | — | |
| 15 | user_destination_liquidity | W | — | |
| 16 | collateral_token_program | R | — | |
| 17 | repay_liquidity_token_program | R | — | |
| 18 | withdraw_liquidity_token_program | R | — | |
| 19 | instruction_sysvar_account | R | — | |

20 accounts. Largest surface for solinv-applicable account-swap testing
(cross-reserve swaps, has_one constraint testing on obligation vs
repay_reserve vs withdraw_reserve).

## solinv invariant active surface

| Invariant | Active accounts/ix | Hit rate vs Anchor auto-protection |
|---|---|---|
| signer-skip | 1 per ix (owner/liquidator) | LOW — Anchor `Signer<>` auto-checks |
| owner-skip | program-owned accounts | LOW — `AccountLoader<T>` auto-checks |
| discriminator-skip | program-owned typed accounts | LOW — `AccountLoader<T>` auto-checks |
| pda-forge | lending_market_authority | MEDIUM — `seeds=` + `bump=` constraints catch most |
| account-swap | reserve / obligation / user-token mixups | **HIGH** — Anchor's `has_one` and address-constraint partially protect, but cross-pool/cross-user surface is rich |

**Best solinv-hit candidate on klend = account-swap**. Lending markets'
many cross-reserve / cross-obligation / cross-user account relationships
are the well-known historic attack surface (Mango, Solend, Cypher,
Drift v1 incidents all involved misuse of obligation-collateral
account relationships).

Per Day 16 Native-vs-Anchor analysis, klend's **Anchor 0.29 stack
auto-protects 3-4 of 5 invariants**. Effective solinv hit rate on
klend = 1-2 active invariants. Compensated by **larger bounty
ceiling ($1.5M vs Raydium AMM $505K)** and **richer cross-account
relationships** for account-swap detection.

## InstructionSpec construction recipe (Day 23+)

For `deposit_reserve_liquidity`:

```rust
let deposit_reserve_liquidity_spec = InstructionSpec {
    program_id: klend_program_id,
    name: "deposit_reserve_liquidity".into(),
    accounts: vec![
        AccountMeta::new_readonly(owner.pubkey(), true),
        AccountMeta::new(reserve_pubkey, false),
        AccountMeta::new_readonly(lending_market_pubkey, false),
        AccountMeta::new_readonly(lending_market_authority_pda, false),
        AccountMeta::new_readonly(reserve_liquidity_mint, false),
        AccountMeta::new(reserve_liquidity_supply, false),
        AccountMeta::new(reserve_collateral_mint, false),
        AccountMeta::new(user_source_liquidity, false),
        AccountMeta::new(user_destination_collateral, false),
        AccountMeta::new_readonly(token_program_id, false),
        AccountMeta::new_readonly(token_program_id, false),  // can be Token2022 interface
        AccountMeta::new_readonly(sysvar::instructions::ID, false),
    ],
    signer_indices: vec![0],
    optional_signer_indices: vec![],
    expected_owners: vec![
        None,                                  // 0: native signer
        Some(klend_program_id),               // 1: Reserve owned by klend
        Some(klend_program_id),               // 2: LendingMarket owned by klend
        None,                                  // 3: PDA, no owner check
        Some(spl_token::ID),                  // 4: SPL Mint
        Some(spl_token::ID),                  // 5: SPL TokenAccount
        Some(spl_token::ID),                  // 6: SPL Mint
        Some(spl_token::ID),                  // 7: SPL TokenAccount
        Some(spl_token::ID),                  // 8: SPL TokenAccount
        None, None, None,                      // 9-11: programs/sysvars
    ],
    expected_discriminators: vec![
        None,                                                          // 0
        Some(account_disc("Reserve")),                                 // 1
        Some(account_disc("LendingMarket")),                           // 2
        None, None, None, None, None, None, None, None, None,         // 3-11
    ],
    expected_pda_seeds: vec![
        None, None, None,
        Some(vec![b"lma".to_vec(), lending_market_pubkey.to_bytes().to_vec()]),  // 3
        None, None, None, None, None, None, None, None,
    ],
    creates_indices: vec![],
    swap_alternates: vec![
        vec![],                                  // 0
        vec![alternate_reserve],                 // 1: cross-reserve swap
        vec![],                                  // 2: same lending_market only
        vec![],                                  // 3: PDA
        vec![],                                  // 4
        vec![alternate_reserve_supply],          // 5: cross-reserve supply vault
        vec![],                                  // 6
        vec![other_user_source_liquidity],       // 7: other user
        vec![other_user_destination_collateral], // 8: other user
        vec![],                                  // 9
        vec![],                                  // 10
        vec![],                                  // 11
    ],
    data_sample: build_deposit_reserve_liquidity_data(liquidity_amount: 1000),
    signers: vec![Arc::clone(&owner)],
};
```

## Fixture setup cost estimate

For klend MVP fixture, must construct (in setup() before action_*):
1. `LendingMarket` account (via `init_lending_market` ix) — moderate
2. `Reserve` account for at least 1 token (via `init_reserve` ix) — heavy
   - Requires SPL Token mints (liquidity + collateral)
   - Reserve config (~30 numeric params)
   - Reserve liquidity supply vault + fee vault
3. `Obligation` account (via `init_obligation` ix)
4. User token accounts (multiple)
5. Token mint funding

**Estimate**: full Reserve setup ~5-7 days work to get a working fixture.
**Alternative**: snapshot a real mainnet Reserve via LiteSVM raw account
inject (similar option (B) raised for Raydium AMM). Investigate Day 23.

## Day 18-22 / Day 23+ split (per Option C parallel plan)

- Day 18-22: Raydium AMM MVP (Native, smaller surface, faster to ship)
- Day 23-27: klend MVP (Anchor 0.29, larger setup cost, larger bounty)
- Day 28-30: Triage + disclosure for both protocols

## Sources

- `programs/klend/src/lib.rs:134-345` — `#[program]` mod with ix signatures
- `programs/klend/src/handlers/handler_*.rs` — Accounts structs
- `programs/klend/src/utils/seeds.rs:1` — `LENDING_MARKET_AUTH = b"lma"`
- README.md — bounty + audit refs
- Audit refs: `github.com/Kamino-Finance/audits`
