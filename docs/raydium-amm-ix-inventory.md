# Raydium AMM — Instruction Inventory (5-7 Critical for solinv MVP)

Date: 2026-05-25 (Day 16)
Source: `github.com/raydium-io/raydium-amm` @ HEAD (cloned 2026-05-25)
Program ID (mainnet): `675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8`
Program ID (devnet):  `DRaya7Kj3aMWQSy19kSjvmuwq9docCHofyP9kanQGaav`

## Wire format — Native (NOT Anchor)

Raydium AMM is a **Native Solana program** with no Anchor dependencies.
Wire format:
- `data[0]` = u8 instruction tag (enum discriminant, NOT sha256 sighash)
- `data[1..]` = args concatenated as **little-endian primitives** in field
  declaration order. `Option<T>` is encoded as **0 bytes if None**, or
  **payload-only if Some** (NO discriminant byte — non-standard, see
  pack() in `program/src/instruction.rs:686-898`).

Solinv harness `ix_sighash()` helper (Day 15 raw_call pattern) does
**NOT apply** to Raydium AMM. Use single-byte tag instead.

## Full ix enum (18 variants, tags 0-17)

Per `instruction.rs:137-396` and `unpack()` at line 400:

| Tag | Variant | Status | Accounts | Args |
|---|---|---|---|---|
| 0 | Initialize | DEPRECATED — use Initialize2 | 21 | u8 + u64 |
| 1 | Initialize2 | live | 21 | u8 + u64 + u64 + u64 |
| 2 | MonitorStep | live | 20 | u16 + u16 + u16 |
| 3 | **Deposit** | live | 14 | u64 + u64 + u64 + Option<u64> |
| 4 | **Withdraw** | live | 20 | u64 + Option<(u64,u64)> |
| 5 | MigrateToOpenBook | live | 21 | none |
| 6 | SetParams | admin only | 17 | variant |
| 7 | WithdrawPnl | admin only | 18 | none |
| 8 | WithdrawSrm | admin only | 6 | u64 |
| 9 | **SwapBaseIn** (orderbook) | live | 18 | u64 + u64 |
| 10 | PreInitialize | DEPRECATED | — | u8 |
| 11 | **SwapBaseOut** (orderbook) | live | 18 | u64 + u64 |
| 12 | SimulateInfo | view-only | — | variant |
| 13 | AdminCancelOrders | admin only | — | u16 |
| 14 | CreateConfigAccount | admin only | — | none |
| 15 | UpdateConfigAccount | admin only | — | variant |
| 16 | **SwapBaseInV2** (no orderbook) | live | **8** | u64 + u64 |
| 17 | **SwapBaseOutV2** (no orderbook) | live | **8** | u64 + u64 |

## Selected 6 for solinv MVP (Day 18-22)

Bolded above. Selection rationale:

- **Skip**: Initialize2 (21 accounts + requires real OpenBook market =
  too heavy for first MVP fixture)
- **Skip**: admin ix (6, 7, 8, 13-15) — solinv invariants don't target
  governance paths
- **Include**: Deposit + Withdraw — user-facing pool participation,
  AccountMeta swap surface for cross-user attacks
- **Include**: SwapBaseInV2 + SwapBaseOutV2 (tags 16, 17) — **modern
  orderbook-disabled swaps, 8 accounts each, minimum surface, dominant
  trading path on current Raydium**
- **Include**: SwapBaseIn + SwapBaseOut (tags 9, 11) — legacy orderbook
  swaps, 18 accounts each, larger surface = more invariant coverage

## Per-ix detail

### Tag 3 — Deposit (14 accounts)

**Wire bytes**: `[3, max_coin: u64 LE, max_pc: u64 LE, base_side: u64 LE
{, other_amount_min: u64 LE if Some}]` = 25 or 33 bytes total.

**AccountMeta order** (from `instruction.rs:970` `pub fn deposit(...)`
ground truth):

| idx | Account | Mut | Signer | Notes |
|---|---|---|---|---|
| 0 | SPL Token program | R | — | `spl_token::id()` |
| 1 | AMM pool | W | — | `Account<AmmInfo>` analog |
| 2 | AMM authority | R | — | **PDA** `[AUTHORITY_AMM, [nonce]]` |
| 3 | AMM open orders | R | — | |
| 4 | AMM target orders | W | — | |
| 5 | AMM lp mint | W | — | Owned by authority |
| 6 | AMM coin vault | W | — | |
| 7 | AMM pc vault | W | — | |
| 8 | Market (OpenBook) | R | — | |
| 9 | User coin token | W | — | User-controlled |
| 10 | User pc token | W | — | User-controlled |
| 11 | User lp token | W | — | User-controlled (mint dest) |
| 12 | User wallet | R | **S** | **signer surface** |
| 13 | Market event queue | R | — | |

**Solinv attack surface**:
- signer-skip: account 12 (user wallet)
- account-swap: 9/10/11 (cross-user token accounts), 6/7 (AMM vault swap)
- pda-forge: account 2 (AMM authority)
- owner-skip: 6/7 (vaults should be SPL Token-owned, authority-owned)

### Tag 4 — Withdraw (20 accounts)

**Wire bytes**: `[4, amount: u64 LE {, min_coin: u64 LE, min_pc: u64 LE
if both Some}]` = 9 or 25 bytes total.

**AccountMeta order** (from `instruction.rs:1027` `pub fn withdraw(...)`):
20 accounts including market bids/asks/event_queue/coin_vault/pc_vault
+ user lp/coin/pc + user wallet (signer at idx 16). Full list per
enum doc at `instruction.rs:212-234`.

**Solinv attack surface**: same classes as Deposit, larger account graph
= more swap_alternates surface.

### Tag 9 — SwapBaseIn (18 accounts, with orderbook)

**Wire bytes**: `[9, amount_in: u64 LE, minimum_amount_out: u64 LE]` =
17 bytes total.

**AccountMeta order** (from `instruction.rs:1101` + enum doc at
`instruction.rs:314-334`):

| idx | Account | Mut | Signer |
|---|---|---|---|
| 0 | SPL Token | R | — |
| 1 | AMM pool | W | — |
| 2 | AMM authority | R | — (PDA) |
| 3 | AMM open orders | W | — |
| 4 | AMM target orders (optional, deprecated) | W | — |
| 5 | AMM coin vault | W | — |
| 6 | AMM pc vault | W | — |
| 7 | Market program | R | — |
| 8 | Market | W | — |
| 9 | Market bids | W | — |
| 10 | Market asks | W | — |
| 11 | Market event queue | W | — |
| 12 | Market coin vault | W | — |
| 13 | Market pc vault | W | — |
| 14 | Market vault signer | R | — |
| 15 | User source token | W | — |
| 16 | User destination token | W | — |
| 17 | User wallet | R | **S** |

### Tag 11 — SwapBaseOut (18 accounts, with orderbook)

Same account layout as SwapBaseIn; wire format `[11, max_amount_in: u64 LE,
amount_out: u64 LE]` = 17 bytes.

### Tag 16 — SwapBaseInV2 (8 accounts, no orderbook) ⭐ PRIMARY MVP TARGET

**Wire bytes**: `[16, amount_in: u64 LE, minimum_amount_out: u64 LE]` =
17 bytes total.

**AccountMeta order** (from `instruction.rs:1162` `pub fn swap_base_in_v2`,
verbatim):

| idx | Account | Mut | Signer | Notes |
|---|---|---|---|---|
| 0 | SPL Token | R | — | `spl_token::id()` |
| 1 | AMM pool | W | — | |
| 2 | AMM authority | R | — | **PDA** `[AUTHORITY_AMM, [nonce]]` |
| 3 | AMM coin vault | W | — | |
| 4 | AMM pc vault | W | — | |
| 5 | User token source | W | — | User-controlled |
| 6 | User token destination | W | — | User-controlled |
| 7 | User source owner | R | **S** | **signer surface** |

**Why this is the best first MVP target**:
- Minimum account count (8) = minimum harness setup cost
- Modern path = dominant on-chain volume = bug here = high bounty
  classification likelihood
- No OpenBook dependency = no Market fixture needed
- Clean swap_alternate surface: 3/4 (vault swap), 5/6 (cross-user)
- All 4 applicable solinv Critical invariants active (signer/owner/
  pda-forge/account-swap; discriminator-skip not applicable to Native)

### Tag 17 — SwapBaseOutV2 (8 accounts, no orderbook)

Same account layout as SwapBaseInV2; wire format `[17, max_amount_in: u64 LE,
amount_out: u64 LE]` = 17 bytes.

## solinv applicability summary

| Invariant | Native ix surface | Notes |
|---|---|---|
| signer-skip | **ALL 6 ix** | Native = manual `is_signer` check required, full surface |
| owner-skip | **ALL 6 ix** | Native = manual owner check, full surface (vaults, mints) |
| discriminator-skip | **N/A** | Native programs have no Anchor account discriminator |
| pda-forge | **ALL 6 ix** | AMM authority is `create_program_address(...)`-derived |
| account-swap | **ALL 6 ix** | No `has_one` analog = full swap surface (cross-pool, cross-user) |

**4 out of 5 Critical invariants active** vs typically 1-3 active for
Anchor programs (per Day 14 hit-rate analysis). This is the structural
advantage of Native protocols as solinv targets.

## InstructionSpec construction recipe (Day 18+)

For each of the 6 chosen ix, build:

```rust
let swap_base_in_v2_spec = InstructionSpec {
    program_id: raydium_amm_program_id,
    name: "swap_base_in_v2".into(),
    accounts: vec![
        AccountMeta::new_readonly(spl_token::ID, false),
        AccountMeta::new(amm_pool_pubkey, false),
        AccountMeta::new_readonly(amm_authority_pda, false),
        AccountMeta::new(amm_coin_vault, false),
        AccountMeta::new(amm_pc_vault, false),
        AccountMeta::new(user_source_token, false),
        AccountMeta::new(user_dest_token, false),
        AccountMeta::new_readonly(user_owner.pubkey(), true),
    ],
    signer_indices: vec![7],
    optional_signer_indices: vec![],
    expected_owners: vec![
        Some(spl_token::ID),       // 0: SPL Token program (its own owner)
        Some(raydium_amm_program_id),  // 1: AMM pool owned by Raydium
        None,                       // 2: authority is PDA, not owned by anyone special
        Some(spl_token::ID),       // 3: vault is SPL Token account
        Some(spl_token::ID),       // 4: same
        Some(spl_token::ID),       // 5: user token
        Some(spl_token::ID),       // 6: user token
        None,                       // 7: user owner = native account
    ],
    expected_discriminators: vec![None; 8],  // N/A for Native
    expected_pda_seeds: vec![
        None,                       // 0
        None,                       // 1
        Some(vec![b"amm authority".to_vec()]),  // 2: AUTHORITY_AMM seed
        None,                       // 3-7
        None, None, None, None, None,
    ],
    creates_indices: vec![],
    swap_alternates: vec![
        vec![],                          // 0: program id
        vec![alternate_pool],            // 1: cross-pool swap
        vec![],                          // 2: PDA derivation (handled separately)
        vec![amm_pc_vault],             // 3: swap coin/pc vault
        vec![amm_coin_vault],           // 4: reverse swap
        vec![other_user_source_token],  // 5: drain other user
        vec![other_user_dest_token],    // 6: redirect to other dest
        vec![],                          // 7: signer identity
    ],
    data_sample: build_swap_base_in_v2_data(amount_in: 1000, min_out: 1),
    signers: vec![Arc::clone(&user_owner)],
};
```

Note: `expected_pda_seeds[2]` for AMM authority needs verification of
the exact `AUTHORITY_AMM` constant value from `program/src/state.rs`
or wherever defined. Day 18 first step.

## Fixture setup cost estimate

For SwapBaseInV2 fixture (smallest):
- Create 2 SPL Token mints (coin, pc)
- Create AMM pool account (Initialize2 — heavy, 21 accounts)
- Create AMM coin + pc vaults
- Create 2 user wallets with token ATAs
- Seed pool liquidity

**Realistic estimate**: Initialize2 setup is non-trivial — may need
to **pre-deploy a Raydium pool on testnet/mainnet and snapshot** rather
than initialize from scratch in fixture. Investigate Day 18.

Alternative: write a minimal Initialize2 harness with mocked OpenBook
market (program id check only, no actual market state). Investigate.

## Day 17-18 first actions

1. Day 17: Inspect Raydium AMM `program/src/state.rs` for AmmInfo
   account layout (so we can read pool state post-attack for state-diff
   detection) + `AUTHORITY_AMM` const lookup.
2. Day 17: Decide setup strategy (full-init vs snapshot-based) for
   AMM pool fixture.
3. Day 18: Begin `examples/raydium-amm-fuzz/` harness scaffold —
   `Cargo.toml`, `src/main.rs` skeleton with EscrowFixture analog
   (RaydiumAmmFixture).

## Sources

- `program/src/instruction.rs` — enum + unpack + pack + constructors
- `program/src/state.rs` — AmmInfo account layout (Day 17 read)
- `program/src/processor.rs` — ix dispatch + validation logic
- README.md — build commands, mainnet/devnet program IDs
- audit refs: `github.com/raydium-io/raydium-docs/tree/master/audit`
