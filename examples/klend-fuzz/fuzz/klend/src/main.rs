//! solinv harness for Kamino klend (Anchor 0.29 lending program).
//!
//! Day 22 scope: scaffold only. Constants + sighash/disc/rent helpers
//! + Fixture struct skeleton + HasContext/HasInstructionSet stubs +
//! compile-passing main.rs. Fixture init (Reserve + LendingMarket +
//! Obligation byte-level construction via write_account) is Day 23.
//! First fuzz campaign is Day 24+.
//!
//! See `docs/klend-ix-inventory.md` for the inventoried 5-ix surface.
//! See `docs/phase2-day22-klend-scaffold.md` for this log.

use crucible_fuzzer::*;
use crucible_fuzzer::AccountBuilderBase;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use std::sync::Arc;

use solinv_fuzz::{
    anchor_account_disc, anchor_ix_sighash, rent_for_raw, write_pubkey_at,
    write_u64_at, write_u8_at, AnchorAccountBuilder, HasContext, HasInstructionSet,
    InstructionSpec,
};

// ============================================================================
// External program — klend .so path
//
// Solinv repo does not vendor klend source (BUSL-1.1, intentionally kept
// external). Build separately per Day 17 incantation:
//   cd ~/src/klend/programs/klend
//   SDKROOT=$(xcrun --show-sdk-path) \
//   CFLAGS="-isysroot $(xcrun --show-sdk-path)" \
//   cargo build-sbf --tools-version v1.39
//
// TODO(portability): hardcoded absolute path, same approach as
// raydium-amm-fuzz. Add env-var support if multi-machine setup needed.
// ============================================================================
const KLEND_SO_PATH: &str =
    env!("KLEND_SO", "set KLEND_SO to your built klend/target/deploy/kamino_lending.so path");

// ============================================================================
// Constants — pubkeys, seeds, struct sizes
// ============================================================================

// klend mainnet program ID = KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD
// (staging: SLendK7ySfcEzyaFqy93gDnD3RtrpXJcnRwb6zFHJSh — not used here)
fn klend_program_id() -> Pubkey {
    use std::str::FromStr;
    Pubkey::from_str("KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD").unwrap()
}

// SPL Token classic program ID
fn spl_token_program_id() -> Pubkey {
    use std::str::FromStr;
    Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap()
}

// SPL Token-2022 program ID — klend uses Interface<TokenInterface> so
// either token program is accepted. Day 23 may need to set up
// multi-owner handling.
#[allow(dead_code)]
fn spl_token_2022_program_id() -> Pubkey {
    use std::str::FromStr;
    Pubkey::from_str("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb").unwrap()
}

// Sysvar Instructions program — required by klend ix for introspection
#[allow(dead_code)]
fn sysvar_instructions_id() -> Pubkey {
    use std::str::FromStr;
    Pubkey::from_str("Sysvar1nstructions1111111111111111111111111").unwrap()
}

const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);

// klend lending_market_authority PDA seed (Day 17 finding,
// `klend/programs/klend/src/utils/seeds.rs:1`)
const LENDING_MARKET_AUTH: &[u8] = b"lma";

// Account size constants from `klend/programs/klend/src/utils/consts.rs`.
// Used for write_account data buffer sizing + rent computation.
// Day 23 will populate actual bytes within these buffers.
#[allow(dead_code)]
const LENDING_MARKET_SIZE: usize = 4656;
#[allow(dead_code)]
const RESERVE_SIZE: usize = 8616;
#[allow(dead_code)]
const OBLIGATION_SIZE: usize = 3336;

// Anchor wire-format helpers (anchor_account_disc / anchor_ix_sighash /
// rent_for_raw / write_*_at / AnchorAccountBuilder) come from
// solinv_fuzz::bytepoke — see crates/solinv-fuzz/src/bytepoke.rs +
// docs/phase5-day57-bytepoke-helper.md.

// ============================================================================
// LendingMarket byte construction
//
// On-chain layout (Anchor zero-copy, #[repr(C)]):
//   [0..8]    discriminator (sha256("account:LendingMarket")[..8])
//   [8..16]   version: u64
//   [16..24]  bump_seed: u64
//   [24..56]  lending_market_owner: Pubkey
//   [56..88]  lending_market_owner_cached: Pubkey
//   [88..120] quote_currency: [u8; 32]
//   [120..]   ... (large tail, mostly defaults to zero are OK)
//
// Total size: 8 (disc) + LENDING_MARKET_SIZE (4656) = 4664 bytes.
//
// For deposit_reserve_liquidity, only `bump_seed` is read from
// LendingMarket. Other fields (version, owner, etc.) get safe default
// values for forward compatibility with other ix.
// ============================================================================

const DISC_LEN: usize = 8;
// Body-relative offsets (subtract DISC_LEN from on-chain offsets — the
// AnchorAccountBuilder prepends the 8-byte discriminator).
const LM_BODY_OFFSET_VERSION: usize = 0;
const LM_BODY_OFFSET_BUMP_SEED: usize = 8;
const LM_BODY_OFFSET_LENDING_MARKET_OWNER: usize = 16;
const LM_BODY_OFFSET_LENDING_MARKET_OWNER_CACHED: usize = 48;
const LM_BODY_OFFSET_QUOTE_CURRENCY: usize = 80;

#[allow(dead_code)]
fn build_lending_market_account(bump: u8, owner: &Pubkey, program_id: Pubkey) -> Account {
    let mut body = vec![0u8; LENDING_MARKET_SIZE];
    write_u64_at(&mut body, LM_BODY_OFFSET_VERSION, 1);
    write_u64_at(&mut body, LM_BODY_OFFSET_BUMP_SEED, bump as u64);
    write_pubkey_at(&mut body, LM_BODY_OFFSET_LENDING_MARKET_OWNER, owner);
    write_pubkey_at(&mut body, LM_BODY_OFFSET_LENDING_MARKET_OWNER_CACHED, owner);
    // quote_currency = "USDC" UTF-8 padded with zeros
    body[LM_BODY_OFFSET_QUOTE_CURRENCY..LM_BODY_OFFSET_QUOTE_CURRENCY + 4]
        .copy_from_slice(b"USDC");
    AnchorAccountBuilder::new("LendingMarket", body)
        .owned_by(program_id)
        .build()
}

// ============================================================================
// Reserve mirror structs (Day 24)
//
// Strategy: mirror klend's #[repr(C)] layout exactly so std::mem::offset_of!
// gives compile-time-verified byte offsets. Only LEADING fields we read
// are explicit Rust fields; trailing fields collapse into opaque [u8; N]
// "tail" arrays sized to make total struct sizes match klend's
// static_assertions::const_assert_eq!(RESERVE_SIZE, sizeof(Reserve)).
//
// Source: klend/programs/klend/src/state/reserve.rs:64-106
// Verified sizes:
//   BigFractionBytes = 6 u64 = 48
//   LastUpdate = u64 + u8 + u8 + [u8; 6] = 16
//   ReserveLiquidity = 1232 (= 4 Pubkey + 6 u64 + 6 u128 + BigFractionBytes + [u64;50] + [u128;32])
//   ReserveCollateral = 1096 (= 2 Pubkey + u64 + [u128;32] + [u128;32])
//   ReserveConfig = 944 (computed: 8616 - other field sizes)
//   WithdrawQueue = 24 (= 3 u64)
// ============================================================================

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

// ReserveConfig leading fields up to deposit_limit (Day 27).
// Per state/reserve.rs:1532-1668 manual offset analysis:
//   status u8 + 1+2+2+1+1+1 + reserved_1[4] + 1+1+1+1+1 +
//   u16+u16+u16(@aligned 18) + u64+u64(@24,32) + ReserveFees(24@40) +
//   BorrowRateCurve(88@64) + borrow_factor_pct u64(@152) +
//   deposit_limit u64(@160)
//
// Mirror uses [u8; 159] filler to land deposit_limit at offset 160
// (naturally 8-aligned, no Rust padding added). Tail [u8; 776] makes
// total ReserveConfigMirror size = 944 bytes.
#[repr(C)]
struct ReserveConfigMirror {
    pub status: u8,                          // offset 0
    pub _filler: [u8; 159],                  // offset 1..160
    pub deposit_limit: u64,                  // offset 160 (8-aligned)
    pub _tail: [u8; 944 - 168],              // offset 168..944
}
const _: () = assert!(std::mem::size_of::<ReserveConfigMirror>() == 944);

#[repr(C)]
struct ReserveMirror {
    pub version: u64,                                  // offset 0
    pub last_update: [u8; 16],                         // offset 8 (opaque LastUpdate)
    pub lending_market: [u8; 32],                      // offset 24
    pub farm_collateral: [u8; 32],                     // offset 56
    pub farm_debt: [u8; 32],                           // offset 88
    pub liquidity: ReserveLiquidityMirror,             // offset 120 (size 1232)
    pub reserve_liquidity_padding: [u8; 1200],         // offset 1352
    pub collateral: ReserveCollateralMirror,           // offset 2552 (size 1096)
    pub reserve_collateral_padding: [u8; 1200],        // offset 3648 (Day 27)
    pub config: ReserveConfigMirror,                   // offset 4848 (size 944)
    pub _tail: [u8; 8616 - 5792],                      // offset 5792..8616 = 2824 bytes
}
const _: () = assert!(std::mem::size_of::<ReserveMirror>() == 8616);

// ----- Compile-time offsets (include +8 for disc prefix) -----

// std::mem::offset_of! is stable since Rust 1.77; nested field paths
// (.subfield) stable since 1.82. We compute via sums of single-field
// offsets for broader Rust-version compatibility.
const _RESERVE_OFFSET_LENDING_MARKET: usize = std::mem::offset_of!(ReserveMirror, lending_market);
const _RESERVE_OFFSET_LIQUIDITY: usize = std::mem::offset_of!(ReserveMirror, liquidity);
const _RESERVE_OFFSET_COLLATERAL: usize = std::mem::offset_of!(ReserveMirror, collateral);

const _RL_OFFSET_MINT_PUBKEY: usize = std::mem::offset_of!(ReserveLiquidityMirror, mint_pubkey);
const _RL_OFFSET_SUPPLY_VAULT: usize = std::mem::offset_of!(ReserveLiquidityMirror, supply_vault);

const _RC_OFFSET_MINT_PUBKEY: usize = std::mem::offset_of!(ReserveCollateralMirror, mint_pubkey);
const _RC_OFFSET_SUPPLY_VAULT: usize = std::mem::offset_of!(ReserveCollateralMirror, supply_vault);

// Byte offsets INTO the on-chain Reserve account data (include 8 disc bytes).
const RES_OFFSET_VERSION: usize = DISC_LEN + 0;
const RES_OFFSET_LENDING_MARKET: usize = DISC_LEN + _RESERVE_OFFSET_LENDING_MARKET;
const RES_OFFSET_LIQUIDITY_MINT: usize = DISC_LEN + _RESERVE_OFFSET_LIQUIDITY + _RL_OFFSET_MINT_PUBKEY;
const RES_OFFSET_LIQUIDITY_SUPPLY: usize = DISC_LEN + _RESERVE_OFFSET_LIQUIDITY + _RL_OFFSET_SUPPLY_VAULT;
const RES_OFFSET_COLLATERAL_MINT: usize = DISC_LEN + _RESERVE_OFFSET_COLLATERAL + _RC_OFFSET_MINT_PUBKEY;
const RES_OFFSET_COLLATERAL_SUPPLY: usize = DISC_LEN + _RESERVE_OFFSET_COLLATERAL + _RC_OFFSET_SUPPLY_VAULT;

// Day 27: ReserveConfig field offsets (within Reserve.config sub-struct)
const _RESERVE_OFFSET_CONFIG: usize = std::mem::offset_of!(ReserveMirror, config);
const _RC_OFFSET_STATUS: usize = std::mem::offset_of!(ReserveConfigMirror, status);
const _RC_OFFSET_DEPOSIT_LIMIT: usize = std::mem::offset_of!(ReserveConfigMirror, deposit_limit);

const RES_OFFSET_CONFIG_STATUS: usize = DISC_LEN + _RESERVE_OFFSET_CONFIG + _RC_OFFSET_STATUS;
const RES_OFFSET_CONFIG_DEPOSIT_LIMIT: usize = DISC_LEN + _RESERVE_OFFSET_CONFIG + _RC_OFFSET_DEPOSIT_LIMIT;

// Compile-time sanity: deposit_limit should be at offset 160 within
// ReserveConfig (manual analysis from state/reserve.rs:1532-1597).
const _: () = assert!(_RC_OFFSET_DEPOSIT_LIMIT == 160);

/// Construct on-chain Reserve account bytes via byte-poke.
///
/// Sets fields read by `deposit_reserve_liquidity` ix:
///   - disc + version
///   - lending_market (has_one binding)
///   - liquidity.mint_pubkey, liquidity.supply_vault
///   - collateral.mint_pubkey, collateral.supply_vault
///
/// Other fields zeroed (sufficient for ix surface tested in Phase 2 MVP).
#[allow(dead_code)]
fn build_reserve_bytes(
    lending_market: &Pubkey,
    liquidity_mint: &Pubkey,
    liquidity_supply: &Pubkey,
    collateral_mint: &Pubkey,
    collateral_supply: &Pubkey,
) -> Vec<u8> {
    let mut buf = vec![0u8; DISC_LEN + RESERVE_SIZE];
    buf[0..8].copy_from_slice(&anchor_account_disc("Reserve"));
    write_u64_at(&mut buf, RES_OFFSET_VERSION, 1);
    write_pubkey_at(&mut buf, RES_OFFSET_LENDING_MARKET, lending_market);
    write_pubkey_at(&mut buf, RES_OFFSET_LIQUIDITY_MINT, liquidity_mint);
    write_pubkey_at(&mut buf, RES_OFFSET_LIQUIDITY_SUPPLY, liquidity_supply);
    write_pubkey_at(&mut buf, RES_OFFSET_COLLATERAL_MINT, collateral_mint);
    write_pubkey_at(&mut buf, RES_OFFSET_COLLATERAL_SUPPLY, collateral_supply);
    buf
}

// ============================================================================
// raw_call ix constructors — Day 23/24 will populate. Sketches for the
// 5 critical lending ix per Day 17 inventory. Wire format always:
//   data = anchor_ix_sighash("<name>") ++ borsh_args
// AccountMeta layouts captured in docs/klend-ix-inventory.md.
// ============================================================================

// klend reserve-related PDA seeds (Day 26)
const RESERVE_LIQ_SUPPLY: &[u8] = b"reserve_liq_supply";
const FEE_RECEIVER: &[u8] = b"fee_receiver";
const RESERVE_COLL_MINT: &[u8] = b"reserve_coll_mint";
const RESERVE_COLL_SUPPLY: &[u8] = b"reserve_coll_supply";

// Day 26: init_reserve (12 accounts, no args).
// Per handler_init_reserve.rs:116-184. Handler creates 4 PDA accounts
// during execution: reserve_liquidity_supply + fee_receiver (manual
// initialize_pda_token_account), reserve_collateral_mint +
// reserve_collateral_supply (Anchor #[account(init)]).
//
// Pre-conditions:
//   - reserve account exists, owned by klend program, all-zero data
//     (Anchor #[account(zero)] requires)
//   - signer == lending_market.lending_market_owner (verified by
//     is_allowed_signer_to_init_reserve)
//   - liquidity_mint is SPL Mint owned by liquidity_token_program
//   - initial_liquidity_source has authority = signer
#[allow(clippy::too_many_arguments)]
fn build_init_reserve_ix(
    program_id: Pubkey,
    signer: Pubkey,
    lending_market: Pubkey,
    lending_market_authority: Pubkey,
    reserve: Pubkey,
    reserve_liquidity_mint: Pubkey,
    reserve_liquidity_supply: Pubkey,
    fee_receiver: Pubkey,
    reserve_collateral_mint: Pubkey,
    reserve_collateral_supply: Pubkey,
    initial_liquidity_source: Pubkey,
) -> Instruction {
    let data = anchor_ix_sighash("init_reserve").to_vec();

    let rent_sysvar: Pubkey = {
        use std::str::FromStr;
        Pubkey::from_str("SysvarRent111111111111111111111111111111111").unwrap()
    };
    let spl_token = spl_token_program_id();

    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(signer, true),                          // 0 signer
            AccountMeta::new_readonly(lending_market, false),        // 1
            AccountMeta::new_readonly(lending_market_authority, false), // 2 LMA PDA
            AccountMeta::new(reserve, false),                        // 3 reserve (mut, init)
            AccountMeta::new_readonly(reserve_liquidity_mint, false),// 4
            AccountMeta::new(reserve_liquidity_supply, false),       // 5 PDA (handler creates)
            AccountMeta::new(fee_receiver, false),                   // 6 PDA (handler creates)
            AccountMeta::new(reserve_collateral_mint, false),        // 7 PDA (Anchor init)
            AccountMeta::new(reserve_collateral_supply, false),      // 8 PDA (Anchor init)
            AccountMeta::new(initial_liquidity_source, false),       // 9
            AccountMeta::new_readonly(rent_sysvar, false),           // 10 rent
            AccountMeta::new_readonly(spl_token, false),             // 11 liquidity_token_program
            AccountMeta::new_readonly(spl_token, false),             // 12 collateral_token_program
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),     // 13 system_program
        ],
        data,
    }
}

// Day 25: deposit_reserve_liquidity (12 accounts, per Day 17 inventory).
// Wire = anchor_ix_sighash("deposit_reserve_liquidity") + liquidity_amount(LE u64).
#[allow(clippy::too_many_arguments)]
fn build_deposit_reserve_liquidity_ix(
    program_id: Pubkey,
    owner: Pubkey,
    reserve: Pubkey,
    lending_market: Pubkey,
    lending_market_authority: Pubkey,
    reserve_liquidity_mint: Pubkey,
    reserve_liquidity_supply: Pubkey,
    reserve_collateral_mint: Pubkey,
    user_source_liquidity: Pubkey,
    user_destination_collateral: Pubkey,
    liquidity_amount: u64,
) -> Instruction {
    let mut data = anchor_ix_sighash("deposit_reserve_liquidity").to_vec();
    data.extend_from_slice(&liquidity_amount.to_le_bytes());

    let spl_token = spl_token_program_id();
    let sysvar_ixs = sysvar_instructions_id();

    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(owner, true),                  // 0 owner (signer)
            AccountMeta::new(reserve, false),                        // 1 reserve (mut)
            AccountMeta::new_readonly(lending_market, false),        // 2 lending_market
            AccountMeta::new_readonly(lending_market_authority, false), // 3 LMA PDA
            AccountMeta::new_readonly(reserve_liquidity_mint, false),// 4
            AccountMeta::new(reserve_liquidity_supply, false),       // 5
            AccountMeta::new(reserve_collateral_mint, false),        // 6
            AccountMeta::new(user_source_liquidity, false),          // 7
            AccountMeta::new(user_destination_collateral, false),    // 8
            AccountMeta::new_readonly(spl_token, false),             // 9 collateral_token_program
            AccountMeta::new_readonly(spl_token, false),             // 10 liquidity_token_program
            AccountMeta::new_readonly(sysvar_ixs, false),            // 11 instruction_sysvar
        ],
        data,
    }
}

// ============================================================================
// Fixture
// ============================================================================

#[derive(Clone)]
#[allow(dead_code)]
struct KlendFixture {
    pub ctx: TestContext,
    program_id: Pubkey,
    fee_payer: Arc<Keypair>,

    // Pool-level state (Day 23 will populate via write_account on
    // LENDING_MARKET_SIZE / RESERVE_SIZE / OBLIGATION_SIZE byte buffers)
    lending_market: Pubkey,
    lending_market_authority: Pubkey,
    lending_market_bump: u8,
    reserve: Pubkey,             // single reserve for MVP; expand Day 25+
    obligation: Pubkey,          // single obligation for User A

    // Mint / supply state
    liquidity_mint: Pubkey,
    collateral_mint: Pubkey,
    reserve_liquidity_supply: Pubkey,
    reserve_collateral_supply: Pubkey,    // klend collateral has its own supply
    reserve_liquidity_fee_receiver: Pubkey,

    // User A — primary trader / depositor / borrower
    user: Arc<Keypair>,
    user_source_liquidity: Pubkey,
    user_destination_collateral: Pubkey,
    user_destination_liquidity: Pubkey,   // for redeem / borrow paths

    // User B — alternate obligation for account-swap detection (Day 17 finding:
    // klend's BEST invariant is account-swap on cross-obligation relationships)
    user_b: Arc<Keypair>,
    obligation_b: Pubkey,
    user_b_source_liquidity: Pubkey,
}

#[fuzz_fixture]
impl KlendFixture {
    pub fn setup() -> Self {
        let mut ctx = TestContext::new();
        let program_id = klend_program_id();
        ctx.add_program(&program_id, KLEND_SO_PATH).unwrap();

        let fee_payer = Arc::new(Keypair::new());
        let user = Arc::new(Keypair::new());
        let user_b = Arc::new(Keypair::new());

        for kp in [&fee_payer, &user, &user_b] {
            ctx.create_account()
                .pubkey(kp.pubkey())
                .lamports(10_000_000_000)
                .owner(SYSTEM_PROGRAM_ID)
                .create()
                .unwrap();
        }

        // ---------- lending_market + authority PDA ----------
        let lending_market = Pubkey::new_unique();
        let (lending_market_authority, lending_market_bump) =
            Pubkey::find_program_address(
                &[LENDING_MARKET_AUTH, lending_market.as_ref()],
                &program_id,
            );

        // ---------- Day 23: write LendingMarket bytes (byte-poke) ----------
        // Set disc + version=1 + bump_seed + lending_market_owner +
        // quote_currency="USDC". Sufficient for deposit_reserve_liquidity
        // which only reads bump_seed from LendingMarket.
        // Day 57: now uses solinv_fuzz::bytepoke::AnchorAccountBuilder
        // (returns a complete Account; rent + disc handled internally).
        let lm_account =
            build_lending_market_account(lending_market_bump, &user.pubkey(), program_id);
        ctx.write_account(&lending_market, lm_account).unwrap();

        // ---------- Day 26: init_reserve via raw_call (Option B) ----------
        // Replaces Day 24 byte-poke of Reserve. Anchor populates ReserveConfig
        // correctly (Day 25 finding: zero-config blocks all flow).

        // Mint authority (we keep this for any post-init mint operations)
        let mint_authority = Arc::new(Keypair::new());
        ctx.create_account()
            .pubkey(mint_authority.pubkey())
            .lamports(10_000_000_000)
            .owner(SYSTEM_PROGRAM_ID)
            .create()
            .unwrap();

        // 1. Create liquidity_mint (regular SPL Mint, our authority)
        let liquidity_mint = Pubkey::new_unique();
        ctx.create_mint()
            .pubkey(liquidity_mint)
            .mint_authority(mint_authority.pubkey())
            .decimals(6)
            .create()
            .unwrap();

        // 2. Create user_source_liquidity (initial_liquidity_source for init_reserve)
        //    and user_b_source_liquidity (will fund alternate-context attacks).
        //    Both must be SPL TokenAccounts with mint=liquidity_mint.
        let user_source_liquidity = Pubkey::new_unique();
        let user_b_source_liquidity = Pubkey::new_unique();
        ctx.create_token_account()
            .pubkey(user_source_liquidity)
            .mint(liquidity_mint)
            .token_owner(user.pubkey())
            .amount(1_000_000_000)
            .create()
            .unwrap();
        ctx.create_token_account()
            .pubkey(user_b_source_liquidity)
            .mint(liquidity_mint)
            .token_owner(user_b.pubkey())
            .amount(1_000_000_000)
            .create()
            .unwrap();

        // 3. Choose reserve pubkey + derive 4 PDAs from it
        let reserve = Pubkey::new_unique();
        let (reserve_liquidity_supply, _) = Pubkey::find_program_address(
            &[RESERVE_LIQ_SUPPLY, reserve.as_ref()], &program_id,
        );
        let (reserve_liquidity_fee_receiver, _) = Pubkey::find_program_address(
            &[FEE_RECEIVER, reserve.as_ref()], &program_id,
        );
        let (collateral_mint, _) = Pubkey::find_program_address(
            &[RESERVE_COLL_MINT, reserve.as_ref()], &program_id,
        );
        let (reserve_collateral_supply, _) = Pubkey::find_program_address(
            &[RESERVE_COLL_SUPPLY, reserve.as_ref()], &program_id,
        );

        // 4. Pre-create reserve account empty (Anchor #[account(zero)] requires
        //    owner=program_id, data=all-zeros, rent-exempt lamports)
        let reserve_data_len = DISC_LEN + RESERVE_SIZE;
        ctx.write_account(
            &reserve,
            Account {
                lamports: rent_for_raw(reserve_data_len),
                data: vec![0u8; reserve_data_len],
                owner: program_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        // 5. Call init_reserve via raw_call (user is signer = lending_market_owner)
        let init_ix = build_init_reserve_ix(
            program_id,
            user.pubkey(),
            lending_market,
            lending_market_authority,
            reserve,
            liquidity_mint,
            reserve_liquidity_supply,
            reserve_liquidity_fee_receiver,
            collateral_mint,
            reserve_collateral_supply,
            user_source_liquidity,
        );
        ctx.raw_call(init_ix)
            .fee_payer(&*fee_payer)
            .signers(&[&*user])
            .send()
            .expect("init_reserve failed — check is_allowed_signer + PDA setup");

        // ---------- Day 27: post-init ReserveConfig byte-poke ----------
        // init_reserve sets status=Hidden (=2) + deposit_limit=0 by Kamino
        // design. Patch directly to bypass admin update_reserve_config flow:
        //   status: 2 → 0 (Active)
        //   deposit_limit: 0 → 100_000_000 (enables deposits up to 100M units)
        let mut reserve_acc = ctx.read_account(&reserve)
            .expect("Reserve account must exist after init_reserve");
        write_u8_at(&mut reserve_acc.data, RES_OFFSET_CONFIG_STATUS, 0);
        write_u64_at(&mut reserve_acc.data, RES_OFFSET_CONFIG_DEPOSIT_LIMIT, 100_000_000);
        ctx.write_account(&reserve, reserve_acc)
            .expect("Reserve write_account failed");

        // 6. Post-init: create user collateral/liquidity destination accounts.
        //    collateral_mint now exists (Anchor #[account(init)] created it
        //    during init_reserve). user_destination_collateral can be made.
        let user_destination_collateral = Pubkey::new_unique();
        let user_destination_liquidity = Pubkey::new_unique();
        ctx.create_token_account()
            .pubkey(user_destination_collateral)
            .mint(collateral_mint)
            .token_owner(user.pubkey())
            .amount(0)
            .create()
            .unwrap();
        ctx.create_token_account()
            .pubkey(user_destination_liquidity)
            .mint(liquidity_mint)
            .token_owner(user.pubkey())
            .amount(0)
            .create()
            .unwrap();

        // Obligation placeholders (Day 27+ if borrow/repay/liquidate added)
        let obligation = Pubkey::new_unique();
        let obligation_b = Pubkey::new_unique();

        Self {
            ctx,
            program_id,
            fee_payer,
            lending_market,
            lending_market_authority,
            lending_market_bump,
            reserve,
            obligation,
            liquidity_mint,
            collateral_mint,
            reserve_liquidity_supply,
            reserve_collateral_supply,
            reserve_liquidity_fee_receiver,
            user,
            user_source_liquidity,
            user_destination_collateral,
            user_destination_liquidity,
            user_b,
            obligation_b,
            user_b_source_liquidity,
        }
    }

    // Day 22 — placeholder action so #[fuzz_fixture] generates the
    // __dispatch_action / __auto_flush methods that #[invariant_test]
    // requires. Returns false (no-op). Kept alongside real Day 25 action.
    pub fn action_noop(&mut self, #[range(0..1)] _x: u8) -> bool {
        false
    }

    // Day 25: deposit_reserve_liquidity — first real klend ix
    pub fn action_deposit_reserve_liquidity(
        &mut self,
        #[range(1..1_000_000)] liquidity_amount: u64,
    ) -> bool {
        let ix = build_deposit_reserve_liquidity_ix(
            self.program_id,
            self.user.pubkey(),
            self.reserve,
            self.lending_market,
            self.lending_market_authority,
            self.liquidity_mint,
            self.reserve_liquidity_supply,
            self.collateral_mint,
            self.user_source_liquidity,
            self.user_destination_collateral,
            liquidity_amount,
        );
        self.ctx
            .raw_call(ix)
            .fee_payer(&*self.fee_payer)
            .signers(&[&*self.user])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }
}

// ============================================================================
// solinv trait wiring
// ============================================================================

impl HasContext for KlendFixture {
    fn ctx(&self) -> &TestContext {
        &self.ctx
    }
    fn ctx_mut(&mut self) -> &mut TestContext {
        &mut self.ctx
    }
    fn program_ids(&self) -> Vec<Pubkey> {
        vec![self.program_id]
    }
    fn fee_payer(&self) -> Arc<Keypair> {
        Arc::clone(&self.fee_payer)
    }
}

impl HasInstructionSet for KlendFixture {
    fn instructions(&self) -> Vec<InstructionSpec> {
        let spl_token = spl_token_program_id();
        let sysvar_ixs = sysvar_instructions_id();

        // ---------- deposit_reserve_liquidity (Day 25) ----------
        let mut data = anchor_ix_sighash("deposit_reserve_liquidity").to_vec();
        data.extend_from_slice(&100_000u64.to_le_bytes()); // liquidity_amount sample

        let deposit_reserve_liquidity_spec = InstructionSpec {
            program_id: self.program_id,
            name: "deposit_reserve_liquidity".into(),
            accounts: vec![
                AccountMeta::new_readonly(self.user.pubkey(), true),
                AccountMeta::new(self.reserve, false),
                AccountMeta::new_readonly(self.lending_market, false),
                AccountMeta::new_readonly(self.lending_market_authority, false),
                AccountMeta::new_readonly(self.liquidity_mint, false),
                AccountMeta::new(self.reserve_liquidity_supply, false),
                AccountMeta::new(self.collateral_mint, false),
                AccountMeta::new(self.user_source_liquidity, false),
                AccountMeta::new(self.user_destination_collateral, false),
                AccountMeta::new_readonly(spl_token, false),
                AccountMeta::new_readonly(spl_token, false),
                AccountMeta::new_readonly(sysvar_ixs, false),
            ],
            signer_indices: vec![0], // owner
            optional_signer_indices: vec![],
            expected_owners: vec![
                None,                       // 0 owner (system)
                Some(self.program_id),      // 1 reserve (klend-owned)
                Some(self.program_id),      // 2 lending_market (klend-owned)
                None,                       // 3 LMA PDA (no specific owner)
                Some(spl_token),            // 4 liquidity_mint
                Some(spl_token),            // 5 reserve_liquidity_supply
                Some(spl_token),            // 6 collateral_mint
                Some(spl_token),            // 7 user_source_liquidity
                Some(spl_token),            // 8 user_destination_collateral
                None,                       // 9 spl_token program (executable)
                None,                       // 10 spl_token program (executable)
                None,                       // 11 sysvar instructions
            ],
            expected_discriminators: vec![
                None,                                       // 0
                Some(anchor_account_disc("Reserve")),              // 1
                Some(anchor_account_disc("LendingMarket")),        // 2
                None, None, None, None, None, None,         // 3-8
                None, None, None,                            // 9-11
            ],
            expected_pda_seeds: vec![
                None, None, None,
                // 3: lending_market_authority = [b"lma", lending_market]
                Some(vec![
                    LENDING_MARKET_AUTH.to_vec(),
                    self.lending_market.to_bytes().to_vec(),
                ]),
                None, None, None, None, None, None, None, None,
            ],
            creates_indices: vec![],
            // Day 20 lesson applied:
            // - account 8 (user_destination_collateral) is USER-CONTROLLED
            //   (Anchor only checks token::mint, no token::authority constraint).
            //   Permissive output semantics, vec![] to avoid false positive.
            // - accounts 4/5/6: Anchor's address= constraint catches mismatch,
            //   so substituting tests Anchor's enforcement (expect catch).
            // - account 7 (user_source_liquidity): SPL Token transfer signer
            //   check catches drain attempt on user_b's account.
            swap_alternates: vec![
                vec![],                                    // 0 owner (signer)
                vec![],                                    // 1 reserve (no 2nd reserve fixture)
                vec![],                                    // 2 lending_market (single fixture)
                vec![],                                    // 3 LMA PDA
                vec![self.collateral_mint],                // 4: substitute wrong mint
                vec![self.reserve_collateral_supply],      // 5: substitute wrong supply
                vec![self.liquidity_mint],                 // 6: substitute wrong mint
                vec![self.user_b_source_liquidity],        // 7: drain user_b
                vec![],                                    // 8: USER-CONTROLLED (Day 20 lesson)
                vec![],                                    // 9 program id
                vec![],                                    // 10 program id
                vec![],                                    // 11 sysvar id
            ],
            data_sample: data,
            signers: vec![Arc::clone(&self.user)],
            state_invariants: vec![],
            cu_budget: None,
            cpi_reentrancy: None,
            realloc_check: None,
            bump_seed_check: None,            };

        vec![deposit_reserve_liquidity_spec]
    }
}

// ============================================================================
// Invariant tests — Day 24+ will populate. Day 22 has only stubs.
// 5 applicable invariants (klend is Anchor → discriminator-skip IS active
// vs Raydium where it was N/A).
// ============================================================================

#[invariant_test]
fn invariant_klend_combined_only(fixture: &mut KlendFixture) {
    // Combined — Day 11 first-violation-wins TLS may mask later invariants.
    // Use isolated variants below for diagnostic clarity.
    solinv_core::invariants::signer_skip::check(fixture);
    solinv_core::invariants::owner_skip::check(fixture);
    solinv_core::invariants::discriminator_skip::check(fixture);
    solinv_core::invariants::pda_forge::check(fixture);
    solinv_core::invariants::account_swap::check(fixture);
}

#[invariant_test]
fn invariant_signer_skip_only(fixture: &mut KlendFixture) {
    solinv_core::invariants::signer_skip::check(fixture);
}

#[invariant_test]
fn invariant_owner_skip_only(fixture: &mut KlendFixture) {
    solinv_core::invariants::owner_skip::check(fixture);
}

#[invariant_test]
fn invariant_discriminator_skip_only(fixture: &mut KlendFixture) {
    solinv_core::invariants::discriminator_skip::check(fixture);
}

#[invariant_test]
fn invariant_pda_forge_only(fixture: &mut KlendFixture) {
    solinv_core::invariants::pda_forge::check(fixture);
}

#[invariant_test]
fn invariant_account_swap_only(fixture: &mut KlendFixture) {
    // Day 17 finding: klend's BEST invariant. Anchor's has_one +
    // address-constraint leave gaps in cross-account relationships.
    solinv_core::invariants::account_swap::check(fixture);
}
