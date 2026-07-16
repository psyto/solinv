//! solinv harness for Raydium AMM (Native, no Anchor).
//!
//! Day 18 scope: scaffold only. AmmInfo wire layout mirror + raw_call
//! ix constructors + RaydiumAmmFixture struct + HasContext /
//! HasInstructionSet wiring. Setup() is a STUB — actual pool init is
//! Day 19. First fuzz campaign is Day 20.
//!
//! See `docs/raydium-amm-ix-inventory.md` for the inventoried surface.
//! See `docs/phase2-day18-raydium-harness-scaffold.md` for this log.

use crucible_fuzzer::*;
use crucible_fuzzer::AccountBuilderBase;
use bytemuck::{Pod, Zeroable};
use sha2::{Digest, Sha256};
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use std::sync::Arc;

/// Rent-exempt lamport minimum for `bytes`-sized accounts. Matches
/// `solana_rent::Rent::default().minimum_balance(bytes)` formula —
/// hardcoded to avoid pulling solana-rent or anchor-lang into this
/// Anchor-version-independent harness.
const fn rent_for(bytes: usize) -> u64 {
    // Rent::default(): lamports_per_byte_year=3480, exemption_threshold=2.0
    // minimum_balance = (128 + size) * lamports_per_byte_year * 2
    ((128 + bytes) as u64) * 3480 * 2
}

use solinv_fuzz::{
    BumpSeedCheckConfig, CpiReentrancyConfig, HasContext, HasInstructionSet, InstructionSpec,
    ReallocCheckConfig, StateInvariant, StateInvariantKind,
};

// ============================================================================
// External program — Raydium AMM .so path
//
// Solinv repo does not vendor Raydium AMM source. Build separately:
//   git clone https://github.com/raydium-io/raydium-amm.git ~/src/raydium-amm
//   cd ~/src/raydium-amm/program && cargo build-sbf
//
// TODO(portability): hardcoded absolute path. For multi-machine setups,
// add `RAYDIUM_AMM_SO` env var support via build.rs or runtime resolve.
// ============================================================================
const RAYDIUM_AMM_SO_PATH: &str =
    env!("RAYDIUM_AMM_SO", "set RAYDIUM_AMM_SO to your built raydium-amm/target/deploy/raydium_amm.so path");

// ============================================================================
// Constants — pubkeys + seeds
// ============================================================================

// Raydium AMM mainnet program ID = 675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8
// Resolved at runtime via Pubkey::from_str (compile-time avoidance: solana_pubkey
// const fn limitations across 3.x).
fn raydium_amm_program_id() -> Pubkey {
    use std::str::FromStr;
    Pubkey::from_str("675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8").unwrap()
}

// SPL Token program ID = TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
fn spl_token_program_id() -> Pubkey {
    use std::str::FromStr;
    Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap()
}

const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);

// Raydium AMM authority PDA seed — `b"amm authority"` per
// `raydium-amm/program/src/processor.rs:111`. Used to derive
// the single program-wide AMM authority via `find_program_address`.
const AUTHORITY_AMM_SEED: &[u8] = b"amm authority";

// AmmStatus enum values (raydium-amm/program/src/state.rs:225)
#[allow(dead_code)]
const AMM_STATUS_UNINITIALIZED: u64 = 0;
#[allow(dead_code)]
const AMM_STATUS_INITIALIZED: u64 = 1;
const AMM_STATUS_SWAP_ONLY: u64 = 6;

// Ix tag bytes (raydium-amm/program/src/instruction.rs unpack switch)
const IX_TAG_DEPOSIT: u8 = 3;
const IX_TAG_WITHDRAW: u8 = 4;
const IX_TAG_SWAP_BASE_IN: u8 = 9;
const IX_TAG_SWAP_BASE_OUT: u8 = 11;
const IX_TAG_SWAP_BASE_IN_V2: u8 = 16;
const IX_TAG_SWAP_BASE_OUT_V2: u8 = 17;

// ============================================================================
// AmmInfo wire mirror — exact byte layout from raydium-amm/program/src/state.rs
//
// `#[repr(C, packed)]` matches Raydium's on-chain layout. Total size MUST
// equal 752 bytes (computed: 16*8 + Fees(64) + StateData(144) + 9*32 +
// padding1(64) + amm_owner(32) + 4*8 = 752). Verified via static_assertion
// below at compile time.
//
// Pubkey fields stored as [u8; 32] because solana_pubkey 3.x does not
// implement bytemuck::Pod. Convert via Pubkey::to_bytes() / new_from_array.
// ============================================================================

#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
#[allow(dead_code)]
struct FeesMirror {
    pub min_separate_numerator: u64,
    pub min_separate_denominator: u64,
    pub trade_fee_numerator: u64,
    pub trade_fee_denominator: u64,
    pub pnl_numerator: u64,
    pub pnl_denominator: u64,
    pub swap_fee_numerator: u64,
    pub swap_fee_denominator: u64,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
#[allow(dead_code)]
struct StateDataMirror {
    pub need_take_pnl_coin: u64,
    pub need_take_pnl_pc: u64,
    pub total_pnl_pc: u64,
    pub total_pnl_coin: u64,
    pub pool_open_time: u64,
    pub padding: [u64; 2],
    pub orderbook_to_init_time: u64,
    pub swap_coin_in_amount: u128,
    pub swap_pc_out_amount: u128,
    pub swap_acc_pc_fee: u64,
    pub swap_pc_in_amount: u128,
    pub swap_coin_out_amount: u128,
    pub swap_acc_coin_fee: u64,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
#[allow(dead_code)]
struct AmmInfoMirror {
    pub status: u64,
    pub nonce: u64,
    pub order_num: u64,
    pub depth: u64,
    pub coin_decimals: u64,
    pub pc_decimals: u64,
    pub state: u64,
    pub reset_flag: u64,
    pub min_size: u64,
    pub vol_max_cut_ratio: u64,
    pub amount_wave: u64,
    pub coin_lot_size: u64,
    pub pc_lot_size: u64,
    pub min_price_multiplier: u64,
    pub max_price_multiplier: u64,
    pub sys_decimal_value: u64,
    pub fees: FeesMirror,
    pub state_data: StateDataMirror,
    pub coin_vault: [u8; 32],
    pub pc_vault: [u8; 32],
    pub coin_vault_mint: [u8; 32],
    pub pc_vault_mint: [u8; 32],
    pub lp_mint: [u8; 32],
    pub open_orders: [u8; 32],
    pub market: [u8; 32],
    pub market_program: [u8; 32],
    pub target_orders: [u8; 32],
    pub padding1: [u64; 8],
    pub amm_owner: [u8; 32],
    pub lp_amount: u64,
    pub client_order_id: u64,
    pub recent_epoch: u64,
    pub padding2: u64,
}

// Compile-time size check — fail loudly if AmmInfoMirror drifts from
// upstream Raydium's wire layout.
const _: () = {
    const EXPECTED: usize = 752;
    let actual = std::mem::size_of::<AmmInfoMirror>();
    assert!(
        actual == EXPECTED,
        "AmmInfoMirror size mismatch — Raydium upstream layout changed"
    );
};

// ============================================================================
// AmmInfo economic baseline
//
// Two sources, selected at compile time. Either way `setup()` rewires the
// cross-reference fields (vaults / mints / decimals / nonce) to the local
// synthetic graph so the SwapBaseInV2 processor path validates — only the
// economic parameters (fees, lot sizes, order/depth) differ by source.
// ============================================================================

// Default: hand-crafted healthy pool (the Day 19 values).
#[cfg(not(feature = "mainnet_snapshot_fixture"))]
fn amm_info_baseline() -> AmmInfoMirror {
    let mut a = AmmInfoMirror::zeroed();
    a.state = 1; // running
    a.order_num = 7;
    a.depth = 3;
    a.min_size = 1;
    a.vol_max_cut_ratio = 500;
    a.amount_wave = 5_000_000;
    a.coin_lot_size = 1;
    a.pc_lot_size = 1;
    a.min_price_multiplier = 1;
    a.max_price_multiplier = 1_000_000;
    // Fees::initialize defaults (state.rs:508-521)
    a.fees.min_separate_numerator = 5;
    a.fees.min_separate_denominator = 10_000;
    a.fees.trade_fee_numerator = 25;
    a.fees.trade_fee_denominator = 10_000;
    a.fees.pnl_numerator = 12;
    a.fees.pnl_denominator = 100;
    a.fees.swap_fee_numerator = 25;
    a.fees.swap_fee_denominator = 10_000;
    a
}

// `mainnet_snapshot_fixture`: real Raydium AMM v4 SOL-USDC pool, fetched
// from mainnet-beta and committed under `snapshots/`. Fees, lot sizes and
// order params come from production state — so the fuzzer exercises the
// pool config real users trade against, not hand-guessed values. Refresh
// via `solinv_corpus::account::clone_account`.
#[cfg(feature = "mainnet_snapshot_fixture")]
fn amm_info_baseline() -> AmmInfoMirror {
    const SNAP: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../snapshots/accounts/",
        "58oQChx4yWmvKdwLLZzBi4ChoCc2fqCUWBkwMihLYQo2.json"
    ));
    let snap = solinv_corpus::account::AccountSnapshot::from_json(SNAP)
        .expect("committed raydium pool snapshot parses");
    assert_eq!(
        snap.data.len(),
        std::mem::size_of::<AmmInfoMirror>(),
        "committed snapshot size != AmmInfoMirror — Raydium layout drift"
    );
    let mut a = bytemuck::pod_read_unaligned::<AmmInfoMirror>(&snap.data);
    a.state = 1; // force running regardless of the pool's live status flag
    a
}

// ============================================================================
// raw_call ix constructors — Native byte packing per Day 16 inventory
// (tag byte + LE primitives, NO sighash, NO Borsh)
// ============================================================================

fn build_swap_base_in_v2_ix(
    program_id: Pubkey,
    spl_token: Pubkey,
    amm_pool: Pubkey,
    amm_authority: Pubkey,
    coin_vault: Pubkey,
    pc_vault: Pubkey,
    user_source: Pubkey,
    user_dest: Pubkey,
    user_owner: Pubkey,
    amount_in: u64,
    minimum_amount_out: u64,
) -> Instruction {
    let mut data = Vec::with_capacity(17);
    data.push(IX_TAG_SWAP_BASE_IN_V2);
    data.extend_from_slice(&amount_in.to_le_bytes());
    data.extend_from_slice(&minimum_amount_out.to_le_bytes());

    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(spl_token, false),
            AccountMeta::new(amm_pool, false),
            AccountMeta::new_readonly(amm_authority, false),
            AccountMeta::new(coin_vault, false),
            AccountMeta::new(pc_vault, false),
            AccountMeta::new(user_source, false),
            AccountMeta::new(user_dest, false),
            AccountMeta::new_readonly(user_owner, true),
        ],
        data,
    }
}

// SwapBaseOutV2 (tag 17) — same 8 AccountMeta layout as InV2, args
// reordered: max_amount_in (cap) + amount_out (target).
fn build_swap_base_out_v2_ix(
    program_id: Pubkey,
    spl_token: Pubkey,
    amm_pool: Pubkey,
    amm_authority: Pubkey,
    coin_vault: Pubkey,
    pc_vault: Pubkey,
    user_source: Pubkey,
    user_dest: Pubkey,
    user_owner: Pubkey,
    max_amount_in: u64,
    amount_out: u64,
) -> Instruction {
    let mut data = Vec::with_capacity(17);
    data.push(IX_TAG_SWAP_BASE_OUT_V2);
    data.extend_from_slice(&max_amount_in.to_le_bytes());
    data.extend_from_slice(&amount_out.to_le_bytes());

    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(spl_token, false),
            AccountMeta::new(amm_pool, false),
            AccountMeta::new_readonly(amm_authority, false),
            AccountMeta::new(coin_vault, false),
            AccountMeta::new(pc_vault, false),
            AccountMeta::new(user_source, false),
            AccountMeta::new(user_dest, false),
            AccountMeta::new_readonly(user_owner, true),
        ],
        data,
    }
}

// ============================================================================
// Fixture
// ============================================================================

#[derive(Clone)]
#[allow(dead_code)]
struct RaydiumAmmFixture {
    pub ctx: TestContext,
    program_id: Pubkey,
    fee_payer: Arc<Keypair>,
    // Mint authority (controls coin_mint + pc_mint for future mint_to())
    mint_authority: Arc<Keypair>,
    // Pool state (hand-crafted, Day 19)
    amm_pool: Pubkey,
    amm_authority: Pubkey,
    amm_nonce: u8,
    coin_vault: Pubkey,
    pc_vault: Pubkey,
    coin_mint: Pubkey,
    pc_mint: Pubkey,
    // User A — primary trader
    user: Arc<Keypair>,
    user_source: Pubkey,
    user_dest: Pubkey,
    // User B — alternate context for account-swap detection (Day 12 pattern)
    user_b: Arc<Keypair>,
    user_b_source: Pubkey,
    user_b_dest: Pubkey,
}

#[fuzz_fixture]
impl RaydiumAmmFixture {
    pub fn setup() -> Self {
        let mut ctx = TestContext::new();
        let program_id = raydium_amm_program_id();
        ctx.add_program(&program_id, RAYDIUM_AMM_SO_PATH).unwrap();

        // ---------- System accounts (lamports only) ----------
        let fee_payer = Arc::new(Keypair::new());
        let user = Arc::new(Keypair::new());
        let user_b = Arc::new(Keypair::new());
        let mint_authority = Arc::new(Keypair::new());

        for kp in [&fee_payer, &user, &user_b, &mint_authority] {
            ctx.create_account()
                .pubkey(kp.pubkey())
                .lamports(10_000_000_000)
                .owner(SYSTEM_PROGRAM_ID)
                .create()
                .unwrap();
        }

        // ---------- AMM authority PDA ----------
        // Note: Raydium validates via `create_program_address([seed, [nonce]])`
        // — non-canonical, requires nonce arg. find_program_address handles the
        // iteration to find a valid bump (= nonce). Same end pubkey.
        let (amm_authority, amm_nonce) =
            Pubkey::find_program_address(&[AUTHORITY_AMM_SEED], &program_id);

        // ---------- SPL Token mints ----------
        let coin_mint = Pubkey::new_unique();
        let pc_mint = Pubkey::new_unique();
        ctx.create_mint()
            .pubkey(coin_mint)
            .mint_authority(mint_authority.pubkey())
            .decimals(6)
            .create()
            .unwrap();
        ctx.create_mint()
            .pubkey(pc_mint)
            .mint_authority(mint_authority.pubkey())
            .decimals(6)
            .create()
            .unwrap();

        // ---------- AMM coin + pc vaults (owner = amm_authority PDA) ----------
        let coin_vault = Pubkey::new_unique();
        let pc_vault = Pubkey::new_unique();
        ctx.create_token_account()
            .pubkey(coin_vault)
            .mint(coin_mint)
            .token_owner(amm_authority)
            .amount(1_000_000_000) // 1B base units = 1000 tokens at 6 decimals
            .create()
            .unwrap();
        ctx.create_token_account()
            .pubkey(pc_vault)
            .mint(pc_mint)
            .token_owner(amm_authority)
            .amount(1_000_000_000)
            .create()
            .unwrap();

        // ---------- User A token accounts ----------
        let user_source = Pubkey::new_unique();
        let user_dest = Pubkey::new_unique();
        ctx.create_token_account()
            .pubkey(user_source)
            .mint(coin_mint)
            .token_owner(user.pubkey())
            .amount(100_000_000) // 100 tokens
            .create()
            .unwrap();
        ctx.create_token_account()
            .pubkey(user_dest)
            .mint(pc_mint)
            .token_owner(user.pubkey())
            .amount(0)
            .create()
            .unwrap();

        // ---------- User B token accounts (account-swap detection) ----------
        let user_b_source = Pubkey::new_unique();
        let user_b_dest = Pubkey::new_unique();
        ctx.create_token_account()
            .pubkey(user_b_source)
            .mint(coin_mint)
            .token_owner(user_b.pubkey())
            .amount(100_000_000)
            .create()
            .unwrap();
        ctx.create_token_account()
            .pubkey(user_b_dest)
            .mint(pc_mint)
            .token_owner(user_b.pubkey())
            .amount(0)
            .create()
            .unwrap();

        // ---------- AmmInfo via write_account ----------
        // Economic params come from `amm_info_baseline()`: hand-crafted
        // healthy defaults by default, or a real committed mainnet pool
        // under the `mainnet_snapshot_fixture` feature. The cross-reference
        // fields are then rewired to the local synthetic graph so the
        // SwapBaseInV2 processor path validates (per
        // raydium-amm/program/src/processor.rs:3032-3145).
        let mut amm_info = amm_info_baseline();
        amm_info.status = AMM_STATUS_SWAP_ONLY;       // swap_permission=true, orderbook=false
        amm_info.nonce = amm_nonce as u64;
        amm_info.coin_decimals = 6;                   // match the synthetic 6-dec mints
        amm_info.pc_decimals = 6;
        amm_info.sys_decimal_value = 1_000_000_000;   // 1e9 standard normalization
        amm_info.coin_vault = coin_vault.to_bytes();
        amm_info.pc_vault = pc_vault.to_bytes();
        amm_info.coin_vault_mint = coin_mint.to_bytes();
        amm_info.pc_vault_mint = pc_mint.to_bytes();
        amm_info.amm_owner = user.pubkey().to_bytes();
        amm_info.lp_amount = 1_000_000_000;
        // Leave open_orders, market, market_program, target_orders zeroed
        // (V2 ix bypasses orderbook → not validated against)

        let amm_pool = Pubkey::new_unique();
        let amm_info_bytes = bytemuck::bytes_of(&amm_info).to_vec();
        ctx.write_account(
            &amm_pool,
            Account {
                lamports: rent_for(amm_info_bytes.len()),
                data: amm_info_bytes,
                owner: program_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        Self {
            ctx,
            program_id,
            fee_payer,
            mint_authority,
            amm_pool,
            amm_authority,
            amm_nonce,
            coin_vault,
            pc_vault,
            coin_mint,
            pc_mint,
            user,
            user_source,
            user_dest,
            user_b,
            user_b_source,
            user_b_dest,
        }
    }

    pub fn action_swap_base_in_v2(
        &mut self,
        #[range(1..1_000_000)] amount_in: u64,
        #[range(0..1_000_000)] minimum_amount_out: u64,
    ) -> bool {
        let ix = build_swap_base_in_v2_ix(
            self.program_id,
            spl_token_program_id(),
            self.amm_pool,
            self.amm_authority,
            self.coin_vault,
            self.pc_vault,
            self.user_source,
            self.user_dest,
            self.user.pubkey(),
            amount_in,
            minimum_amount_out,
        );
        self.ctx
            .raw_call(ix)
            .signers(&[&*self.user])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_swap_base_out_v2(
        &mut self,
        #[range(1..1_000_000)] max_amount_in: u64,
        #[range(1..1_000_000)] amount_out: u64,
    ) -> bool {
        let ix = build_swap_base_out_v2_ix(
            self.program_id,
            spl_token_program_id(),
            self.amm_pool,
            self.amm_authority,
            self.coin_vault,
            self.pc_vault,
            self.user_source,
            self.user_dest,
            self.user.pubkey(),
            max_amount_in,
            amount_out,
        );
        self.ctx
            .raw_call(ix)
            .signers(&[&*self.user])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }
}

// ============================================================================
// solinv trait wiring
// ============================================================================

impl HasContext for RaydiumAmmFixture {
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

impl HasInstructionSet for RaydiumAmmFixture {
    fn instructions(&self) -> Vec<InstructionSpec> {
        // SwapBaseInV2 InstructionSpec — Day 16 inventory translated.
        // Day 20 will populate this with the real metadata once Day 19
        // fixture initializes AmmInfo + vaults + token accounts properly.
        let spl_token = spl_token_program_id();

        let mut data = Vec::with_capacity(17);
        data.push(IX_TAG_SWAP_BASE_IN_V2);
        data.extend_from_slice(&100_000u64.to_le_bytes()); // amount_in sample
        data.extend_from_slice(&1u64.to_le_bytes()); // minimum_amount_out sample

        let swap_base_in_v2_spec = InstructionSpec {
            program_id: self.program_id,
            name: "swap_base_in_v2".into(),
            accounts: vec![
                AccountMeta::new_readonly(spl_token, false),
                AccountMeta::new(self.amm_pool, false),
                AccountMeta::new_readonly(self.amm_authority, false),
                AccountMeta::new(self.coin_vault, false),
                AccountMeta::new(self.pc_vault, false),
                AccountMeta::new(self.user_source, false),
                AccountMeta::new(self.user_dest, false),
                AccountMeta::new_readonly(self.user.pubkey(), true),
            ],
            signer_indices: vec![7], // user_owner
            optional_signer_indices: vec![],
            expected_owners: vec![
                None,                    // 0: SPL Token program (its own owner)
                Some(self.program_id),  // 1: AMM pool owned by Raydium AMM
                None,                    // 2: AMM authority is PDA
                Some(spl_token),         // 3: coin vault = SPL TokenAccount
                Some(spl_token),         // 4: pc vault = SPL TokenAccount
                Some(spl_token),         // 5: user source = SPL TokenAccount
                Some(spl_token),         // 6: user dest = SPL TokenAccount
                None,                    // 7: user wallet = system-owned
            ],
            // Native = no Anchor account discriminator
            expected_discriminators: vec![None; 8],
            expected_pda_seeds: vec![
                None,                                                      // 0
                None,                                                      // 1
                Some(vec![AUTHORITY_AMM_SEED.to_vec()]),                  // 2: AMM authority PDA
                None, None, None, None, None,                              // 3-7
            ],
            creates_indices: vec![],
            // Day 20 refinement after Day 19 false-positive analysis:
            //   - account 6 (user_dest) is USER-CONTROLLED per DEX semantics.
            //     Output token account can be any holder with matching mint
            //     (same as Uniswap/Orca/Meteora). NOT context-bound. Empty.
            //   - account 5 (user_source) IS bound — user_source.owner must
            //     match user_source_owner signer per SPL Token transfer. Keep.
            //   - account 3/4 (vaults) bound to AmmInfo via vault-key check.
            //     Substituting tests that Raydium catches mismatch.
            swap_alternates: vec![
                vec![],                            // 0: program id (fixed)
                vec![],                            // 1: cross-pool — Day 21 (needs 2nd pool fixture)
                vec![],                            // 2: PDA derivation
                vec![self.pc_vault],               // 3: swap coin/pc vault
                vec![self.coin_vault],             // 4: reverse swap
                vec![self.user_b_source],          // 5: drain other user (signer mismatch should fail)
                vec![],                            // 6: USER-CONTROLLED (DEX permissive)
                vec![],                            // 7: signer identity
            ],
            data_sample: data,
            signers: vec![Arc::clone(&self.user)],
            // Day 34 — unchecked-math Bounded on coin / pc vault token balances.
            // SPL TokenAccount.amount lives at offset 64 (32-byte mint +
            // 32-byte owner). Cap = 10^18: far above any legitimate AMM
            // vault balance (init = 1e9; even a runaway trader can't
            // legitimately push it past 10^18). Wrap-to-near-u64::MAX
            // signature exceeds 10^18; tighter precision-loss bugs that
            // stay below 10^18 won't fire — that's the conservative
            // setting per the Day 31 spec §5 false-positive analysis.
            state_invariants: vec![
                StateInvariant {
                    name: "coin_vault_amount_bounded".to_string(),
                    kind: StateInvariantKind::Bounded {
                        field_offset: 64,
                        field_size: 8,
                        min: 0,
                        max: 1_000_000_000_000_000_000,
                    },
                    accounts: vec![3],
                },
                StateInvariant {
                    name: "pc_vault_amount_bounded".to_string(),
                    kind: StateInvariantKind::Bounded {
                        field_offset: 64,
                        field_size: 8,
                        min: 0,
                        max: 1_000_000_000_000_000_000,
                    },
                    accounts: vec![4],
                },
            ],
            // Day 38 — cu-dos Gate 2 cap. 100K = ~2× the upper end of
            // observed-legitimate swap CU (typical SwapBaseInV2 ~30-50K
            // pre-test). Below the 200K runtime ceiling, above any
            // reasonable legitimate consumption — fires only on
            // genuinely pathological code paths.
            cu_budget: Some(100_000),
            // Day 58 — cpi-reentrancy Gate 2 enrollment. Empty allowlist:
            // any observed CPI cycle through Raydium AMM fires. Under
            // Phase 2.5 framing the expected result is 0 violations
            // (Raydium's CPI graph is 2-3 hops, non-cyclic). A surprise
            // ≥1 finding triages as parser FP first, then real bug.
            cpi_reentrancy: Some(CpiReentrancyConfig { allowlist: vec![] }),
            realloc_check: Some(ReallocCheckConfig::default()),
            bump_seed_check: Some(BumpSeedCheckConfig { bump_data_offset: None }),
            };

        // SwapBaseOutV2 — Day 21 addition. Same 8-account layout as InV2,
        // tag=17, wire = [17, max_amount_in u64 LE, amount_out u64 LE].
        let mut out_v2_data = Vec::with_capacity(17);
        out_v2_data.push(IX_TAG_SWAP_BASE_OUT_V2);
        out_v2_data.extend_from_slice(&1_000_000u64.to_le_bytes()); // max_amount_in
        out_v2_data.extend_from_slice(&1u64.to_le_bytes());          // amount_out

        let swap_base_out_v2_spec = InstructionSpec {
            program_id: self.program_id,
            name: "swap_base_out_v2".into(),
            accounts: vec![
                AccountMeta::new_readonly(spl_token, false),
                AccountMeta::new(self.amm_pool, false),
                AccountMeta::new_readonly(self.amm_authority, false),
                AccountMeta::new(self.coin_vault, false),
                AccountMeta::new(self.pc_vault, false),
                AccountMeta::new(self.user_source, false),
                AccountMeta::new(self.user_dest, false),
                AccountMeta::new_readonly(self.user.pubkey(), true),
            ],
            signer_indices: vec![7],
            optional_signer_indices: vec![],
            expected_owners: vec![
                None,
                Some(self.program_id),
                None,
                Some(spl_token),
                Some(spl_token),
                Some(spl_token),
                Some(spl_token),
                None,
            ],
            expected_discriminators: vec![None; 8],
            expected_pda_seeds: vec![
                None, None,
                Some(vec![AUTHORITY_AMM_SEED.to_vec()]),
                None, None, None, None, None,
            ],
            creates_indices: vec![],
            // Identical alternates to InV2 — same DEX semantics: user_dest
            // is user-controlled (Day 20 lesson), user_source must match
            // signer, vaults bound to AmmInfo.
            swap_alternates: vec![
                vec![],
                vec![],
                vec![],
                vec![self.pc_vault],
                vec![self.coin_vault],
                vec![self.user_b_source],
                vec![],
                vec![],
            ],
            data_sample: out_v2_data,
            signers: vec![Arc::clone(&self.user)],
            // Day 34 — same Bounded pair as InV2 (vaults bound to AmmInfo,
            // same SPL TokenAccount layout, same wrap threshold).
            state_invariants: vec![
                StateInvariant {
                    name: "coin_vault_amount_bounded".to_string(),
                    kind: StateInvariantKind::Bounded {
                        field_offset: 64,
                        field_size: 8,
                        min: 0,
                        max: 1_000_000_000_000_000_000,
                    },
                    accounts: vec![3],
                },
                StateInvariant {
                    name: "pc_vault_amount_bounded".to_string(),
                    kind: StateInvariantKind::Bounded {
                        field_offset: 64,
                        field_size: 8,
                        min: 0,
                        max: 1_000_000_000_000_000_000,
                    },
                    accounts: vec![4],
                },
            ],
            // Day 38 — same cu-dos cap as InV2 (same ix shape, same
            // expected legitimate CU band).
            cu_budget: Some(100_000),
            // Day 58 — cpi-reentrancy Gate 2 enrollment. Empty allowlist:
            // any observed CPI cycle through Raydium AMM fires. Under
            // Phase 2.5 framing the expected result is 0 violations
            // (Raydium's CPI graph is 2-3 hops, non-cyclic). A surprise
            // ≥1 finding triages as parser FP first, then real bug.
            cpi_reentrancy: Some(CpiReentrancyConfig { allowlist: vec![] }),
            realloc_check: Some(ReallocCheckConfig::default()),
            bump_seed_check: Some(BumpSeedCheckConfig { bump_data_offset: None }),
            };

        vec![swap_base_in_v2_spec, swap_base_out_v2_spec]
    }
}

// ============================================================================
// Invariant tests — Day 20 will populate. Day 18 has only the stub variant.
// ============================================================================

// Combined variant — first-violation-wins TLS may mask later invariants
// per Day 11/12 escrow-demo lesson. Use isolated variants below to
// observe each invariant independently.
#[invariant_test]
fn invariant_swap_base_in_v2_only(fixture: &mut RaydiumAmmFixture) {
    solinv_core::invariants::signer_skip::check(fixture);
    solinv_core::invariants::owner_skip::check(fixture);
    solinv_core::invariants::pda_forge::check(fixture);
    solinv_core::invariants::account_swap::check(fixture);
}

// Day 20 — isolated per-invariant variants (Day 12 escrow-demo pattern).
// Each variant runs ONE invariant; selected via cargo feature flag.
// Native Raydium AMM = 4 applicable invariants (discriminator-skip N/A).

#[invariant_test]
fn invariant_signer_skip_only(fixture: &mut RaydiumAmmFixture) {
    solinv_core::invariants::signer_skip::check(fixture);
}

#[invariant_test]
fn invariant_owner_skip_only(fixture: &mut RaydiumAmmFixture) {
    solinv_core::invariants::owner_skip::check(fixture);
}

#[invariant_test]
fn invariant_pda_forge_only(fixture: &mut RaydiumAmmFixture) {
    solinv_core::invariants::pda_forge::check(fixture);
}

#[invariant_test]
fn invariant_account_swap_only(fixture: &mut RaydiumAmmFixture) {
    solinv_core::invariants::account_swap::check(fixture);
}

// Day 34 — Gate 2 of the unchecked-math kill criterion
// (docs/invariants/unchecked-math.md §9). Bounded { 0, 10^18 } on
// coin_vault.amount and pc_vault.amount. Pass: ≥1 violation across
// the SwapV2 surface → continue High-tier expansion. Fail: 0
// violations across the full budget → strategy pivot.
#[invariant_test]
fn invariant_unchecked_math_only(fixture: &mut RaydiumAmmFixture) {
    solinv_core::invariants::run_with_transition_metrics("unchecked-math", || {
        solinv_core::invariants::unchecked_math::check(fixture);
    });
}

// Day 38 — Gate 2 of the cu-dos kill criterion
// (docs/invariants/cu-dos.md §9 + §10). cu_budget = 100_000 declared
// on both SwapV2 specs. Pass: ≥1 violation → continue to
// cpi-reentrancy under same gating. Fail (0 violations across full
// 2-min budget): pivot binds across the entire High-tier program.
#[invariant_test]
fn invariant_cu_dos_only(fixture: &mut RaydiumAmmFixture) {
    solinv_core::invariants::run_with_transition_metrics("cu-dos", || {
        solinv_core::invariants::cu_dos::check(fixture);
    });
}

// Day 58 — Gate 2 of cpi-reentrancy under Phase 2.5 OSS catalog
// framing (docs/invariants/cpi-reentrancy.md §9 + §10). Both SwapV2
// specs carry cpi_reentrancy: Some(default()). Expected: 0 violations
// (Raydium AMM's CPI graph is 2-3 hops, non-cyclic — AMM → SerumDEX-
// shim → SPL Token). A surprise ≥1 finding triages first as parser
// false-positive, then as a real disclosure-template-using bounty
// submission. NOT a kill criterion — null result is publishable
// catalog evidence under Phase 2.5.
#[invariant_test]
fn invariant_cpi_reentrancy_only(fixture: &mut RaydiumAmmFixture) {
    solinv_core::invariants::run_with_transition_metrics("cpi-reentrancy", || {
        solinv_core::invariants::cpi_reentrancy::check(fixture);
    });
}

// Day 59 — Gate 2 of realloc-race under Phase 2.5 OSS catalog
// framing (docs/invariants/realloc-race.md §9 + §10). Both SwapV2
// specs carry realloc_check: Some(default()). Expected: 0 violations
// — Raydium AMM swap is a pure state-mutation operation on fixed-size
// accounts (AmmInfo 752, vault TokenAccount 165, etc.); no realloc
// in the swap path. A surprise ≥1 finding here would be highly
// unusual and triages first as detector FP, then real bug.
#[invariant_test]
fn invariant_realloc_race_only(fixture: &mut RaydiumAmmFixture) {
    solinv_core::invariants::run_with_transition_metrics("realloc-race", || {
        solinv_core::invariants::realloc_race::check(fixture);
    });
}

// Day 60 — Gate 2 of bump-seed-canonicalization under Phase 2.5 OSS
// catalog framing (docs/invariants/bump-seed-canonicalization.md
// §9 + §10). Both SwapV2 specs carry bump_seed_check: Some(default).
// Expected: 0 violations — Raydium AMM SwapV2's PDA is amm_authority
// (seeds = [b"amm authority"]); Raydium's processor.rs validates
// amm_authority against the canonical derivation. Alt-bump
// substitution gives a different pubkey; Raydium rejects.
#[invariant_test]
fn invariant_bump_seed_canonicalization_only(fixture: &mut RaydiumAmmFixture) {
    solinv_core::invariants::run_with_transition_metrics(
        "bump-seed-canonicalization",
        || {
            solinv_core::invariants::bump_seed_canonicalization::check(fixture);
        },
    );
}
