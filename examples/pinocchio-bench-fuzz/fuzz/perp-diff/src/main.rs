//! # perp_diff_fuzz — anchor↔pinocchio differential harness for W12 perp open_position
//!
//! Third green-field-trait harness (after vault-diff and oracle-diff).
//! Phase 0's final differential surface — perp open_position, the largest
//! combined surface in the bench (3 mut zero-copy + 2 SPL token + 1 CPI).
//!
//! ## Surface
//!
//! Targets `anchor_w12_perp` / `pinocchio_w12_perp`. `open_position(position_size,
//! current_slot)` performs:
//! - margin check (`collateral × max_leverage_bps / 10_000 ≥ position_size`)
//! - fee computation (`position_size × fee_bps / 10_000`)
//! - state mutation across user, perp_market, and oracle
//! - SPL transfer of fee from user_token to fee_vault
//!
//! ## Account pairs
//!
//! | Pair | Anchor offset | Pinocchio offset | Body size |
//! | ---- | ------------: | ---------------: | --------: |
//! | user        | 8 | 0 | 32 |
//! | perp_market | 8 | 0 | 24 |
//! | oracle      | 8 | 0 | 16 |
//! | user_token  | 0 | 0 | 165 |
//! | fee_vault   | 0 | 0 | 165 |
//!
//! 5 pairs — matches W8's surface size. The complexity of the math
//! (margin + fee + oracle propagation) makes this the strongest single
//! differential target in the suite.
//!
//! ## Pinned by note
//!
//! `action_open_position` is one-shot per fuzz iteration in spirit — once
//! a position is open (`user.position_size != 0`), subsequent calls fail
//! the precondition. This means the fuzzer mostly probes the "first open
//! succeeds, second open rejects" sequence, which is exactly the
//! double-open protection that invariant #5 (RESULTS.md W12 invariants)
//! cares about.

use crucible_fuzzer::*;
use sha2::{Digest, Sha256};
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use std::str::FromStr;
use std::sync::Arc;

use solinv_fuzz::{
    check_all_pairs, read_pair_bodies, DiffAccountPair, DifferentialFixture, HasContext,
    ParityDivergence,
};

const ANCHOR_W12_PROGRAM_ID_STR: &str = "AUe7aMBwQieB84WLK2CpbySsiQdjU5E3D3xmtY4s1vNd";
const PINO_W12_PROGRAM_ID_STR: &str = "FF8a4bNwL6CP2bbd295kMCAut3UtK8Fiw2KkhhHaRbCR";
const ANCHOR_W12_SO_PATH: &str =
    "../../../../pinocchio-bench/target/deploy/anchor_w12_perp.so";
const PINO_W12_SO_PATH: &str =
    "../../../../pinocchio-bench/target/deploy/pinocchio_w12_perp.so";

const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);
const TOKEN_PROGRAM_ID_STR: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

const W12_USER_BODY: usize = 32;
const W12_MARKET_BODY: usize = 24;
const W12_ORACLE_BODY: usize = 16;
const ANCHOR_DISC_LEN: usize = 8;
const MINT_LEN: usize = 82;
const TOKEN_ACCOUNT_LEN: usize = 165;

const INITIAL_COLLATERAL: u64 = 10_000_000;
const INITIAL_MARK_PRICE: u64 = 1_000;
const INITIAL_MAX_LEVERAGE_BPS: u32 = 100_000;
const INITIAL_FEE_BPS: u32 = 10;
const USER_TOKEN_BALANCE: u64 = 10_000_000;

// Field offsets within UserPerp body
const USER_COLLATERAL_OFFSET: usize = 0;
const USER_POSITION_SIZE_OFFSET: usize = 8;

// Field offsets within PerpMarket body
const MARKET_OPEN_INTEREST_OFFSET: usize = 0;
const MARKET_MAX_LEVERAGE_OFFSET: usize = 16;

const FEE_PAYER_BALANCE: u64 = 100_000_000_000;
const USER_BALANCE: u64 = 10_000_000_000;
const ZERO_COPY_LAMPORTS: u64 = 2_000_000;
const TOKEN_ACCOUNT_LAMPORTS: u64 = 2_500_000;
const MINT_LAMPORTS: u64 = 2_000_000;

fn anchor_acc_disc(name: &str) -> [u8; 8] {
    let h = Sha256::digest(format!("account:{name}").as_bytes());
    h[..8].try_into().unwrap()
}
fn anchor_ix_disc(name: &str) -> [u8; 8] {
    let h = Sha256::digest(format!("global:{name}").as_bytes());
    h[..8].try_into().unwrap()
}

fn make_mint(authority: &Pubkey, supply: u64, decimals: u8) -> Vec<u8> {
    let mut buf = vec![0u8; MINT_LEN];
    buf[0..4].copy_from_slice(&1u32.to_le_bytes());
    buf[4..36].copy_from_slice(authority.as_ref());
    buf[36..44].copy_from_slice(&supply.to_le_bytes());
    buf[44] = decimals;
    buf[45] = 1;
    buf
}

fn make_token_account(mint: &Pubkey, owner: &Pubkey, amount: u64) -> Vec<u8> {
    let mut buf = vec![0u8; TOKEN_ACCOUNT_LEN];
    buf[0..32].copy_from_slice(mint.as_ref());
    buf[32..64].copy_from_slice(owner.as_ref());
    buf[64..72].copy_from_slice(&amount.to_le_bytes());
    buf[108] = 1;
    buf
}

fn make_user_body(collateral: u64) -> Vec<u8> {
    let mut body = vec![0u8; W12_USER_BODY];
    body[0..8].copy_from_slice(&collateral.to_le_bytes());
    body
}

fn make_market_body(mark_price: u64, max_leverage_bps: u32, fee_bps: u32) -> Vec<u8> {
    let mut body = vec![0u8; W12_MARKET_BODY];
    body[8..16].copy_from_slice(&mark_price.to_le_bytes());
    body[16..20].copy_from_slice(&max_leverage_bps.to_le_bytes());
    body[20..24].copy_from_slice(&fee_bps.to_le_bytes());
    body
}

fn make_oracle_body(mark_price: u64) -> Vec<u8> {
    let mut body = vec![0u8; W12_ORACLE_BODY];
    body[0..8].copy_from_slice(&mark_price.to_le_bytes());
    body
}

fn build_anchor_open_ix(
    program_id: Pubkey,
    authority: Pubkey,
    user: Pubkey,
    market: Pubkey,
    oracle: Pubkey,
    user_token: Pubkey,
    fee_vault: Pubkey,
    token_program: Pubkey,
    position_size: u64,
    current_slot: u64,
) -> Instruction {
    let mut data = anchor_ix_disc("open_position").to_vec();
    data.extend_from_slice(&position_size.to_le_bytes());
    data.extend_from_slice(&current_slot.to_le_bytes());
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(user, false),
            AccountMeta::new(market, false),
            AccountMeta::new(oracle, false),
            AccountMeta::new(user_token, false),
            AccountMeta::new(fee_vault, false),
            AccountMeta::new_readonly(token_program, false),
        ],
        data,
    }
}

fn build_pino_open_ix(
    program_id: Pubkey,
    authority: Pubkey,
    user: Pubkey,
    market: Pubkey,
    oracle: Pubkey,
    user_token: Pubkey,
    fee_vault: Pubkey,
    token_program: Pubkey,
    position_size: u64,
    current_slot: u64,
) -> Instruction {
    let mut data = position_size.to_le_bytes().to_vec();
    data.extend_from_slice(&current_slot.to_le_bytes());
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(user, false),
            AccountMeta::new(market, false),
            AccountMeta::new(oracle, false),
            AccountMeta::new(user_token, false),
            AccountMeta::new(fee_vault, false),
            AccountMeta::new_readonly(token_program, false),
        ],
        data,
    }
}

#[derive(Clone)]
struct PerpDiffFixture {
    pub ctx: TestContext,
    anchor_program_id: Pubkey,
    pino_program_id: Pubkey,
    token_program: Pubkey,

    anchor_user: Pubkey,
    anchor_market: Pubkey,
    anchor_oracle: Pubkey,
    anchor_user_token: Pubkey,
    anchor_fee_vault: Pubkey,

    pino_user: Pubkey,
    pino_market: Pubkey,
    pino_oracle: Pubkey,
    pino_user_token: Pubkey,
    pino_fee_vault: Pubkey,

    user: Arc<Keypair>,
    fee_payer: Arc<Keypair>,
}

#[fuzz_fixture]
impl PerpDiffFixture {
    pub fn setup() -> Self {
        let mut ctx = TestContext::new();

        let anchor_program_id =
            Pubkey::from_str(ANCHOR_W12_PROGRAM_ID_STR).expect("valid anchor program id");
        let pino_program_id =
            Pubkey::from_str(PINO_W12_PROGRAM_ID_STR).expect("valid pino program id");
        let token_program = Pubkey::from_str(TOKEN_PROGRAM_ID_STR).expect("valid token program id");

        ctx.add_program(&anchor_program_id, ANCHOR_W12_SO_PATH)
            .expect("build pinocchio-bench programs/anchor-w12-perp first");
        ctx.add_program(&pino_program_id, PINO_W12_SO_PATH)
            .expect("build pinocchio-bench programs/pinocchio-w12-perp first");

        let user = Arc::new(Keypair::new());
        let fee_payer = Arc::new(Keypair::new());
        for (kp, lamports) in [(&user, USER_BALANCE), (&fee_payer, FEE_PAYER_BALANCE)] {
            ctx.create_account()
                .pubkey(kp.pubkey())
                .lamports(lamports)
                .owner(SYSTEM_PROGRAM_ID)
                .create()
                .unwrap();
        }

        // Shared mint between sides.
        let mint = Keypair::new();
        ctx.write_account(
            &mint.pubkey(),
            Account {
                lamports: MINT_LAMPORTS,
                data: make_mint(&user.pubkey(), 1_000_000_000_000, 6),
                owner: token_program,
                executable: false,
                rent_epoch: 0,
            },
        )
        .expect("mint pre-fund");

        let make_anchor_acc =
            |ctx: &mut TestContext, disc_name: &str, body: Vec<u8>, body_len: usize| -> Pubkey {
                let kp = Keypair::new();
                let mut data = vec![0u8; ANCHOR_DISC_LEN + body_len];
                data[..ANCHOR_DISC_LEN].copy_from_slice(&anchor_acc_disc(disc_name));
                data[ANCHOR_DISC_LEN..].copy_from_slice(&body);
                ctx.write_account(
                    &kp.pubkey(),
                    Account {
                        lamports: ZERO_COPY_LAMPORTS,
                        data,
                        owner: anchor_program_id,
                        executable: false,
                        rent_epoch: 0,
                    },
                )
                .expect("anchor zero-copy pre-fund");
                kp.pubkey()
            };

        let make_pino_acc = |ctx: &mut TestContext, body: Vec<u8>| -> Pubkey {
            let kp = Keypair::new();
            ctx.write_account(
                &kp.pubkey(),
                Account {
                    lamports: ZERO_COPY_LAMPORTS,
                    data: body,
                    owner: pino_program_id,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .expect("pino zero-copy pre-fund");
            kp.pubkey()
        };

        let make_token = |ctx: &mut TestContext, amount: u64| -> Pubkey {
            let kp = Keypair::new();
            ctx.write_account(
                &kp.pubkey(),
                Account {
                    lamports: TOKEN_ACCOUNT_LAMPORTS,
                    data: make_token_account(&mint.pubkey(), &user.pubkey(), amount),
                    owner: token_program,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .expect("token account pre-fund");
            kp.pubkey()
        };

        let anchor_user = make_anchor_acc(
            &mut ctx,
            "UserPerp",
            make_user_body(INITIAL_COLLATERAL),
            W12_USER_BODY,
        );
        let anchor_market = make_anchor_acc(
            &mut ctx,
            "PerpMarket",
            make_market_body(INITIAL_MARK_PRICE, INITIAL_MAX_LEVERAGE_BPS, INITIAL_FEE_BPS),
            W12_MARKET_BODY,
        );
        let anchor_oracle = make_anchor_acc(
            &mut ctx,
            "MarketOracle",
            make_oracle_body(INITIAL_MARK_PRICE),
            W12_ORACLE_BODY,
        );
        let anchor_user_token = make_token(&mut ctx, USER_TOKEN_BALANCE);
        let anchor_fee_vault = make_token(&mut ctx, 0);

        let pino_user = make_pino_acc(&mut ctx, make_user_body(INITIAL_COLLATERAL));
        let pino_market = make_pino_acc(
            &mut ctx,
            make_market_body(INITIAL_MARK_PRICE, INITIAL_MAX_LEVERAGE_BPS, INITIAL_FEE_BPS),
        );
        let pino_oracle = make_pino_acc(&mut ctx, make_oracle_body(INITIAL_MARK_PRICE));
        let pino_user_token = make_token(&mut ctx, USER_TOKEN_BALANCE);
        let pino_fee_vault = make_token(&mut ctx, 0);

        Self {
            ctx,
            anchor_program_id,
            pino_program_id,
            token_program,
            anchor_user,
            anchor_market,
            anchor_oracle,
            anchor_user_token,
            anchor_fee_vault,
            pino_user,
            pino_market,
            pino_oracle,
            pino_user_token,
            pino_fee_vault,
            user,
            fee_payer,
        }
    }

    pub fn action_open_position(
        &mut self,
        #[range(1..100_000_000)] position_size: u64,
        #[range(1..1_000_000)] current_slot: u64,
    ) -> bool {
        let anchor_ix = build_anchor_open_ix(
            self.anchor_program_id,
            self.user.pubkey(),
            self.anchor_user,
            self.anchor_market,
            self.anchor_oracle,
            self.anchor_user_token,
            self.anchor_fee_vault,
            self.token_program,
            position_size,
            current_slot,
        );
        let pino_ix = build_pino_open_ix(
            self.pino_program_id,
            self.user.pubkey(),
            self.pino_user,
            self.pino_market,
            self.pino_oracle,
            self.pino_user_token,
            self.pino_fee_vault,
            self.token_program,
            position_size,
            current_slot,
        );

        let anchor_ok = self
            .ctx
            .raw_call(anchor_ix)
            .fee_payer(&*self.fee_payer)
            .signers(&[&*self.fee_payer, &*self.user])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);

        let pino_ok = self
            .ctx
            .raw_call(pino_ix)
            .fee_payer(&*self.fee_payer)
            .signers(&[&*self.fee_payer, &*self.user])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);

        anchor_ok || pino_ok
    }
}

impl HasContext for PerpDiffFixture {
    fn ctx(&self) -> &TestContext {
        &self.ctx
    }
    fn ctx_mut(&mut self) -> &mut TestContext {
        &mut self.ctx
    }
    fn program_ids(&self) -> Vec<Pubkey> {
        vec![self.anchor_program_id, self.pino_program_id]
    }
    fn fee_payer(&self) -> Arc<Keypair> {
        Arc::clone(&self.fee_payer)
    }
}

impl DifferentialFixture for PerpDiffFixture {
    fn anchor_program_id(&self) -> Pubkey {
        self.anchor_program_id
    }
    fn pino_program_id(&self) -> Pubkey {
        self.pino_program_id
    }
    /// Five pairs covering the entire surface: 3 zero-copy state +
    /// 2 SPL token accounts. The bench's largest combined surface.
    fn diff_pairs(&self) -> Vec<DiffAccountPair> {
        vec![
            DiffAccountPair::anchor_disc_8(
                "user",
                self.anchor_user,
                self.pino_user,
                W12_USER_BODY,
            ),
            DiffAccountPair::anchor_disc_8(
                "perp_market",
                self.anchor_market,
                self.pino_market,
                W12_MARKET_BODY,
            ),
            DiffAccountPair::anchor_disc_8(
                "oracle",
                self.anchor_oracle,
                self.pino_oracle,
                W12_ORACLE_BODY,
            ),
            DiffAccountPair::raw(
                "user_token",
                self.anchor_user_token,
                self.pino_user_token,
                TOKEN_ACCOUNT_LEN,
            ),
            DiffAccountPair::raw(
                "fee_vault",
                self.anchor_fee_vault,
                self.pino_fee_vault,
                TOKEN_ACCOUNT_LEN,
            ),
        ]
    }
}

// ---------------------------------------------------------------------
// Differential checks
// ---------------------------------------------------------------------

fn check_execution_parity(fixture: &mut PerpDiffFixture) {
    // Probes target boundary cases: tiny size, near-margin-limit size,
    // over-margin rejection, and the double-open protection.
    let probes: &[(u64, u64)] = &[
        (1, 1),
        (100_000, 200),
        (10_000_000_000, 250),  // exceeds margin → both reject
        (50_000, 300),
    ];

    for &(position_size, current_slot) in probes {
        let anchor_ix = build_anchor_open_ix(
            fixture.anchor_program_id,
            fixture.user.pubkey(),
            fixture.anchor_user,
            fixture.anchor_market,
            fixture.anchor_oracle,
            fixture.anchor_user_token,
            fixture.anchor_fee_vault,
            fixture.token_program,
            position_size,
            current_slot,
        );
        let pino_ix = build_pino_open_ix(
            fixture.pino_program_id,
            fixture.user.pubkey(),
            fixture.pino_user,
            fixture.pino_market,
            fixture.pino_oracle,
            fixture.pino_user_token,
            fixture.pino_fee_vault,
            fixture.token_program,
            position_size,
            current_slot,
        );

        let anchor_ok = fixture
            .ctx
            .raw_call(anchor_ix)
            .fee_payer(&*fixture.fee_payer)
            .signers(&[&*fixture.fee_payer, &*fixture.user])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);

        let pino_ok = fixture
            .ctx
            .raw_call(pino_ix)
            .fee_payer(&*fixture.fee_payer)
            .signers(&[&*fixture.fee_payer, &*fixture.user])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);

        if let Some(div) = ParityDivergence::check(
            &format!("open_position(size={}, slot={})", position_size, current_slot),
            anchor_ok,
            pino_ok,
        ) {
            fuzz_assert!(false, "{}", div);
        }
    }
}

/// Open-interest match — surface-specific. Both sides' perp_market
/// open_interest must agree, AND each side's open_interest must equal
/// that side's user.position_size (single user fixture, so the sum
/// trivially equals the lone user's size).
fn check_open_interest_match(fixture: &mut PerpDiffFixture) {
    let market_pair = DiffAccountPair::anchor_disc_8(
        "perp_market",
        fixture.anchor_market,
        fixture.pino_market,
        W12_MARKET_BODY,
    );
    let user_pair = DiffAccountPair::anchor_disc_8(
        "user",
        fixture.anchor_user,
        fixture.pino_user,
        W12_USER_BODY,
    );
    let Some((am, pm)) = read_pair_bodies(fixture.ctx(), &market_pair) else {
        return;
    };
    let Some((au, pu)) = read_pair_bodies(fixture.ctx(), &user_pair) else {
        return;
    };

    let a_oi = u64::from_le_bytes(
        am[MARKET_OPEN_INTEREST_OFFSET..MARKET_OPEN_INTEREST_OFFSET + 8]
            .try_into()
            .unwrap(),
    );
    let p_oi = u64::from_le_bytes(
        pm[MARKET_OPEN_INTEREST_OFFSET..MARKET_OPEN_INTEREST_OFFSET + 8]
            .try_into()
            .unwrap(),
    );
    fuzz_assert!(
        a_oi == p_oi,
        "perp_market.open_interest divergence: anchor={} pino={}",
        a_oi,
        p_oi,
    );

    let a_size = u64::from_le_bytes(
        au[USER_POSITION_SIZE_OFFSET..USER_POSITION_SIZE_OFFSET + 8]
            .try_into()
            .unwrap(),
    );
    let p_size = u64::from_le_bytes(
        pu[USER_POSITION_SIZE_OFFSET..USER_POSITION_SIZE_OFFSET + 8]
            .try_into()
            .unwrap(),
    );

    // Single-user fixture: open_interest == that user's position_size.
    fuzz_assert!(
        a_oi == a_size,
        "anchor open_interest ({}) != user.position_size ({})",
        a_oi,
        a_size,
    );
    fuzz_assert!(
        p_oi == p_size,
        "pino open_interest ({}) != user.position_size ({})",
        p_oi,
        p_size,
    );
}

/// Margin invariant — post-state must satisfy
/// `collateral × max_leverage_bps / 10_000 ≥ position_size`.
fn check_margin_invariant(fixture: &mut PerpDiffFixture) {
    let market_pair = DiffAccountPair::anchor_disc_8(
        "perp_market",
        fixture.anchor_market,
        fixture.pino_market,
        W12_MARKET_BODY,
    );
    let user_pair = DiffAccountPair::anchor_disc_8(
        "user",
        fixture.anchor_user,
        fixture.pino_user,
        W12_USER_BODY,
    );
    let Some((am, _pm)) = read_pair_bodies(fixture.ctx(), &market_pair) else {
        return;
    };
    let Some((au, pu)) = read_pair_bodies(fixture.ctx(), &user_pair) else {
        return;
    };

    let max_lev = u32::from_le_bytes(
        am[MARKET_MAX_LEVERAGE_OFFSET..MARKET_MAX_LEVERAGE_OFFSET + 4]
            .try_into()
            .unwrap(),
    );

    for (label, body) in [("anchor", au), ("pino", pu)] {
        let collateral = u64::from_le_bytes(
            body[USER_COLLATERAL_OFFSET..USER_COLLATERAL_OFFSET + 8]
                .try_into()
                .unwrap(),
        ) as u128;
        let position_size = u64::from_le_bytes(
            body[USER_POSITION_SIZE_OFFSET..USER_POSITION_SIZE_OFFSET + 8]
                .try_into()
                .unwrap(),
        ) as u128;
        if position_size == 0 {
            continue;
        }
        let max_notional = collateral.saturating_mul(max_lev as u128) / 10_000u128;
        fuzz_assert!(
            max_notional >= position_size,
            "{} margin invariant violated: collateral={} × leverage_bps={} / 10000 = {} < position_size={}",
            label,
            collateral,
            max_lev,
            max_notional,
            position_size,
        );
    }
}

// ---------------------------------------------------------------------
// Invariant variants
// ---------------------------------------------------------------------

#[invariant_test]
fn invariant_perp_diff_smoke(fixture: &mut PerpDiffFixture) {
    if let Some(div) = check_all_pairs(fixture) {
        fuzz_assert!(false, "{}", div);
    }
    check_open_interest_match(fixture);
    check_margin_invariant(fixture);
    check_execution_parity(fixture);
}

#[invariant_test]
fn invariant_perp_diff_execution_parity_only(fixture: &mut PerpDiffFixture) {
    check_execution_parity(fixture);
}

#[invariant_test]
fn invariant_perp_diff_state_equivalent_only(fixture: &mut PerpDiffFixture) {
    if let Some(div) = check_all_pairs(fixture) {
        fuzz_assert!(false, "{}", div);
    }
}

#[invariant_test]
fn invariant_perp_diff_open_interest_match_only(fixture: &mut PerpDiffFixture) {
    check_open_interest_match(fixture);
}

#[invariant_test]
fn invariant_perp_diff_margin_invariant_only(fixture: &mut PerpDiffFixture) {
    check_margin_invariant(fixture);
}
