//! # vault_diff_fuzz — anchor↔pinocchio differential harness for W10 vault deposit
//!
//! First differential harness written **with the `solinv-fuzz::differential`
//! trait pattern from the start** (matching-diff, amm-diff, refresh-diff
//! pre-date the trait). The full body-equivalence layer collapses to a
//! single `DifferentialFixture` impl + `check_all_pairs(fixture)` call.
//!
//! ## Surface
//!
//! Targets `anchor_w10_vault` / `pinocchio_w10_vault` from `psyto/pinocchio-bench`.
//! `deposit(deposit_amount)` exercises NAV-weighted share computation against
//! a vault seeded at `total_assets=1_000_000, total_shares=1_000_000` (1:1 NAV).
//!
//! ## Account pairs (declared via `DifferentialFixture::diff_pairs()`)
//!
//! | Pair | Anchor body offset | Pinocchio body offset | Size |
//! | ---- | -----------------: | --------------------: | ---: |
//! | vault         | 8 (Anchor disc) | 0 | 16 |
//! | user_position | 8 (Anchor disc) | 0 | 16 |
//! | user_underlying  | 0 (SPL Token) | 0 | 165 |
//! | vault_underlying | 0 (SPL Token) | 0 | 165 |
//!
//! ## Surface-specific invariants
//!
//! Beyond byte equivalence (which catches all of these implicitly), the
//! harness also extracts NAV ratio on both sides and asserts they match.
//! This is redundant with body equivalence but useful for orthogonal
//! libafl reports — pinpoints math bugs directly to the NAV formula.

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

const ANCHOR_W10_PROGRAM_ID_STR: &str = "2N5cmNMVnqrQDWaKE2oP92bVDwMvGNW69k7mpQfyyiMh";
const PINO_W10_PROGRAM_ID_STR: &str = "BHTGrn49Rw47mahPPhupKShja328C13ibSve4b2gAF9E";
const ANCHOR_W10_SO_PATH: &str =
    "../../../../pinocchio-bench/target/deploy/anchor_w10_vault.so";
const PINO_W10_SO_PATH: &str =
    "../../../../pinocchio-bench/target/deploy/pinocchio_w10_vault.so";

const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);
const TOKEN_PROGRAM_ID_STR: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

const W10_VAULT_BODY: usize = 16;
const W10_USER_POSITION_BODY: usize = 16;
const ANCHOR_DISC_LEN: usize = 8;
const MINT_LEN: usize = 82;
const TOKEN_ACCOUNT_LEN: usize = 165;

const INITIAL_TOTAL_ASSETS: u64 = 1_000_000;
const INITIAL_TOTAL_SHARES: u64 = 1_000_000;
const INITIAL_USER_UNDERLYING: u64 = 10_000_000;

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

fn make_vault_body(total_assets: u64, total_shares: u64) -> Vec<u8> {
    let mut body = vec![0u8; W10_VAULT_BODY];
    body[0..8].copy_from_slice(&total_assets.to_le_bytes());
    body[8..16].copy_from_slice(&total_shares.to_le_bytes());
    body
}

fn build_anchor_deposit_ix(
    program_id: Pubkey,
    authority: Pubkey,
    vault: Pubkey,
    user_position: Pubkey,
    user_underlying: Pubkey,
    vault_underlying: Pubkey,
    token_program: Pubkey,
    deposit_amount: u64,
) -> Instruction {
    let mut data = anchor_ix_disc("deposit").to_vec();
    data.extend_from_slice(&deposit_amount.to_le_bytes());
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(vault, false),
            AccountMeta::new(user_position, false),
            AccountMeta::new(user_underlying, false),
            AccountMeta::new(vault_underlying, false),
            AccountMeta::new_readonly(token_program, false),
        ],
        data,
    }
}

fn build_pino_deposit_ix(
    program_id: Pubkey,
    authority: Pubkey,
    vault: Pubkey,
    user_position: Pubkey,
    user_underlying: Pubkey,
    vault_underlying: Pubkey,
    token_program: Pubkey,
    deposit_amount: u64,
) -> Instruction {
    let data = deposit_amount.to_le_bytes().to_vec();
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(vault, false),
            AccountMeta::new(user_position, false),
            AccountMeta::new(user_underlying, false),
            AccountMeta::new(vault_underlying, false),
            AccountMeta::new_readonly(token_program, false),
        ],
        data,
    }
}

#[derive(Clone)]
struct VaultDiffFixture {
    pub ctx: TestContext,
    anchor_program_id: Pubkey,
    pino_program_id: Pubkey,
    token_program: Pubkey,

    anchor_vault: Pubkey,
    anchor_user_position: Pubkey,
    anchor_user_underlying: Pubkey,
    anchor_vault_underlying: Pubkey,

    pino_vault: Pubkey,
    pino_user_position: Pubkey,
    pino_user_underlying: Pubkey,
    pino_vault_underlying: Pubkey,

    user: Arc<Keypair>,
    fee_payer: Arc<Keypair>,
}

#[fuzz_fixture]
impl VaultDiffFixture {
    pub fn setup() -> Self {
        let mut ctx = TestContext::new();

        let anchor_program_id =
            Pubkey::from_str(ANCHOR_W10_PROGRAM_ID_STR).expect("valid anchor program id");
        let pino_program_id =
            Pubkey::from_str(PINO_W10_PROGRAM_ID_STR).expect("valid pino program id");
        let token_program = Pubkey::from_str(TOKEN_PROGRAM_ID_STR).expect("valid token program id");

        ctx.add_program(&anchor_program_id, ANCHOR_W10_SO_PATH)
            .expect("build pinocchio-bench programs/anchor-w10-vault first");
        ctx.add_program(&pino_program_id, PINO_W10_SO_PATH)
            .expect("build pinocchio-bench programs/pinocchio-w10-vault first");

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

        // Shared mint — Token Program owns the mint, both sides reference it.
        let mint = Keypair::new();
        ctx.write_account(
            &mint.pubkey(),
            Account {
                lamports: MINT_LAMPORTS,
                data: make_mint(&user.pubkey(), 100_000_000_000, 6),
                owner: token_program,
                executable: false,
                rent_epoch: 0,
            },
        )
        .expect("mint pre-fund");

        // Helpers for per-side accounts.
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

        let anchor_vault = make_anchor_acc(
            &mut ctx,
            "Vault",
            make_vault_body(INITIAL_TOTAL_ASSETS, INITIAL_TOTAL_SHARES),
            W10_VAULT_BODY,
        );
        let anchor_user_position = make_anchor_acc(
            &mut ctx,
            "UserPosition",
            vec![0u8; W10_USER_POSITION_BODY],
            W10_USER_POSITION_BODY,
        );
        let anchor_user_underlying = make_token(&mut ctx, INITIAL_USER_UNDERLYING);
        let anchor_vault_underlying = make_token(&mut ctx, INITIAL_TOTAL_ASSETS);

        let pino_vault = make_pino_acc(
            &mut ctx,
            make_vault_body(INITIAL_TOTAL_ASSETS, INITIAL_TOTAL_SHARES),
        );
        let pino_user_position = make_pino_acc(&mut ctx, vec![0u8; W10_USER_POSITION_BODY]);
        let pino_user_underlying = make_token(&mut ctx, INITIAL_USER_UNDERLYING);
        let pino_vault_underlying = make_token(&mut ctx, INITIAL_TOTAL_ASSETS);

        Self {
            ctx,
            anchor_program_id,
            pino_program_id,
            token_program,
            anchor_vault,
            anchor_user_position,
            anchor_user_underlying,
            anchor_vault_underlying,
            pino_vault,
            pino_user_position,
            pino_user_underlying,
            pino_vault_underlying,
            user,
            fee_payer,
        }
    }

    /// Deposit `deposit_amount` units through both targets and let the
    /// invariant variants compare the resulting state.
    ///
    /// Range is 1..1M so the first ~10 deposits fit within user_underlying's
    /// 10M starting balance — past that, deposits would fail SPL transfer
    /// and exercise the execution-parity path instead.
    pub fn action_deposit(
        &mut self,
        #[range(1..1_000_000)] deposit_amount: u64,
    ) -> bool {
        let anchor_ix = build_anchor_deposit_ix(
            self.anchor_program_id,
            self.user.pubkey(),
            self.anchor_vault,
            self.anchor_user_position,
            self.anchor_user_underlying,
            self.anchor_vault_underlying,
            self.token_program,
            deposit_amount,
        );
        let pino_ix = build_pino_deposit_ix(
            self.pino_program_id,
            self.user.pubkey(),
            self.pino_vault,
            self.pino_user_position,
            self.pino_user_underlying,
            self.pino_vault_underlying,
            self.token_program,
            deposit_amount,
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

impl HasContext for VaultDiffFixture {
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

impl DifferentialFixture for VaultDiffFixture {
    fn anchor_program_id(&self) -> Pubkey {
        self.anchor_program_id
    }
    fn pino_program_id(&self) -> Pubkey {
        self.pino_program_id
    }
    /// Four pairs: 2 zero-copy state accounts (Anchor disc on Anchor side)
    /// + 2 SPL TokenAccount bodies (no disc on either, Token Program owns
    /// both). New-trait pattern: `anchor_disc_8` for zero-copy, `raw` for
    /// SPL.
    fn diff_pairs(&self) -> Vec<DiffAccountPair> {
        vec![
            DiffAccountPair::anchor_disc_8(
                "vault",
                self.anchor_vault,
                self.pino_vault,
                W10_VAULT_BODY,
            ),
            DiffAccountPair::anchor_disc_8(
                "user_position",
                self.anchor_user_position,
                self.pino_user_position,
                W10_USER_POSITION_BODY,
            ),
            DiffAccountPair::raw(
                "user_underlying",
                self.anchor_user_underlying,
                self.pino_user_underlying,
                TOKEN_ACCOUNT_LEN,
            ),
            DiffAccountPair::raw(
                "vault_underlying",
                self.anchor_vault_underlying,
                self.pino_vault_underlying,
                TOKEN_ACCOUNT_LEN,
            ),
        ]
    }
}

// ---------------------------------------------------------------------
// Differential checks
// ---------------------------------------------------------------------

fn check_execution_parity(fixture: &mut VaultDiffFixture) {
    let probes: &[u64] = &[1, 100, 1_000, 10_000, 100_000];
    for &deposit_amount in probes {
        let anchor_ix = build_anchor_deposit_ix(
            fixture.anchor_program_id,
            fixture.user.pubkey(),
            fixture.anchor_vault,
            fixture.anchor_user_position,
            fixture.anchor_user_underlying,
            fixture.anchor_vault_underlying,
            fixture.token_program,
            deposit_amount,
        );
        let pino_ix = build_pino_deposit_ix(
            fixture.pino_program_id,
            fixture.user.pubkey(),
            fixture.pino_vault,
            fixture.pino_user_position,
            fixture.pino_user_underlying,
            fixture.pino_vault_underlying,
            fixture.token_program,
            deposit_amount,
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
            &format!("deposit(amount={})", deposit_amount),
            anchor_ok,
            pino_ok,
        ) {
            fuzz_assert!(false, "{}", div);
        }
    }
}

/// Vault NAV comparison: read both sides' `total_assets` / `total_shares`
/// and assert the ratios match (specifically the cross-product to avoid
/// integer division).
fn check_nav_match(fixture: &mut VaultDiffFixture) {
    let vault_pair = DiffAccountPair::anchor_disc_8(
        "vault",
        fixture.anchor_vault,
        fixture.pino_vault,
        W10_VAULT_BODY,
    );
    let Some((a, p)) = read_pair_bodies(fixture.ctx(), &vault_pair) else {
        return;
    };

    let a_assets = u64::from_le_bytes(a[0..8].try_into().unwrap()) as u128;
    let a_shares = u64::from_le_bytes(a[8..16].try_into().unwrap()) as u128;
    let p_assets = u64::from_le_bytes(p[0..8].try_into().unwrap()) as u128;
    let p_shares = u64::from_le_bytes(p[8..16].try_into().unwrap()) as u128;

    fuzz_assert!(
        a_assets == p_assets,
        "vault.total_assets divergence: anchor={} pino={}",
        a_assets,
        p_assets,
    );
    fuzz_assert!(
        a_shares == p_shares,
        "vault.total_shares divergence: anchor={} pino={}",
        a_shares,
        p_shares,
    );
    // Cross-product NAV equivalence (integer-safe):
    // a_assets × p_shares == p_assets × a_shares
    let lhs = a_assets.saturating_mul(p_shares);
    let rhs = p_assets.saturating_mul(a_shares);
    fuzz_assert!(
        lhs == rhs,
        "NAV ratio divergence: anchor=({} / {}) pino=({} / {})",
        a_assets,
        a_shares,
        p_assets,
        p_shares,
    );
}

// ---------------------------------------------------------------------
// Invariant variants
// ---------------------------------------------------------------------

#[invariant_test]
fn invariant_vault_diff_smoke(fixture: &mut VaultDiffFixture) {
    if let Some(div) = check_all_pairs(fixture) {
        fuzz_assert!(false, "{}", div);
    }
    check_nav_match(fixture);
    check_execution_parity(fixture);
}

#[invariant_test]
fn invariant_vault_diff_execution_parity_only(fixture: &mut VaultDiffFixture) {
    check_execution_parity(fixture);
}

#[invariant_test]
fn invariant_vault_diff_state_equivalent_only(fixture: &mut VaultDiffFixture) {
    if let Some(div) = check_all_pairs(fixture) {
        fuzz_assert!(false, "{}", div);
    }
}

#[invariant_test]
fn invariant_vault_diff_nav_match_only(fixture: &mut VaultDiffFixture) {
    check_nav_match(fixture);
}
