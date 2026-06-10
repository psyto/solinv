//! amm-buggy — solinv acceptance harness for anchor-w8-buggy.so
//!
//! Mirrors matching-buggy but targets the planted-bug W8 AMM. Each
//! invariant_*_only feature is expected to surface a violation within
//! a few seconds, demonstrating that the harness's inline checks fire
//! on the modal AMM rewrite bugs.
//!
//! Bug ↔ invariant mapping:
//!   Bug A (amount_out doubled)        ↔ invariant_k_non_decreasing_only
//!   Bug B (reserve_in credited twice) ↔ invariant_reserve_vault_consistent_only

use crucible_fuzzer::*;
use sha2::{Digest, Sha256};
use solinv_fuzz::HasContext;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use std::str::FromStr;
use std::sync::Arc;

const BUGGY_PROGRAM_ID_STR: &str = "8mpVGKhPT933rJ4pjoVQTtS8z5oB2fFFe1Gn3FGBh45C";
const BUGGY_SO_PATH: &str =
    "../../programs/anchor-w8-buggy/target/deploy/anchor_w8_buggy.so";

const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);
const TOKEN_PROGRAM_ID_STR: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

// Layout constants (mirror programs/anchor-w8-buggy/src/lib.rs and
// fuzz/amm-diff/src/main.rs).
const W8_POOL_BODY: usize = 24;
const ANCHOR_DISC_LEN: usize = 8;
const MINT_LEN: usize = 82;
const TOKEN_ACCOUNT_LEN: usize = 165;

const FEE_PAYER_BALANCE: u64 = 100_000_000_000;
const USER_BALANCE: u64 = 10_000_000_000;
const POOL_LAMPORTS: u64 = 5_000_000;
const TOKEN_ACCOUNT_LAMPORTS: u64 = 2_500_000;
const MINT_LAMPORTS: u64 = 2_000_000;

const INITIAL_RESERVE_IN: u64 = 1_000_000;
const INITIAL_RESERVE_OUT: u64 = 2_000_000;
const INITIAL_FEE_BPS: u16 = 30;
const INITIAL_USER_SRC_BALANCE: u64 = 1_000_000_000;
const INITIAL_POOL_VAULT_IN_BALANCE: u64 = INITIAL_RESERVE_IN;
const INITIAL_POOL_VAULT_OUT_BALANCE: u64 = INITIAL_RESERVE_OUT;

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

fn make_pool_body(reserve_in: u64, reserve_out: u64, fee_bps: u16) -> Vec<u8> {
    let mut body = vec![0u8; W8_POOL_BODY];
    body[0..8].copy_from_slice(&reserve_in.to_le_bytes());
    body[8..16].copy_from_slice(&reserve_out.to_le_bytes());
    body[16..18].copy_from_slice(&fee_bps.to_le_bytes());
    body
}

fn build_swap_ix(
    program_id: Pubkey,
    authority: Pubkey,
    pool: Pubkey,
    user_src: Pubkey,
    user_dst: Pubkey,
    pool_vault_in: Pubkey,
    pool_vault_out: Pubkey,
    token_program: Pubkey,
    amount_in: u64,
    min_out: u64,
) -> Instruction {
    let mut data = anchor_ix_disc("swap").to_vec();
    data.extend_from_slice(&amount_in.to_le_bytes());
    data.extend_from_slice(&min_out.to_le_bytes());
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(pool, false),
            AccountMeta::new(user_src, false),
            AccountMeta::new(user_dst, false),
            AccountMeta::new(pool_vault_in, false),
            AccountMeta::new(pool_vault_out, false),
            AccountMeta::new_readonly(token_program, false),
        ],
        data,
    }
}

#[derive(Clone)]
struct AmmBuggyFixture {
    pub ctx: TestContext,
    program_id: Pubkey,
    token_program: Pubkey,

    pool: Pubkey,
    user_src: Pubkey,
    user_dst: Pubkey,
    pool_vault_in: Pubkey,
    pool_vault_out: Pubkey,

    user: Arc<Keypair>,
    fee_payer: Arc<Keypair>,

    // Pre-action snapshots written by action_swap; the inline invariant
    // checks read from these.
    pre_reserve_in: u64,
    pre_reserve_out: u64,
    pre_vault_in_amount: u64,
    pre_vault_out_amount: u64,
    // Set to true once the most recent action_swap call observed a
    // successful tx. Invariant checks skip themselves when this is
    // false (since they can't say anything meaningful about a
    // rejected swap).
    last_swap_succeeded: bool,
}

#[fuzz_fixture]
impl AmmBuggyFixture {
    pub fn setup() -> Self {
        let mut ctx = TestContext::new();
        let program_id = Pubkey::from_str(BUGGY_PROGRAM_ID_STR).expect("valid base58");
        let token_program = Pubkey::from_str(TOKEN_PROGRAM_ID_STR).expect("valid base58");
        ctx.add_program(&program_id, BUGGY_SO_PATH)
            .expect("build programs/anchor-w8-buggy first");

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

        // Two mints, both controlled by `user`.
        let mint_a = Keypair::new().pubkey();
        let mint_b = Keypair::new().pubkey();
        for mint in [mint_a, mint_b] {
            ctx.write_account(
                &mint,
                Account {
                    lamports: MINT_LAMPORTS,
                    data: make_mint(&user.pubkey(), 1_000_000_000_000, 6),
                    owner: token_program,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        }

        // Pool account (8-byte Anchor discriminator + 24-byte body).
        let pool_kp = Keypair::new();
        let mut pool_data = vec![0u8; ANCHOR_DISC_LEN + W8_POOL_BODY];
        pool_data[..8].copy_from_slice(&anchor_acc_disc("Pool"));
        pool_data[8..].copy_from_slice(&make_pool_body(
            INITIAL_RESERVE_IN,
            INITIAL_RESERVE_OUT,
            INITIAL_FEE_BPS,
        ));
        ctx.write_account(
            &pool_kp.pubkey(),
            Account {
                lamports: POOL_LAMPORTS,
                data: pool_data,
                owner: program_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        // 4 token accounts. Seed the pool vaults at the same balance as
        // pool.reserve_{in,out} so the delta(reserve) == delta(vault)
        // check has a clean baseline.
        let mut make_acc = |mint: Pubkey, amount: u64| -> Pubkey {
            let kp = Keypair::new();
            ctx.write_account(
                &kp.pubkey(),
                Account {
                    lamports: TOKEN_ACCOUNT_LAMPORTS,
                    data: make_token_account(&mint, &user.pubkey(), amount),
                    owner: token_program,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
            kp.pubkey()
        };
        let user_src = make_acc(mint_a, INITIAL_USER_SRC_BALANCE);
        let user_dst = make_acc(mint_b, 0);
        let pool_vault_in = make_acc(mint_a, INITIAL_POOL_VAULT_IN_BALANCE);
        let pool_vault_out = make_acc(mint_b, INITIAL_POOL_VAULT_OUT_BALANCE);

        Self {
            ctx,
            program_id,
            token_program,
            pool: pool_kp.pubkey(),
            user_src,
            user_dst,
            pool_vault_in,
            pool_vault_out,
            user,
            fee_payer,
            pre_reserve_in: INITIAL_RESERVE_IN,
            pre_reserve_out: INITIAL_RESERVE_OUT,
            pre_vault_in_amount: INITIAL_POOL_VAULT_IN_BALANCE,
            pre_vault_out_amount: INITIAL_POOL_VAULT_OUT_BALANCE,
            last_swap_succeeded: false,
        }
    }

    /// Action: pull pre-state, run swap, leave invariants to compare
    /// the post-state against the stashed pre-state.
    pub fn action_swap(
        &mut self,
        #[range(1..1_000)] amount_in: u64,
        #[range(0..1)] _min_out_hint: u64,
    ) -> bool {
        // Snapshot pre-state.
        let pool_pre = self
            .ctx
            .get_account(&self.pool)
            .map(|a| a.data)
            .unwrap_or_default();
        self.pre_reserve_in = read_u64(&pool_pre, ANCHOR_DISC_LEN);
        self.pre_reserve_out = read_u64(&pool_pre, ANCHOR_DISC_LEN + 8);
        self.pre_vault_in_amount = token_account_amount(&self.ctx, &self.pool_vault_in);
        self.pre_vault_out_amount = token_account_amount(&self.ctx, &self.pool_vault_out);

        let ix = build_swap_ix(
            self.program_id,
            self.user.pubkey(),
            self.pool,
            self.user_src,
            self.user_dst,
            self.pool_vault_in,
            self.pool_vault_out,
            self.token_program,
            amount_in,
            0, // min_out — keep at 0 to avoid slippage rejections crowding the corpus
        );

        let ok = self
            .ctx
            .raw_call(ix)
            .fee_payer(&*self.fee_payer)
            .signers(&[&*self.fee_payer, &*self.user])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        self.last_swap_succeeded = ok;
        ok
    }
}

impl solinv_fuzz::HasContext for AmmBuggyFixture {
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

// ---------- helpers ----------

fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

fn token_account_amount(ctx: &TestContext, addr: &Pubkey) -> u64 {
    ctx.get_account(addr)
        .ok()
        .and_then(|a| {
            if a.data.len() >= 72 {
                Some(read_u64(&a.data, 64))
            } else {
                None
            }
        })
        .unwrap_or(0)
}

// ---------- inline invariant checks ----------

/// k = reserve_in × reserve_out must be non-decreasing across every
/// successful swap. The fee guarantees strict increase in the limit;
/// even fee-less the formula keeps k constant in continuous math. Any
/// drop = the program gave the user too much output.
fn check_k_non_decreasing(fixture: &mut AmmBuggyFixture) {
    if !fixture.last_swap_succeeded {
        return;
    }
    let pool_data = match fixture.ctx().get_account(&fixture.pool) {
        Ok(a) => a.data,
        Err(_) => return,
    };
    let reserve_in_post = read_u64(&pool_data, ANCHOR_DISC_LEN);
    let reserve_out_post = read_u64(&pool_data, ANCHOR_DISC_LEN + 8);
    let k_pre = (fixture.pre_reserve_in as u128) * (fixture.pre_reserve_out as u128);
    let k_post = (reserve_in_post as u128) * (reserve_out_post as u128);
    fuzz_assert!(
        k_post >= k_pre,
        "k decreased across swap: k_pre={} (reserve_in_pre={}, reserve_out_pre={}) → k_post={} (reserve_in_post={}, reserve_out_post={})",
        k_pre, fixture.pre_reserve_in, fixture.pre_reserve_out,
        k_post, reserve_in_post, reserve_out_post,
    );
}

/// delta(pool.reserve_X) must equal delta(pool_vault_X.amount). Pool
/// reserves are bookkeeping; vault amounts are the on-chain truth. Any
/// drift = the program is lying about its own reserves.
fn check_reserve_vault_consistent(fixture: &mut AmmBuggyFixture) {
    if !fixture.last_swap_succeeded {
        return;
    }
    let pool_data = match fixture.ctx().get_account(&fixture.pool) {
        Ok(a) => a.data,
        Err(_) => return,
    };
    let reserve_in_post = read_u64(&pool_data, ANCHOR_DISC_LEN);
    let reserve_out_post = read_u64(&pool_data, ANCHOR_DISC_LEN + 8);
    let vault_in_post = token_account_amount(fixture.ctx(), &fixture.pool_vault_in);
    let vault_out_post = token_account_amount(fixture.ctx(), &fixture.pool_vault_out);

    let dr_in = reserve_in_post as i128 - fixture.pre_reserve_in as i128;
    let dv_in = vault_in_post as i128 - fixture.pre_vault_in_amount as i128;
    let dr_out = reserve_out_post as i128 - fixture.pre_reserve_out as i128;
    let dv_out = vault_out_post as i128 - fixture.pre_vault_out_amount as i128;

    fuzz_assert!(
        dr_in == dv_in,
        "reserve_in/vault_in drift: Δreserve={} vs Δvault={} (pre reserve={}/vault={}, post reserve={}/vault={})",
        dr_in, dv_in,
        fixture.pre_reserve_in, fixture.pre_vault_in_amount,
        reserve_in_post, vault_in_post,
    );
    fuzz_assert!(
        dr_out == dv_out,
        "reserve_out/vault_out drift: Δreserve={} vs Δvault={} (pre reserve={}/vault={}, post reserve={}/vault={})",
        dr_out, dv_out,
        fixture.pre_reserve_out, fixture.pre_vault_out_amount,
        reserve_out_post, vault_out_post,
    );
}

// ---------- invariant variants ----------

#[invariant_test]
fn invariant_amm_buggy_smoke(fixture: &mut AmmBuggyFixture) {
    check_k_non_decreasing(fixture);
    check_reserve_vault_consistent(fixture);
}

#[invariant_test]
fn invariant_k_non_decreasing_only(fixture: &mut AmmBuggyFixture) {
    check_k_non_decreasing(fixture);
}

#[invariant_test]
fn invariant_reserve_vault_consistent_only(fixture: &mut AmmBuggyFixture) {
    check_reserve_vault_consistent(fixture);
}
