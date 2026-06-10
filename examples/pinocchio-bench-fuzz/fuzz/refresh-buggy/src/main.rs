//! refresh-buggy — solinv acceptance harness for anchor-w9-buggy.so
//!
//! Mirrors amm-buggy but targets the planted-bug W9 lending refresh.
//! Bug ↔ invariant mapping:
//!   Bug A (reserve_a.last_update_slot skipped) ↔ invariant_reserve_slot_tracks_only
//!   Bug B (obligation.last_health forced to 0) ↔ invariant_health_positive_only

use crucible_fuzzer::*;
use sha2::{Digest, Sha256};
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solinv_fuzz::HasContext;
use std::str::FromStr;
use std::sync::Arc;

const BUGGY_PROGRAM_ID_STR: &str = "7UJrnvwb7Mnek8R1JrwKciVZhywDnEHEX46mwoaBy8MK";
const BUGGY_SO_PATH: &str =
    "../../programs/anchor-w9-buggy/target/deploy/anchor_w9_buggy.so";

const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);

const ANCHOR_DISC_LEN: usize = 8;
const OBLIGATION_BODY: usize = 32; // 4 × u64
const RESERVE_BODY: usize = 40; // 3 × u64 + u32 + u32 + u64
const ORACLE_BODY: usize = 24; // 3 × u64

const FEE_PAYER_BALANCE: u64 = 10_000_000_000;
const ACCT_LAMPORTS: u64 = 5_000_000;

// Initial state for the fixture's accounts. Chosen so the clean program
// would compute last_health > 0 (collateral > 0, debt > 0) — that gives
// Bug B (forced 0 health) a clean signal.
const INITIAL_DEPOSIT: u64 = 1_000_000;
const INITIAL_BORROW: u64 = 500_000;
const INITIAL_ORACLE_A_PRICE: u64 = 100;
const INITIAL_ORACLE_B_PRICE: u64 = 100;
const INITIAL_BORROW_RATE_BPS: u32 = 500;

fn anchor_acc_disc(name: &str) -> [u8; 8] {
    let h = Sha256::digest(format!("account:{name}").as_bytes());
    h[..8].try_into().unwrap()
}
fn anchor_ix_disc(name: &str) -> [u8; 8] {
    let h = Sha256::digest(format!("global:{name}").as_bytes());
    h[..8].try_into().unwrap()
}

fn make_obligation_body(deposit: u64, borrow: u64) -> Vec<u8> {
    let mut buf = vec![0u8; OBLIGATION_BODY];
    buf[0..8].copy_from_slice(&deposit.to_le_bytes());
    buf[8..16].copy_from_slice(&borrow.to_le_bytes());
    // last_health, last_update_slot = 0
    buf
}

fn make_reserve_body(borrow_rate_bps: u32) -> Vec<u8> {
    let mut buf = vec![0u8; RESERVE_BODY];
    // total_liquidity, total_borrows, cumulative_borrow_rate = 0
    buf[24..28].copy_from_slice(&borrow_rate_bps.to_le_bytes());
    // _pad, last_update_slot = 0
    buf
}

fn make_oracle_body(price: u64) -> Vec<u8> {
    let mut buf = vec![0u8; ORACLE_BODY];
    buf[0..8].copy_from_slice(&price.to_le_bytes());
    // conf, last_update_slot = 0
    buf
}

fn build_refresh_ix(
    program_id: Pubkey,
    signer: Pubkey,
    obligation: Pubkey,
    reserve_a: Pubkey,
    reserve_b: Pubkey,
    oracle_a: Pubkey,
    oracle_b: Pubkey,
    current_slot: u64,
) -> Instruction {
    let mut data = anchor_ix_disc("refresh").to_vec();
    data.extend_from_slice(&current_slot.to_le_bytes());
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(signer, true),
            AccountMeta::new(obligation, false),
            AccountMeta::new(reserve_a, false),
            AccountMeta::new(reserve_b, false),
            AccountMeta::new(oracle_a, false),
            AccountMeta::new(oracle_b, false),
        ],
        data,
    }
}

#[derive(Clone)]
struct RefreshBuggyFixture {
    pub ctx: TestContext,
    program_id: Pubkey,
    obligation: Pubkey,
    reserve_a: Pubkey,
    reserve_b: Pubkey,
    oracle_a: Pubkey,
    oracle_b: Pubkey,
    user: Arc<Keypair>,
    fee_payer: Arc<Keypair>,
    // The most recent current_slot the harness sent, captured for
    // the inline check to compare against the post-state slot fields.
    last_current_slot: u64,
    last_refresh_succeeded: bool,
}

#[fuzz_fixture]
impl RefreshBuggyFixture {
    pub fn setup() -> Self {
        let mut ctx = TestContext::new();
        let program_id = Pubkey::from_str(BUGGY_PROGRAM_ID_STR).expect("valid base58");
        ctx.add_program(&program_id, BUGGY_SO_PATH)
            .expect("build programs/anchor-w9-buggy first");

        let user = Arc::new(Keypair::new());
        let fee_payer = Arc::new(Keypair::new());
        for (kp, lamports) in [(&user, ACCT_LAMPORTS), (&fee_payer, FEE_PAYER_BALANCE)] {
            ctx.create_account()
                .pubkey(kp.pubkey())
                .lamports(lamports)
                .owner(SYSTEM_PROGRAM_ID)
                .create()
                .unwrap();
        }

        let make_account = |ctx: &mut TestContext, disc_name: &str, body: Vec<u8>| -> Pubkey {
            let kp = Keypair::new();
            let mut data = vec![0u8; ANCHOR_DISC_LEN + body.len()];
            data[..8].copy_from_slice(&anchor_acc_disc(disc_name));
            data[8..].copy_from_slice(&body);
            ctx.write_account(
                &kp.pubkey(),
                Account {
                    lamports: ACCT_LAMPORTS,
                    data,
                    owner: program_id,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
            kp.pubkey()
        };

        let obligation =
            make_account(&mut ctx, "Obligation", make_obligation_body(INITIAL_DEPOSIT, INITIAL_BORROW));
        let reserve_a = make_account(&mut ctx, "Reserve", make_reserve_body(INITIAL_BORROW_RATE_BPS));
        let reserve_b = make_account(&mut ctx, "Reserve", make_reserve_body(INITIAL_BORROW_RATE_BPS));
        let oracle_a = make_account(&mut ctx, "Oracle", make_oracle_body(INITIAL_ORACLE_A_PRICE));
        let oracle_b = make_account(&mut ctx, "Oracle", make_oracle_body(INITIAL_ORACLE_B_PRICE));

        Self {
            ctx,
            program_id,
            obligation,
            reserve_a,
            reserve_b,
            oracle_a,
            oracle_b,
            user,
            fee_payer,
            last_current_slot: 0,
            last_refresh_succeeded: false,
        }
    }

    pub fn action_refresh(
        &mut self,
        #[range(1..1_000_000)] current_slot: u64,
    ) -> bool {
        self.last_current_slot = current_slot;
        let ix = build_refresh_ix(
            self.program_id,
            self.user.pubkey(),
            self.obligation,
            self.reserve_a,
            self.reserve_b,
            self.oracle_a,
            self.oracle_b,
            current_slot,
        );
        let ok = self
            .ctx
            .raw_call(ix)
            .fee_payer(&*self.fee_payer)
            .signers(&[&*self.fee_payer, &*self.user])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        self.last_refresh_succeeded = ok;
        ok
    }
}

impl HasContext for RefreshBuggyFixture {
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

// ---------- inline invariant checks ----------

/// reserve_a.last_update_slot must equal the most recent current_slot
/// the harness passed in. Real refresh callers consume this field as
/// freshness telemetry; a stale slot is a real bug, not a no-op.
fn check_reserve_a_slot_tracks(fixture: &mut RefreshBuggyFixture) {
    if !fixture.last_refresh_succeeded {
        return;
    }
    let data = match fixture.ctx().get_account(&fixture.reserve_a) {
        Ok(a) => a.data,
        Err(_) => return,
    };
    // Reserve layout: 24 bytes (3 × u64) + u32 + u32 + last_update_slot(u64)
    // → last_update_slot at body offset 32 (or 40 with discriminator).
    let post_slot = read_u64(&data, ANCHOR_DISC_LEN + 32);
    fuzz_assert!(
        post_slot == fixture.last_current_slot,
        "reserve_a.last_update_slot stale: passed current_slot={} but reserve_a.last_update_slot={} after refresh",
        fixture.last_current_slot,
        post_slot,
    );
}

/// obligation.last_health must be > 0 when the fixture has both
/// deposit_amount > 0 and oracle_a.price > 0 (which the fixture
/// guarantees). last_health = 0 means the program is reporting every
/// position as insolvent — caught immediately.
fn check_health_positive(fixture: &mut RefreshBuggyFixture) {
    if !fixture.last_refresh_succeeded {
        return;
    }
    let data = match fixture.ctx().get_account(&fixture.obligation) {
        Ok(a) => a.data,
        Err(_) => return,
    };
    // Obligation layout: deposit(u64) + borrow(u64) + last_health(u64) + last_update_slot(u64)
    // → last_health at body offset 16 (24 with discriminator).
    let last_health = read_u64(&data, ANCHOR_DISC_LEN + 16);
    let deposit = read_u64(&data, ANCHOR_DISC_LEN);
    fuzz_assert!(
        last_health > 0,
        "obligation.last_health = 0 despite deposit_amount={} > 0 and oracle_a price > 0",
        deposit,
    );
}

// ---------- invariant variants ----------

#[invariant_test]
fn invariant_refresh_buggy_smoke(fixture: &mut RefreshBuggyFixture) {
    check_reserve_a_slot_tracks(fixture);
    check_health_positive(fixture);
}

#[invariant_test]
fn invariant_reserve_slot_tracks_only(fixture: &mut RefreshBuggyFixture) {
    check_reserve_a_slot_tracks(fixture);
}

#[invariant_test]
fn invariant_health_positive_only(fixture: &mut RefreshBuggyFixture) {
    check_health_positive(fixture);
}
