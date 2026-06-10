//! oracle-buggy — solinv acceptance harness for anchor-w11-buggy.so
//!
//! Mirrors refresh-buggy. Bug ↔ invariant mapping:
//!   Bug A (feed.last_slot = new_slot skipped)
//!     ↔ invariant_last_slot_tracks_only
//!   Bug B (feed.publish_count flip-flops 0 ↔ 1)
//!     ↔ invariant_publish_count_strictly_increases_only

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

const BUGGY_PROGRAM_ID_STR: &str = "4Db9tz2hu7hBWapD6xqSJnaysV1A5pJtDuTwYpHJ7v2Q";
const BUGGY_SO_PATH: &str =
    "../../programs/anchor-w11-buggy/target/deploy/anchor_w11_buggy.so";

const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);

const ANCHOR_DISC_LEN: usize = 8;
// PriceFeed = price + conf + ema_price + last_slot + publish_count, all u64.
const PRICE_FEED_BODY: usize = 5 * 8;
const PRICE_OFFSET: usize = 0;
const CONF_OFFSET: usize = 8;
const EMA_OFFSET: usize = 16;
const LAST_SLOT_OFFSET: usize = 24;
const PUBLISH_COUNT_OFFSET: usize = 32;

const FEE_PAYER_BALANCE: u64 = 10_000_000_000;
const ACCT_LAMPORTS: u64 = 5_000_000;

fn anchor_acc_disc(name: &str) -> [u8; 8] {
    let h = Sha256::digest(format!("account:{name}").as_bytes());
    h[..8].try_into().unwrap()
}
fn anchor_ix_disc(name: &str) -> [u8; 8] {
    let h = Sha256::digest(format!("global:{name}").as_bytes());
    h[..8].try_into().unwrap()
}

fn build_publish_ix(
    program_id: Pubkey,
    publisher: Pubkey,
    price_feed: Pubkey,
    new_price: u64,
    new_conf: u64,
    new_slot: u64,
) -> Instruction {
    let mut data = anchor_ix_disc("publish_price").to_vec();
    data.extend_from_slice(&new_price.to_le_bytes());
    data.extend_from_slice(&new_conf.to_le_bytes());
    data.extend_from_slice(&new_slot.to_le_bytes());
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(publisher, true),
            AccountMeta::new(price_feed, false),
        ],
        data,
    }
}

#[derive(Clone)]
struct OracleBuggyFixture {
    pub ctx: TestContext,
    program_id: Pubkey,
    price_feed: Pubkey,
    publisher: Arc<Keypair>,
    fee_payer: Arc<Keypair>,

    pre_publish_count: u64,
    // The action mutates `next_slot` monotonically so the program's
    // `require!(new_slot > feed.last_slot)` check passes every call —
    // the fuzzer can't trivially break the slot monotonicity guard.
    next_slot: u64,
    last_slot_arg: u64,
    last_publish_succeeded: bool,
}

#[fuzz_fixture]
impl OracleBuggyFixture {
    pub fn setup() -> Self {
        let mut ctx = TestContext::new();
        let program_id = Pubkey::from_str(BUGGY_PROGRAM_ID_STR).expect("valid base58");
        ctx.add_program(&program_id, BUGGY_SO_PATH)
            .expect("build programs/anchor-w11-buggy first");

        let publisher = Arc::new(Keypair::new());
        let fee_payer = Arc::new(Keypair::new());
        for (kp, lamports) in [(&publisher, ACCT_LAMPORTS), (&fee_payer, FEE_PAYER_BALANCE)] {
            ctx.create_account()
                .pubkey(kp.pubkey())
                .lamports(lamports)
                .owner(SYSTEM_PROGRAM_ID)
                .create()
                .unwrap();
        }

        let price_feed_kp = Keypair::new();
        let mut data = vec![0u8; ANCHOR_DISC_LEN + PRICE_FEED_BODY];
        data[..8].copy_from_slice(&anchor_acc_disc("PriceFeed"));
        ctx.write_account(
            &price_feed_kp.pubkey(),
            Account {
                lamports: ACCT_LAMPORTS,
                data,
                owner: program_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        Self {
            ctx,
            program_id,
            price_feed: price_feed_kp.pubkey(),
            publisher,
            fee_payer,
            pre_publish_count: 0,
            next_slot: 1,
            last_slot_arg: 0,
            last_publish_succeeded: false,
        }
    }

    pub fn action_publish(
        &mut self,
        #[range(1..1_000_000)] new_price: u64,
        #[range(0..1_000)] new_conf: u64,
    ) -> bool {
        // Slot advances deterministically from the harness side so the
        // program's `require!(new_slot > feed.last_slot)` check is
        // never the bottleneck.
        let new_slot = self.next_slot;
        self.next_slot = self.next_slot.saturating_add(1);
        self.last_slot_arg = new_slot;

        let feed_pre = self.ctx.get_account(&self.price_feed).map(|a| a.data).unwrap_or_default();
        self.pre_publish_count = read_u64(&feed_pre, ANCHOR_DISC_LEN + PUBLISH_COUNT_OFFSET);

        let ix = build_publish_ix(
            self.program_id,
            self.publisher.pubkey(),
            self.price_feed,
            new_price,
            new_conf,
            new_slot,
        );
        let ok = self
            .ctx
            .raw_call(ix)
            .fee_payer(&*self.fee_payer)
            .signers(&[&*self.fee_payer, &*self.publisher])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        self.last_publish_succeeded = ok;
        ok
    }
}

impl HasContext for OracleBuggyFixture {
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

fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

// feed.last_slot must equal the most recent new_slot the harness passed.
// A stale slot would let downstream consumers misjudge freshness on
// every read.
fn check_last_slot_tracks(fixture: &mut OracleBuggyFixture) {
    if !fixture.last_publish_succeeded {
        return;
    }
    let data = match fixture.ctx().get_account(&fixture.price_feed) {
        Ok(a) => a.data,
        Err(_) => return,
    };
    let post_slot = read_u64(&data, ANCHOR_DISC_LEN + LAST_SLOT_OFFSET);
    fuzz_assert!(
        post_slot == fixture.last_slot_arg,
        "feed.last_slot stale: passed new_slot={} but feed.last_slot={} after publish_price",
        fixture.last_slot_arg,
        post_slot,
    );
}

// feed.publish_count must strictly increase across every successful
// publish_price. Catches Bug B's flip-flop on the down-step.
fn check_publish_count_strictly_increases(fixture: &mut OracleBuggyFixture) {
    if !fixture.last_publish_succeeded {
        return;
    }
    let data = match fixture.ctx().get_account(&fixture.price_feed) {
        Ok(a) => a.data,
        Err(_) => return,
    };
    let post_count = read_u64(&data, ANCHOR_DISC_LEN + PUBLISH_COUNT_OFFSET);
    fuzz_assert!(
        post_count > fixture.pre_publish_count,
        "feed.publish_count failed to strictly increase: pre={} post={}",
        fixture.pre_publish_count,
        post_count,
    );
}

#[invariant_test]
fn invariant_oracle_buggy_smoke(fixture: &mut OracleBuggyFixture) {
    check_last_slot_tracks(fixture);
    check_publish_count_strictly_increases(fixture);
}

#[invariant_test]
fn invariant_last_slot_tracks_only(fixture: &mut OracleBuggyFixture) {
    check_last_slot_tracks(fixture);
}

#[invariant_test]
fn invariant_publish_count_strictly_increases_only(fixture: &mut OracleBuggyFixture) {
    check_publish_count_strictly_increases(fixture);
}
