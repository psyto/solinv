//! oracle-pino-buggy — acceptance harness for pinocchio-w11-buggy.so
//!
//! Bug ↔ invariant mapping:
//!   Bug A (publisher.is_signer() check skipped)
//!     ↔ invariant_signer_skip_only  (uses solinv-core)
//!   Bug B (feed.last_slot = new_slot skipped)
//!     ↔ invariant_last_slot_tracks_only  (inline structural)

use crucible_fuzzer::*;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solinv_fuzz::{HasContext, HasInstructionSet, InstructionSpec};
use std::str::FromStr;
use std::sync::Arc;

const BUGGY_PROGRAM_ID_STR: &str = "8W7esXVgBKsYQLL4AU28yPB2xUipthS4c3dAe5YEpb77";
const BUGGY_SO_PATH: &str =
    "../../programs/pinocchio-w11-buggy/target/deploy/pinocchio_w11_buggy.so";

const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);

// PriceFeed = 5 × u64. No Anchor discriminator.
const PRICE_FEED_BODY: usize = 5 * 8;
const LAST_SLOT_OFFSET: usize = 24; // bytes after price + conf + ema_price

const FEE_PAYER_BALANCE: u64 = 10_000_000_000;
const ACCT_LAMPORTS: u64 = 5_000_000;

fn build_publish_ix(
    program_id: Pubkey,
    publisher: Pubkey,
    price_feed: Pubkey,
    new_price: u64,
    new_conf: u64,
    new_slot: u64,
) -> Instruction {
    let mut data = Vec::with_capacity(24);
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
struct OraclePinoBuggyFixture {
    pub ctx: TestContext,
    program_id: Pubkey,
    price_feed: Pubkey,
    publisher: Arc<Keypair>,
    fee_payer: Arc<Keypair>,

    next_slot: u64,
    last_slot_arg: u64,
    last_publish_succeeded: bool,
}

#[fuzz_fixture]
impl OraclePinoBuggyFixture {
    pub fn setup() -> Self {
        let mut ctx = TestContext::new();
        let program_id = Pubkey::from_str(BUGGY_PROGRAM_ID_STR).expect("valid base58");
        ctx.add_program(&program_id, BUGGY_SO_PATH)
            .expect("build programs/pinocchio-w11-buggy first");

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
        ctx.write_account(
            &price_feed_kp.pubkey(),
            Account {
                lamports: ACCT_LAMPORTS,
                data: vec![0u8; PRICE_FEED_BODY],
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
        let new_slot = self.next_slot;
        self.next_slot = self.next_slot.saturating_add(1);
        self.last_slot_arg = new_slot;

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

impl HasContext for OraclePinoBuggyFixture {
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

impl HasInstructionSet for OraclePinoBuggyFixture {
    fn instructions(&self) -> Vec<InstructionSpec> {
        let mut sample = Vec::with_capacity(24);
        sample.extend_from_slice(&123u64.to_le_bytes());
        sample.extend_from_slice(&1u64.to_le_bytes());
        // Slot 1 is fine for the spec sample — the program's guard
        // is `new_slot > feed.last_slot` and feed starts at 0.
        sample.extend_from_slice(&1u64.to_le_bytes());

        vec![InstructionSpec {
            program_id: self.program_id,
            name: "publish_price".into(),
            accounts: vec![
                AccountMeta::new_readonly(self.publisher.pubkey(), true),
                AccountMeta::new(self.price_feed, false),
            ],
            signer_indices: vec![0],
            optional_signer_indices: vec![],
            expected_owners: vec![None, Some(self.program_id)],
            expected_discriminators: vec![None, None],
            expected_pda_seeds: vec![None, None],
            creates_indices: vec![],
            swap_alternates: vec![vec![], vec![]],
            data_sample: sample,
            signers: vec![Arc::clone(&self.publisher)],
            state_invariants: vec![],
            cu_budget: Some(50_000),
            cpi_reentrancy: None,
            realloc_check: None,
            bump_seed_check: None,            }]
    }
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

fn check_last_slot_tracks(fixture: &mut OraclePinoBuggyFixture) {
    if !fixture.last_publish_succeeded {
        return;
    }
    let data = match fixture.ctx().get_account(&fixture.price_feed) {
        Ok(a) => a.data,
        Err(_) => return,
    };
    let post_slot = read_u64(&data, LAST_SLOT_OFFSET);
    fuzz_assert!(
        post_slot == fixture.last_slot_arg,
        "feed.last_slot stale: passed new_slot={} but feed.last_slot={} after publish_price",
        fixture.last_slot_arg,
        post_slot,
    );
}

#[invariant_test]
fn invariant_oracle_pino_buggy_smoke(fixture: &mut OraclePinoBuggyFixture) {
    solinv_core::invariants::signer_skip::check(fixture);
    check_last_slot_tracks(fixture);
}

#[invariant_test]
fn invariant_signer_skip_only(fixture: &mut OraclePinoBuggyFixture) {
    solinv_core::invariants::signer_skip::check(fixture);
}

#[invariant_test]
fn invariant_last_slot_tracks_only(fixture: &mut OraclePinoBuggyFixture) {
    check_last_slot_tracks(fixture);
}
