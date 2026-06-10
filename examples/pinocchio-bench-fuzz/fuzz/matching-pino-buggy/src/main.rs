//! matching-pino-buggy — acceptance harness for pinocchio-w4-buggy.so
//!
//! Target program is the Pinocchio-side W4 matching engine with two
//! permanent plants. This harness specifically exercises **rewrite-class**
//! bugs — the bug shapes a customer would pay to catch after migrating
//! an Anchor program to Pinocchio.
//!
//! Bug ↔ invariant mapping:
//!   Bug A (signer.is_signer() check skipped)
//!     ↔ invariant_signer_skip_only  (uses solinv-core)
//!   Bug B (insert at `count` ignoring binary-search lo)
//!     ↔ invariant_tick_sort_only    (inline structural)

use crucible_fuzzer::*;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solinv_fuzz::{HasContext, HasInstructionSet, InstructionSpec};
use std::str::FromStr;
use std::sync::Arc;

const BUGGY_PROGRAM_ID_STR: &str = "D2LcWGCK5hRuRptcr9AWd9wgrMSknqcqAPMyQ8KuEkw8";
const BUGGY_SO_PATH: &str =
    "../../programs/pinocchio-w4-buggy/target/deploy/pinocchio_w4_buggy.so";

const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);

// No Anchor discriminator on Pinocchio state accounts. Offsets are
// relative to the start of the account data.
const PINO_MARKET_BODY: usize = 16;
const PINO_BOOK_BODY: usize = 4 + 4 + 32 * 208;
const TICK_SIZE: usize = 208;

const FEE_PAYER_BALANCE: u64 = 10_000_000_000;
const USER_BALANCE: u64 = 1_000_000_000;
const MARKET_LAMPORTS: u64 = 5_000_000;
const BOOK_LAMPORTS: u64 = 100_000_000;

fn build_place_order_ix(
    program_id: Pubkey,
    signer: Pubkey,
    market: Pubkey,
    book: Pubkey,
    price: u64,
    qty: u64,
) -> Instruction {
    let mut data = Vec::with_capacity(16);
    data.extend_from_slice(&price.to_le_bytes());
    data.extend_from_slice(&qty.to_le_bytes());
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(signer, true),
            AccountMeta::new(market, false),
            AccountMeta::new(book, false),
        ],
        data,
    }
}

#[derive(Clone)]
struct PinoBuggyFixture {
    pub ctx: TestContext,
    program_id: Pubkey,
    market: Pubkey,
    book: Pubkey,
    user: Arc<Keypair>,
    fee_payer: Arc<Keypair>,
}

#[fuzz_fixture]
impl PinoBuggyFixture {
    pub fn setup() -> Self {
        let mut ctx = TestContext::new();
        let program_id = Pubkey::from_str(BUGGY_PROGRAM_ID_STR).expect("valid base58");
        ctx.add_program(&program_id, BUGGY_SO_PATH)
            .expect("build programs/pinocchio-w4-buggy first");

        let market_kp = Keypair::new();
        let book_kp = Keypair::new();

        ctx.write_account(
            &market_kp.pubkey(),
            Account {
                lamports: MARKET_LAMPORTS,
                data: vec![0u8; PINO_MARKET_BODY],
                owner: program_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
        ctx.write_account(
            &book_kp.pubkey(),
            Account {
                lamports: BOOK_LAMPORTS,
                data: vec![0u8; PINO_BOOK_BODY],
                owner: program_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

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

        Self {
            ctx,
            program_id,
            market: market_kp.pubkey(),
            book: book_kp.pubkey(),
            user,
            fee_payer,
        }
    }

    pub fn action_place_order(
        &mut self,
        #[range(1..1_000_000_000)] price: u64,
        #[range(1..1_000_000_000)] qty: u64,
    ) -> bool {
        let ix = build_place_order_ix(
            self.program_id,
            self.user.pubkey(),
            self.market,
            self.book,
            price,
            qty,
        );
        self.ctx
            .raw_call(ix)
            .fee_payer(&*self.fee_payer)
            .signers(&[&*self.fee_payer, &*self.user])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }
}

impl HasContext for PinoBuggyFixture {
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

impl HasInstructionSet for PinoBuggyFixture {
    fn instructions(&self) -> Vec<InstructionSpec> {
        let mut sample = Vec::with_capacity(16);
        sample.extend_from_slice(&500u64.to_le_bytes());
        sample.extend_from_slice(&10u64.to_le_bytes());

        vec![InstructionSpec {
            program_id: self.program_id,
            name: "place_order".into(),
            accounts: vec![
                AccountMeta::new_readonly(self.user.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(self.book, false),
            ],
            // signer_skip needs this to know which AccountMeta to unsign.
            signer_indices: vec![0],
            optional_signer_indices: vec![],
            expected_owners: vec![None, Some(self.program_id), Some(self.program_id)],
            // No Anchor account discriminator on Pinocchio state.
            expected_discriminators: vec![None, None, None],
            expected_pda_seeds: vec![None, None, None],
            creates_indices: vec![],
            swap_alternates: vec![vec![], vec![], vec![]],
            data_sample: sample,
            signers: vec![Arc::clone(&self.user)],
            state_invariants: vec![],
            cu_budget: Some(50_000),
            cpi_reentrancy: None,
            realloc_check: None,
            bump_seed_check: None,            }]
    }
}

// ---------- inline check: tick-sort (offsets shifted vs Anchor twin)

const ACC_DISC_LEN: usize = 0; // Pinocchio: state starts at offset 0.

fn read_book(fixture: &PinoBuggyFixture) -> Option<Vec<u8>> {
    fixture.ctx().get_account(&fixture.book).ok().map(|a| a.data)
}

fn tick_price(data: &[u8], i: usize) -> u64 {
    let base = ACC_DISC_LEN + 4 + 4 + i * TICK_SIZE;
    u64::from_le_bytes(data[base..base + 8].try_into().unwrap())
}

fn check_tick_sort(fixture: &mut PinoBuggyFixture) {
    let Some(data) = read_book(fixture) else { return };
    // Walk the entire array — Bug B writes ticks at `count` so the
    // populated region is dense at the front, but in insertion order
    // (not sorted order). check skips zero-price tail slots.
    let mut last: u64 = 0;
    for i in 0..32 {
        let p = tick_price(&data, i);
        if p == 0 {
            continue;
        }
        fuzz_assert!(
            p > last,
            "tick-sort violated at tick[{}]: prices {} -> {} not strictly increasing",
            i, last, p,
        );
        last = p;
    }
}

// ---------- invariant variants ----------

#[invariant_test]
fn invariant_matching_pino_buggy_smoke(fixture: &mut PinoBuggyFixture) {
    // Bug A path
    solinv_core::invariants::signer_skip::check(fixture);
    // Bug B path
    check_tick_sort(fixture);
}

#[invariant_test]
fn invariant_signer_skip_only(fixture: &mut PinoBuggyFixture) {
    solinv_core::invariants::signer_skip::check(fixture);
}

#[invariant_test]
fn invariant_tick_sort_only(fixture: &mut PinoBuggyFixture) {
    check_tick_sort(fixture);
}
