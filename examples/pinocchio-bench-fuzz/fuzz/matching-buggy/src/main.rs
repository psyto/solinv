//! matching-buggy — solinv acceptance harness against anchor-w4-buggy.so
//!
//! Mirrors matching/ but points at the planted-bug program. Each
//! invariant_*_only feature is expected to surface a violation within
//! a few seconds, demonstrating that the harness actually fires on
//! real bugs (not just passes on clean code).
//!
//! Bug ↔ invariant mapping:
//!   Bug A (count never incremented)   ↔ invariant_tick_sort_only
//!   Bug B (n_orders = 5 on new tick)  ↔ invariant_count_consistency_only
//!   Bug C (sequence never bumped)     ↔ invariant_sequence_monotonic_only
//!   Bug D (owner_pk written as zero)  ↔ invariant_owner_attribution_only

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
    HasContext, HasInstructionSet, InstructionSpec, MonotonicDir, StateInvariant,
    StateInvariantKind,
};

const BUGGY_PROGRAM_ID_STR: &str = "GtFb94asScD3ophzCbMwXuoH3rH2yjYVqkkShdHkf8Qt";
const BUGGY_SO_PATH: &str =
    "../../programs/anchor-w4-buggy/target/deploy/anchor_w4_buggy.so";

const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);

const MARKET_BODY: usize = 16;
const BOOK_BODY: usize = 4 + 4 + 32 * 208;
const TICK_SIZE: usize = 208;
const ACC_DISC_LEN: usize = 8;

const FEE_PAYER_BALANCE: u64 = 10_000_000_000;
const USER_BALANCE: u64 = 1_000_000_000;
const MARKET_LAMPORTS: u64 = 5_000_000;
const BOOK_LAMPORTS: u64 = 100_000_000;

fn anchor_acc_disc(name: &str) -> [u8; 8] {
    let h = Sha256::digest(format!("account:{name}").as_bytes());
    h[..8].try_into().unwrap()
}
fn anchor_ix_disc(name: &str) -> [u8; 8] {
    let h = Sha256::digest(format!("global:{name}").as_bytes());
    h[..8].try_into().unwrap()
}

fn build_place_order_ix(
    program_id: Pubkey,
    signer: Pubkey,
    market: Pubkey,
    book: Pubkey,
    price: u64,
    qty: u64,
) -> Instruction {
    let mut data = anchor_ix_disc("place_order").to_vec();
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
struct BuggyFixture {
    pub ctx: TestContext,
    program_id: Pubkey,
    market: Pubkey,
    book: Pubkey,
    user: Arc<Keypair>,
    fee_payer: Arc<Keypair>,
}

#[fuzz_fixture]
impl BuggyFixture {
    pub fn setup() -> Self {
        let mut ctx = TestContext::new();
        let program_id = Pubkey::from_str(BUGGY_PROGRAM_ID_STR).expect("valid base58");
        ctx.add_program(&program_id, BUGGY_SO_PATH)
            .expect("build programs/anchor-w4-buggy first");

        let market_kp = Keypair::new();
        let book_kp = Keypair::new();

        let mut market_data = vec![0u8; ACC_DISC_LEN + MARKET_BODY];
        market_data[..8].copy_from_slice(&anchor_acc_disc("Market"));
        ctx.write_account(
            &market_kp.pubkey(),
            Account {
                lamports: MARKET_LAMPORTS,
                data: market_data,
                owner: program_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        let mut book_data = vec![0u8; ACC_DISC_LEN + BOOK_BODY];
        book_data[..8].copy_from_slice(&anchor_acc_disc("Book"));
        ctx.write_account(
            &book_kp.pubkey(),
            Account {
                lamports: BOOK_LAMPORTS,
                data: book_data,
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

impl HasContext for BuggyFixture {
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

impl HasInstructionSet for BuggyFixture {
    fn instructions(&self) -> Vec<InstructionSpec> {
        let mut sample = anchor_ix_disc("place_order").to_vec();
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
            signer_indices: vec![0],
            optional_signer_indices: vec![],
            expected_owners: vec![None, Some(self.program_id), Some(self.program_id)],
            expected_discriminators: vec![
                None,
                Some(anchor_acc_disc("Market")),
                Some(anchor_acc_disc("Book")),
            ],
            expected_pda_seeds: vec![None, None, None],
            creates_indices: vec![],
            swap_alternates: vec![vec![], vec![], vec![]],
            data_sample: sample,
            signers: vec![Arc::clone(&self.user)],
            state_invariants: vec![StateInvariant {
                name: "market_sequence_monotonic".to_string(),
                kind: StateInvariantKind::Monotonic {
                    field_offset: 8,
                    field_size: 8,
                    direction: MonotonicDir::NonDecreasing,
                },
                accounts: vec![1],
            }],
            cu_budget: Some(50_000),
            cpi_reentrancy: None,
            realloc_check: None,
            bump_seed_check: None,            }]
    }
}

// ---------- inline structural checks (same offsets as matching/) ----

fn read_book(fixture: &BuggyFixture) -> Option<Vec<u8>> {
    fixture.ctx().get_account(&fixture.book).ok().map(|a| a.data)
}
fn book_count(data: &[u8]) -> u32 {
    u32::from_le_bytes(data[ACC_DISC_LEN..ACC_DISC_LEN + 4].try_into().unwrap())
}
fn tick_price(data: &[u8], i: usize) -> u64 {
    let base = ACC_DISC_LEN + 4 + 4 + i * TICK_SIZE;
    u64::from_le_bytes(data[base..base + 8].try_into().unwrap())
}
fn tick_n_orders(data: &[u8], i: usize) -> u32 {
    let base = ACC_DISC_LEN + 4 + 4 + i * TICK_SIZE + 8;
    u32::from_le_bytes(data[base..base + 4].try_into().unwrap())
}

// Tick-sort: walk the populated portion of the book and assert prices
// are strictly increasing. Bug A skips `book.count += 1`, so a second
// insert with a *smaller* price ends up clobbering the same tick slot,
// but the array body (which still holds prior writes at higher
// indices) ends up non-monotonic — fires within a couple of
// successful inserts.
fn check_tick_sort(fixture: &mut BuggyFixture) {
    let Some(data) = read_book(fixture) else { return };
    // Walk the ENTIRE array, not just [0..count], because Bug A keeps
    // count pinned at 0. The non-monotonic ticks live at indices 1+,
    // outside `count`'s view — but real on-chain readers will see them.
    let mut last: u64 = 0;
    for i in 0..32 {
        let p = tick_price(&data, i);
        if p == 0 {
            // skip uninitialized tail
            continue;
        }
        fuzz_assert!(
            p > last,
            "tick-sort violated at tick[{}]: prices {} -> {} not strictly increasing",
            i,
            last,
            p,
        );
        last = p;
    }
}

fn check_count_consistency(fixture: &mut BuggyFixture) {
    let Some(data) = read_book(fixture) else { return };
    let count = book_count(&data) as usize;
    fuzz_assert!(count <= 32, "book.count overflowed N_TICKS=32: got {}", count);
    // Walk the entire array; Bug B writes n_orders=5 on every new tick.
    for i in 0..32 {
        let n = tick_n_orders(&data, i);
        // n=0 is fine (uninitialized tail or sparse slot).
        if n == 0 {
            continue;
        }
        fuzz_assert!(
            n <= 4,
            "tick[{}].n_orders overflowed TICK_DEPTH=4: got {}",
            i,
            n,
        );
    }
}

fn check_owner_attribution(fixture: &mut BuggyFixture) {
    let Some(data) = read_book(fixture) else { return };
    let user_pk = fixture.user.pubkey().to_bytes();
    // Walk the entire array. Bug D writes owner_pk = zeros on every
    // successful insert, so any slot whose qty != 0 must NOT have
    // owner_pk == zero. (Sparse slots have qty == 0 and are skipped.)
    let zero = [0u8; 32];
    for i in 0..32 {
        for d in 0..4 {
            let order_base = ACC_DISC_LEN + 4 + 4 + i * TICK_SIZE + 16 + d * 48;
            let qty_base = order_base + 32;
            let qty = u64::from_le_bytes(data[qty_base..qty_base + 8].try_into().unwrap());
            if qty == 0 {
                continue;
            }
            let owner: [u8; 32] = data[order_base..order_base + 32].try_into().unwrap();
            fuzz_assert!(
                owner == user_pk,
                "owner-attribution violated at tick[{}].orders[{}]: pk={:?} (expected user)",
                i,
                d,
                owner,
            );
            let _ = zero; // suppress unused warning when running other variants
        }
    }
}

// ---------- invariant variants ----------

#[invariant_test]
fn invariant_buggy_smoke(fixture: &mut BuggyFixture) {
    // Runs solinv-core invariants (which exercise the Monotonic
    // StateInvariant on market.sequence — covers Bug C) plus all 3
    // structural inline checks (Bugs A/B/D). First-violation-wins per
    // CLAUDE.md, so individual `_only` variants are the canonical
    // acceptance path; smoke is a one-shot kitchen-sink check.
    solinv_core::invariants::signer_skip::check(fixture);
    solinv_core::invariants::owner_skip::check(fixture);
    solinv_core::invariants::unchecked_math::check(fixture);
    check_tick_sort(fixture);
    check_count_consistency(fixture);
    check_owner_attribution(fixture);
}

#[invariant_test]
fn invariant_tick_sort_only(fixture: &mut BuggyFixture) {
    check_tick_sort(fixture);
}

#[invariant_test]
fn invariant_count_consistency_only(fixture: &mut BuggyFixture) {
    check_count_consistency(fixture);
}

#[invariant_test]
fn invariant_owner_attribution_only(fixture: &mut BuggyFixture) {
    check_owner_attribution(fixture);
}

#[invariant_test]
fn invariant_sequence_monotonic_only(fixture: &mut BuggyFixture) {
    // The Monotonic StateInvariant lives on the InstructionSpec and is
    // run by solinv-core's per-ix transition machinery (the same path
    // unchecked-math drives). Run unchecked-math against this fixture
    // — it pumps the state-invariant evaluator on each call, which
    // is what surfaces Bug C.
    solinv_core::invariants::run_with_transition_metrics("unchecked-math", || {
        solinv_core::invariants::unchecked_math::check(fixture);
    });
}
