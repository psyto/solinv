//! # matching_fuzz — solinv harness for anchor-w4-matching
//!
//! Mirrors `slumlord-fuzz` shape. Target program is `anchor_w4_matching`
//! from the public `psyto/pinocchio-bench` repo — a small matching
//! engine that exposes `place_order(price, qty)` over two zero-copy
//! accounts (Market with a sequence counter; Book with 32 price levels
//! × 4-deep FIFO of orders).
//!
//! Builds 6 implemented solinv invariants over this surface plus inline
//! W4/W5-specific structural checks (tick sort, count consistency,
//! owner attribution) declared as separate `#[invariant_test]`s.

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

// ---------------------------------------------------------------------
// Target program identity (matches keys/anchor-w4-matching.json in
// psyto/pinocchio-bench).
// ---------------------------------------------------------------------

const ANCHOR_W4_PROGRAM_ID_STR: &str = "F84VDYJd5ukacECaHVkR6QJR1rD9nGmd2AJUw3qDvMN2";
const ANCHOR_W4_SO_PATH: &str =
    "../../../../pinocchio-bench/target/deploy/anchor_w4_matching.so";

const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);

// Account sizes (see pinocchio-bench/bench/src/main.rs W4 constants):
//   Market body = 16 bytes (sequence u64 + side u8 + 7 pad)
//   Book   body = 8 + 16 * 64 = ... no — for W4 it's 32 ticks × 208 bytes + header.
//   See programs/anchor-w4-matching/src/lib.rs:
//     Tick = price u64 + n_orders u32 + pad u32 + [Order; 4]
//     Order = owner_pk [u8; 32] + qty u64 + sequence u64 = 48
//     Tick = 8 + 4 + 4 + 4*48 = 208
//     Book = 4 + 4 + 32 * 208 = 6664
const W4_MARKET_BODY: usize = 16;
const W4_BOOK_BODY: usize = 4 + 4 + 32 * 208;

// Anchor 0.32 adds 8-byte account discriminator: sha256("account:<Type>")[..8].
fn anchor_acc_disc(name: &str) -> [u8; 8] {
    let h = Sha256::digest(format!("account:{name}").as_bytes());
    h[..8].try_into().unwrap()
}
fn anchor_ix_disc(name: &str) -> [u8; 8] {
    let h = Sha256::digest(format!("global:{name}").as_bytes());
    h[..8].try_into().unwrap()
}

const FEE_PAYER_BALANCE: u64 = 10_000_000_000;
const USER_BALANCE: u64 = 1_000_000_000;
const W4_MARKET_LAMPORTS: u64 = 5_000_000;
const W4_BOOK_LAMPORTS: u64 = 100_000_000;

// ---------------------------------------------------------------------
// ix constructor — single ix surface for W4/W5: place_order
// ---------------------------------------------------------------------

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

// ---------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------

#[derive(Clone)]
struct MatchingFixture {
    pub ctx: TestContext,
    program_id: Pubkey,
    market: Pubkey,
    book: Pubkey,
    user: Arc<Keypair>,
    fee_payer: Arc<Keypair>,
}

#[fuzz_fixture]
impl MatchingFixture {
    pub fn setup() -> Self {
        let mut ctx = TestContext::new();

        let program_id =
            Pubkey::from_str(ANCHOR_W4_PROGRAM_ID_STR).expect("valid base58 program id");
        ctx.add_program(&program_id, ANCHOR_W4_SO_PATH)
            .expect("build pinocchio-bench programs/anchor-w4-matching first");

        // Two fresh keypairs to serve as the Market + Book accounts.
        // Both are owned by the program; bodies are zero-initialized
        // with the Anchor 8-byte discriminator prefix so the program's
        // AccountLoader::load_mut accepts them.
        let market_kp = Keypair::new();
        let book_kp = Keypair::new();

        let mut market_data = vec![0u8; 8 + W4_MARKET_BODY];
        market_data[..8].copy_from_slice(&anchor_acc_disc("Market"));
        ctx.write_account(
            &market_kp.pubkey(),
            Account {
                lamports: W4_MARKET_LAMPORTS,
                data: market_data,
                owner: program_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .expect("market account pre-fund");

        let mut book_data = vec![0u8; 8 + W4_BOOK_BODY];
        book_data[..8].copy_from_slice(&anchor_acc_disc("Book"));
        ctx.write_account(
            &book_kp.pubkey(),
            Account {
                lamports: W4_BOOK_LAMPORTS,
                data: book_data,
                owner: program_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .expect("book account pre-fund");

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

    /// Action: place a fuzz-derived order into the book.
    ///
    /// Price + qty drawn from a wide range so the binary-search + shift
    /// path exercises many tree shapes across iterations. Returns
    /// `false` for legitimate program-side rejections (book full, tick
    /// full) — these are normal, not bugs.
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

// ---------------------------------------------------------------------
// solinv integration — HasContext + HasInstructionSet
// ---------------------------------------------------------------------

impl HasContext for MatchingFixture {
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

impl HasInstructionSet for MatchingFixture {
    fn instructions(&self) -> Vec<InstructionSpec> {
        // place_order ix data layout: [disc:8][price:u64 LE][qty:u64 LE] = 24 bytes.
        let mut sample = anchor_ix_disc("place_order").to_vec();
        sample.extend_from_slice(&500u64.to_le_bytes());
        sample.extend_from_slice(&10u64.to_le_bytes());

        let spec = InstructionSpec {
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
            // Layer-2 structural: market.sequence is NonDecreasing.
            // Offset 0 of the Market account body (after Anchor's
            // 8-byte discriminator at 0..8, the sequence u64 lives at
            // 8..16; solinv reads from the raw data slice so we use 8).
            state_invariants: vec![StateInvariant {
                name: "market_sequence_monotonic".to_string(),
                kind: StateInvariantKind::Monotonic {
                    field_offset: 8,
                    field_size: 8,
                    direction: MonotonicDir::NonDecreasing,
                },
                accounts: vec![1], // market account index
            }],
            // place_order CU budget — measured ~1,318 CU on Anchor for
            // empty book (W4), ~1,383 CU for FIFO append (W5). Headroom
            // to 50K means the cu-dos invariant fires only on real
            // pathological executions, not benign growth.
            cu_budget: Some(50_000),
            cpi_reentrancy: None,
            realloc_check: None,
            bump_seed_check: None,            };

        vec![spec]
    }
}

// ---------------------------------------------------------------------
// Inline W4/W5-specific structural checks (not in solinv-core catalog).
//
// These read the Book account post-action and assert structural
// invariants no generic Solana invariant catches. They run inside their
// own #[invariant_test] variants so libafl reports each failure mode
// independently.
// ---------------------------------------------------------------------

const TICK_SIZE: usize = 208;
const ACC_DISC_LEN: usize = 8;

fn read_book(fixture: &MatchingFixture) -> Option<Vec<u8>> {
    fixture.ctx().get_account(&fixture.book).ok().map(|a| a.data)
}

fn book_count(data: &[u8]) -> u32 {
    // Book = disc(8) + count u32 + pad u32 + ticks
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

fn check_tick_sort(fixture: &mut MatchingFixture) {
    let Some(data) = read_book(fixture) else { return };
    let count = book_count(&data) as usize;
    if count < 2 {
        return;
    }
    for i in 0..count - 1 {
        let p_lo = tick_price(&data, i);
        let p_hi = tick_price(&data, i + 1);
        fuzz_assert!(
            p_lo < p_hi,
            "tick-sort violated at index {}: prices [{}, {}] not strictly increasing",
            i,
            p_lo,
            p_hi,
        );
    }
}

fn check_count_consistency(fixture: &mut MatchingFixture) {
    let Some(data) = read_book(fixture) else { return };
    let count = book_count(&data) as usize;
    fuzz_assert!(count <= 32, "book.count overflowed N_TICKS=32: got {}", count);
    for i in 0..count {
        let n = tick_n_orders(&data, i);
        fuzz_assert!(
            n <= 4,
            "tick[{}].n_orders overflowed TICK_DEPTH=4: got {}",
            i,
            n,
        );
    }
}

fn check_owner_attribution(fixture: &mut MatchingFixture) {
    let Some(data) = read_book(fixture) else { return };
    let count = book_count(&data) as usize;
    let user_pk_bytes = fixture.user.pubkey().to_bytes();
    let zero = [0u8; 32];
    for i in 0..count {
        let n = tick_n_orders(&data, i) as usize;
        for d in 0..n {
            let order_base = ACC_DISC_LEN + 4 + 4 + i * TICK_SIZE + 16 + d * 48;
            let owner: [u8; 32] = data[order_base..order_base + 32].try_into().unwrap();
            // Either the placeholder zero (untouched slot) — which by
            // virtue of n_orders should be unreachable here — or the
            // signer that placed it. In this single-user fixture, all
            // orders are placed by `user`, so owner_pk must equal it.
            fuzz_assert!(
                owner == user_pk_bytes || owner == zero,
                "owner-attribution violated at tick[{}].orders[{}]: pk={:?}",
                i,
                d,
                owner,
            );
        }
    }
}

// ---------------------------------------------------------------------
// Invariant variants — generic solinv-core + W4/W5-specific structural
// ---------------------------------------------------------------------

#[invariant_test]
fn invariant_matching_smoke(fixture: &mut MatchingFixture) {
    solinv_core::invariants::signer_skip::check(fixture);
    solinv_core::invariants::owner_skip::check(fixture);
    solinv_core::invariants::discriminator_skip::check(fixture);
    solinv_core::invariants::pda_forge::check(fixture);
    solinv_core::invariants::unchecked_math::check(fixture);
    solinv_core::invariants::cu_dos::check(fixture);
    check_tick_sort(fixture);
    check_count_consistency(fixture);
    check_owner_attribution(fixture);
}

#[invariant_test]
fn invariant_signer_skip_only(fixture: &mut MatchingFixture) {
    solinv_core::invariants::signer_skip::check(fixture);
}

#[invariant_test]
fn invariant_owner_skip_only(fixture: &mut MatchingFixture) {
    solinv_core::invariants::owner_skip::check(fixture);
}

#[invariant_test]
fn invariant_discriminator_skip_only(fixture: &mut MatchingFixture) {
    solinv_core::invariants::discriminator_skip::check(fixture);
}

#[invariant_test]
fn invariant_pda_forge_only(fixture: &mut MatchingFixture) {
    solinv_core::invariants::pda_forge::check(fixture);
}

#[invariant_test]
fn invariant_unchecked_math_only(fixture: &mut MatchingFixture) {
    solinv_core::invariants::run_with_transition_metrics("unchecked-math", || {
        solinv_core::invariants::unchecked_math::check(fixture);
    });
}

#[invariant_test]
fn invariant_cu_dos_only(fixture: &mut MatchingFixture) {
    solinv_core::invariants::run_with_transition_metrics("cu-dos", || {
        solinv_core::invariants::cu_dos::check(fixture);
    });
}

#[invariant_test]
fn invariant_tick_sort_only(fixture: &mut MatchingFixture) {
    check_tick_sort(fixture);
}

#[invariant_test]
fn invariant_count_consistency_only(fixture: &mut MatchingFixture) {
    check_count_consistency(fixture);
}

#[invariant_test]
fn invariant_owner_attribution_only(fixture: &mut MatchingFixture) {
    check_owner_attribution(fixture);
}
