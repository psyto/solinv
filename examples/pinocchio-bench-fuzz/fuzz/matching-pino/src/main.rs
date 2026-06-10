//! # matching_pino_fuzz — solinv twin for pinocchio-w4-matching
//!
//! Counterpart to the `matching/` Anchor harness. Target program is
//! `pinocchio_w4_matching` from the public `psyto/pinocchio-bench`
//! repo — a Pinocchio rewrite of the same matching-engine surface that
//! `anchor_w4_matching` implements with `AccountLoader`.
//!
//! The point of this twin is the **paired-service wedge**: showing that
//! the same invariants the Anchor original satisfies (matching/) also
//! hold for the Pinocchio rewrite. The CU savings live in
//! `pinocchio-bench/RESULTS.md`; the safety proof lives here.
//!
//! Differences vs the Anchor harness:
//!   - **No 8-byte account discriminator** on Market or Book — state
//!     starts at offset 0, not 8. Inline structural checks adjust
//!     offsets accordingly.
//!   - **No Anchor sighash** on instruction data — `place_order` data
//!     is just `[price u64 LE][qty u64 LE]` = 16 bytes (no discriminator
//!     prefix). InstructionSpec carries the raw layout.
//!   - **`discriminator-skip` and `pda-forge` invariant variants are
//!     N/A** for this target — Pinocchio doesn't use either pattern.
//!     The `signer-skip` / `owner-skip` / `unchecked-math` / `cu-dos`
//!     invariants from solinv-core still apply.

use crucible_fuzzer::*;
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
// Target program identity (matches keys/pinocchio-w4-matching.json in
// psyto/pinocchio-bench).
// ---------------------------------------------------------------------

const PINO_W4_PROGRAM_ID_STR: &str = "EZxAdAKQbnD6HZqchzuFdD3UZYVUeF5u7ffYj2pHPbc8";
const PINO_W4_SO_PATH: &str =
    "../../../../pinocchio-bench/target/deploy/pinocchio_w4_matching.so";

const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);

// Account sizes — no 8-byte discriminator on either Market or Book.
//   Market = sequence u64 + side u8 + 7 pad      = 16
//   Book   = count u32 + pad u32 + [Tick; 32]    = 6664
//   Tick   = price u64 + n_orders u32 + pad u32 + [Order; 4] = 208
//   Order  = owner_pk [u8;32] + qty u64 + sequence u64       = 48
const PINO_MARKET_BODY: usize = 16;
const PINO_BOOK_BODY: usize = 4 + 4 + 32 * 208;

const FEE_PAYER_BALANCE: u64 = 10_000_000_000;
const USER_BALANCE: u64 = 1_000_000_000;
const PINO_MARKET_LAMPORTS: u64 = 5_000_000;
const PINO_BOOK_LAMPORTS: u64 = 100_000_000;

// ---------------------------------------------------------------------
// ix constructor — Pinocchio target has no Anchor sighash. Data is
// just [price u64 LE][qty u64 LE], 16 bytes.
// ---------------------------------------------------------------------

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

// ---------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------

#[derive(Clone)]
struct MatchingPinoFixture {
    pub ctx: TestContext,
    program_id: Pubkey,
    market: Pubkey,
    book: Pubkey,
    user: Arc<Keypair>,
    fee_payer: Arc<Keypair>,
}

#[fuzz_fixture]
impl MatchingPinoFixture {
    pub fn setup() -> Self {
        let mut ctx = TestContext::new();

        let program_id =
            Pubkey::from_str(PINO_W4_PROGRAM_ID_STR).expect("valid base58 program id");
        ctx.add_program(&program_id, PINO_W4_SO_PATH)
            .expect("build pinocchio-bench programs/pinocchio-w4-matching first");

        let market_kp = Keypair::new();
        let book_kp = Keypair::new();

        // Pinocchio Market: bare 16-byte body, no discriminator.
        ctx.write_account(
            &market_kp.pubkey(),
            Account {
                lamports: PINO_MARKET_LAMPORTS,
                data: vec![0u8; PINO_MARKET_BODY],
                owner: program_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .expect("market account pre-fund");

        // Pinocchio Book: bare 6664-byte body, no discriminator.
        ctx.write_account(
            &book_kp.pubkey(),
            Account {
                lamports: PINO_BOOK_LAMPORTS,
                data: vec![0u8; PINO_BOOK_BODY],
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

impl HasContext for MatchingPinoFixture {
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

impl HasInstructionSet for MatchingPinoFixture {
    fn instructions(&self) -> Vec<InstructionSpec> {
        // No Anchor sighash — data is just the args. The
        // discriminator-skip invariant doesn't run against this target
        // (excluded from the smoke list), so leaving sample as
        // 16 bytes of (price, qty) is accurate.
        let mut sample = Vec::with_capacity(16);
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
            // No Anchor account discriminator on Pinocchio Market / Book.
            expected_discriminators: vec![None, None, None],
            expected_pda_seeds: vec![None, None, None],
            creates_indices: vec![],
            swap_alternates: vec![vec![], vec![], vec![]],
            data_sample: sample,
            signers: vec![Arc::clone(&self.user)],
            // Sequence monotonicity: market.sequence at offset 0 (no
            // 8-byte Anchor discriminator shift like the Anchor twin
            // has).
            state_invariants: vec![StateInvariant {
                name: "market_sequence_monotonic".to_string(),
                kind: StateInvariantKind::Monotonic {
                    field_offset: 0,
                    field_size: 8,
                    direction: MonotonicDir::NonDecreasing,
                },
                accounts: vec![1], // market account index
            }],
            // Pinocchio measured ~141 CU (W4 empty) / ~208 CU (W5
            // append). 50K budget gives huge headroom; cu-dos only
            // fires on real pathological executions.
            cu_budget: Some(50_000),
            cpi_reentrancy: None,
            realloc_check: None,
            bump_seed_check: None,            };

        vec![spec]
    }
}

// ---------------------------------------------------------------------
// Inline W4/W5-specific structural checks — same shape as the Anchor
// twin but offsets shifted by 8 (no Anchor account discriminator).
// ---------------------------------------------------------------------

const TICK_SIZE: usize = 208;
const ACC_DISC_LEN: usize = 0; // Pinocchio: no 8-byte discriminator prefix.

fn read_book(fixture: &MatchingPinoFixture) -> Option<Vec<u8>> {
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

fn check_tick_sort(fixture: &mut MatchingPinoFixture) {
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

fn check_count_consistency(fixture: &mut MatchingPinoFixture) {
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

fn check_owner_attribution(fixture: &mut MatchingPinoFixture) {
    let Some(data) = read_book(fixture) else { return };
    let count = book_count(&data) as usize;
    let user_pk_bytes = fixture.user.pubkey().to_bytes();
    let zero = [0u8; 32];
    for i in 0..count {
        let n = tick_n_orders(&data, i) as usize;
        for d in 0..n {
            let order_base = ACC_DISC_LEN + 4 + 4 + i * TICK_SIZE + 16 + d * 48;
            let owner: [u8; 32] = data[order_base..order_base + 32].try_into().unwrap();
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
// Invariant variants — subset that applies to Pinocchio targets.
// ---------------------------------------------------------------------

#[invariant_test]
fn invariant_matching_smoke(fixture: &mut MatchingPinoFixture) {
    solinv_core::invariants::signer_skip::check(fixture);
    solinv_core::invariants::owner_skip::check(fixture);
    solinv_core::invariants::unchecked_math::check(fixture);
    solinv_core::invariants::cu_dos::check(fixture);
    check_tick_sort(fixture);
    check_count_consistency(fixture);
    check_owner_attribution(fixture);
}

#[invariant_test]
fn invariant_signer_skip_only(fixture: &mut MatchingPinoFixture) {
    solinv_core::invariants::signer_skip::check(fixture);
}

#[invariant_test]
fn invariant_owner_skip_only(fixture: &mut MatchingPinoFixture) {
    solinv_core::invariants::owner_skip::check(fixture);
}

#[invariant_test]
fn invariant_unchecked_math_only(fixture: &mut MatchingPinoFixture) {
    solinv_core::invariants::run_with_transition_metrics("unchecked-math", || {
        solinv_core::invariants::unchecked_math::check(fixture);
    });
}

#[invariant_test]
fn invariant_cu_dos_only(fixture: &mut MatchingPinoFixture) {
    solinv_core::invariants::run_with_transition_metrics("cu-dos", || {
        solinv_core::invariants::cu_dos::check(fixture);
    });
}

#[invariant_test]
fn invariant_tick_sort_only(fixture: &mut MatchingPinoFixture) {
    check_tick_sort(fixture);
}

#[invariant_test]
fn invariant_count_consistency_only(fixture: &mut MatchingPinoFixture) {
    check_count_consistency(fixture);
}

#[invariant_test]
fn invariant_owner_attribution_only(fixture: &mut MatchingPinoFixture) {
    check_owner_attribution(fixture);
}
