//! # matching_diff_fuzz — anchor↔pinocchio differential harness for W4
//!
//! Drives the **same logical action** (place_order with fuzz-derived
//! price + qty) through both the Anchor and Pinocchio W4 matching-engine
//! programs in one Crucible `TestContext`, and asserts that their
//! post-states agree byte-for-byte (after stripping Anchor's 8-byte
//! account discriminator).
//!
//! ## Why this exists
//!
//! `pinocchio-bench` quantifies the **CU savings** of rewriting an
//! Anchor program in Pinocchio. The `matching/` and `matching-pino/`
//! harnesses fuzz each side **independently** for invariant violations.
//! Neither answers the question a paying customer actually asks:
//!
//! > "How do I know your Pinocchio rewrite preserves the semantics
//! > of my Anchor original?"
//!
//! This differential harness answers it: the two programs receive the
//! same input, and after every action their state-account bodies must
//! be identical. Any divergence — either an execution-result mismatch
//! (one accepts what the other rejects) or a state-body byte
//! difference — is recorded as an invariant violation.
//!
//! This is the **safety half** of the paired-service wedge; the CU
//! savings half lives in `pinocchio-bench/RESULTS.md`.
//!
//! ## Design
//!
//! - **One TestContext.** Both Anchor and Pinocchio W4 `.so`s are
//!   loaded at their respective program IDs. The same user keypair
//!   signs both transactions, so the `owner_pk` field that
//!   `place_order` writes into Order slots matches across the pair.
//! - **Two account pairs.** Separate Market + Book pubkeys per side.
//!   Each pair is initialized to the same logical state: zeros, with
//!   the Anchor side carrying an 8-byte account discriminator.
//! - **Equivalence comparison.** After both ix run, the post-state of
//!   Anchor's account body (offset 8 onwards) is compared to
//!   Pinocchio's account body (offset 0). They must match byte-for-byte.
//!
//! ## What the divergence catches
//!
//! - Pinocchio rewrite using `<` instead of `<=` in binary search →
//!   different insertion index → state diverges
//! - Pinocchio rewrite forgetting to bump `market.sequence` → sequence
//!   field diverges
//! - Pinocchio rewrite mis-handling tick-full vs book-full ordering →
//!   one side accepts what the other rejects, execution-parity fails
//! - Endian mismatch on any u64 field → state diverges immediately

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
    check_all_pairs, check_pair_equivalent, read_pair_bodies, DiffAccountPair,
    DifferentialFixture, HasContext, ParityDivergence,
};

// ---------------------------------------------------------------------
// Target program identities — match the keys checked into
// psyto/pinocchio-bench/keys/ for the W4 pair.
// ---------------------------------------------------------------------

const ANCHOR_W4_PROGRAM_ID_STR: &str = "F84VDYJd5ukacECaHVkR6QJR1rD9nGmd2AJUw3qDvMN2";
const PINO_W4_PROGRAM_ID_STR: &str = "EZxAdAKQbnD6HZqchzuFdD3UZYVUeF5u7ffYj2pHPbc8";
const ANCHOR_W4_SO_PATH: &str =
    "../../../../pinocchio-bench/target/deploy/anchor_w4_matching.so";
const PINO_W4_SO_PATH: &str =
    "../../../../pinocchio-bench/target/deploy/pinocchio_w4_matching.so";

const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);

// Account body sizes — identical between the two sides modulo the
// 8-byte Anchor discriminator prefix.
//   Market body = sequence u64 + side u8 + 7 pad             = 16 bytes
//   Book body   = count u32 + pad u32 + [Tick; 32]           = 6664 bytes
//   (Tick = price u64 + n_orders u32 + pad u32 + [Order; 4]  = 208 bytes
//    Order = owner_pk [u8;32] + qty u64 + sequence u64       = 48 bytes)
const W4_MARKET_BODY: usize = 16;
const W4_BOOK_BODY: usize = 4 + 4 + 32 * 208;
const ANCHOR_DISC_LEN: usize = 8;

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
// ix constructors — Anchor side prepends an 8-byte sighash; Pinocchio
// side ships raw (price, qty) bytes.
// ---------------------------------------------------------------------

fn build_anchor_place_order_ix(
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

fn build_pino_place_order_ix(
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
struct MatchingDiffFixture {
    pub ctx: TestContext,
    anchor_program_id: Pubkey,
    pino_program_id: Pubkey,
    anchor_market: Pubkey,
    anchor_book: Pubkey,
    pino_market: Pubkey,
    pino_book: Pubkey,
    user: Arc<Keypair>,
    fee_payer: Arc<Keypair>,
}

#[fuzz_fixture]
impl MatchingDiffFixture {
    pub fn setup() -> Self {
        let mut ctx = TestContext::new();

        let anchor_program_id =
            Pubkey::from_str(ANCHOR_W4_PROGRAM_ID_STR).expect("valid base58 anchor program id");
        let pino_program_id =
            Pubkey::from_str(PINO_W4_PROGRAM_ID_STR).expect("valid base58 pino program id");

        ctx.add_program(&anchor_program_id, ANCHOR_W4_SO_PATH)
            .expect("build pinocchio-bench programs/anchor-w4-matching first");
        ctx.add_program(&pino_program_id, PINO_W4_SO_PATH)
            .expect("build pinocchio-bench programs/pinocchio-w4-matching first");

        // Anchor side: market + book with 8-byte account discriminator.
        let anchor_market_kp = Keypair::new();
        let anchor_book_kp = Keypair::new();

        let mut anchor_market_data = vec![0u8; ANCHOR_DISC_LEN + W4_MARKET_BODY];
        anchor_market_data[..ANCHOR_DISC_LEN].copy_from_slice(&anchor_acc_disc("Market"));
        ctx.write_account(
            &anchor_market_kp.pubkey(),
            Account {
                lamports: W4_MARKET_LAMPORTS,
                data: anchor_market_data,
                owner: anchor_program_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .expect("anchor market pre-fund");

        let mut anchor_book_data = vec![0u8; ANCHOR_DISC_LEN + W4_BOOK_BODY];
        anchor_book_data[..ANCHOR_DISC_LEN].copy_from_slice(&anchor_acc_disc("Book"));
        ctx.write_account(
            &anchor_book_kp.pubkey(),
            Account {
                lamports: W4_BOOK_LAMPORTS,
                data: anchor_book_data,
                owner: anchor_program_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .expect("anchor book pre-fund");

        // Pinocchio side: same logical body, no discriminator prefix.
        let pino_market_kp = Keypair::new();
        let pino_book_kp = Keypair::new();

        ctx.write_account(
            &pino_market_kp.pubkey(),
            Account {
                lamports: W4_MARKET_LAMPORTS,
                data: vec![0u8; W4_MARKET_BODY],
                owner: pino_program_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .expect("pino market pre-fund");

        ctx.write_account(
            &pino_book_kp.pubkey(),
            Account {
                lamports: W4_BOOK_LAMPORTS,
                data: vec![0u8; W4_BOOK_BODY],
                owner: pino_program_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .expect("pino book pre-fund");

        // Shared user + fee payer so the owner_pk written into Order
        // slots matches across both sides.
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
            anchor_program_id,
            pino_program_id,
            anchor_market: anchor_market_kp.pubkey(),
            anchor_book: anchor_book_kp.pubkey(),
            pino_market: pino_market_kp.pubkey(),
            pino_book: pino_book_kp.pubkey(),
            user,
            fee_payer,
        }
    }

    /// Differential action: drive `place_order` through both targets
    /// with the same fuzz-derived input.
    ///
    /// Returns `true` if the action altered state on either side
    /// (so libafl considers it interesting input). All actual
    /// equivalence assertions live in the `#[invariant_test]` variants
    /// below — this function only generates a synchronized state
    /// transition for them to inspect.
    pub fn action_place_order(
        &mut self,
        #[range(1..1_000_000_000)] price: u64,
        #[range(1..1_000_000_000)] qty: u64,
    ) -> bool {
        let anchor_ix = build_anchor_place_order_ix(
            self.anchor_program_id,
            self.user.pubkey(),
            self.anchor_market,
            self.anchor_book,
            price,
            qty,
        );
        let pino_ix = build_pino_place_order_ix(
            self.pino_program_id,
            self.user.pubkey(),
            self.pino_market,
            self.pino_book,
            price,
            qty,
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

        // Any state change (either side succeeded) counts as interesting
        // input for libafl's corpus-growth heuristic.
        anchor_ok || pino_ok
    }
}

impl HasContext for MatchingDiffFixture {
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

impl DifferentialFixture for MatchingDiffFixture {
    fn anchor_program_id(&self) -> Pubkey {
        self.anchor_program_id
    }
    fn pino_program_id(&self) -> Pubkey {
        self.pino_program_id
    }
    /// Two pairs: market (16-byte body) and book (6,664-byte body).
    /// Both use the standard Anchor-8-byte-disc / Pinocchio-raw pattern.
    fn diff_pairs(&self) -> Vec<DiffAccountPair> {
        vec![
            DiffAccountPair::anchor_disc_8(
                "market",
                self.anchor_market,
                self.pino_market,
                W4_MARKET_BODY,
            ),
            DiffAccountPair::anchor_disc_8(
                "book",
                self.anchor_book,
                self.pino_book,
                W4_BOOK_BODY,
            ),
        ]
    }
}

// ---------------------------------------------------------------------
// Differential checks
// ---------------------------------------------------------------------

/// Replays the last fuzz-derived action against both sides and asserts
/// execution parity: either both succeed or both fail. A divergence
/// where one side accepts and the other rejects is an immediate bug.
fn check_execution_parity(fixture: &mut MatchingDiffFixture) {
    // Use a deterministic probe input. The real fuzz inputs already
    // went through action_place_order above and produced any state
    // changes; this probe is a stress against ordering edge cases.
    let probe_inputs: &[(u64, u64)] = &[
        (500, 10),
        (1000, 100),
        (1, 1),
        (u64::MAX / 2, 50),
        (777, 333),
    ];

    for &(price, qty) in probe_inputs {
        let anchor_ix = build_anchor_place_order_ix(
            fixture.anchor_program_id,
            fixture.user.pubkey(),
            fixture.anchor_market,
            fixture.anchor_book,
            price,
            qty,
        );
        let pino_ix = build_pino_place_order_ix(
            fixture.pino_program_id,
            fixture.user.pubkey(),
            fixture.pino_market,
            fixture.pino_book,
            price,
            qty,
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
            &format!("place_order(price={}, qty={})", price, qty),
            anchor_ok,
            pino_ok,
        ) {
            fuzz_assert!(false, "{}", div);
        }
    }
}

/// Market-body equivalence (single-pair variant, isolated for an
/// orthogonal libafl report).
fn check_market_equivalent(fixture: &mut MatchingDiffFixture) {
    let pair = DiffAccountPair::anchor_disc_8(
        "market",
        fixture.anchor_market,
        fixture.pino_market,
        W4_MARKET_BODY,
    );
    if let Some(div) = check_pair_equivalent(fixture.ctx(), &pair) {
        fuzz_assert!(false, "{}", div);
    }
}

/// Book-body equivalence (single-pair variant).
fn check_book_equivalent(fixture: &mut MatchingDiffFixture) {
    let pair = DiffAccountPair::anchor_disc_8(
        "book",
        fixture.anchor_book,
        fixture.pino_book,
        W4_BOOK_BODY,
    );
    if let Some(div) = check_pair_equivalent(fixture.ctx(), &pair) {
        fuzz_assert!(false, "{}", div);
    }
}

/// Narrow check: the first 8 bytes of each Market body are the
/// `sequence` counter. The book/market equivalence checks above
/// already catch any drift, but this isolates the most operationally
/// load-bearing field for its own variant report.
fn check_sequence_match(fixture: &mut MatchingDiffFixture) {
    let market_pair = DiffAccountPair::anchor_disc_8(
        "market",
        fixture.anchor_market,
        fixture.pino_market,
        W4_MARKET_BODY,
    );
    let Some((anchor_body, pino_body)) = read_pair_bodies(fixture.ctx(), &market_pair) else {
        return;
    };

    let anchor_seq = u64::from_le_bytes(anchor_body[..8].try_into().unwrap());
    let pino_seq = u64::from_le_bytes(pino_body[..8].try_into().unwrap());

    fuzz_assert!(
        anchor_seq == pino_seq,
        "market.sequence divergence: anchor={} pino={}",
        anchor_seq,
        pino_seq,
    );
}

// ---------------------------------------------------------------------
// Invariant variants
// ---------------------------------------------------------------------

#[invariant_test]
fn invariant_diff_smoke(fixture: &mut MatchingDiffFixture) {
    // The trait-driven shortcut: walks all 2 declared pairs in one call.
    if let Some(div) = check_all_pairs(fixture) {
        fuzz_assert!(false, "{}", div);
    }
    check_sequence_match(fixture);
    check_execution_parity(fixture);
}

#[invariant_test]
fn invariant_diff_execution_parity_only(fixture: &mut MatchingDiffFixture) {
    check_execution_parity(fixture);
}

#[invariant_test]
fn invariant_diff_state_equivalent_only(fixture: &mut MatchingDiffFixture) {
    check_market_equivalent(fixture);
    check_book_equivalent(fixture);
}

#[invariant_test]
fn invariant_diff_sequence_match_only(fixture: &mut MatchingDiffFixture) {
    check_sequence_match(fixture);
}
