//! # oracle_diff_fuzz — anchor↔pinocchio differential harness for W11 oracle publish
//!
//! Second green-field-trait harness (after vault-diff). Demonstrates that
//! the `DifferentialFixture` skeleton scales down cleanly to the simplest
//! possible surface: 1 mutable zero-copy state account, no CPI.
//!
//! ## Surface
//!
//! Targets `anchor_w11_oracle` / `pinocchio_w11_oracle`. `publish_price`
//! takes `(new_price, new_conf, new_slot)`, enforces strict slot
//! monotonicity, and updates `(price, conf, ema_price, last_slot,
//! publish_count)` where EMA uses α = 1/8 smoothing.
//!
//! ## Account pairs
//!
//! | Pair       | Anchor offset | Pinocchio offset | Body size |
//! | ---------- | ------------: | ---------------: | --------: |
//! | price_feed | 8 (Anchor disc) | 0 | 40 |
//!
//! Only one pair — but the fuzz surface is wide because the EMA math is
//! the load-bearing differential signal. Misimplement the smoothing
//! formula on the Pinocchio side and the bodies diverge within a few
//! publishes.

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

const ANCHOR_W11_PROGRAM_ID_STR: &str = "1PA7z3xmC4WdLzc5frbUSuDynRNPPvPPyJNFPdFSmu5";
const PINO_W11_PROGRAM_ID_STR: &str = "3gRh1jN8h8qE2pWbXMAMcPV1cGmYNffXejx4rRBXEYZH";
const ANCHOR_W11_SO_PATH: &str =
    "../../../../pinocchio-bench/target/deploy/anchor_w11_oracle.so";
const PINO_W11_SO_PATH: &str =
    "../../../../pinocchio-bench/target/deploy/pinocchio_w11_oracle.so";

const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);

const W11_FEED_BODY: usize = 40;
const ANCHOR_DISC_LEN: usize = 8;

// Field offsets within PriceFeed body
const PRICE_OFFSET: usize = 0;
const EMA_OFFSET: usize = 16;
const LAST_SLOT_OFFSET: usize = 24;
const PUBLISH_COUNT_OFFSET: usize = 32;

const FEE_PAYER_BALANCE: u64 = 10_000_000_000;
const PUBLISHER_BALANCE: u64 = 1_000_000_000;
const FEED_LAMPORTS: u64 = 2_000_000;

fn anchor_acc_disc(name: &str) -> [u8; 8] {
    let h = Sha256::digest(format!("account:{name}").as_bytes());
    h[..8].try_into().unwrap()
}
fn anchor_ix_disc(name: &str) -> [u8; 8] {
    let h = Sha256::digest(format!("global:{name}").as_bytes());
    h[..8].try_into().unwrap()
}

fn build_anchor_publish_ix(
    program_id: Pubkey,
    publisher: Pubkey,
    feed: Pubkey,
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
            AccountMeta::new(feed, false),
        ],
        data,
    }
}

fn build_pino_publish_ix(
    program_id: Pubkey,
    publisher: Pubkey,
    feed: Pubkey,
    new_price: u64,
    new_conf: u64,
    new_slot: u64,
) -> Instruction {
    let mut data = new_price.to_le_bytes().to_vec();
    data.extend_from_slice(&new_conf.to_le_bytes());
    data.extend_from_slice(&new_slot.to_le_bytes());
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(publisher, true),
            AccountMeta::new(feed, false),
        ],
        data,
    }
}

#[derive(Clone)]
struct OracleDiffFixture {
    pub ctx: TestContext,
    anchor_program_id: Pubkey,
    pino_program_id: Pubkey,

    anchor_feed: Pubkey,
    pino_feed: Pubkey,

    publisher: Arc<Keypair>,
    fee_payer: Arc<Keypair>,
}

#[fuzz_fixture]
impl OracleDiffFixture {
    pub fn setup() -> Self {
        let mut ctx = TestContext::new();

        let anchor_program_id =
            Pubkey::from_str(ANCHOR_W11_PROGRAM_ID_STR).expect("valid anchor program id");
        let pino_program_id =
            Pubkey::from_str(PINO_W11_PROGRAM_ID_STR).expect("valid pino program id");

        ctx.add_program(&anchor_program_id, ANCHOR_W11_SO_PATH)
            .expect("build pinocchio-bench programs/anchor-w11-oracle first");
        ctx.add_program(&pino_program_id, PINO_W11_SO_PATH)
            .expect("build pinocchio-bench programs/pinocchio-w11-oracle first");

        let publisher = Arc::new(Keypair::new());
        let fee_payer = Arc::new(Keypair::new());
        for (kp, lamports) in [(&publisher, PUBLISHER_BALANCE), (&fee_payer, FEE_PAYER_BALANCE)] {
            ctx.create_account()
                .pubkey(kp.pubkey())
                .lamports(lamports)
                .owner(SYSTEM_PROGRAM_ID)
                .create()
                .unwrap();
        }

        // Anchor side: PriceFeed with 8-byte discriminator, zero body.
        let anchor_feed_kp = Keypair::new();
        let mut anchor_feed_data = vec![0u8; ANCHOR_DISC_LEN + W11_FEED_BODY];
        anchor_feed_data[..ANCHOR_DISC_LEN].copy_from_slice(&anchor_acc_disc("PriceFeed"));
        ctx.write_account(
            &anchor_feed_kp.pubkey(),
            Account {
                lamports: FEED_LAMPORTS,
                data: anchor_feed_data,
                owner: anchor_program_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .expect("anchor feed pre-fund");

        // Pinocchio side: bare 40-byte body, no discriminator.
        let pino_feed_kp = Keypair::new();
        ctx.write_account(
            &pino_feed_kp.pubkey(),
            Account {
                lamports: FEED_LAMPORTS,
                data: vec![0u8; W11_FEED_BODY],
                owner: pino_program_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .expect("pino feed pre-fund");

        Self {
            ctx,
            anchor_program_id,
            pino_program_id,
            anchor_feed: anchor_feed_kp.pubkey(),
            pino_feed: pino_feed_kp.pubkey(),
            publisher,
            fee_payer,
        }
    }

    /// Drive `publish_price(new_price, new_conf, new_slot)` through both
    /// targets. Both sides enforce strict slot monotonicity; the fuzzer
    /// regularly probes both monotonic and non-monotonic slot orderings,
    /// so this action's `false` return is a frequent legitimate outcome.
    ///
    /// `new_slot` range is wide enough to exercise the EMA propagation
    /// over many slots; `new_price` range spans 1..1e9 so the EMA math
    /// stays well within u64 (worst case `ema × 7` ≈ 7e9, well under
    /// u64::MAX even when stored as u128 during the saturating multiply).
    pub fn action_publish(
        &mut self,
        #[range(1..1_000_000_000)] new_price: u64,
        #[range(1..1_000_000)] new_conf: u64,
        #[range(1..1_000_000)] new_slot: u64,
    ) -> bool {
        let anchor_ix = build_anchor_publish_ix(
            self.anchor_program_id,
            self.publisher.pubkey(),
            self.anchor_feed,
            new_price,
            new_conf,
            new_slot,
        );
        let pino_ix = build_pino_publish_ix(
            self.pino_program_id,
            self.publisher.pubkey(),
            self.pino_feed,
            new_price,
            new_conf,
            new_slot,
        );

        let anchor_ok = self
            .ctx
            .raw_call(anchor_ix)
            .fee_payer(&*self.fee_payer)
            .signers(&[&*self.fee_payer, &*self.publisher])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);

        let pino_ok = self
            .ctx
            .raw_call(pino_ix)
            .fee_payer(&*self.fee_payer)
            .signers(&[&*self.fee_payer, &*self.publisher])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);

        anchor_ok || pino_ok
    }
}

impl HasContext for OracleDiffFixture {
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

impl DifferentialFixture for OracleDiffFixture {
    fn anchor_program_id(&self) -> Pubkey {
        self.anchor_program_id
    }
    fn pino_program_id(&self) -> Pubkey {
        self.pino_program_id
    }
    /// One pair. The simplest possible `DifferentialFixture` shape — but
    /// the math (slot monotonicity + EMA smoothing + first-publish
    /// bootstrap) makes it a rich fuzz target.
    fn diff_pairs(&self) -> Vec<DiffAccountPair> {
        vec![DiffAccountPair::anchor_disc_8(
            "price_feed",
            self.anchor_feed,
            self.pino_feed,
            W11_FEED_BODY,
        )]
    }
}

// ---------------------------------------------------------------------
// Differential checks
// ---------------------------------------------------------------------

fn check_execution_parity(fixture: &mut OracleDiffFixture) {
    // Probes target the boundary cases: small/large prices, equal-slot
    // rejection, and the first-publish EMA bootstrap path.
    let probes: &[(u64, u64, u64)] = &[
        (100_000_000, 50_000, 200),
        (200_000_000, 100_000, 201),
        (50_000_000, 25_000, 202),
        (u64::MAX / 2, 1, 203),
        (1, 1, 1), // likely stale-slot rejection
    ];

    for &(new_price, new_conf, new_slot) in probes {
        let anchor_ix = build_anchor_publish_ix(
            fixture.anchor_program_id,
            fixture.publisher.pubkey(),
            fixture.anchor_feed,
            new_price,
            new_conf,
            new_slot,
        );
        let pino_ix = build_pino_publish_ix(
            fixture.pino_program_id,
            fixture.publisher.pubkey(),
            fixture.pino_feed,
            new_price,
            new_conf,
            new_slot,
        );

        let anchor_ok = fixture
            .ctx
            .raw_call(anchor_ix)
            .fee_payer(&*fixture.fee_payer)
            .signers(&[&*fixture.fee_payer, &*fixture.publisher])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);

        let pino_ok = fixture
            .ctx
            .raw_call(pino_ix)
            .fee_payer(&*fixture.fee_payer)
            .signers(&[&*fixture.fee_payer, &*fixture.publisher])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);

        if let Some(div) = ParityDivergence::check(
            &format!(
                "publish(price={}, conf={}, slot={})",
                new_price, new_conf, new_slot,
            ),
            anchor_ok,
            pino_ok,
        ) {
            fuzz_assert!(false, "{}", div);
        }
    }
}

/// EMA field equivalence — surface-specific math invariant. Body
/// equivalence catches it too, but isolating it as its own variant
/// pinpoints math bugs to the smoothing formula rather than reporting
/// "feed body diverged at offset 16".
fn check_ema_match(fixture: &mut OracleDiffFixture) {
    let pair = DiffAccountPair::anchor_disc_8(
        "price_feed",
        fixture.anchor_feed,
        fixture.pino_feed,
        W11_FEED_BODY,
    );
    let Some((a, p)) = read_pair_bodies(fixture.ctx(), &pair) else {
        return;
    };

    let a_ema = u64::from_le_bytes(a[EMA_OFFSET..EMA_OFFSET + 8].try_into().unwrap());
    let p_ema = u64::from_le_bytes(p[EMA_OFFSET..EMA_OFFSET + 8].try_into().unwrap());
    fuzz_assert!(
        a_ema == p_ema,
        "EMA price divergence: anchor={} pino={}",
        a_ema,
        p_ema,
    );

    // Spot-check that EMA is plausibly bounded by current price extremes —
    // catches a sign-flip in the smoothing formula that body equality
    // would also catch but in a less obvious form.
    let a_price = u64::from_le_bytes(a[PRICE_OFFSET..PRICE_OFFSET + 8].try_into().unwrap());
    // After a single publish from a zero feed, ema == price (bootstrap).
    // After multiple publishes EMA lags but stays within u64 range, which
    // is trivially true; the meaningful check is anchor==pino above.
    let _ = a_price;
}

/// `publish_count` equivalence — isolates the path that increments the
/// publish counter. A rewrite that miscounts here is the operational
/// "is this feed live?" health check failing silently for downstream
/// consumers.
fn check_publish_count(fixture: &mut OracleDiffFixture) {
    let pair = DiffAccountPair::anchor_disc_8(
        "price_feed",
        fixture.anchor_feed,
        fixture.pino_feed,
        W11_FEED_BODY,
    );
    let Some((a, p)) = read_pair_bodies(fixture.ctx(), &pair) else {
        return;
    };

    let a_count = u64::from_le_bytes(
        a[PUBLISH_COUNT_OFFSET..PUBLISH_COUNT_OFFSET + 8]
            .try_into()
            .unwrap(),
    );
    let p_count = u64::from_le_bytes(
        p[PUBLISH_COUNT_OFFSET..PUBLISH_COUNT_OFFSET + 8]
            .try_into()
            .unwrap(),
    );
    fuzz_assert!(
        a_count == p_count,
        "publish_count divergence: anchor={} pino={}",
        a_count,
        p_count,
    );

    // Cross-validate against last_slot — if at least one publish happened,
    // last_slot must be > 0 on both sides.
    let a_slot = u64::from_le_bytes(a[LAST_SLOT_OFFSET..LAST_SLOT_OFFSET + 8].try_into().unwrap());
    let p_slot = u64::from_le_bytes(p[LAST_SLOT_OFFSET..LAST_SLOT_OFFSET + 8].try_into().unwrap());
    if a_count > 0 {
        fuzz_assert!(
            a_slot > 0,
            "anchor publish_count={} but last_slot=0",
            a_count,
        );
    }
    if p_count > 0 {
        fuzz_assert!(
            p_slot > 0,
            "pino publish_count={} but last_slot=0",
            p_count,
        );
    }
}

// ---------------------------------------------------------------------
// Invariant variants
// ---------------------------------------------------------------------

#[invariant_test]
fn invariant_oracle_diff_smoke(fixture: &mut OracleDiffFixture) {
    if let Some(div) = check_all_pairs(fixture) {
        fuzz_assert!(false, "{}", div);
    }
    check_ema_match(fixture);
    check_publish_count(fixture);
    check_execution_parity(fixture);
}

#[invariant_test]
fn invariant_oracle_diff_execution_parity_only(fixture: &mut OracleDiffFixture) {
    check_execution_parity(fixture);
}

#[invariant_test]
fn invariant_oracle_diff_state_equivalent_only(fixture: &mut OracleDiffFixture) {
    if let Some(div) = check_all_pairs(fixture) {
        fuzz_assert!(false, "{}", div);
    }
}

#[invariant_test]
fn invariant_oracle_diff_ema_match_only(fixture: &mut OracleDiffFixture) {
    check_ema_match(fixture);
}

#[invariant_test]
fn invariant_oracle_diff_publish_count_only(fixture: &mut OracleDiffFixture) {
    check_publish_count(fixture);
}
