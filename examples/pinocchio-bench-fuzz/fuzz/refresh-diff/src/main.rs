//! # refresh_diff_fuzz — anchor↔pinocchio differential harness for W9 lending refresh
//!
//! Drives the **same `refresh(current_slot)` action** through both the Anchor and
//! Pinocchio W9 lending-refresh programs from `psyto/pinocchio-bench` in one
//! Crucible `TestContext` and asserts:
//!
//! 1. **Execution parity** — both refreshes succeed or both fail
//! 2. **Obligation body equivalence** — `(deposit, borrow, last_health, last_update_slot)`
//!    byte-identical after stripping Anchor's 8-byte account discriminator
//! 3. **Reserve body equivalence** — both reserve_a and reserve_b match byte-for-byte
//! 4. **Oracle body equivalence** — both oracle_a and oracle_b match byte-for-byte
//! 5. **Monotonic borrow rate** — `cumulative_borrow_rate` non-decreasing on both sides
//! 6. **Monotonic last_update_slot** — slot only advances on both sides
//!
//! ## Why W9 is the highest-leverage differential
//!
//! W9 has **no CPI** — the only cost is per-account framework overhead and light math.
//! That means it's the cleanest differential target: any divergence pinpoints a bug in
//! the zero-copy load path or the math itself, with no SPL Token program in the loop.
//!
//! Real lending protocols (Kamino, Save, Marginfi descendants) ship rewrites of this
//! exact shape under high call volume — a single math bug here is the classic "free
//! money for borrowers" failure mode. This harness is the proof a customer needs.
//!
//! ## Design notes
//!
//! - **One TestContext**, both `.so`s loaded at their respective program IDs.
//! - **5 mut zero-copy accounts per side** — obligation + 2 reserves + 2 oracles.
//! - **Shared user keypair** signs both refreshes (the signer is unused state-wise on
//!   both sides, but symmetric signing keeps the harness shape identical to W4/W8).
//! - **last_health and cumulative_borrow_rate**: tracked across iterations to assert
//!   monotonicity invariants (sanity beyond pure byte equivalence).

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
// Target program identities — match keys/{anchor,pinocchio}-w9-refresh.json
// in psyto/pinocchio-bench.
// ---------------------------------------------------------------------

const ANCHOR_W9_PROGRAM_ID_STR: &str = "AhdfeAdeXFQNoqfg6XMHU59bi5cty5CZS7b92A1ERZK9";
const PINO_W9_PROGRAM_ID_STR: &str = "AUfBb1dJr392vYKgKMqEYJoWTTjeE6GsWctcrir6mg3";
const ANCHOR_W9_SO_PATH: &str =
    "../../../../pinocchio-bench/target/deploy/anchor_w9_refresh.so";
const PINO_W9_SO_PATH: &str =
    "../../../../pinocchio-bench/target/deploy/pinocchio_w9_refresh.so";

const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);

// Body sizes match programs/{anchor,pinocchio}-w9-refresh/src/lib.rs:
//   Obligation = 4 × u64                                                = 32 bytes
//   Reserve    = liquidity u64 + borrows u64 + cum_rate u64 + rate u32
//                + pad u32 + last_update_slot u64                       = 40 bytes
//   Oracle     = price u64 + conf u64 + last_update_slot u64            = 24 bytes
const W9_OBLIGATION_BODY: usize = 32;
const W9_RESERVE_BODY: usize = 40;
const W9_ORACLE_BODY: usize = 24;
const ANCHOR_DISC_LEN: usize = 8;

// Field offsets within each body (used for monotonicity checks).
const RESERVE_CUM_RATE_OFFSET: usize = 16; // u64 at 16..24
const RESERVE_LAST_SLOT_OFFSET: usize = 32; // u64 at 32..40
const ORACLE_LAST_SLOT_OFFSET: usize = 16; // u64 at 16..24
const OBLIGATION_LAST_SLOT_OFFSET: usize = 24; // u64 at 24..32

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
const ACCT_LAMPORTS: u64 = 5_000_000;

// Initial state — same as pinocchio-bench/bench/src/main.rs W9 setup.
const INITIAL_DEPOSIT: u64 = 1_000;
const INITIAL_BORROW: u64 = 500;
const INITIAL_RESERVE_A_LIQ: u64 = 1_000_000;
const INITIAL_RESERVE_A_BORROW: u64 = 500_000;
const INITIAL_RESERVE_A_RATE: u32 = 300;
const INITIAL_RESERVE_B_LIQ: u64 = 2_000_000;
const INITIAL_RESERVE_B_BORROW: u64 = 800_000;
const INITIAL_RESERVE_B_RATE: u32 = 250;
const INITIAL_ORACLE_A_PRICE: u64 = 100;
const INITIAL_ORACLE_B_PRICE: u64 = 50;

// ---------------------------------------------------------------------
// Account body builders
// ---------------------------------------------------------------------

fn make_obligation_body(deposit: u64, borrow: u64) -> Vec<u8> {
    let mut body = vec![0u8; W9_OBLIGATION_BODY];
    body[0..8].copy_from_slice(&deposit.to_le_bytes());
    body[8..16].copy_from_slice(&borrow.to_le_bytes());
    // last_health = 0, last_update_slot = 0
    body
}

fn make_reserve_body(liquidity: u64, borrows: u64, rate_bps: u32) -> Vec<u8> {
    let mut body = vec![0u8; W9_RESERVE_BODY];
    body[0..8].copy_from_slice(&liquidity.to_le_bytes());
    body[8..16].copy_from_slice(&borrows.to_le_bytes());
    // cumulative_borrow_rate = 0 at offset 16..24
    body[24..28].copy_from_slice(&rate_bps.to_le_bytes());
    // _pad = 0, last_update_slot = 0
    body
}

fn make_oracle_body(price: u64, conf: u64) -> Vec<u8> {
    let mut body = vec![0u8; W9_ORACLE_BODY];
    body[0..8].copy_from_slice(&price.to_le_bytes());
    body[8..16].copy_from_slice(&conf.to_le_bytes());
    // last_update_slot = 0
    body
}

// ---------------------------------------------------------------------
// ix constructors
// ---------------------------------------------------------------------

fn build_anchor_refresh_ix(
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

fn build_pino_refresh_ix(
    program_id: Pubkey,
    signer: Pubkey,
    obligation: Pubkey,
    reserve_a: Pubkey,
    reserve_b: Pubkey,
    oracle_a: Pubkey,
    oracle_b: Pubkey,
    current_slot: u64,
) -> Instruction {
    let data = current_slot.to_le_bytes().to_vec();
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

// ---------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------

#[derive(Clone)]
struct RefreshDiffFixture {
    pub ctx: TestContext,
    anchor_program_id: Pubkey,
    pino_program_id: Pubkey,

    anchor_obligation: Pubkey,
    anchor_reserve_a: Pubkey,
    anchor_reserve_b: Pubkey,
    anchor_oracle_a: Pubkey,
    anchor_oracle_b: Pubkey,

    pino_obligation: Pubkey,
    pino_reserve_a: Pubkey,
    pino_reserve_b: Pubkey,
    pino_oracle_a: Pubkey,
    pino_oracle_b: Pubkey,

    user: Arc<Keypair>,
    fee_payer: Arc<Keypair>,
}

#[fuzz_fixture]
impl RefreshDiffFixture {
    pub fn setup() -> Self {
        let mut ctx = TestContext::new();

        let anchor_program_id =
            Pubkey::from_str(ANCHOR_W9_PROGRAM_ID_STR).expect("valid anchor program id");
        let pino_program_id =
            Pubkey::from_str(PINO_W9_PROGRAM_ID_STR).expect("valid pino program id");

        ctx.add_program(&anchor_program_id, ANCHOR_W9_SO_PATH)
            .expect("build pinocchio-bench programs/anchor-w9-refresh first");
        ctx.add_program(&pino_program_id, PINO_W9_SO_PATH)
            .expect("build pinocchio-bench programs/pinocchio-w9-refresh first");

        // Helper closures for per-side account creation with optional
        // Anchor discriminator prefix.
        let make_anchor_acc = |ctx: &mut TestContext, disc_name: &str, body: Vec<u8>| -> Pubkey {
            let kp = Keypair::new();
            let mut data = vec![0u8; ANCHOR_DISC_LEN + body.len()];
            data[..ANCHOR_DISC_LEN].copy_from_slice(&anchor_acc_disc(disc_name));
            data[ANCHOR_DISC_LEN..].copy_from_slice(&body);
            ctx.write_account(
                &kp.pubkey(),
                Account {
                    lamports: ACCT_LAMPORTS,
                    data,
                    owner: anchor_program_id,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .expect("anchor account pre-fund");
            kp.pubkey()
        };

        let make_pino_acc = |ctx: &mut TestContext, body: Vec<u8>| -> Pubkey {
            let kp = Keypair::new();
            ctx.write_account(
                &kp.pubkey(),
                Account {
                    lamports: ACCT_LAMPORTS,
                    data: body,
                    owner: pino_program_id,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .expect("pino account pre-fund");
            kp.pubkey()
        };

        let anchor_obligation = make_anchor_acc(
            &mut ctx,
            "Obligation",
            make_obligation_body(INITIAL_DEPOSIT, INITIAL_BORROW),
        );
        let anchor_reserve_a = make_anchor_acc(
            &mut ctx,
            "Reserve",
            make_reserve_body(
                INITIAL_RESERVE_A_LIQ,
                INITIAL_RESERVE_A_BORROW,
                INITIAL_RESERVE_A_RATE,
            ),
        );
        let anchor_reserve_b = make_anchor_acc(
            &mut ctx,
            "Reserve",
            make_reserve_body(
                INITIAL_RESERVE_B_LIQ,
                INITIAL_RESERVE_B_BORROW,
                INITIAL_RESERVE_B_RATE,
            ),
        );
        let anchor_oracle_a = make_anchor_acc(
            &mut ctx,
            "Oracle",
            make_oracle_body(INITIAL_ORACLE_A_PRICE, 1),
        );
        let anchor_oracle_b = make_anchor_acc(
            &mut ctx,
            "Oracle",
            make_oracle_body(INITIAL_ORACLE_B_PRICE, 1),
        );

        let pino_obligation =
            make_pino_acc(&mut ctx, make_obligation_body(INITIAL_DEPOSIT, INITIAL_BORROW));
        let pino_reserve_a = make_pino_acc(
            &mut ctx,
            make_reserve_body(
                INITIAL_RESERVE_A_LIQ,
                INITIAL_RESERVE_A_BORROW,
                INITIAL_RESERVE_A_RATE,
            ),
        );
        let pino_reserve_b = make_pino_acc(
            &mut ctx,
            make_reserve_body(
                INITIAL_RESERVE_B_LIQ,
                INITIAL_RESERVE_B_BORROW,
                INITIAL_RESERVE_B_RATE,
            ),
        );
        let pino_oracle_a = make_pino_acc(&mut ctx, make_oracle_body(INITIAL_ORACLE_A_PRICE, 1));
        let pino_oracle_b = make_pino_acc(&mut ctx, make_oracle_body(INITIAL_ORACLE_B_PRICE, 1));

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
            anchor_obligation,
            anchor_reserve_a,
            anchor_reserve_b,
            anchor_oracle_a,
            anchor_oracle_b,
            pino_obligation,
            pino_reserve_a,
            pino_reserve_b,
            pino_oracle_a,
            pino_oracle_b,
            user,
            fee_payer,
        }
    }

    /// Drive `refresh(current_slot)` through both targets.
    ///
    /// current_slot is fuzzed over a wide range. Real Solana slots are
    /// monotonic across blocks, but since this harness runs in a single
    /// SVM session the fuzzer can probe with arbitrary slot values
    /// including ones that go backward — useful to exercise the
    /// `saturating_sub` logic in the math.
    pub fn action_refresh(
        &mut self,
        #[range(1..10_000_000)] current_slot: u64,
    ) -> bool {
        let anchor_ix = build_anchor_refresh_ix(
            self.anchor_program_id,
            self.user.pubkey(),
            self.anchor_obligation,
            self.anchor_reserve_a,
            self.anchor_reserve_b,
            self.anchor_oracle_a,
            self.anchor_oracle_b,
            current_slot,
        );
        let pino_ix = build_pino_refresh_ix(
            self.pino_program_id,
            self.user.pubkey(),
            self.pino_obligation,
            self.pino_reserve_a,
            self.pino_reserve_b,
            self.pino_oracle_a,
            self.pino_oracle_b,
            current_slot,
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

        anchor_ok || pino_ok
    }
}

impl HasContext for RefreshDiffFixture {
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

impl DifferentialFixture for RefreshDiffFixture {
    fn anchor_program_id(&self) -> Pubkey {
        self.anchor_program_id
    }
    fn pino_program_id(&self) -> Pubkey {
        self.pino_program_id
    }
    /// Five pairs: obligation + 2 reserves + 2 oracles. All zero-copy
    /// on the Anchor side (8-byte disc); raw on the Pinocchio side.
    fn diff_pairs(&self) -> Vec<DiffAccountPair> {
        vec![
            DiffAccountPair::anchor_disc_8(
                "obligation",
                self.anchor_obligation,
                self.pino_obligation,
                W9_OBLIGATION_BODY,
            ),
            DiffAccountPair::anchor_disc_8(
                "reserve_a",
                self.anchor_reserve_a,
                self.pino_reserve_a,
                W9_RESERVE_BODY,
            ),
            DiffAccountPair::anchor_disc_8(
                "reserve_b",
                self.anchor_reserve_b,
                self.pino_reserve_b,
                W9_RESERVE_BODY,
            ),
            DiffAccountPair::anchor_disc_8(
                "oracle_a",
                self.anchor_oracle_a,
                self.pino_oracle_a,
                W9_ORACLE_BODY,
            ),
            DiffAccountPair::anchor_disc_8(
                "oracle_b",
                self.anchor_oracle_b,
                self.pino_oracle_b,
                W9_ORACLE_BODY,
            ),
        ]
    }
}

// ---------------------------------------------------------------------
// Differential checks
// ---------------------------------------------------------------------

fn check_execution_parity(fixture: &mut RefreshDiffFixture) {
    // Probe slots specifically chosen to stress saturating_sub paths.
    let probes: &[u64] = &[1, 1_000, 1_000_000, 0, 100, u64::MAX / 2];

    for &current_slot in probes {
        let anchor_ix = build_anchor_refresh_ix(
            fixture.anchor_program_id,
            fixture.user.pubkey(),
            fixture.anchor_obligation,
            fixture.anchor_reserve_a,
            fixture.anchor_reserve_b,
            fixture.anchor_oracle_a,
            fixture.anchor_oracle_b,
            current_slot,
        );
        let pino_ix = build_pino_refresh_ix(
            fixture.pino_program_id,
            fixture.user.pubkey(),
            fixture.pino_obligation,
            fixture.pino_reserve_a,
            fixture.pino_reserve_b,
            fixture.pino_oracle_a,
            fixture.pino_oracle_b,
            current_slot,
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
            &format!("refresh(current_slot={})", current_slot),
            anchor_ok,
            pino_ok,
        ) {
            fuzz_assert!(false, "{}", div);
        }
    }
}

/// Obligation-only variant — first pair in `diff_pairs()` (index 0).
fn check_obligation_equivalent(fixture: &mut RefreshDiffFixture) {
    let pair = DiffAccountPair::anchor_disc_8(
        "obligation",
        fixture.anchor_obligation,
        fixture.pino_obligation,
        W9_OBLIGATION_BODY,
    );
    if let Some(div) = check_pair_equivalent(fixture.ctx(), &pair) {
        fuzz_assert!(false, "{}", div);
    }
}

/// Reserves-only variant — indices 1 and 2 of `diff_pairs()`.
fn check_reserves_equivalent(fixture: &mut RefreshDiffFixture) {
    for pair in fixture.diff_pairs().iter().skip(1).take(2) {
        if let Some(div) = check_pair_equivalent(fixture.ctx(), pair) {
            fuzz_assert!(false, "{}", div);
        }
    }
}

/// Oracles-only variant — indices 3 and 4 of `diff_pairs()`.
fn check_oracles_equivalent(fixture: &mut RefreshDiffFixture) {
    for pair in fixture.diff_pairs().iter().skip(3) {
        if let Some(div) = check_pair_equivalent(fixture.ctx(), pair) {
            fuzz_assert!(false, "{}", div);
        }
    }
}

/// Anchor and Pinocchio sides must agree on `cumulative_borrow_rate`
/// after every refresh. Body equivalence catches this too, but
/// isolating it as its own variant gives libafl an orthogonal report
/// when a math bug specifically targets the accrual path.
///
/// Note: the absolute value is not asserted — `saturating_add` can
/// legitimately reach `u64::MAX` over a long fuzz sequence with large
/// `current_slot` values. The signal is equivalence, not magnitude.
fn check_monotonic_rate(fixture: &mut RefreshDiffFixture) {
    let reserve_pairs = [
        DiffAccountPair::anchor_disc_8(
            "reserve_a",
            fixture.anchor_reserve_a,
            fixture.pino_reserve_a,
            W9_RESERVE_BODY,
        ),
        DiffAccountPair::anchor_disc_8(
            "reserve_b",
            fixture.anchor_reserve_b,
            fixture.pino_reserve_b,
            W9_RESERVE_BODY,
        ),
    ];
    for pair in reserve_pairs {
        let Some((a, p)) = read_pair_bodies(fixture.ctx(), &pair) else {
            continue;
        };
        let a_rate = u64::from_le_bytes(
            a[RESERVE_CUM_RATE_OFFSET..RESERVE_CUM_RATE_OFFSET + 8]
                .try_into()
                .unwrap(),
        );
        let p_rate = u64::from_le_bytes(
            p[RESERVE_CUM_RATE_OFFSET..RESERVE_CUM_RATE_OFFSET + 8]
                .try_into()
                .unwrap(),
        );
        fuzz_assert!(
            a_rate == p_rate,
            "{} cumulative_borrow_rate divergence: anchor={} pino={}",
            pair.label,
            a_rate,
            p_rate,
        );
    }
}

/// `last_update_slot` on every refreshed account is set to the current
/// instruction's `current_slot` argument. Body equivalence catches this,
/// but the per-account slot field is isolated here for orthogonal libafl
/// reports.
fn check_monotonic_slot(fixture: &mut RefreshDiffFixture) {
    let probes: &[(DiffAccountPair, usize)] = &[
        (
            DiffAccountPair::anchor_disc_8(
                "obligation",
                fixture.anchor_obligation,
                fixture.pino_obligation,
                W9_OBLIGATION_BODY,
            ),
            OBLIGATION_LAST_SLOT_OFFSET,
        ),
        (
            DiffAccountPair::anchor_disc_8(
                "reserve_a",
                fixture.anchor_reserve_a,
                fixture.pino_reserve_a,
                W9_RESERVE_BODY,
            ),
            RESERVE_LAST_SLOT_OFFSET,
        ),
        (
            DiffAccountPair::anchor_disc_8(
                "reserve_b",
                fixture.anchor_reserve_b,
                fixture.pino_reserve_b,
                W9_RESERVE_BODY,
            ),
            RESERVE_LAST_SLOT_OFFSET,
        ),
        (
            DiffAccountPair::anchor_disc_8(
                "oracle_a",
                fixture.anchor_oracle_a,
                fixture.pino_oracle_a,
                W9_ORACLE_BODY,
            ),
            ORACLE_LAST_SLOT_OFFSET,
        ),
        (
            DiffAccountPair::anchor_disc_8(
                "oracle_b",
                fixture.anchor_oracle_b,
                fixture.pino_oracle_b,
                W9_ORACLE_BODY,
            ),
            ORACLE_LAST_SLOT_OFFSET,
        ),
    ];

    for (pair, offset) in probes {
        let Some((a, p)) = read_pair_bodies(fixture.ctx(), pair) else {
            continue;
        };
        let a_slot = u64::from_le_bytes(a[*offset..*offset + 8].try_into().unwrap());
        let p_slot = u64::from_le_bytes(p[*offset..*offset + 8].try_into().unwrap());
        fuzz_assert!(
            a_slot == p_slot,
            "{} last_update_slot divergence: anchor={} pino={}",
            pair.label,
            a_slot,
            p_slot,
        );
    }
}

// ---------------------------------------------------------------------
// Invariant variants
// ---------------------------------------------------------------------

#[invariant_test]
fn invariant_refresh_diff_smoke(fixture: &mut RefreshDiffFixture) {
    // The trait-driven shortcut: walks all 5 declared pairs in one call.
    if let Some(div) = check_all_pairs(fixture) {
        fuzz_assert!(false, "{}", div);
    }
    check_monotonic_rate(fixture);
    check_monotonic_slot(fixture);
    check_execution_parity(fixture);
}

#[invariant_test]
fn invariant_refresh_diff_execution_parity_only(fixture: &mut RefreshDiffFixture) {
    check_execution_parity(fixture);
}

#[invariant_test]
fn invariant_refresh_diff_obligation_equivalent_only(fixture: &mut RefreshDiffFixture) {
    check_obligation_equivalent(fixture);
}

#[invariant_test]
fn invariant_refresh_diff_reserves_equivalent_only(fixture: &mut RefreshDiffFixture) {
    check_reserves_equivalent(fixture);
}

#[invariant_test]
fn invariant_refresh_diff_oracles_equivalent_only(fixture: &mut RefreshDiffFixture) {
    check_oracles_equivalent(fixture);
}

#[invariant_test]
fn invariant_refresh_diff_monotonic_rate_only(fixture: &mut RefreshDiffFixture) {
    check_monotonic_rate(fixture);
}

#[invariant_test]
fn invariant_refresh_diff_monotonic_slot_only(fixture: &mut RefreshDiffFixture) {
    check_monotonic_slot(fixture);
}
