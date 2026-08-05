//! # amm_diff_fuzz — anchor↔pinocchio differential harness for W8 AMM swap
//!
//! Drives the **same `swap(amount_in, min_out)` action** through both the
//! Anchor and Pinocchio W8 AMM programs from `psyto/pinocchio-bench` in one
//! Crucible `TestContext` and asserts:
//!
//! 1. **Execution parity** — both swaps succeed or both fail, and when
//!    they fail they fail with the same custom error code
//! 2. **Pool body equivalence** — `(reserve_in, reserve_out, fee_bps)` byte-identical
//!    after stripping Anchor's 8-byte account discriminator
//! 3. **Token-account equivalence** — all four token-account pairs match byte-for-byte
//!    (SPL Token format is the same on both sides; both go through SPL Token CPI)
//! 4. **Constant-product k non-decreasing** — `reserve_in × reserve_out` never shrinks
//!    on either side (fee makes it strictly increasing in the limit of nonzero swaps)
//!
//! ## Design notes
//!
//! - **One TestContext**, both `.so`s loaded at their respective program IDs.
//! - **Shared mints + signer.** mint_a and mint_b are loaded once. The same `user`
//!   keypair owns all 8 token accounts (4 per side). This makes the SPL Token
//!   transfers symmetric and the byte-comparison meaningful.
//! - **Bench simplification carried over.** W8 bench used `authority = signer` for
//!   all 4 token accounts (no PDA-derived authority). This harness inherits that —
//!   it measures swap-path equivalence, not invoke_signed equivalence. A future
//!   W8b-diff harness can isolate the PDA-signing axis.
//! - **Initial state symmetric.** Both pools start at
//!   `(reserve_in=1_000_000, reserve_out=2_000_000, fee_bps=30)`. Both user_src
//!   accounts hold 1_000_000 of mint_a. Both pool_vault_out accounts hold
//!   10_000_000 of mint_b. Headroom for ~10⁴ swaps before user balance exhaustion.

mod evidence;

use crucible_fuzzer::*;
use sha2::{Digest, Sha256};
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use std::str::FromStr;
use std::sync::Arc;

use solana_clock::Clock;
use solinv_disclose::{
    AccountRef, ActionRef, DivergenceReport, ExecutionContext, ProgramRef, ReproBundle, Sides,
    SignerPolicy,
};
use solinv_fuzz::{
    check_all_pairs, check_pair_equivalent, CuComparison, DiffAccountPair, DifferentialFixture,
    HasContext, ParityDivergence, SendFailure, TxOutcome,
};

// ---------------------------------------------------------------------
// Target program identities — match keys/{anchor,pinocchio}-w8-amm.json
// in psyto/pinocchio-bench.
// ---------------------------------------------------------------------

const ANCHOR_W8_PROGRAM_ID_STR: &str = "Hf89Tqt9FdVdAEsgt3UkmzriXRLPFYqeYE4hHJaSzTjN";
const PINO_W8_PROGRAM_ID_STR: &str = "DRJ9FZj2xNjSnydfSMiagn49JcXDmDfqV8miH4hhfZds";
const ANCHOR_W8_SO_PATH: &str = "../../../../pinocchio-bench/target/deploy/anchor_w8_amm.so";
const PINO_W8_SO_PATH: &str = "../../../../pinocchio-bench/target/deploy/pinocchio_w8_amm.so";

const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);
const TOKEN_PROGRAM_ID_STR: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

// Pool body layout (matches programs/{anchor,pinocchio}-w8-amm/src/lib.rs):
//   reserve_in:  u64  (0..8)
//   reserve_out: u64  (8..16)
//   fee_bps:     u16  (16..18)
//   _pad:        [u8; 6] (18..24)
const W8_POOL_BODY: usize = 24;
const ANCHOR_DISC_LEN: usize = 8;

const MINT_LEN: usize = 82;
const TOKEN_ACCOUNT_LEN: usize = 165;

fn anchor_acc_disc(name: &str) -> [u8; 8] {
    let h = Sha256::digest(format!("account:{name}").as_bytes());
    h[..8].try_into().unwrap()
}
fn anchor_ix_disc(name: &str) -> [u8; 8] {
    let h = Sha256::digest(format!("global:{name}").as_bytes());
    h[..8].try_into().unwrap()
}

const FEE_PAYER_BALANCE: u64 = 100_000_000_000;
const USER_BALANCE: u64 = 10_000_000_000;
const POOL_LAMPORTS: u64 = 5_000_000;
const TOKEN_ACCOUNT_LAMPORTS: u64 = 2_500_000;
const MINT_LAMPORTS: u64 = 2_000_000;

const INITIAL_RESERVE_IN: u64 = 1_000_000;
const INITIAL_RESERVE_OUT: u64 = 2_000_000;
const INITIAL_FEE_BPS: u16 = 30;
const INITIAL_USER_SRC_BALANCE: u64 = 1_000_000;
const INITIAL_POOL_VAULT_OUT_BALANCE: u64 = 10_000_000;

// ---------------------------------------------------------------------
// Account body builders
// ---------------------------------------------------------------------

fn make_mint(authority: &Pubkey, supply: u64, decimals: u8) -> Vec<u8> {
    let mut buf = vec![0u8; MINT_LEN];
    buf[0..4].copy_from_slice(&1u32.to_le_bytes()); // COption tag = Some
    buf[4..36].copy_from_slice(authority.as_ref());
    buf[36..44].copy_from_slice(&supply.to_le_bytes());
    buf[44] = decimals;
    buf[45] = 1; // is_initialized
    buf
}

fn make_token_account(mint: &Pubkey, owner: &Pubkey, amount: u64) -> Vec<u8> {
    let mut buf = vec![0u8; TOKEN_ACCOUNT_LEN];
    buf[0..32].copy_from_slice(mint.as_ref());
    buf[32..64].copy_from_slice(owner.as_ref());
    buf[64..72].copy_from_slice(&amount.to_le_bytes());
    buf[108] = 1; // state = Initialized
    buf
}

fn make_pool_body(reserve_in: u64, reserve_out: u64, fee_bps: u16) -> Vec<u8> {
    let mut body = vec![0u8; W8_POOL_BODY];
    body[0..8].copy_from_slice(&reserve_in.to_le_bytes());
    body[8..16].copy_from_slice(&reserve_out.to_le_bytes());
    body[16..18].copy_from_slice(&fee_bps.to_le_bytes());
    body
}

// ---------------------------------------------------------------------
// ix constructors
// ---------------------------------------------------------------------

fn build_anchor_swap_ix(
    program_id: Pubkey,
    authority: Pubkey,
    pool: Pubkey,
    user_src: Pubkey,
    user_dst: Pubkey,
    pool_vault_in: Pubkey,
    pool_vault_out: Pubkey,
    token_program: Pubkey,
    amount_in: u64,
    min_out: u64,
) -> Instruction {
    let mut data = anchor_ix_disc("swap").to_vec();
    data.extend_from_slice(&amount_in.to_le_bytes());
    data.extend_from_slice(&min_out.to_le_bytes());
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(pool, false),
            AccountMeta::new(user_src, false),
            AccountMeta::new(user_dst, false),
            AccountMeta::new(pool_vault_in, false),
            AccountMeta::new(pool_vault_out, false),
            AccountMeta::new_readonly(token_program, false),
        ],
        data,
    }
}

fn build_pino_swap_ix(
    program_id: Pubkey,
    authority: Pubkey,
    pool: Pubkey,
    user_src: Pubkey,
    user_dst: Pubkey,
    pool_vault_in: Pubkey,
    pool_vault_out: Pubkey,
    token_program: Pubkey,
    amount_in: u64,
    min_out: u64,
) -> Instruction {
    let mut data = amount_in.to_le_bytes().to_vec();
    data.extend_from_slice(&min_out.to_le_bytes());
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(pool, false),
            AccountMeta::new(user_src, false),
            AccountMeta::new(user_dst, false),
            AccountMeta::new(pool_vault_in, false),
            AccountMeta::new(pool_vault_out, false),
            AccountMeta::new_readonly(token_program, false),
        ],
        data,
    }
}

// ---------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------

#[derive(Clone)]
struct AmmDiffFixture {
    pub ctx: TestContext,
    anchor_program_id: Pubkey,
    pino_program_id: Pubkey,
    token_program: Pubkey,

    // Per-side pool state
    anchor_pool: Pubkey,
    pino_pool: Pubkey,

    // Per-side token accounts (same mint between paired accounts)
    anchor_user_src: Pubkey,
    anchor_user_dst: Pubkey,
    anchor_pool_vault_in: Pubkey,
    anchor_pool_vault_out: Pubkey,

    pino_user_src: Pubkey,
    pino_user_dst: Pubkey,
    pino_pool_vault_in: Pubkey,
    pino_pool_vault_out: Pubkey,

    user: Arc<Keypair>,
    fee_payer: Arc<Keypair>,
}

#[fuzz_fixture]
impl AmmDiffFixture {
    pub fn setup() -> Self {
        let mut ctx = TestContext::new();

        let anchor_program_id =
            Pubkey::from_str(ANCHOR_W8_PROGRAM_ID_STR).expect("valid base58 anchor program id");
        let pino_program_id =
            Pubkey::from_str(PINO_W8_PROGRAM_ID_STR).expect("valid base58 pino program id");
        let token_program = Pubkey::from_str(TOKEN_PROGRAM_ID_STR).expect("valid token program id");

        ctx.add_program(&anchor_program_id, ANCHOR_W8_SO_PATH)
            .expect("build pinocchio-bench programs/anchor-w8-amm first");
        ctx.add_program(&pino_program_id, PINO_W8_SO_PATH)
            .expect("build pinocchio-bench programs/pinocchio-w8-amm first");

        // Shared user + fee payer
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

        // Shared mints — Token Program owns these; both sides reference them
        let mint_a = Keypair::new();
        let mint_b = Keypair::new();
        for (kp, supply) in [
            (&mint_a, 1_000_000_000_000u64),
            (&mint_b, 1_000_000_000_000u64),
        ] {
            ctx.write_account(
                &kp.pubkey(),
                Account {
                    lamports: MINT_LAMPORTS,
                    data: make_mint(&user.pubkey(), supply, 6),
                    owner: token_program,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .expect("mint pre-fund");
        }

        // Per-side pool state
        let anchor_pool_kp = Keypair::new();
        let mut anchor_pool_data = vec![0u8; ANCHOR_DISC_LEN + W8_POOL_BODY];
        anchor_pool_data[..ANCHOR_DISC_LEN].copy_from_slice(&anchor_acc_disc("Pool"));
        anchor_pool_data[ANCHOR_DISC_LEN..].copy_from_slice(&make_pool_body(
            INITIAL_RESERVE_IN,
            INITIAL_RESERVE_OUT,
            INITIAL_FEE_BPS,
        ));
        ctx.write_account(
            &anchor_pool_kp.pubkey(),
            Account {
                lamports: POOL_LAMPORTS,
                data: anchor_pool_data,
                owner: anchor_program_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .expect("anchor pool pre-fund");

        let pino_pool_kp = Keypair::new();
        ctx.write_account(
            &pino_pool_kp.pubkey(),
            Account {
                lamports: POOL_LAMPORTS,
                data: make_pool_body(INITIAL_RESERVE_IN, INITIAL_RESERVE_OUT, INITIAL_FEE_BPS),
                owner: pino_program_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .expect("pino pool pre-fund");

        // Per-side token accounts. The amount field will diverge if the
        // two programs disagree on math or write order — that's the
        // signal the differential check is looking for.
        let make_acc = |ctx: &mut TestContext, mint: &Pubkey, amount: u64| -> Pubkey {
            let kp = Keypair::new();
            ctx.write_account(
                &kp.pubkey(),
                Account {
                    lamports: TOKEN_ACCOUNT_LAMPORTS,
                    data: make_token_account(mint, &user.pubkey(), amount),
                    owner: token_program,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .expect("token account pre-fund");
            kp.pubkey()
        };

        let anchor_user_src = make_acc(&mut ctx, &mint_a.pubkey(), INITIAL_USER_SRC_BALANCE);
        let anchor_user_dst = make_acc(&mut ctx, &mint_b.pubkey(), 0);
        let anchor_pool_vault_in = make_acc(&mut ctx, &mint_a.pubkey(), 0);
        let anchor_pool_vault_out =
            make_acc(&mut ctx, &mint_b.pubkey(), INITIAL_POOL_VAULT_OUT_BALANCE);

        let pino_user_src = make_acc(&mut ctx, &mint_a.pubkey(), INITIAL_USER_SRC_BALANCE);
        let pino_user_dst = make_acc(&mut ctx, &mint_b.pubkey(), 0);
        let pino_pool_vault_in = make_acc(&mut ctx, &mint_a.pubkey(), 0);
        let pino_pool_vault_out =
            make_acc(&mut ctx, &mint_b.pubkey(), INITIAL_POOL_VAULT_OUT_BALANCE);

        Self {
            ctx,
            anchor_program_id,
            pino_program_id,
            token_program,
            anchor_pool: anchor_pool_kp.pubkey(),
            pino_pool: pino_pool_kp.pubkey(),
            anchor_user_src,
            anchor_user_dst,
            anchor_pool_vault_in,
            anchor_pool_vault_out,
            pino_user_src,
            pino_user_dst,
            pino_pool_vault_in,
            pino_pool_vault_out,
            user,
            fee_payer,
        }
    }

    /// Differential action: drive `swap` through both targets with the
    /// same fuzz-derived input.
    ///
    /// amount_in range is capped at 10_000 so the initial 1M user_src
    /// balance survives ~100 swaps before exhaustion (giving libafl
    /// plenty of corpus growth space). min_out is fuzzed too so the
    /// slippage-check path is exercised.
    pub fn action_swap(
        &mut self,
        #[range(1..10_000)] amount_in: u64,
        #[range(0..2_000)] min_out: u64,
    ) -> bool {
        let anchor_ix = build_anchor_swap_ix(
            self.anchor_program_id,
            self.user.pubkey(),
            self.anchor_pool,
            self.anchor_user_src,
            self.anchor_user_dst,
            self.anchor_pool_vault_in,
            self.anchor_pool_vault_out,
            self.token_program,
            amount_in,
            min_out,
        );
        let pino_ix = build_pino_swap_ix(
            self.pino_program_id,
            self.user.pubkey(),
            self.pino_pool,
            self.pino_user_src,
            self.pino_user_dst,
            self.pino_pool_vault_in,
            self.pino_pool_vault_out,
            self.token_program,
            amount_in,
            min_out,
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

impl HasContext for AmmDiffFixture {
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

impl DifferentialFixture for AmmDiffFixture {
    fn anchor_program_id(&self) -> Pubkey {
        self.anchor_program_id
    }
    fn pino_program_id(&self) -> Pubkey {
        self.pino_program_id
    }
    /// Five pairs: 1 zero-copy Pool (Anchor has 8-byte disc; Pinocchio
    /// raw) + 4 SPL Token accounts (no discriminator on either side
    /// since Token Program owns both).
    fn diff_pairs(&self) -> Vec<DiffAccountPair> {
        vec![
            DiffAccountPair::anchor_disc_8("pool", self.anchor_pool, self.pino_pool, W8_POOL_BODY),
            DiffAccountPair::raw(
                "user_src",
                self.anchor_user_src,
                self.pino_user_src,
                TOKEN_ACCOUNT_LEN,
            ),
            DiffAccountPair::raw(
                "user_dst",
                self.anchor_user_dst,
                self.pino_user_dst,
                TOKEN_ACCOUNT_LEN,
            ),
            DiffAccountPair::raw(
                "pool_vault_in",
                self.anchor_pool_vault_in,
                self.pino_pool_vault_in,
                TOKEN_ACCOUNT_LEN,
            ),
            DiffAccountPair::raw(
                "pool_vault_out",
                self.anchor_pool_vault_out,
                self.pino_pool_vault_out,
                TOKEN_ACCOUNT_LEN,
            ),
        ]
    }
}

// ---------------------------------------------------------------------
// Differential checks
// ---------------------------------------------------------------------

/// One executed probe: what was driven through both sides, and what
/// each side did with it.
///
/// `Err` carries the `send()` failure text — kept rather than collapsed
/// so a probe that produced no evidence can be reported as such. The
/// two instructions are kept because a report has to carry the action
/// in a form someone can replay, not just a label describing it.
/// One run of the probe set: the state it started from, and what each
/// probe did.
///
/// The pre-state is captured before the first send, because that is the
/// only moment it exists — the probes mutate as they go. Bundling it
/// with the probes is what lets the parity and CU evaluators stay pure
/// functions over an already-executed run while still being able to
/// produce a report.
struct ProbeRun {
    /// `(label, pubkey, account)` for both sides of every declared pair.
    pre_state: Vec<(String, Pubkey, Account)>,
    /// Clock the run executed under, read before the first probe.
    clock_slot: u64,
    clock_unix_timestamp: i64,
    probes: Vec<Probe>,
}

struct Probe {
    label: String,
    anchor_ix: Instruction,
    pino_ix: Instruction,
    anchor: Result<TxOutcome, String>,
    pino: Result<TxOutcome, String>,
}

/// Drive the probe swaps through both sides and hand back the raw
/// outcomes, labelled by the action that produced them.
///
/// The outcomes are returned rather than collapsed to booleans on the
/// spot because two of the three comparison surfaces live inside them:
/// the rejection *reason* (custom error code) and the compute units
/// consumed. `map(|o| o.is_success())` throws both away.
///
/// `Err` on a side means `send()` itself failed — a harness-level
/// failure (blockhash, signers, serialization), not a statement about
/// program behaviour. Such a probe produced no evidence, so parity and
/// CU skip it, and `check_probe_evidence` reports it. Skipping without
/// reporting is what would let a harness whose sends are all failing
/// run to completion and call itself clean.
fn probe_actions(fixture: &mut AmmDiffFixture) -> ProbeRun {
    let pre_state = snapshot_pre_state(fixture);
    let clock: Clock = fixture.ctx.svm.get_sysvar();
    let probes: &[(u64, u64)] = &[
        (1, 0),
        (100, 0),
        (1_000, 0),
        (5_000, 100),
        (10_000, 500),
        (50_000, 0),
    ];

    let mut out = Vec::with_capacity(probes.len());

    for &(amount_in, min_out) in probes {
        let anchor_ix = build_anchor_swap_ix(
            fixture.anchor_program_id,
            fixture.user.pubkey(),
            fixture.anchor_pool,
            fixture.anchor_user_src,
            fixture.anchor_user_dst,
            fixture.anchor_pool_vault_in,
            fixture.anchor_pool_vault_out,
            fixture.token_program,
            amount_in,
            min_out,
        );
        let pino_ix = build_pino_swap_ix(
            fixture.pino_program_id,
            fixture.user.pubkey(),
            fixture.pino_pool,
            fixture.pino_user_src,
            fixture.pino_user_dst,
            fixture.pino_pool_vault_in,
            fixture.pino_pool_vault_out,
            fixture.token_program,
            amount_in,
            min_out,
        );

        let anchor = fixture
            .ctx
            .raw_call(anchor_ix.clone())
            .fee_payer(&*fixture.fee_payer)
            .signers(&[&*fixture.fee_payer, &*fixture.user])
            .send()
            .map_err(|e| e.to_string());

        let pino = fixture
            .ctx
            .raw_call(pino_ix.clone())
            .fee_payer(&*fixture.fee_payer)
            .signers(&[&*fixture.fee_payer, &*fixture.user])
            .send()
            .map_err(|e| e.to_string());

        out.push(Probe {
            label: format!("swap(amount_in={}, min_out={})", amount_in, min_out),
            anchor_ix,
            pino_ix,
            anchor,
            pino,
        });
    }

    ProbeRun {
        pre_state,
        clock_slot: clock.slot,
        clock_unix_timestamp: clock.unix_timestamp,
        probes: out,
    }
}

/// Read every declared pair's accounts as they stand right now.
///
/// Called once, before the probes run. Accounts that are not present
/// are skipped rather than faked — an absent account is a fact about
/// the fixture, and inventing an empty one would put a claim in the
/// report that no reader could reproduce.
fn snapshot_pre_state(fixture: &AmmDiffFixture) -> Vec<(String, Pubkey, Account)> {
    let mut out = Vec::new();
    for pair in fixture.diff_pairs() {
        for (side, pubkey) in [("anchor", pair.anchor), ("pinocchio", pair.pino)] {
            if let Ok(account) = fixture.ctx().get_account(&pubkey) {
                out.push((format!("{side}/{}", pair.label), pubkey, account));
            }
        }
    }
    out
}

/// Execution parity: the two sides must make the same accept/reject
/// decision **and**, when they reject, reject for the same reason —
/// custom code against custom code, builtin variant against builtin
/// variant.
///
/// Comparing only the custom code is not enough: every builtin
/// `ProgramError` reports no code, so two sides rejecting with
/// different builtins would compare equal. That is the likeliest place
/// for a divergence to hide here, because the Pinocchio side returns
/// builtins exclusively.
///
/// Takes an already-executed probe set so parity and CU can be
/// evaluated from one run of the actions rather than re-sending them.
fn check_execution_parity(run: &ProbeRun) {
    for probe in &run.probes {
        let (label, anchor, pino) = (&probe.label, &probe.anchor, &probe.pino);
        // A probe that never reached the program produces no evidence.
        // It is reported by `check_probe_evidence`, not silently reread
        // as agreement here.
        let (Ok(anchor), Ok(pino)) = (anchor, pino) else {
            continue;
        };

        if let Some(div) = ParityDivergence::check_outcomes(label, anchor, pino) {
            // Emitted before the assert, because fuzz_assert! ends the
            // iteration — the report has to be built while the run that
            // produced it is still in hand.
            evidence::emit(|| build_report(run, solinv_disclose::Divergence::from(&div)));
            fuzz_assert!(false, "{}", div);
        }
    }
}

/// CU non-regression: the Pinocchio side must not cost more than the
/// Anchor side it replaces.
///
/// Deliberately its own variant rather than part of the parity check.
/// A CU difference is the *point* of the rewrite, so it is a
/// measurement, not a defect — only the wrong direction is a defect,
/// and mixing that into a correctness campaign would report a
/// performance finding as a behavioural one.
///
/// It still belongs in the differential rather than in the
/// pinocchio-bench leaderboard: CU is consensus-relevant, so a slower
/// rewrite writing byte-identical state is not equivalent — it can
/// exceed the transaction limit and fail where the original succeeded.
fn check_cu_no_regression(run: &ProbeRun) {
    for probe in &run.probes {
        let (label, anchor, pino) = (&probe.label, &probe.anchor, &probe.pino);
        let (Ok(anchor), Ok(pino)) = (anchor, pino) else {
            continue;
        };

        if let Some(cmp) = CuComparison::regression(label, anchor, pino) {
            evidence::emit(|| build_report(run, solinv_disclose::Divergence::from(&cmp)));
            fuzz_assert!(false, "{}", cmp);
        }
    }
}

/// Every probe must actually have reached the program on both sides.
///
/// `send()` returning `Err` is a harness-level failure, not a statement
/// about program behaviour — but it must be reported rather than
/// skipped. A harness whose sends are all failing would otherwise run
/// to completion and declare itself clean: nothing diverges when
/// nothing executes.
fn check_probe_evidence(run: &ProbeRun) {
    for probe in &run.probes {
        if let Some(f) = SendFailure::check(&probe.label, &probe.anchor, &probe.pino) {
            fuzz_assert!(false, "{}", f);
        }
    }
}

/// Pool-body equivalence check (single-pair variant, isolated for an
/// orthogonal libafl violation report).
fn check_pool_equivalent(fixture: &mut AmmDiffFixture) {
    let pair = DiffAccountPair::anchor_disc_8(
        "pool",
        fixture.anchor_pool,
        fixture.pino_pool,
        W8_POOL_BODY,
    );
    if let Some(div) = check_pair_equivalent(fixture.ctx(), &pair) {
        fuzz_assert!(false, "{}", div);
    }
}

/// Token-account equivalence — checks the 4 SPL Token pairs declared by
/// the fixture, skipping the Pool pair (which is index 0 in
/// `diff_pairs()`).
fn check_token_accounts_equivalent(fixture: &mut AmmDiffFixture) {
    for pair in fixture.diff_pairs().iter().skip(1) {
        if let Some(div) = check_pair_equivalent(fixture.ctx(), pair) {
            fuzz_assert!(false, "{}", div);
        }
    }
}

/// k = reserve_in × reserve_out must be non-decreasing across any
/// successful swap sequence on both sides independently.
///
/// Implementation: compare against the initial product. Any successful
/// swap with nonzero fee makes k strictly greater (since the LP fee
/// stays in the pool); a swap that lowered k would indicate a math bug.
fn check_constant_product(fixture: &mut AmmDiffFixture) {
    let initial_k = (INITIAL_RESERVE_IN as u128) * (INITIAL_RESERVE_OUT as u128);

    let read_pool = |data: &[u8], offset: usize| -> Option<u128> {
        if data.len() < offset + 16 {
            return None;
        }
        let r_in = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap()) as u128;
        let r_out = u64::from_le_bytes(data[offset + 8..offset + 16].try_into().unwrap()) as u128;
        Some(r_in.saturating_mul(r_out))
    };

    if let Ok(a) = fixture.ctx().get_account(&fixture.anchor_pool) {
        if let Some(k) = read_pool(&a.data, ANCHOR_DISC_LEN) {
            fuzz_assert!(
                k >= initial_k,
                "anchor constant-product violated: k={} < initial={}",
                k,
                initial_k,
            );
        }
    }

    if let Ok(p) = fixture.ctx().get_account(&fixture.pino_pool) {
        if let Some(k) = read_pool(&p.data, 0) {
            fuzz_assert!(
                k >= initial_k,
                "pino constant-product violated: k={} < initial={}",
                k,
                initial_k,
            );
        }
    }
}

// ---------------------------------------------------------------------
// Invariant variants
// ---------------------------------------------------------------------

#[invariant_test]
fn invariant_amm_diff_smoke(fixture: &mut AmmDiffFixture) {
    // The trait-driven shortcut: walks all 5 declared pairs in one call.
    if let Some(div) = check_all_pairs(fixture) {
        fuzz_assert!(false, "{}", div);
    }
    check_constant_product(fixture);
    let run = probe_actions(fixture);
    check_probe_evidence(&run);
    check_execution_parity(&run);
}

#[invariant_test]
fn invariant_amm_diff_execution_parity_only(fixture: &mut AmmDiffFixture) {
    let run = probe_actions(fixture);
    check_probe_evidence(&run);
    check_execution_parity(&run);
}

#[invariant_test]
fn invariant_amm_diff_pool_equivalent_only(fixture: &mut AmmDiffFixture) {
    check_pool_equivalent(fixture);
}

#[invariant_test]
fn invariant_amm_diff_token_accounts_equivalent_only(fixture: &mut AmmDiffFixture) {
    check_token_accounts_equivalent(fixture);
}

#[invariant_test]
fn invariant_amm_diff_constant_product_only(fixture: &mut AmmDiffFixture) {
    check_constant_product(fixture);
}

#[invariant_test]
fn invariant_amm_diff_cu_no_regression_only(fixture: &mut AmmDiffFixture) {
    let run = probe_actions(fixture);
    check_probe_evidence(&run);
    check_cu_no_regression(&run);
}

// ---------------------------------------------------------------------
// Report assembly
// ---------------------------------------------------------------------

/// Build the finding as a report a third party can check.
///
/// Everything here is drawn from the run itself rather than restated:
/// the `.so` bytes are hashed off disk, the account pre-state is the
/// snapshot taken before the first probe, and the actions carry the
/// real instruction encodings both sides were driven with.
///
/// The one field that is a *statement* rather than a measurement is the
/// feature set. LiteSVM does not expose an enumerated activated-feature
/// list, so the string says which runtime it was rather than pretending
/// to a cluster feature set it cannot name.
fn build_report(run: &ProbeRun, finding: solinv_disclose::Divergence) -> DivergenceReport {
    let inline = evidence::inline_artifacts();

    let program = |side: &str, id: &str, path: &str| {
        let bytes = std::fs::read(path).unwrap_or_default();
        if inline {
            ProgramRef::with_code_inline(side, id, &bytes)
        } else {
            ProgramRef::from_code(side, id, &bytes)
        }
    };

    let mut bundle = ReproBundle::new()
        .with_program(program(
            "anchor",
            ANCHOR_W8_PROGRAM_ID_STR,
            ANCHOR_W8_SO_PATH,
        ))
        .with_program(program(
            "pinocchio",
            PINO_W8_PROGRAM_ID_STR,
            PINO_W8_SO_PATH,
        ))
        .with_feature_set(
            "litesvm default via crucible v0.1.0 (not an enumerated Solana feature set)",
        );

    for (label, pubkey, account) in &run.pre_state {
        let acct = if inline {
            AccountRef::with_data_inline(label.clone(), pubkey.to_string(), &account.data)
        } else {
            AccountRef::from_data(label.clone(), pubkey.to_string(), &account.data)
        };
        bundle = bundle.with_account(acct.with_metadata(
            account.owner.to_string(),
            account.lamports,
            account.executable,
            account.rent_epoch,
        ));
    }

    for probe in &run.probes {
        for (side, ix) in [("anchor", &probe.anchor_ix), ("pinocchio", &probe.pino_ix)] {
            bundle = bundle.with_action(ActionRef::encoded(
                format!("{} [{}]", probe.label, side),
                ix.program_id.to_string(),
                &ix.data,
                ix.accounts
                    .iter()
                    .map(|m| (m.pubkey.to_string(), m.is_signer, m.is_writable))
                    .collect(),
            ));
        }
    }

    // LiteSVM is constructed `with_sigverify(false)` by Crucible, so a
    // reader reproduces by also disabling it and needs no keys. Stating
    // the policy is what makes that reproducible rather than folklore.
    bundle = bundle.with_context(
        ExecutionContext::new(
            "litesvm 0.9.1 via crucible v0.1.0 (sigverify off, blockhash check off)",
            SignerPolicy::SigverifyDisabled,
        )
        .with_clock(run.clock_slot, run.clock_unix_timestamp),
    );

    DivergenceReport::new("amm-diff (W8 AMM swap)", Sides::anchor_pinocchio(), bundle)
        .with_divergence(finding)
}
