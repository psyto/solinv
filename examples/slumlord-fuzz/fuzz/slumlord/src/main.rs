//! # slumlord-fuzz — Phase 4 N=1 protocol-variety harness
//!
//! Tests the existing 5 implemented invariants (signer-skip, owner-skip,
//! pda-forge, unchecked-math, cu-dos) against Slumlord — a simple
//! zero-fee SOL flash loan program from igneous-labs. discriminator-skip
//! is N/A (Native, 1-byte disc) and account-swap is N/A (no
//! alternate-context concept — single PDA per program).
//!
//! See docs/slumlord-ix-inventory.md for per-ix analysis + honest
//! pre-fuzz estimate (likely 0 violations across the board — Slumlord
//! uses solores-generated `*_verify_account_keys` helpers that strictly
//! check pubkey equality, functionally equivalent to Anchor's
//! Account<'info, T>).

use crucible_fuzzer::*;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use std::str::FromStr;
use std::sync::Arc;

use solinv_fuzz::{HasContext, HasInstructionSet, InstructionSpec};

// ---------------------------------------------------------------------
// Slumlord on-chain identity
// ---------------------------------------------------------------------

/// Mainnet program ID per idl.json:129 — same address used regardless
/// of whether we load the .so locally or fork from mainnet.
const SLUMLORD_PROGRAM_ID_STR: &str = "s1umBj7CEUA6djs6V1c6o2Nym3QrqF4ryKDr1Nm1FKt";

/// Absolute path to the locally-built .so. User must run
/// `SDKROOT=$(xcrun --show-sdk-path) CFLAGS=... cargo build-sbf --tools-version v1.39`
/// against ~/src/slumlord/slumlord/Cargo.toml first (Day 40
/// build-smoke result).
const SLUMLORD_SO_PATH: &str = env!("SLUMLORD_SO", "set SLUMLORD_SO to your built slumlord/target/deploy/slumlord.so path");

/// Slumlord PDA single seed per idl.json + slumlord-lib::program.
const SLUMLORD_SEED: &[u8] = b"slumlord";

/// System Program ID = 32 zero bytes. Inlined so harness has no
/// anchor-lang / solana-system-interface dep.
const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);

/// 1-byte u8 discriminants per idl.json.
const SLUMLORD_DISC_INIT: u8 = 0;
const SLUMLORD_DISC_BORROW: u8 = 1;
const SLUMLORD_DISC_REPAY: u8 = 2;
const SLUMLORD_DISC_CHECK_REPAID: u8 = 3;

/// PDA pre-funding amount. Becomes the flash-loan-able lamports
/// (slumlord_balance - 1 is transferred on Borrow). 10M lamports
/// = 0.01 SOL — well above rent-exempt minimum for 8-byte data.
const SLUMLORD_INITIAL_LAMPORTS: u64 = 10_000_000;

const FEE_PAYER_BALANCE: u64 = 10_000_000_000;
const USER_BALANCE: u64 = 1_000_000_000;

// ---------------------------------------------------------------------
// ix constructors — raw_call shape (Day 15 refactor pattern)
// ---------------------------------------------------------------------

fn build_init_ix(program_id: Pubkey, slumlord_pda: Pubkey) -> Instruction {
    let data = vec![SLUMLORD_DISC_INIT];
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(slumlord_pda, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data,
    }
}

fn build_borrow_ix(
    program_id: Pubkey,
    slumlord_pda: Pubkey,
    dst: Pubkey,
    instructions_sysvar: Pubkey,
) -> Instruction {
    let data = vec![SLUMLORD_DISC_BORROW];
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(slumlord_pda, false),
            AccountMeta::new(dst, false),
            AccountMeta::new_readonly(instructions_sysvar, false),
        ],
        data,
    }
}

fn build_repay_ix(program_id: Pubkey, slumlord_pda: Pubkey, src: Pubkey) -> Instruction {
    let data = vec![SLUMLORD_DISC_REPAY];
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(slumlord_pda, false),
            AccountMeta::new(src, true),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data,
    }
}

fn build_check_repaid_ix(program_id: Pubkey, slumlord_pda: Pubkey) -> Instruction {
    let data = vec![SLUMLORD_DISC_CHECK_REPAID];
    Instruction {
        program_id,
        accounts: vec![AccountMeta::new(slumlord_pda, false)],
        data,
    }
}

// ---------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------

#[derive(Clone)]
struct SlumlordFixture {
    pub ctx: TestContext,
    program_id: Pubkey,
    slumlord_pda: Pubkey,
    user: Arc<Keypair>,
    fee_payer: Arc<Keypair>,
    instructions_sysvar: Pubkey,
}

#[fuzz_fixture]
impl SlumlordFixture {
    pub fn setup() -> Self {
        let mut ctx = TestContext::new();

        let program_id =
            Pubkey::from_str(SLUMLORD_PROGRAM_ID_STR).expect("valid base58 program id");
        ctx.add_program(&program_id, SLUMLORD_SO_PATH)
            .expect("slumlord.so must be built per Day 40 — see docs/slumlord-ix-inventory.md");

        // Derive the canonical slumlord PDA.
        let (slumlord_pda, _bump) = Pubkey::find_program_address(&[SLUMLORD_SEED], &program_id);

        // Instructions sysvar address — well-known fixed address.
        // Per solana_program::sysvar::instructions::ID =
        // Sysvar1nstructions1111111111111111111111111
        let instructions_sysvar =
            Pubkey::from_str("Sysvar1nstructions1111111111111111111111111")
                .expect("valid sysvar address");

        // Fund user + fee_payer as standard system-owned accounts.
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

        // Pre-fund the slumlord PDA as a SystemProgram-owned account
        // with empty data + 10M lamports. The Init ix will assign
        // ownership to slumlord program via system_program::assign.
        // Empty data is required — SystemProgram-owned with non-empty
        // data is silently rejected by LiteSVM (Day 32 finding on the
        // unchecked-math regression tests).
        ctx.write_account(
            &slumlord_pda,
            Account {
                lamports: SLUMLORD_INITIAL_LAMPORTS,
                data: Vec::new(),
                owner: SYSTEM_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .expect("slumlord PDA pre-fund");

        // Init the slumlord PDA (assigns it to the slumlord program).
        // Permissionless ix — no signers required beyond the fee payer.
        ctx.raw_call(build_init_ix(program_id, slumlord_pda))
            .fee_payer(&*fee_payer)
            .signers(&[&*fee_payer])
            .send()
            .expect("Slumlord Init ix");

        Self {
            ctx,
            program_id,
            slumlord_pda,
            user,
            fee_payer,
            instructions_sysvar,
        }
    }

    // -----------------------------------------------------------------
    // Actions — Day 41 ships Init + Repay + CheckRepaid as standalone
    // actions. Borrow is NOT a standalone fuzz action because the
    // handler scans the tx's instructions sysvar for a succeeding
    // CheckRepaid ix; a single-ix Borrow tx always returns
    // NoSucceedingCheckRepaid. Multi-ix flash-loan-flow actions (Day 42)
    // will wrap Borrow + CheckRepaid in a single tx.
    // -----------------------------------------------------------------

    pub fn action_init(&mut self) -> bool {
        // Idempotent per slumlord/src/lib.rs:60-77 — assign_invoke_signed
        // is a no-op when already owned. Fuzzer can call multiple times.
        self.ctx
            .raw_call(build_init_ix(self.program_id, self.slumlord_pda))
            .fee_payer(&*self.fee_payer)
            .signers(&[&*self.fee_payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_check_repaid(&mut self) -> bool {
        // Idempotent per slumlord/src/lib.rs:175-197 — if slumlord.data
        // is empty (no loan active), it's a successful no-op.
        self.ctx
            .raw_call(build_check_repaid_ix(self.program_id, self.slumlord_pda))
            .fee_payer(&*self.fee_payer)
            .signers(&[&*self.fee_payer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_repay(&mut self, #[range(0..1_000_000)] _amount_hint: u64) -> bool {
        // The Repay handler computes the outstanding loan internally;
        // amount is determined by slumlord.curr_loan_lamports_outstanding(),
        // not by ix args. With no active borrow, this should error out
        // cleanly (data_is_empty path inside curr_loan_lamports_outstanding,
        // returning Err which Repay surfaces as failure).
        self.ctx
            .raw_call(build_repay_ix(
                self.program_id,
                self.slumlord_pda,
                self.user.pubkey(),
            ))
            .fee_payer(&*self.fee_payer)
            .signers(&[&*self.fee_payer, &*self.user])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    /// Day 42 — multi-ix flash loan flow. Borrow's handler scans the
    /// tx's instructions sysvar for a succeeding CheckRepaid; without
    /// that follow-up, a standalone Borrow always returns
    /// NoSucceedingCheckRepaid. So we bundle Borrow + Repay +
    /// CheckRepaid in a single tx via InstructionBuilder::add_transaction
    /// — the public API path that pushes ix + signers into TestContext's
    /// pending queue, then send_batch() flushes (TransactionBuilder::send
    /// is todo!() in Crucible v0.1.0; this is the working multi-ix path
    /// per test-context instruction_builder.rs:79-82).
    ///
    /// On success: slumlord-1 lamports flow to user during Borrow,
    /// Repay returns them, CheckRepaid validates and shrinks state.
    /// Grows the corpus's PDA-state exploration without needing an
    /// attacker-controlled amount arg (none of the slumlord ixs take
    /// args — all state is account-driven).
    pub fn action_flash_loan(&mut self) -> bool {
        let borrow_ix = build_borrow_ix(
            self.program_id,
            self.slumlord_pda,
            self.user.pubkey(),
            self.instructions_sysvar,
        );
        let repay_ix = build_repay_ix(
            self.program_id,
            self.slumlord_pda,
            self.user.pubkey(),
        );
        let check_repaid_ix = build_check_repaid_ix(self.program_id, self.slumlord_pda);

        // Queue all three ix. First signer (fee_payer) on the first
        // ix determines the tx fee payer per send_batch logic.
        if self
            .ctx
            .raw_call(borrow_ix)
            .fee_payer(&*self.fee_payer)
            .signers(&[&*self.fee_payer])
            .add_transaction()
            .is_err()
        {
            return false;
        }
        if self
            .ctx
            .raw_call(repay_ix)
            .signers(&[&*self.user])
            .add_transaction()
            .is_err()
        {
            return false;
        }
        if self
            .ctx
            .raw_call(check_repaid_ix)
            .add_transaction()
            .is_err()
        {
            return false;
        }

        self.ctx
            .send_batch()
            .map(|opt| opt.map(|o| o.is_success()).unwrap_or(false))
            .unwrap_or(false)
    }
}

// ---------------------------------------------------------------------
// solinv integration — HasContext + HasInstructionSet
// ---------------------------------------------------------------------

impl HasContext for SlumlordFixture {
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

impl HasInstructionSet for SlumlordFixture {
    fn instructions(&self) -> Vec<InstructionSpec> {
        // Day 41 ships Init + Repay + CheckRepaid InstructionSpecs.
        // Borrow is intentionally deferred to Day 42 — it requires
        // multi-ix tx orchestration that doesn't fit the standard
        // raw_call(spec.to_instruction()) re-execution path solinv
        // invariants use.

        let init_spec = InstructionSpec {
            program_id: self.program_id,
            name: "init".into(),
            accounts: vec![
                AccountMeta::new(self.slumlord_pda, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            ],
            signer_indices: vec![],
            optional_signer_indices: vec![],
            expected_owners: vec![Some(self.program_id), None],
            expected_discriminators: vec![None, None],
            expected_pda_seeds: vec![Some(vec![SLUMLORD_SEED.to_vec()]), None],
            creates_indices: vec![],
            swap_alternates: vec![vec![], vec![]],
            data_sample: vec![SLUMLORD_DISC_INIT],
            signers: vec![],
            state_invariants: vec![],
            cu_budget: Some(20_000),
            cpi_reentrancy: None,
            realloc_check: None,
            bump_seed_check: None,            };

        let repay_spec = InstructionSpec {
            program_id: self.program_id,
            name: "repay".into(),
            accounts: vec![
                AccountMeta::new(self.slumlord_pda, false),
                AccountMeta::new(self.user.pubkey(), true),
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            ],
            signer_indices: vec![1], // src is the only signer
            optional_signer_indices: vec![],
            expected_owners: vec![Some(self.program_id), None, None],
            expected_discriminators: vec![None, None, None],
            expected_pda_seeds: vec![Some(vec![SLUMLORD_SEED.to_vec()]), None, None],
            creates_indices: vec![],
            swap_alternates: vec![vec![], vec![], vec![]],
            data_sample: vec![SLUMLORD_DISC_REPAY],
            signers: vec![Arc::clone(&self.user)],
            // Bounded on slumlord.old_lamports (offset 0, u64). Only
            // populated mid-flash-loan (post-Borrow, pre-CheckRepaid);
            // fires only if a wrap somehow drove the u64 above 10^18.
            // honest framing: state_invariants on account.data don't
            // catch SOL-balance wrap because slumlord.lamports is a
            // separate field not in data — a v2 extension to
            // unchecked-math (read_field on .lamports) would be the
            // right surface here. Declared anyway for code-path coverage.
            state_invariants: vec![solinv_fuzz::StateInvariant {
                name: "old_lamports_bounded".to_string(),
                kind: solinv_fuzz::StateInvariantKind::Bounded {
                    field_offset: 0,
                    field_size: 8,
                    min: 0,
                    max: 1_000_000_000_000_000_000,
                },
                accounts: vec![0], // slumlord PDA
            }],
            cu_budget: Some(20_000),
            cpi_reentrancy: None,
            realloc_check: None,
            bump_seed_check: None,            };

        let check_repaid_spec = InstructionSpec {
            program_id: self.program_id,
            name: "check_repaid".into(),
            accounts: vec![AccountMeta::new(self.slumlord_pda, false)],
            signer_indices: vec![],
            optional_signer_indices: vec![],
            expected_owners: vec![Some(self.program_id)],
            expected_discriminators: vec![None],
            expected_pda_seeds: vec![Some(vec![SLUMLORD_SEED.to_vec()])],
            creates_indices: vec![],
            swap_alternates: vec![vec![]],
            data_sample: vec![SLUMLORD_DISC_CHECK_REPAID],
            signers: vec![],
            state_invariants: vec![],
            cu_budget: Some(10_000),
            cpi_reentrancy: None,
            realloc_check: None,
            bump_seed_check: None,            };

        vec![init_spec, repay_spec, check_repaid_spec]
    }
}

// ---------------------------------------------------------------------
// Invariant variants — 5 applicable invariants × 1 combined smoke
// ---------------------------------------------------------------------

#[invariant_test]
fn invariant_slumlord_smoke(fixture: &mut SlumlordFixture) {
    solinv_core::invariants::signer_skip::check(fixture);
    solinv_core::invariants::owner_skip::check(fixture);
    solinv_core::invariants::pda_forge::check(fixture);
    solinv_core::invariants::unchecked_math::check(fixture);
    solinv_core::invariants::cu_dos::check(fixture);
}

#[invariant_test]
fn invariant_signer_skip_only(fixture: &mut SlumlordFixture) {
    solinv_core::invariants::signer_skip::check(fixture);
}

#[invariant_test]
fn invariant_owner_skip_only(fixture: &mut SlumlordFixture) {
    solinv_core::invariants::owner_skip::check(fixture);
}

#[invariant_test]
fn invariant_pda_forge_only(fixture: &mut SlumlordFixture) {
    solinv_core::invariants::pda_forge::check(fixture);
}

#[invariant_test]
fn invariant_unchecked_math_only(fixture: &mut SlumlordFixture) {
    solinv_core::invariants::run_with_transition_metrics("unchecked-math", || {
        solinv_core::invariants::unchecked_math::check(fixture);
    });
}

#[invariant_test]
fn invariant_cu_dos_only(fixture: &mut SlumlordFixture) {
    solinv_core::invariants::run_with_transition_metrics("cu-dos", || {
        solinv_core::invariants::cu_dos::check(fixture);
    });
}
