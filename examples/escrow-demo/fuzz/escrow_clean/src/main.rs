//! Fuzz harness for `escrow-clean` — solinv's mutation-testing target.
//!
//! The contract this harness is built around: **on the unmutated
//! program, every detector must report nothing.** That is the property
//! that makes a mutation score mean anything. If a detector fires here
//! before a single line has been mutated, then either the program has a
//! real bug or a declaration below is wrong, and until that is settled
//! no campaign run against this target can attribute a kill to a
//! mutation. `scripts/run_mutation_campaign.sh` measures the baseline
//! and subtracts it for exactly this reason, but a non-empty baseline
//! here should be treated as a defect to fix, not a number to subtract.
//!
//! The declarations are therefore the substance of this file, not
//! boilerplate. `expected_owners`, `expected_discriminators`,
//! `expected_pda_seeds` and `signer_indices` tell the Critical 5 what
//! the program is supposed to enforce; `state_invariants` tells
//! unchecked-math what arithmetic is supposed to preserve. A mutation
//! that removes an enforcement is caught only if the declaration said
//! the enforcement was there.
use crucible_fuzzer::*;
use escrow_clean::ID;
use sha2::{Digest, Sha256};
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use std::sync::Arc;

use solinv_fuzz::{GuardCondition, GuardOp, GuardOperand, HasContext, HasInstructionSet,
                  InstructionSpec, StateInvariant, StateInvariantKind};

const INITIAL_BALANCE: u64 = 10_000_000_000;
const UNLOCK_DELAY: u64 = 10;
const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);

// Anchor instruction sighash: sha256("global:{ix_name}")[..8]. Computed
// here rather than imported so the harness stays independent of the
// program's anchor-lang version.
fn ix_sighash(ix_name: &str) -> [u8; 8] {
    let mut hasher = Sha256::new();
    hasher.update(b"global:");
    hasher.update(ix_name.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

// Anchor account discriminator: sha256("account:{Name}")[..8].
fn account_disc(name: &str) -> [u8; 8] {
    let mut hasher = Sha256::new();
    hasher.update(b"account:");
    hasher.update(name.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

fn vault_discriminator() -> [u8; 8] {
    account_disc("Vault")
}

// Vault layout: 8-byte discriminator, then depositor (32), beneficiary
// (32), unlock_slot (8), amount (8).
const VAULT_UNLOCK_SLOT_OFFSET: usize = 8 + 32 + 32;
const VAULT_AMOUNT_OFFSET: usize = 8 + 32 + 32 + 8;

// Anchor puts the 8-byte sighash first, so the first argument starts here.
const IX_ARG0_OFFSET: usize = 8;

fn vault_field(offset: usize) -> GuardOperand {
    GuardOperand::Field {
        account_index: 0,
        field_offset: offset,
        field_size: 8,
    }
}

fn arg_amount() -> GuardOperand {
    GuardOperand::IxData {
        offset: IX_ARG0_OFFSET,
        size: 8,
    }
}

fn guard(name: &str, lhs: GuardOperand, op: GuardOp, rhs: GuardOperand) -> GuardCondition {
    GuardCondition {
        name: name.to_string(),
        lhs,
        op,
        rhs,
    }
}

fn build_initialize_ix(
    program_id: Pubkey,
    vault: Pubkey,
    depositor: Pubkey,
    beneficiary: Pubkey,
    unlock_slot: u64,
) -> Instruction {
    let mut data = ix_sighash("initialize").to_vec();
    data.extend_from_slice(beneficiary.as_ref());
    data.extend_from_slice(&unlock_slot.to_le_bytes());
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(vault, false),
            AccountMeta::new(depositor, true),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data,
    }
}

fn build_deposit_ix(
    program_id: Pubkey,
    vault: Pubkey,
    depositor: Pubkey,
    amount: u64,
) -> Instruction {
    let mut data = ix_sighash("deposit").to_vec();
    data.extend_from_slice(&amount.to_le_bytes());
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(vault, false),
            AccountMeta::new(depositor, true),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data,
    }
}

fn build_withdraw_ix(
    program_id: Pubkey,
    vault: Pubkey,
    depositor: Pubkey,
    amount: u64,
) -> Instruction {
    let mut data = ix_sighash("withdraw").to_vec();
    data.extend_from_slice(&amount.to_le_bytes());
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(vault, false),
            AccountMeta::new(depositor, true),
        ],
        data,
    }
}

fn build_claim_ix(
    program_id: Pubkey,
    vault: Pubkey,
    depositor: Pubkey,
    beneficiary: Pubkey,
) -> Instruction {
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(vault, false),
            AccountMeta::new_readonly(depositor, false),
            AccountMeta::new(beneficiary, true),
        ],
        data: ix_sighash("claim").to_vec(),
    }
}

#[derive(Clone)]
struct EscrowCleanFixture {
    pub ctx: TestContext,
    program_id: Pubkey,
    depositor: Arc<Keypair>,
    depositor_b: Arc<Keypair>, // alternate context, for account-swap
    beneficiary: Arc<Keypair>,
    fee_payer: Arc<Keypair>,
    // Payer for the `initialize` spec. Deliberately not `fee_payer`:
    // the fee payer signs the transaction whatever its AccountMeta
    // says, so clearing its is_signer flag removes nothing and
    // signer-skip reports a violation on correct code — measured, at
    // 19998 findings against the unmutated program.
    initializer: Arc<Keypair>,
    vault_pda: Pubkey,
    vault_b_pda: Pubkey,
    // Vault for `initialize`, left uncreated by setup so the handler
    // has somewhere to succeed.
    vault_init_pda: Pubkey,
    unlock_slot: u64,
    // IDL-built specs, inferred once against the post-setup state and
    // shared by clones of this fixture. Re-inferring on every call would
    // read state a detector is midway through tampering with.
    #[cfg(feature = "idl_specs")]
    idl_cache: Arc<std::sync::Mutex<std::collections::HashMap<String, InstructionSpec>>>,
}

#[fuzz_fixture]
impl EscrowCleanFixture {
    pub fn setup() -> Self {
        let mut ctx = TestContext::new();
        let program_id = Pubkey::new_from_array(ID.to_bytes());
        ctx.add_program(&program_id, "../../target/deploy/escrow_clean.so")
            .unwrap();

        let depositor = Arc::new(Keypair::new());
        let depositor_b = Arc::new(Keypair::new());
        let beneficiary = Arc::new(Keypair::new());
        let fee_payer = Arc::new(Keypair::new());
        let initializer = Arc::new(Keypair::new());
        for kp in [&depositor, &depositor_b, &beneficiary, &fee_payer, &initializer] {
            ctx.create_account()
                .pubkey(kp.pubkey())
                .lamports(INITIAL_BALANCE)
                .owner(SYSTEM_PROGRAM_ID)
                .create()
                .unwrap();
        }

        let (vault_pda, _) =
            Pubkey::find_program_address(&[b"vault", depositor.pubkey().as_ref()], &program_id);
        let (vault_b_pda, _) =
            Pubkey::find_program_address(&[b"vault", depositor_b.pubkey().as_ref()], &program_id);
        let (vault_init_pda, _) =
            Pubkey::find_program_address(&[b"vault", initializer.pubkey().as_ref()], &program_id);
        let unlock_slot = ctx.slot() + UNLOCK_DELAY;

        ctx.raw_call(build_initialize_ix(
            program_id,
            vault_pda,
            depositor.pubkey(),
            beneficiary.pubkey(),
            unlock_slot,
        ))
        .signers(&[&*depositor])
        .send()
        .unwrap();

        // Alternate-context vault, funded, so account-swap has a real
        // PDA of the right owner and discriminator to substitute in.
        ctx.raw_call(build_initialize_ix(
            program_id,
            vault_b_pda,
            depositor_b.pubkey(),
            beneficiary.pubkey(),
            unlock_slot,
        ))
        .signers(&[&*depositor_b])
        .send()
        .unwrap();

        ctx.raw_call(build_deposit_ix(
            program_id,
            vault_b_pda,
            depositor_b.pubkey(),
            5_000_000,
        ))
        .signers(&[&*depositor_b])
        .send()
        .unwrap();

        let fixture = Self {
            ctx,
            program_id,
            depositor,
            depositor_b,
            beneficiary,
            fee_payer,
            initializer,
            vault_pda,
            vault_b_pda,
            vault_init_pda,
            unlock_slot,
            #[cfg(feature = "idl_specs")]
            idl_cache: Default::default(),
        };
        #[cfg(feature = "idl_specs")]
        let _ = fixture.instructions();
        fixture
    }

    /// Record a canonical action's instruction as reached when it lands.
    ///
    /// The `ix_name` must match the program's `pub fn` identifier:
    /// `solinv mutate plan` records the enclosing function of each
    /// mutation site and the campaign runner joins the two by name.
    fn note_reached(&self, ix_name: &str, success: bool) -> bool {
        if success {
            solinv_core::invariants::reachability::record_ix_reached(&self.program_id, ix_name);
        }
        success
    }

    pub fn action_deposit(&mut self, #[range(1..1_000_000)] amount: u64) -> bool {
        let ok = self
            .ctx
            .raw_call(build_deposit_ix(
                self.program_id,
                self.vault_pda,
                self.depositor.pubkey(),
                amount,
            ))
            .signers(&[&*self.depositor])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        self.note_reached("deposit", ok)
    }

    pub fn action_withdraw(&mut self, #[range(1..1_000_000)] amount: u64) -> bool {
        let ok = self
            .ctx
            .raw_call(build_withdraw_ix(
                self.program_id,
                self.vault_pda,
                self.depositor.pubkey(),
                amount,
            ))
            .signers(&[&*self.depositor])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        self.note_reached("withdraw", ok)
    }

    pub fn action_claim(&mut self) -> bool {
        let ok = self
            .ctx
            .raw_call(build_claim_ix(
                self.program_id,
                self.vault_pda,
                self.depositor.pubkey(),
                self.beneficiary.pubkey(),
            ))
            .signers(&[&*self.beneficiary])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        self.note_reached("claim", ok)
    }

    /// Create the initializer's vault.
    ///
    /// Keeps `initialize` on the reachable set. `setup` creates the
    /// depositor's and depositor_b's vaults, so an action re-running
    /// either would fail on an already-initialized account every time
    /// and the handler would read as unreachable — mutants inside it
    /// excluded from the denominator for want of anything driving them.
    /// The initializer's vault is untouched by setup, so the first call
    /// in each iteration lands.
    pub fn action_initialize_third(&mut self, #[range(1..1000)] delay: u64) -> bool {
        let unlock = self.ctx.slot() + delay;
        let ok = self
            .ctx
            .raw_call(build_initialize_ix(
                self.program_id,
                self.vault_init_pda,
                self.initializer.pubkey(),
                self.beneficiary.pubkey(),
                unlock,
            ))
            .signers(&[&*self.initializer])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        self.note_reached("initialize", ok)
    }

    pub fn action_advance_slots(&mut self, #[range(0..15)] slots: u64) -> bool {
        let new_slot = self.ctx.slot() + slots;
        self.ctx.warp_to_slot(new_slot);
        true
    }
}

impl HasContext for EscrowCleanFixture {
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

impl HasInstructionSet for EscrowCleanFixture {
    fn instructions(&self) -> Vec<InstructionSpec> {
        let vault_seeds = vec![
            b"vault".to_vec(),
            self.depositor.pubkey().to_bytes().to_vec(),
        ];

        // deposit — the one handler with arithmetic worth declaring.
        // `vault.amount` must never exceed the vault's lamport balance;
        // a checked_add rewritten to wrapping breaks it.
        let mut deposit_data = ix_sighash("deposit").to_vec();
        deposit_data.extend_from_slice(&50_000u64.to_le_bytes());

        let deposit_spec = InstructionSpec {
            program_id: self.program_id,
            name: "deposit".into(),
            accounts: vec![
                AccountMeta::new(self.vault_pda, false),
                AccountMeta::new(self.depositor.pubkey(), true),
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            ],
            signer_indices: vec![1],
            optional_signer_indices: vec![],
            expected_owners: vec![Some(self.program_id), None, None],
            expected_discriminators: vec![Some(vault_discriminator()), None, None],
            expected_pda_seeds: vec![Some(vault_seeds.clone()), None, None],
            creates_indices: vec![],
            swap_alternates: vec![vec![self.vault_b_pda], vec![], vec![]],
            data_sample: deposit_data,
            signers: vec![Arc::clone(&self.depositor)],
            state_invariants: vec![StateInvariant {
                name: "vault_amount_bounded".to_string(),
                kind: StateInvariantKind::Bounded {
                    field_offset: VAULT_AMOUNT_OFFSET,
                    field_size: 8,
                    min: 0,
                    max: INITIAL_BALANCE as u128,
                },
                accounts: vec![0],
            }],
            cu_budget: None,
            cpi_reentrancy: None,
            realloc_check: None,
            bump_seed_check: None,
            guards: vec![guard(
                "deposit only a positive amount",
                arg_amount(),
                GuardOp::Gt,
                GuardOperand::Const(0),
            )],
        };

        let mut withdraw_data = ix_sighash("withdraw").to_vec();
        withdraw_data.extend_from_slice(&1_000u64.to_le_bytes());

        let withdraw_spec = InstructionSpec {
            program_id: self.program_id,
            name: "withdraw".into(),
            accounts: vec![
                AccountMeta::new(self.vault_pda, false),
                AccountMeta::new(self.depositor.pubkey(), true),
            ],
            signer_indices: vec![1],
            optional_signer_indices: vec![],
            expected_owners: vec![Some(self.program_id), None],
            expected_discriminators: vec![Some(vault_discriminator()), None],
            expected_pda_seeds: vec![Some(vault_seeds.clone()), None],
            creates_indices: vec![],
            swap_alternates: vec![vec![self.vault_b_pda], vec![]],
            data_sample: withdraw_data,
            signers: vec![Arc::clone(&self.depositor)],
            state_invariants: vec![StateInvariant {
                name: "vault_amount_bounded".to_string(),
                kind: StateInvariantKind::Bounded {
                    field_offset: VAULT_AMOUNT_OFFSET,
                    field_size: 8,
                    min: 0,
                    max: INITIAL_BALANCE as u128,
                },
                accounts: vec![0],
            }],
            cu_budget: None,
            cpi_reentrancy: None,
            realloc_check: None,
            bump_seed_check: None,
            // The three `require!`s at the top of `withdraw`. The first
            // is the timelock, and dropping it reproduces exactly the
            // race `escrow` plants as its flagship bug.
            guards: vec![
                guard(
                    "withdraw only strictly before unlock",
                    GuardOperand::Slot,
                    GuardOp::Lt,
                    vault_field(VAULT_UNLOCK_SLOT_OFFSET),
                ),
                guard(
                    "withdraw only a positive amount",
                    arg_amount(),
                    GuardOp::Gt,
                    GuardOperand::Const(0),
                ),
                guard(
                    "withdraw no more than the vault holds",
                    arg_amount(),
                    GuardOp::Le,
                    vault_field(VAULT_AMOUNT_OFFSET),
                ),
            ],
        };

        // claim — beneficiary is the signer here, not the depositor,
        // and the depositor slot is a bare seed. Declaring index 2 (and
        // not 1) is what lets signer-skip notice if the Signer<'info>
        // on `beneficiary` is ever weakened.
        let claim_spec = InstructionSpec {
            program_id: self.program_id,
            name: "claim".into(),
            accounts: vec![
                AccountMeta::new(self.vault_pda, false),
                AccountMeta::new_readonly(self.depositor.pubkey(), false),
                AccountMeta::new(self.beneficiary.pubkey(), true),
            ],
            signer_indices: vec![2],
            optional_signer_indices: vec![],
            expected_owners: vec![Some(self.program_id), None, None],
            expected_discriminators: vec![Some(vault_discriminator()), None, None],
            expected_pda_seeds: vec![Some(vault_seeds), None, None],
            creates_indices: vec![],
            swap_alternates: vec![vec![self.vault_b_pda], vec![], vec![]],
            data_sample: ix_sighash("claim").to_vec(),
            signers: vec![Arc::clone(&self.beneficiary)],
            state_invariants: vec![],
            cu_budget: None,
            cpi_reentrancy: None,
            realloc_check: None,
            bump_seed_check: None,
            guards: vec![
                guard(
                    "claim only at or after unlock",
                    GuardOperand::Slot,
                    GuardOp::Ge,
                    vault_field(VAULT_UNLOCK_SLOT_OFFSET),
                ),
                guard(
                    "claim only a non-empty vault",
                    vault_field(VAULT_AMOUNT_OFFSET),
                    GuardOp::Gt,
                    GuardOperand::Const(0),
                ),
            ],
        };

        // initialize — declared so the Critical 5 attack it too. Without
        // this the `Signer<'info>` on its depositor is unprotected by
        // any declaration, and a mutation weakening it survives for want
        // of anyone asking, which reads in the report as a detector
        // blind spot. It creates the vault rather than reading it, hence
        // `creates_indices` and no owner/discriminator expectation on
        // account 0.
        let mut init_data = ix_sighash("initialize").to_vec();
        init_data.extend_from_slice(self.beneficiary.pubkey().as_ref());
        init_data.extend_from_slice(&self.unlock_slot.to_le_bytes());

        let initialize_spec = InstructionSpec {
            program_id: self.program_id,
            name: "initialize".into(),
            accounts: vec![
                AccountMeta::new(self.vault_init_pda, false),
                AccountMeta::new(self.initializer.pubkey(), true),
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            ],
            signer_indices: vec![1],
            optional_signer_indices: vec![],
            expected_owners: vec![None, None, None],
            expected_discriminators: vec![None, None, None],
            expected_pda_seeds: vec![
                Some(vec![
                    b"vault".to_vec(),
                    self.initializer.pubkey().to_bytes().to_vec(),
                ]),
                None,
                None,
            ],
            creates_indices: vec![0],
            swap_alternates: vec![vec![], vec![], vec![]],
            data_sample: init_data,
            signers: vec![Arc::clone(&self.initializer)],
            state_invariants: vec![],
            cu_budget: None,
            cpi_reentrancy: None,
            realloc_check: None,
            bump_seed_check: None,
            guards: vec![],
        };

        // `idl_specs`: the account-validation fields come from
        // idl/escrow_clean.json plus the fixture's state instead; the
        // semantic fields (alternates, state invariants, guards) stay
        // hand-written. On this clean program it must still find nothing.
        #[cfg(feature = "idl_specs")]
        let [initialize_spec, deposit_spec, withdraw_spec, claim_spec] = {
            let hand = |idl: InstructionSpec, h: InstructionSpec| InstructionSpec {
                swap_alternates: h.swap_alternates,
                state_invariants: h.state_invariants,
                guards: h.guards,
                ..idl
            };
            let mut init_args = self.beneficiary.pubkey().to_bytes().to_vec();
            init_args.extend_from_slice(&self.unlock_slot.to_le_bytes());
            let amount = |spec: &InstructionSpec| spec.data_sample[8..].to_vec();
            [
                hand(
                    self.idl_spec("initialize", |b| {
                        b.account("vault", self.vault_init_pda)
                            .signer("depositor", Arc::clone(&self.initializer))
                            .args(&init_args)
                    }),
                    initialize_spec,
                ),
                hand(
                    self.idl_spec("deposit", |b| {
                        b.account("vault", self.vault_pda)
                            .signer("depositor", Arc::clone(&self.depositor))
                            .args(&amount(&deposit_spec))
                    }),
                    deposit_spec,
                ),
                hand(
                    self.idl_spec("withdraw", |b| {
                        b.account("vault", self.vault_pda)
                            .signer("depositor", Arc::clone(&self.depositor))
                            .args(&amount(&withdraw_spec))
                    }),
                    withdraw_spec,
                ),
                hand(
                    self.idl_spec("claim", |b| {
                        b.account("vault", self.vault_pda)
                            .account("depositor", self.depositor.pubkey())
                            .signer("beneficiary", Arc::clone(&self.beneficiary))
                    }),
                    claim_spec,
                ),
            ]
        };

        vec![initialize_spec, deposit_spec, withdraw_spec, claim_spec]
    }
}

#[cfg(feature = "idl_specs")]
const ESCROW_CLEAN_IDL: &str = include_str!("../../../idl/escrow_clean.json");

#[cfg(feature = "idl_specs")]
impl EscrowCleanFixture {
    fn idl_spec(
        &self,
        ix: &str,
        bind: impl FnOnce(solinv_fuzz::SpecBuilder<'_>) -> solinv_fuzz::SpecBuilder<'_>,
    ) -> InstructionSpec {
        let mut cache = self.idl_cache.lock().unwrap();
        if let Some(spec) = cache.get(ix) {
            return spec.clone();
        }
        static IDL: std::sync::OnceLock<solinv_fuzz::Idl> = std::sync::OnceLock::new();
        let idl = IDL.get_or_init(|| solinv_fuzz::Idl::from_json(ESCROW_CLEAN_IDL).unwrap());
        use solinv_fuzz::IdlSpecExt;
        let spec = bind(idl.spec(ix, self.program_id).unwrap())
            .build()
            .unwrap()
            .infer_from_state(|pk| self.ctx.get_account(pk).ok())
            .infer_candidates(|pk| self.ctx.get_account(pk).ok());
        // Once per fixture: findings on these slots are leads.
        for line in spec.candidate_log() {
            eprintln!("{line}");
        }
        let spec = spec.into_spec();
        cache.insert(ix.to_string(), spec.clone());
        spec
    }
}

// ============================================================================
// Invariant tests
// ============================================================================

// Reachability-only run: drives actions, asserts nothing, so sequences
// are not cut short by a violation and state-dependent instructions get
// a chance to succeed. See the note on the same test in the `escrow`
// harness for why killing and reaching cannot share a run.
#[invariant_test]
fn invariant_reachability(_fixture: &mut EscrowCleanFixture) {}

// The campaign's scoring run. On the unmutated program this must find
// nothing; anything it reports is a defect in the program or in the
// declarations above, not a baseline to subtract.
#[invariant_test]
fn invariant_all(fixture: &mut EscrowCleanFixture) {
    solinv_core::invariants::unchecked_math::check(fixture);
    solinv_core::invariants::signer_skip::check(fixture);
    solinv_core::invariants::owner_skip::check(fixture);
    solinv_core::invariants::discriminator_skip::check(fixture);
    solinv_core::invariants::pda_forge::check(fixture);
    solinv_core::invariants::account_swap::check(fixture);
    solinv_core::invariants::precondition_skip::check(fixture);
}
