use crucible_fuzzer::*;
use escrow::ID;
use sha2::{Digest, Sha256};
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use std::sync::Arc;

use solinv_fuzz::{
    BumpSeedCheckConfig, CpiReentrancyConfig, HasContext, HasInstructionSet, InstructionSpec,
    ReallocCheckConfig, StateInvariant, StateInvariantKind,
};

const INITIAL_BALANCE: u64 = 10_000_000_000;
const UNLOCK_DELAY: u64 = 10;

// System Program ID = 32 zero bytes. Hardcoded so harness doesn't import
// anchor_lang::system_program (must stay Anchor-version-agnostic per
// docs/phase2-day14-anchor-version-mismatch.md).
const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);

// Anchor instruction sighash: sha256("global:{ix_name}")[..8].
// Version-independent — same bytes for anchor-lang 0.28, 0.29, 0.32, 1.0.x.
// This is what `instruction::Foo::DISCRIMINATOR` expands to internally,
// computed at harness build time from the ix name string instead.
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

// ----------------------------------------------------------------------------
// raw_call ix constructors — Anchor-version-independent. AccountMeta order +
// (is_writable, is_signer) flags mirror the program's #[derive(Accounts)]
// layout for each ix. Args are borsh-serialized inline.
// ----------------------------------------------------------------------------

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

fn build_unsafe_compute_dos_ix(
    program_id: Pubkey,
    authority: Pubkey,
    iterations: u32,
) -> Instruction {
    let mut data = ix_sighash("unsafe_compute_dos").to_vec();
    data.extend_from_slice(&iterations.to_le_bytes());
    Instruction {
        program_id,
        accounts: vec![AccountMeta::new_readonly(authority, true)],
        data,
    }
}

// Day 60 — planted bump-seed-canonicalization ix builder. Accepts
// vault, depositor, amount (u64), bump (u8). Bug: handler uses
// create_program_address with user-supplied bump without canonical
// check. Detector substitutes alt PDA + patches bump byte at offset
// 16 (after sighash[8] + amount[8]).
fn build_unsafe_withdraw_with_bump_ix(
    program_id: Pubkey,
    vault: Pubkey,
    depositor: Pubkey,
    amount: u64,
    bump: u8,
) -> Instruction {
    let mut data = ix_sighash("unsafe_withdraw_with_bump").to_vec();
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(bump);
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(vault, false),
            AccountMeta::new(depositor, false),
        ],
        data,
    }
}

// Day 59 — planted realloc-race ix builder. Grows the vault account
// by a fuzz-derived delta without lamport top-up. Detector observes
// pre/post (data.len(), lamports) and fires on the resulting rent
// shortfall.
fn build_unsafe_realloc_grow_ix(
    program_id: Pubkey,
    vault: Pubkey,
    depositor: Pubkey,
    delta: u32,
) -> Instruction {
    let mut data = ix_sighash("unsafe_realloc_grow").to_vec();
    data.extend_from_slice(&delta.to_le_bytes());
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(vault, false),
            AccountMeta::new_readonly(depositor, true),
        ],
        data,
    }
}

// Day 58 — planted cpi-reentrancy ix builder. Outer ix accounts:
//   [0] vault (mut)            — same vault the inner CPI will mutate
//   [1] depositor (signer)     — propagates to inner ix's signer
//   [2] escrow_program (ro)    — AccountInfo for the self-CPI invoke target
// The outer handler invokes `unsafe_inner_mutate` on escrow itself,
// producing a CPI cycle (escrow → escrow at depth 2). solinv's
// cpi_reentrancy detector parses TxOutcome.logs to surface it.
fn build_unsafe_self_reentry_ix(
    program_id: Pubkey,
    vault: Pubkey,
    depositor: Pubkey,
) -> Instruction {
    let data = ix_sighash("unsafe_self_reentry").to_vec();
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(vault, false),
            AccountMeta::new_readonly(depositor, true),
            AccountMeta::new_readonly(program_id, false),
        ],
        data,
    }
}

fn build_unsafe_accumulate_yield_ix(
    program_id: Pubkey,
    vault: Pubkey,
    depositor: Pubkey,
    rate_bps: u64,
) -> Instruction {
    let mut data = ix_sighash("unsafe_accumulate_yield").to_vec();
    data.extend_from_slice(&rate_bps.to_le_bytes());
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(vault, false),
            AccountMeta::new_readonly(depositor, true),
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
    let data = ix_sighash("claim").to_vec();
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(vault, false),
            AccountMeta::new_readonly(depositor, false),
            AccountMeta::new(beneficiary, true),
        ],
        data,
    }
}

#[derive(Clone)]
struct EscrowFixture {
    pub ctx: TestContext,
    program_id: Pubkey,
    depositor: Arc<Keypair>,        // primary trader / used by all action_*
    depositor_b: Arc<Keypair>,      // Day 12 — alternate context for account-swap detection
    beneficiary: Arc<Keypair>,
    fee_payer: Arc<Keypair>,
    vault_pda: Pubkey,              // primary vault (depositor's)
    vault_b_pda: Pubkey,            // Day 12 — alternate-context vault (depositor_b's)
    unlock_slot: u64,
    successful_withdraw_slots: Vec<u64>,
}

#[fuzz_fixture]
impl EscrowFixture {
    pub fn setup() -> Self {
        let mut ctx = TestContext::new();
        let program_id = Pubkey::new_from_array(ID.to_bytes());
        ctx.add_program(&program_id, "../../target/deploy/escrow.so")
            .unwrap();

        let depositor = Arc::new(Keypair::new());
        let depositor_b = Arc::new(Keypair::new());     // Day 12 — alternate trader
        let beneficiary = Arc::new(Keypair::new());
        let fee_payer = Arc::new(Keypair::new());
        for kp in [&depositor, &depositor_b, &beneficiary, &fee_payer] {
            ctx.create_account()
                .pubkey(kp.pubkey())
                .lamports(INITIAL_BALANCE)
                .owner(SYSTEM_PROGRAM_ID)
                .create()
                .unwrap();
        }

        let (vault_pda, _) = Pubkey::find_program_address(
            &[b"vault", depositor.pubkey().as_ref()],
            &program_id,
        );
        let (vault_b_pda, _) = Pubkey::find_program_address(
            &[b"vault", depositor_b.pubkey().as_ref()],
            &program_id,
        );
        let unlock_slot = ctx.slot() + UNLOCK_DELAY;

        // Initialize primary vault (depositor's) — raw_call.
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

        // Day 12 — alternate-context vault for account_swap detection.
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

        Self {
            ctx,
            program_id,
            depositor,
            depositor_b,
            beneficiary,
            fee_payer,
            vault_pda,
            vault_b_pda,
            unlock_slot,
            successful_withdraw_slots: Vec::new(),
        }
    }

    pub fn action_deposit(&mut self, #[range(1..1_000_000)] amount: u64) -> bool {
        self.ctx
            .raw_call(build_deposit_ix(
                self.program_id,
                self.vault_pda,
                self.depositor.pubkey(),
                amount,
            ))
            .signers(&[&*self.depositor])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_withdraw(&mut self, #[range(1..1_000_000)] amount: u64) -> bool {
        let pre_slot = self.ctx.slot();
        let success = self
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
        if success {
            self.successful_withdraw_slots.push(pre_slot);
        }
        success
    }

    pub fn action_claim(&mut self) -> bool {
        self.ctx
            .raw_call(build_claim_ix(
                self.program_id,
                self.vault_pda,
                self.depositor.pubkey(),
                self.beneficiary.pubkey(),
            ))
            .signers(&[&*self.beneficiary])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    pub fn action_advance_slots(&mut self, #[range(0..15)] slots: u64) -> bool {
        let new_slot = self.ctx.slot() + slots;
        self.ctx.warp_to_slot(new_slot);
        true
    }

    // Day 37 — planted cu-dos action. `iterations` ranges across a
    // bounded u32 window so Crucible's mutator can find values that
    // succeed (within 200K CU ceiling) but exceed the declared
    // cu_budget cap. Upper bound 50_000 caps consumed CU well below
    // the 200K runtime ceiling at ~5 CU/iter, so the ix succeeds
    // throughout the corpus and detection lands on the Success branch.
    pub fn action_unsafe_compute_dos(
        &mut self,
        #[range(0..50_000)] iterations: u32,
    ) -> bool {
        self.ctx
            .raw_call(build_unsafe_compute_dos_ix(
                self.program_id,
                self.depositor.pubkey(),
                iterations,
            ))
            .signers(&[&*self.depositor])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    // Day 60 — planted bump-seed-canonicalization action. Calls the
    // ix with the CANONICAL bump (legitimate-path) so the corpus
    // exercises the success branch. The detector's re-execution
    // patches the bump byte with the alt bump and substitutes the
    // alt PDA — that's where the violation fires.
    pub fn action_unsafe_withdraw_with_bump(
        &mut self,
        #[range(1..100)] amount: u64,
    ) -> bool {
        let (_, canonical_bump) = Pubkey::find_program_address(
            &[b"vault", self.depositor.pubkey().as_ref()],
            &self.program_id,
        );
        self.ctx
            .raw_call(build_unsafe_withdraw_with_bump_ix(
                self.program_id,
                self.vault_pda,
                self.depositor.pubkey(),
                amount,
                canonical_bump,
            ))
            .signers(&[&*self.depositor])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    // Day 59 — planted realloc-race action. `delta` ranges across a
    // bounded u32 window so Crucible's mutator finds values that
    // succeed (within the 10_240-byte per-ix grow cap) but break the
    // rent invariant. Upper bound 5_000 caps the grow at 5K bytes,
    // well below the runtime cap, ensuring the ix succeeds throughout
    // the corpus and detection lands on the Success branch.
    pub fn action_unsafe_realloc_grow(
        &mut self,
        #[range(1..5_000)] delta: u32,
    ) -> bool {
        self.ctx
            .raw_call(build_unsafe_realloc_grow_ix(
                self.program_id,
                self.vault_pda,
                self.depositor.pubkey(),
                delta,
            ))
            .signers(&[&*self.depositor])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    // Day 58 — planted cpi-reentrancy action. No fuzz-derived arg; the
    // bug is structural (self-CPI cycle) and fires on every successful
    // invocation. Crucible mutator still has Coverage value (account
    // address variation through signer/PDA paths) but the action body
    // is single-shape.
    pub fn action_unsafe_self_reentry(&mut self) -> bool {
        self.ctx
            .raw_call(build_unsafe_self_reentry_ix(
                self.program_id,
                self.vault_pda,
                self.depositor.pubkey(),
            ))
            .signers(&[&*self.depositor])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }

    // Day 33 — planted unchecked-math action. `rate_bps` is fuzzed across
    // the full u64 range so Crucible's mutator finds wrap-triggering values.
    pub fn action_unsafe_accumulate_yield(
        &mut self,
        #[range(0..u64::MAX)] rate_bps: u64,
    ) -> bool {
        self.ctx
            .raw_call(build_unsafe_accumulate_yield_ix(
                self.program_id,
                self.vault_pda,
                self.depositor.pubkey(),
                rate_bps,
            ))
            .signers(&[&*self.depositor])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }
}

// ============================================================================
// solinv integration — implements HasContext + HasInstructionSet so the
// 5 Critical invariant functions can introspect EscrowFixture's instruction
// surface and run their detection attacks.
// ============================================================================

impl HasContext for EscrowFixture {
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

// Anchor discriminator for the Vault account — computed via account_disc
// instead of pulling in anchor_lang::Discriminator trait.
fn vault_discriminator() -> [u8; 8] {
    account_disc("Vault")
}

impl HasInstructionSet for EscrowFixture {
    fn instructions(&self) -> Vec<InstructionSpec> {
        // Encode the `unsafe_withdraw` ix for solinv to attack.
        // The ix data is the 8-byte sighash of "global:unsafe_withdraw" +
        // borsh-serialized amount.
        let mut data = unsafe_withdraw_sighash().to_vec();
        data.extend_from_slice(&100_000u64.to_le_bytes());

        let unsafe_withdraw_spec = InstructionSpec {
            program_id: self.program_id,
            name: "unsafe_withdraw".into(),
            accounts: vec![
                AccountMeta::new(self.vault_pda, false),     // vault
                AccountMeta::new(self.depositor.pubkey(), true), // depositor (signer)
            ],
            // depositor at idx 1 SHOULD be a signer (planted bug: it isn't)
            signer_indices: vec![1],
            optional_signer_indices: vec![],
            // vault at idx 0 SHOULD be owned by escrow program
            expected_owners: vec![Some(self.program_id), None],
            // vault at idx 0 SHOULD have Vault's discriminator
            expected_discriminators: vec![Some(vault_discriminator()), None],
            // vault at idx 0 SHOULD be the PDA at [b"vault", depositor]
            expected_pda_seeds: vec![
                Some(vec![b"vault".to_vec(), self.depositor.pubkey().to_bytes().to_vec()]),
                None,
            ],
            creates_indices: vec![],
            // Day 12 — alternate context provided for account-swap detection.
            // vault at idx 0: substitute with vault_b_pda (depositor_b's vault) —
            // a real PDA owned by escrow program with correct discriminator,
            // but bound to a different depositor. Without context-binding
            // check, unsafe_withdraw drains vault_b lamports to depositor (A).
            swap_alternates: vec![
                vec![self.vault_b_pda],   // vault: alternate is depositor_b's vault
                vec![],                    // depositor: no swap (caller identity)
            ],
            data_sample: data,
            signers: vec![Arc::clone(&self.depositor)],
            state_invariants: vec![],   // unchecked-math declarations live on accumulate_yield (Day 33)
            cu_budget: None,            // cu-dos cap declared on unsafe_compute_dos (Day 37)
            cpi_reentrancy: None,       // cpi-reentrancy planted-bug surface is unsafe_callback_dispatch (Day 58)
            realloc_check: None,        // realloc-race planted-bug surface is unsafe_realloc_grow (Day 59)
            bump_seed_check: None,      // bump-seed-canonicalization planted-bug surface is unsafe_withdraw_with_bump (Day 60)
        };

        // Day 13 — additional ix for owner-skip unmask. unsafe_set_amount_from_source
        // reads from UncheckedAccount source (no owner check) and writes into
        // target.amount. No lamport debit on source = no runtime debit-block.
        // No instruction args; sighash alone
        let read_admin_data = read_admin_sighash().to_vec();

        let canonical_source = self.vault_b_pda;   // legit escrow-owned source

        let read_admin_spec = InstructionSpec {
            program_id: self.program_id,
            name: "unsafe_set_amount_from_source".into(),
            accounts: vec![
                AccountMeta::new_readonly(canonical_source, false),  // source (UncheckedAccount)
                AccountMeta::new(self.vault_pda, false),             // target (Account<Vault>)
            ],
            signer_indices: vec![],
            optional_signer_indices: vec![],
            // source at idx 0 SHOULD be escrow-program-owned (bug: no check)
            // target at idx 1 IS Account<Vault> = Anchor auto-checks owner
            expected_owners: vec![Some(self.program_id), Some(self.program_id)],
            expected_discriminators: vec![Some(vault_discriminator()), Some(vault_discriminator())],
            // No PDA derivation seed declared for either (target IS a PDA but
            // we leave it as None to focus on owner-skip detection — Anchor's
            // Account<Vault> auto-handles target's checks)
            expected_pda_seeds: vec![None, None],
            creates_indices: vec![],
            swap_alternates: vec![vec![], vec![]],
            data_sample: read_admin_data,
            signers: vec![],   // no business signers; fee-payer auto-added by invariant
            state_invariants: vec![],
            cu_budget: None,
            cpi_reentrancy: None,
            realloc_check: None,
            bump_seed_check: None,            };

        // Day 33 — accumulate_yield ix for unchecked-math detection.
        // data_sample carries rate_bps = u64::MAX so solinv's re-execution
        // through unchecked_math::check reliably triggers the wrap path
        // for any pre.amount >= 1.
        let mut accumulate_yield_data = ix_sighash("unsafe_accumulate_yield").to_vec();
        accumulate_yield_data.extend_from_slice(&u64::MAX.to_le_bytes());

        // Field offset of `Vault::amount` in account.data:
        // 8 (Anchor disc) + 32 (depositor) + 32 (beneficiary) + 8 (unlock_slot) = 80.
        const VAULT_AMOUNT_OFFSET: usize = 8 + 32 + 32 + 8;

        let accumulate_yield_spec = InstructionSpec {
            program_id: self.program_id,
            name: "unsafe_accumulate_yield".into(),
            accounts: vec![
                AccountMeta::new(self.vault_pda, false),                  // vault
                AccountMeta::new_readonly(self.depositor.pubkey(), true), // depositor (signer)
            ],
            signer_indices: vec![1],
            optional_signer_indices: vec![],
            expected_owners: vec![Some(self.program_id), None],
            expected_discriminators: vec![Some(vault_discriminator()), None],
            expected_pda_seeds: vec![
                Some(vec![b"vault".to_vec(), self.depositor.pubkey().to_bytes().to_vec()]),
                None,
            ],
            creates_indices: vec![],
            swap_alternates: vec![vec![], vec![]],
            data_sample: accumulate_yield_data,
            signers: vec![Arc::clone(&self.depositor)],
            // 10 trillion cap — far above any legitimate vault state in the
            // fuzz harness (which deposits in the millions). Wrap from
            // wrapping_mul + wrapping_add overshoots this cap for any
            // pre.amount >= 1 with rate_bps = u64::MAX.
            state_invariants: vec![StateInvariant {
                name: "vault_amount_bounded".to_string(),
                kind: StateInvariantKind::Bounded {
                    field_offset: VAULT_AMOUNT_OFFSET,
                    field_size: 8,
                    min: 0,
                    max: 10_000_000_000_000,
                },
                accounts: vec![0], // vault
            }],
            cu_budget: None,    // cu-dos cap declared on unsafe_compute_dos (Day 37)
            cpi_reentrancy: None,
            realloc_check: None,
            bump_seed_check: None,
            };

        // Day 37 — compute_dos ix for cu-dos detection. data_sample
        // pins iterations = 5_000 so solinv's re-execution through
        // cu_dos::check reliably consumes ~25-50K CU (above the
        // 5_000 cap, well below the 200K runtime ceiling).
        let mut compute_dos_data = ix_sighash("unsafe_compute_dos").to_vec();
        compute_dos_data.extend_from_slice(&5_000u32.to_le_bytes());

        let compute_dos_spec = InstructionSpec {
            program_id: self.program_id,
            name: "unsafe_compute_dos".into(),
            accounts: vec![AccountMeta::new_readonly(self.depositor.pubkey(), true)],
            signer_indices: vec![0],
            optional_signer_indices: vec![],
            expected_owners: vec![None],
            expected_discriminators: vec![None],
            expected_pda_seeds: vec![None],
            creates_indices: vec![],
            swap_alternates: vec![vec![]],
            data_sample: compute_dos_data,
            signers: vec![Arc::clone(&self.depositor)],
            state_invariants: vec![],
            cu_budget: Some(5_000),
            cpi_reentrancy: None,
            realloc_check: None,
            bump_seed_check: None,            };

        // Day 58 — self_reentry ix for cpi-reentrancy detection. No
        // data args (the bug is structural). InstructionSpec exposes
        // the 3-account shape (vault, depositor, escrow_program) that
        // the outer handler needs for the inner CPI to escrow itself.
        // Setting `cpi_reentrancy: Some(CpiReentrancyConfig::default())`
        // (empty allowlist) tells solinv's detector to fire on any
        // observed CPI cycle through this program.
        let self_reentry_spec = InstructionSpec {
            program_id: self.program_id,
            name: "unsafe_self_reentry".into(),
            accounts: vec![
                AccountMeta::new(self.vault_pda, false),
                AccountMeta::new_readonly(self.depositor.pubkey(), true),
                AccountMeta::new_readonly(self.program_id, false),
            ],
            signer_indices: vec![1],
            optional_signer_indices: vec![],
            expected_owners: vec![Some(self.program_id), None, None],
            expected_discriminators: vec![Some(vault_discriminator()), None, None],
            expected_pda_seeds: vec![
                Some(vec![b"vault".to_vec(), self.depositor.pubkey().to_bytes().to_vec()]),
                None,
                None,
            ],
            creates_indices: vec![],
            swap_alternates: vec![vec![], vec![], vec![]],
            data_sample: ix_sighash("unsafe_self_reentry").to_vec(),
            signers: vec![Arc::clone(&self.depositor)],
            state_invariants: vec![],
            cu_budget: None,
            cpi_reentrancy: Some(CpiReentrancyConfig::default()),
            realloc_check: None,
            bump_seed_check: None,        };

        // Day 59 — realloc_grow ix for realloc-race detection.
        // data_sample pins delta = 200 so solinv's re-execution
        // through realloc_race::check reliably grows the vault from
        // 88 → 288 bytes (without the lamport top-up the bug
        // requires). Detector compares post.lamports against
        // rent_for(288) = 2_895_360 and fires on the shortfall
        // (~1.4M lamports).
        let mut realloc_grow_data = ix_sighash("unsafe_realloc_grow").to_vec();
        realloc_grow_data.extend_from_slice(&200u32.to_le_bytes());

        let realloc_grow_spec = InstructionSpec {
            program_id: self.program_id,
            name: "unsafe_realloc_grow".into(),
            accounts: vec![
                AccountMeta::new(self.vault_pda, false),
                AccountMeta::new_readonly(self.depositor.pubkey(), true),
            ],
            signer_indices: vec![1],
            optional_signer_indices: vec![],
            expected_owners: vec![Some(self.program_id), None],
            expected_discriminators: vec![Some(vault_discriminator()), None],
            expected_pda_seeds: vec![
                Some(vec![b"vault".to_vec(), self.depositor.pubkey().to_bytes().to_vec()]),
                None,
            ],
            creates_indices: vec![],
            swap_alternates: vec![vec![], vec![]],
            data_sample: realloc_grow_data,
            signers: vec![Arc::clone(&self.depositor)],
            state_invariants: vec![],
            cu_budget: None,
            cpi_reentrancy: None,
            realloc_check: Some(ReallocCheckConfig::default()),
            bump_seed_check: None,        };

        // Day 60 — withdraw_with_bump spec for bump-seed-canonicalization
        // detection. data_sample carries amount=1 + the CANONICAL bump
        // so the un-patched ix succeeds (legitimate path). Detector
        // re-derives the alt bump + alt PDA, substitutes both,
        // re-executes. If the program lacks the canonical-bump check,
        // the alt-PDA ix succeeds → violation fires.
        let (_, vault_canonical_bump) = Pubkey::find_program_address(
            &[b"vault", self.depositor.pubkey().as_ref()],
            &self.program_id,
        );
        let mut withdraw_with_bump_data = ix_sighash("unsafe_withdraw_with_bump").to_vec();
        withdraw_with_bump_data.extend_from_slice(&1u64.to_le_bytes());
        withdraw_with_bump_data.push(vault_canonical_bump);

        let withdraw_with_bump_spec = InstructionSpec {
            program_id: self.program_id,
            name: "unsafe_withdraw_with_bump".into(),
            accounts: vec![
                AccountMeta::new(self.vault_pda, false),
                AccountMeta::new(self.depositor.pubkey(), false),
            ],
            signer_indices: vec![],
            optional_signer_indices: vec![],
            expected_owners: vec![Some(self.program_id), None],
            expected_discriminators: vec![Some(vault_discriminator()), None],
            expected_pda_seeds: vec![
                // vault PDA seed prefix (no bump — that lives in data_sample byte 16)
                Some(vec![
                    b"vault".to_vec(),
                    self.depositor.pubkey().to_bytes().to_vec(),
                ]),
                None,
            ],
            creates_indices: vec![],
            swap_alternates: vec![vec![], vec![]],
            data_sample: withdraw_with_bump_data,
            signers: vec![Arc::clone(&self.depositor)],
            state_invariants: vec![],
            cu_budget: None,
            cpi_reentrancy: None,
            realloc_check: None,
            // bump_data_offset = 16 (after 8 sighash + 8 amount u64)
            bump_seed_check: Some(BumpSeedCheckConfig {
                bump_data_offset: Some(16),
            }),
        };

        vec![
            unsafe_withdraw_spec,
            read_admin_spec,
            accumulate_yield_spec,
            compute_dos_spec,
            self_reentry_spec,
            realloc_grow_spec,
            withdraw_with_bump_spec,
        ]
    }
}

// Sighashes for the two planted-bug ix — computed via ix_sighash instead
// of anchor_lang::Discriminator. Both ix names match the program's
// `pub fn` snake_case identifiers.
fn read_admin_sighash() -> [u8; 8] {
    ix_sighash("unsafe_set_amount_from_source")
}

fn unsafe_withdraw_sighash() -> [u8; 8] {
    ix_sighash("unsafe_withdraw")
}

// ============================================================================
// Invariant tests
// ============================================================================

// Time-guard invariant: every successful withdraw must have happened strictly
// before unlock. The seeded bug in `withdraw` (uses `<=`) should be found.
#[invariant_test]
fn invariant_escrow(fixture: &mut EscrowFixture) {
    for &s in &fixture.successful_withdraw_slots {
        fuzz_assert_lt!(
            s,
            fixture.unlock_slot,
            "withdraw at slot {} should have been rejected (unlock_slot = {})",
            s,
            fixture.unlock_slot
        );
    }
}

// solinv acceptance test: 5 Critical invariants chained against the
// instruction set. First violation in each fuzz iteration is reported
// (Day 3 Correction #3: first-violation-wins TLS). The first invariant
// to detect masks the others within the same iteration.
#[invariant_test]
fn invariant_solinv_acceptance(fixture: &mut EscrowFixture) {
    solinv_core::invariants::signer_skip::check(fixture);
    solinv_core::invariants::owner_skip::check(fixture);
    solinv_core::invariants::discriminator_skip::check(fixture);
    solinv_core::invariants::pda_forge::check(fixture);
    solinv_core::invariants::account_swap::check(fixture);
}

// Day 12 — isolated per-invariant test variants so the 5 Critical
// invariants are each individually observable (vs first-violation-wins
// masking in invariant_solinv_acceptance). Each variant runs only ONE
// invariant; selected via cargo feature flag.

#[invariant_test]
fn invariant_signer_skip_only(fixture: &mut EscrowFixture) {
    solinv_core::invariants::signer_skip::check(fixture);
}

#[invariant_test]
fn invariant_owner_skip_only(fixture: &mut EscrowFixture) {
    solinv_core::invariants::owner_skip::check(fixture);
}

#[invariant_test]
fn invariant_discriminator_skip_only(fixture: &mut EscrowFixture) {
    solinv_core::invariants::discriminator_skip::check(fixture);
}

#[invariant_test]
fn invariant_pda_forge_only(fixture: &mut EscrowFixture) {
    solinv_core::invariants::pda_forge::check(fixture);
}

#[invariant_test]
fn invariant_account_swap_only(fixture: &mut EscrowFixture) {
    solinv_core::invariants::account_swap::check(fixture);
}

// Day 33 — first High-tier variant. Gate 1 of the unchecked-math kill
// criterion (docs/invariants/unchecked-math.md §9): must detect within
// 30s of `crucible run escrow invariant_unchecked_math_only --release`.
#[invariant_test]
fn invariant_unchecked_math_only(fixture: &mut EscrowFixture) {
    solinv_core::invariants::run_with_transition_metrics("unchecked-math", || {
        solinv_core::invariants::unchecked_math::check(fixture);
    });
}

// Day 37 — second High-tier variant. Gate 1 of the cu-dos kill
// criterion (docs/invariants/cu-dos.md §9): must detect within 30s.
#[invariant_test]
fn invariant_cu_dos_only(fixture: &mut EscrowFixture) {
    solinv_core::invariants::run_with_transition_metrics("cu-dos", || {
        solinv_core::invariants::cu_dos::check(fixture);
    });
}

// Day 58 — cpi-reentrancy Gate 1 variant. Per
// docs/invariants/cpi-reentrancy.md §9: must detect the self-CPI
// cycle (escrow → escrow via unsafe_self_reentry → unsafe_inner_mutate)
// within 30s of running the planted-bug action.
#[invariant_test]
fn invariant_cpi_reentrancy_only(fixture: &mut EscrowFixture) {
    solinv_core::invariants::run_with_transition_metrics("cpi-reentrancy", || {
        solinv_core::invariants::cpi_reentrancy::check(fixture);
    });
}

// Day 59 — realloc-race Gate 1 variant. Per
// docs/invariants/realloc-race.md §9: must detect the rent-shortfall
// from unsafe_realloc_grow (vault grown 88 → 288 without lamport
// top-up) within 30s.
#[invariant_test]
fn invariant_realloc_race_only(fixture: &mut EscrowFixture) {
    solinv_core::invariants::run_with_transition_metrics("realloc-race", || {
        solinv_core::invariants::realloc_race::check(fixture);
    });
}

// Day 60 — bump-seed-canonicalization Gate 1 variant. Per
// docs/invariants/bump-seed-canonicalization.md §9: must detect the
// alt-PDA substitution (vault re-derived with non-canonical bump,
// program accepts) within 30s.
#[invariant_test]
fn invariant_bump_seed_canonicalization_only(fixture: &mut EscrowFixture) {
    solinv_core::invariants::run_with_transition_metrics(
        "bump-seed-canonicalization",
        || {
            solinv_core::invariants::bump_seed_canonicalization::check(fixture);
        },
    );
}
