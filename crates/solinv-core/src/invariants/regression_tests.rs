use std::sync::Arc;

use crucible_test_context::{clear_violation_tracking, has_violation, take_violation, TestContext};
use solana_account::Account;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solinv_fuzz::{
    HasContext, HasInstructionSet, InstructionSpec, MonotonicDir, StateInvariant,
    StateInvariantKind,
};

use super::{
    account_swap, cu_dos, discriminator_skip, owner_skip, pda_forge, signer_skip, unchecked_math,
};

const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);

struct TestFixture {
    pub ctx: TestContext,
    fee_payer: Arc<Keypair>,
    ixs: Vec<InstructionSpec>,
}

impl HasContext for TestFixture {
    fn ctx(&self) -> &TestContext {
        &self.ctx
    }
    fn ctx_mut(&mut self) -> &mut TestContext {
        &mut self.ctx
    }
    fn program_ids(&self) -> Vec<Pubkey> {
        vec![SYSTEM_PROGRAM_ID]
    }
    fn fee_payer(&self) -> Arc<Keypair> {
        self.fee_payer.clone()
    }
}

impl HasInstructionSet for TestFixture {
    fn instructions(&self) -> Vec<InstructionSpec> {
        self.ixs.clone()
    }
}

fn mk_account(lamports: u64, owner: Pubkey, data: Vec<u8>) -> Account {
    Account {
        lamports,
        data,
        owner,
        executable: false,
        rent_epoch: 0,
    }
}

fn base_fixture(
    spec: InstructionSpec,
    extras: &[(Pubkey, Account)],
    fee_lamports: u64,
    fee_payer: Arc<Keypair>,
) -> TestFixture {
    let mut ctx = TestContext::new();
    let _ = ctx.write_account(
        &fee_payer.pubkey(),
        mk_account(fee_lamports, SYSTEM_PROGRAM_ID, Vec::new()),
    );
    for (pk, acct) in extras {
        let _ = ctx.write_account(pk, acct.clone());
    }
    TestFixture {
        ctx,
        fee_payer,
        ixs: vec![spec],
    }
}

fn base_transfer_spec(to: Pubkey, signers: Vec<Arc<Keypair>>) -> InstructionSpec {
    let ix = solana_system_interface::instruction::transfer(
        &signers[0].pubkey(),
        &to,
        1,
    );
    InstructionSpec {
        program_id: ix.program_id,
        name: "transfer".to_string(),
        accounts: ix.accounts,
        signer_indices: vec![],
        optional_signer_indices: vec![],
        expected_owners: vec![None, None],
        expected_discriminators: vec![None, None],
        expected_pda_seeds: vec![None, None],
        creates_indices: vec![],
        swap_alternates: vec![vec![], vec![]],
        data_sample: ix.data,
        signers,
        state_invariants: vec![],
        cu_budget: None,
        cpi_reentrancy: None,
        realloc_check: None,
        bump_seed_check: None,
    }
}

fn assert_detected(prefix: &str) {
    let msg = take_violation();
    assert!(msg.is_some(), "expected violation, got none");
    let msg = msg.unwrap_or_default();
    assert!(
        msg.contains(prefix),
        "expected violation containing {prefix}, got: {msg}"
    );
}

fn assert_not_detected() {
    assert!(!has_violation(), "unexpected violation: {:?}", take_violation());
}

#[test]
fn signer_skip_detect_pair() {
    clear_violation_tracking();
    let recipient = Arc::new(Keypair::new());
    let fee_payer = Arc::new(Keypair::new());
    let mut spec = base_transfer_spec(recipient.pubkey(), vec![fee_payer.clone(), recipient.clone()]);
    spec.signer_indices = vec![1];
    spec.accounts[1].is_signer = true;
    let recipient_acct = mk_account(0, SYSTEM_PROGRAM_ID, vec![0; 16]);
    let mut fixture = base_fixture(spec, &[(recipient.pubkey(), recipient_acct)], 1_000_000, fee_payer);
    signer_skip::check(&mut fixture);
    assert_detected("[signer-skip:");

    clear_violation_tracking();
    let recipient2 = Arc::new(Keypair::new());
    let fee_payer2 = Arc::new(Keypair::new());
    let spec2 = base_transfer_spec(recipient2.pubkey(), vec![fee_payer2.clone()]);
    let recipient_acct2 = mk_account(0, SYSTEM_PROGRAM_ID, vec![0; 16]);
    let mut fixture2 =
        base_fixture(spec2, &[(recipient2.pubkey(), recipient_acct2)], 1_000_000, fee_payer2);
    signer_skip::check(&mut fixture2);
    assert_not_detected();
}

#[test]
#[ignore = "Needs a purposely vulnerable fixture where swapped accounts still drive state changes"]
fn owner_skip_detect_pair() {
    clear_violation_tracking();
    let recipient = Keypair::new();
    let fee_payer = Arc::new(Keypair::new());
    let mut spec = base_transfer_spec(recipient.pubkey(), vec![fee_payer.clone()]);
    spec.expected_owners = vec![None, Some(SYSTEM_PROGRAM_ID)];
    let mut fixture = base_fixture(
        spec,
        &[(recipient.pubkey(), mk_account(0, SYSTEM_PROGRAM_ID, Vec::new()))],
        1_000_000,
        fee_payer,
    );
    owner_skip::check(&mut fixture);
    assert_detected("[owner-skip:");

    clear_violation_tracking();
    let recipient2 = Keypair::new();
    let fee_payer2 = Arc::new(Keypair::new());
    let spec2 = base_transfer_spec(recipient2.pubkey(), vec![fee_payer2.clone()]);
    let mut fixture2 = base_fixture(
        spec2,
        &[(recipient2.pubkey(), mk_account(0, SYSTEM_PROGRAM_ID, Vec::new()))],
        1_000_000,
        fee_payer2,
    );
    owner_skip::check(&mut fixture2);
    assert_not_detected();
}

#[test]
#[ignore = "Needs a purposely vulnerable fixture where discriminator-corrupted account is still consumed"]
fn discriminator_skip_detect_pair() {
    clear_violation_tracking();
    let recipient = Keypair::new();
    let fee_payer = Arc::new(Keypair::new());
    let mut spec = base_transfer_spec(recipient.pubkey(), vec![fee_payer.clone()]);
    spec.expected_discriminators = vec![None, Some([1, 2, 3, 4, 5, 6, 7, 8])];
    let mut data = vec![0u8; 16];
    data[0..8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let mut fixture = base_fixture(
        spec,
        &[(recipient.pubkey(), mk_account(0, SYSTEM_PROGRAM_ID, data))],
        1_000_000,
        fee_payer,
    );
    discriminator_skip::check(&mut fixture);
    assert_detected("[discriminator-skip:");

    clear_violation_tracking();
    let recipient2 = Keypair::new();
    let fee_payer2 = Arc::new(Keypair::new());
    let spec2 = base_transfer_spec(recipient2.pubkey(), vec![fee_payer2.clone()]);
    let mut fixture2 = base_fixture(
        spec2,
        &[(recipient2.pubkey(), mk_account(0, SYSTEM_PROGRAM_ID, vec![0; 16]))],
        1_000_000,
        fee_payer2,
    );
    discriminator_skip::check(&mut fixture2);
    assert_not_detected();
}

#[test]
#[ignore = "Needs a purposely vulnerable fixture where forged PDA still mutates canonical state"]
fn pda_forge_detect_pair() {
    clear_violation_tracking();
    let fee_payer = Arc::new(Keypair::new());
    let seed = b"pda-forge-test".to_vec();
    let seed_slices = [seed.as_slice()];
    let (pda, _bump) = Pubkey::find_program_address(&seed_slices, &SYSTEM_PROGRAM_ID);
    let mut spec = base_transfer_spec(pda, vec![fee_payer.clone()]);
    spec.expected_pda_seeds = vec![None, Some(vec![seed.clone()])];
    let mut fixture = base_fixture(
        spec,
        &[(pda, mk_account(0, SYSTEM_PROGRAM_ID, Vec::new()))],
        1_000_000,
        fee_payer,
    );
    pda_forge::check(&mut fixture);
    assert_detected("[pda-forge:");

    clear_violation_tracking();
    let fee_payer2 = Arc::new(Keypair::new());
    let seed2 = b"pda-forge-test-2".to_vec();
    let seed_slices2 = [seed2.as_slice()];
    let (pda2, _bump2) = Pubkey::find_program_address(&seed_slices2, &SYSTEM_PROGRAM_ID);
    let mut spec2 = base_transfer_spec(pda2, vec![fee_payer2.clone()]);
    spec2.expected_pda_seeds = vec![None, Some(vec![seed2])];
    spec2.creates_indices = vec![1];
    let mut fixture2 = base_fixture(
        spec2,
        &[(pda2, mk_account(0, SYSTEM_PROGRAM_ID, Vec::new()))],
        1_000_000,
        fee_payer2,
    );
    pda_forge::check(&mut fixture2);
    assert_not_detected();
}

#[test]
#[ignore = "Needs a purposely vulnerable fixture where alternate account swap mutates canonical state"]
fn account_swap_detect_pair() {
    clear_violation_tracking();
    let recipient = Keypair::new();
    let alternate = Keypair::new();
    let fee_payer = Arc::new(Keypair::new());
    let mut spec = base_transfer_spec(recipient.pubkey(), vec![fee_payer.clone()]);
    spec.swap_alternates = vec![vec![], vec![alternate.pubkey()]];
    let mut fixture = base_fixture(
        spec,
        &[
            (recipient.pubkey(), mk_account(0, SYSTEM_PROGRAM_ID, Vec::new())),
            (alternate.pubkey(), mk_account(0, SYSTEM_PROGRAM_ID, Vec::new())),
        ],
        1_000_000,
        fee_payer,
    );
    account_swap::check(&mut fixture);
    assert_detected("[account-swap:");

    clear_violation_tracking();
    let recipient2 = Keypair::new();
    let fee_payer2 = Arc::new(Keypair::new());
    let spec2 = base_transfer_spec(recipient2.pubkey(), vec![fee_payer2.clone()]);
    let mut fixture2 = base_fixture(
        spec2,
        &[(recipient2.pubkey(), mk_account(0, SYSTEM_PROGRAM_ID, Vec::new()))],
        1_000_000,
        fee_payer2,
    );
    account_swap::check(&mut fixture2);
    assert_not_detected();
}

#[test]
fn owner_skip_non_detect() {
    clear_violation_tracking();
    let recipient = Keypair::new();
    let fee_payer = Arc::new(Keypair::new());
    let spec = base_transfer_spec(recipient.pubkey(), vec![fee_payer.clone()]);
    let mut fixture = base_fixture(
        spec,
        &[(recipient.pubkey(), mk_account(0, SYSTEM_PROGRAM_ID, Vec::new()))],
        1_000_000,
        fee_payer,
    );
    owner_skip::check(&mut fixture);
    assert_not_detected();
}

#[test]
fn discriminator_skip_non_detect() {
    clear_violation_tracking();
    let recipient = Keypair::new();
    let fee_payer = Arc::new(Keypair::new());
    let spec = base_transfer_spec(recipient.pubkey(), vec![fee_payer.clone()]);
    let mut fixture = base_fixture(
        spec,
        &[(recipient.pubkey(), mk_account(0, SYSTEM_PROGRAM_ID, vec![0; 16]))],
        1_000_000,
        fee_payer,
    );
    discriminator_skip::check(&mut fixture);
    assert_not_detected();
}

#[test]
fn pda_forge_non_detect() {
    clear_violation_tracking();
    let fee_payer = Arc::new(Keypair::new());
    let seed = b"pda-forge-nondetect".to_vec();
    let seed_slices = [seed.as_slice()];
    let (pda, _bump) = Pubkey::find_program_address(&seed_slices, &SYSTEM_PROGRAM_ID);
    let mut spec = base_transfer_spec(pda, vec![fee_payer.clone()]);
    spec.expected_pda_seeds = vec![None, Some(vec![seed])];
    spec.creates_indices = vec![1];
    let mut fixture = base_fixture(
        spec,
        &[(pda, mk_account(0, SYSTEM_PROGRAM_ID, Vec::new()))],
        1_000_000,
        fee_payer,
    );
    pda_forge::check(&mut fixture);
    assert_not_detected();
}

#[test]
fn account_swap_non_detect() {
    clear_violation_tracking();
    let recipient = Keypair::new();
    let fee_payer = Arc::new(Keypair::new());
    let spec = base_transfer_spec(recipient.pubkey(), vec![fee_payer.clone()]);
    let mut fixture = base_fixture(
        spec,
        &[(recipient.pubkey(), mk_account(0, SYSTEM_PROGRAM_ID, Vec::new()))],
        1_000_000,
        fee_payer,
    );
    account_swap::check(&mut fixture);
    assert_not_detected();
}

// ---------------------------------------------------------------------
// unchecked-math (High tier, Day 31+)
// ---------------------------------------------------------------------
// Non-detect baselines only: system_program-owned accounts in LiteSVM
// can't carry non-empty `data`, so we can't construct a positive
// pre-state in-tree. Pure detection logic is covered by direct tests
// of `check_kind` in `crates/solinv-core/src/invariants/unchecked_math.rs`
// (cfg(test) mod tests). Full-pipe positive detection is exercised
// via escrow-demo's planted unsafe_accumulate_yield ix (Day 33+).

fn unchecked_math_inv_for_acct1() -> StateInvariant {
    StateInvariant {
        name: "amount_bounded".to_string(),
        kind: StateInvariantKind::Bounded {
            field_offset: 0,
            field_size: 8,
            min: 0,
            max: u128::MAX,
        },
        accounts: vec![1],
    }
}

#[test]
fn unchecked_math_non_detect_bounded() {
    clear_violation_tracking();
    let recipient = Arc::new(Keypair::new());
    let fee_payer = Arc::new(Keypair::new());
    let mut spec = base_transfer_spec(recipient.pubkey(), vec![fee_payer.clone()]);
    spec.state_invariants = vec![unchecked_math_inv_for_acct1()];

    let mut fixture = base_fixture(
        spec,
        &[(recipient.pubkey(), mk_account(0, SYSTEM_PROGRAM_ID, Vec::new()))],
        1_000_000,
        fee_payer,
    );
    unchecked_math::check(&mut fixture);
    assert_not_detected();
}

#[test]
fn unchecked_math_non_detect_monotonic() {
    clear_violation_tracking();
    let recipient = Arc::new(Keypair::new());
    let fee_payer = Arc::new(Keypair::new());
    let mut spec = base_transfer_spec(recipient.pubkey(), vec![fee_payer.clone()]);
    spec.state_invariants = vec![StateInvariant {
        name: "amount_monotonic".to_string(),
        kind: StateInvariantKind::Monotonic {
            field_offset: 0,
            field_size: 8,
            direction: MonotonicDir::NonDecreasing,
        },
        accounts: vec![1],
    }];

    let mut fixture = base_fixture(
        spec,
        &[(recipient.pubkey(), mk_account(0, SYSTEM_PROGRAM_ID, Vec::new()))],
        1_000_000,
        fee_payer,
    );
    unchecked_math::check(&mut fixture);
    assert_not_detected();
}

#[test]
#[ignore = "Needs a planted-bug program that wraps u64 arithmetic on \
            account data (escrow-demo unsafe_accumulate_yield, Day 33+)"]
fn unchecked_math_detect_pair() {
    // Reserved for Day 33+ — exercises Monotonic / Bounded detection
    // against an ix that actually wraps account.data math, mirroring
    // the detect_pair pattern of the Critical 5.
}

// ---------------------------------------------------------------------
// cu-dos (High tier #2, Day 35+)
// ---------------------------------------------------------------------
// system_program::transfer consumes ~150 CU end-to-end — orders of
// magnitude below any sensible cu_budget. So the non-detect baseline
// is a generous cap (10_000 CU) against transfer's tiny footprint.
// Detection of >budget ix is exercised via escrow-demo's planted
// unsafe_compute_dos in Day 37+.

#[test]
fn cu_dos_non_detect() {
    clear_violation_tracking();
    let recipient = Arc::new(Keypair::new());
    let fee_payer = Arc::new(Keypair::new());
    let mut spec = base_transfer_spec(recipient.pubkey(), vec![fee_payer.clone()]);
    spec.cu_budget = Some(10_000);

    let mut fixture = base_fixture(
        spec,
        &[(recipient.pubkey(), mk_account(0, SYSTEM_PROGRAM_ID, Vec::new()))],
        1_000_000,
        fee_payer,
    );
    cu_dos::check(&mut fixture);
    assert_not_detected();
}

#[test]
fn cu_dos_skipped_when_budget_is_none() {
    clear_violation_tracking();
    let recipient = Arc::new(Keypair::new());
    let fee_payer = Arc::new(Keypair::new());
    let spec = base_transfer_spec(recipient.pubkey(), vec![fee_payer.clone()]);
    // base_transfer_spec leaves cu_budget = None; the check should
    // be a no-op even if transfer somehow exceeded a hypothetical cap.

    let mut fixture = base_fixture(
        spec,
        &[(recipient.pubkey(), mk_account(0, SYSTEM_PROGRAM_ID, Vec::new()))],
        1_000_000,
        fee_payer,
    );
    cu_dos::check(&mut fixture);
    assert_not_detected();
}

#[test]
#[ignore = "Needs a planted-bug program with an O(n) loop on an \
            attacker-controllable input (escrow-demo unsafe_compute_dos, Day 37+)"]
fn cu_dos_detect_pair() {
    // Reserved for Day 37+ — exercises detection against an ix that
    // actually consumes more CU than declared, matching Gate 1 of
    // the cu-dos kill criterion (docs/invariants/cu-dos.md §9).
}
