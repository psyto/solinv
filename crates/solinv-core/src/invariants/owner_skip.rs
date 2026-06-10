//! # Invariant: owner-skip
//!
//! Detects missing `account.owner == expected_program` checks,
//! enabling account-type confusion attacks where an attacker passes
//! an account they control (owned by a different program) with bytes
//! laid out to look like the legitimate account type.
//!
//! For each instruction with declared `expected_owners`, substitutes
//! a fake account containing identical bytes but owned by a non-expected
//! program. If the instruction succeeds AND state changes occur,
//! report owner-skip violation.
//!
//! See `docs/invariants/owner-skip.md` for full bug-class background,
//! Crema Finance precedent, severity classification, and openhl-solana
//! test fixture.
//!
//! Implementation per `docs/implementation-day3-crucible-internals.md`
//! §7 revised template; same 7-phase pattern as signer_skip with
//! account-substitution attack vector instead of signer-flip.

use crucible_test_context::{fuzz_assert, TxOutcome};
use solana_account::Account;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solinv_fuzz::{HasContext, HasInstructionSet};

use super::util::{
    cleanup_temp_account, hash_accounts, hash_accounts_now, restore_accounts, save_accounts,
};

/// The Solana system program ID = 32 zero bytes ("11111111111111111111111111111111").
/// `Pubkey::default()` happens to equal system_program::ID — exploit this
/// to avoid pulling in another crate just for the constant.
const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);

/// Check fixture's instruction set for owner-skip vulnerabilities.
///
/// For each instruction × signer-checked account index, runs multi-pass
/// substitution with several "wrong" owner programs (system_program,
/// attacker-controlled random pubkey). First pass to succeed reports
/// violation.
pub fn check<F>(fixture: &mut F)
where
    F: HasContext + HasInstructionSet,
{
    let ixs = fixture.instructions();
    for spec in &ixs {
        for (idx, expected) in spec.expected_owners.iter().enumerate() {
            let Some(expected_owner) = expected else { continue };

            for wrong_owner in wrong_owners_for(*expected_owner) {
                run_swap_attempt(fixture, spec, idx, wrong_owner, *expected_owner);
            }
        }
    }
}

/// Wrong owner candidates to substitute. Multi-pass: different wrong
/// owners catch different bug patterns.
fn wrong_owners_for(expected: Pubkey) -> Vec<Pubkey> {
    vec![SYSTEM_PROGRAM_ID, Pubkey::new_unique()]
        .into_iter()
        .filter(|p| *p != expected)
        .collect()
}

/// Single attempt: substitute one fake account with wrong owner.
fn run_swap_attempt<F>(
    fixture: &mut F,
    spec: &solinv_fuzz::InstructionSpec,
    idx: usize,
    wrong_owner: Pubkey,
    expected_owner: Pubkey,
) where
    F: HasContext + HasInstructionSet,
{
    if idx >= spec.accounts.len() {
        return;
    }

    // 1. Manual save (Day 3 Correction #4)
    let pubkeys: Vec<_> = spec.accounts.iter().map(|m| m.pubkey).collect();
    let saves = save_accounts(fixture.ctx(), &pubkeys);
    let pre_hash = hash_accounts(&saves);

    // 2. Get real account bytes for cloning into fake
    let real_pubkey = spec.accounts[idx].pubkey;
    let Some((_, real_account)) = saves.iter().find(|(pk, _)| *pk == real_pubkey).cloned()
    else {
        // Account doesn't exist in ctx yet (e.g., created mid-ix); skip
        restore_accounts(fixture.ctx_mut(), saves);
        return;
    };

    // 3. Build fake account: same data + same lamports, wrong owner
    let fake_pubkey = Pubkey::new_unique();
    let fake_account = Account {
        owner: wrong_owner,
        data: real_account.data.clone(),
        lamports: real_account.lamports,
        executable: false,
        rent_epoch: real_account.rent_epoch,
    };
    if fixture
        .ctx_mut()
        .write_account(&fake_pubkey, fake_account)
        .is_err()
    {
        restore_accounts(fixture.ctx_mut(), saves);
        return;
    }

    // 4. Build mutated AccountMeta list with fake substituted at idx
    let mut metas = spec.accounts.clone();
    metas[idx].pubkey = fake_pubkey;

    let ix = solana_instruction::Instruction {
        program_id: spec.program_id,
        accounts: metas,
        data: spec.data_sample.clone(),
    };

    // 5. Signers list unchanged from canonical, plus fee-payer prepended
    //    so the tx always has a fee-paying signer regardless of which
    //    keypairs the business logic requires.
    let fee_payer = fixture.fee_payer();
    let mut signer_refs: Vec<&Keypair> = vec![&*fee_payer];
    for kp in &spec.signers {
        if kp.pubkey() != fee_payer.pubkey() {
            signer_refs.push(&**kp);
        }
    }

    // 6. Execute via raw_call (Day 3 Correction #2)
    let result = fixture
        .ctx_mut()
        .raw_call(ix)
        .fee_payer(&*fee_payer)
        .signers(&signer_refs)
        .send();

    // 7. Compute post hash (on REAL accounts, not the fake)
    let post_hash = hash_accounts_now(fixture.ctx(), pubkeys.iter().copied());

    let succeeded = matches!(result, Ok(TxOutcome::Success { .. }));
    let state_changed = pre_hash != post_hash;

    fuzz_assert!(
        !(succeeded && state_changed),
        "[owner-skip:{}] ix {} succeeded with account {} owned by {} \
         instead of expected {}; real pubkey {} → fake pubkey {}",
        spec.program_id,
        spec.name,
        idx,
        wrong_owner,
        expected_owner,
        real_pubkey,
        fake_pubkey,
    );

    // 8. Manual restore of originals + fake-account cleanup.
    restore_accounts(fixture.ctx_mut(), saves);
    cleanup_temp_account(fixture.ctx_mut(), &fake_pubkey);
}
