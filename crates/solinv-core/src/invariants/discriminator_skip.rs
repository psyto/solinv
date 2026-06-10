//! # Invariant: discriminator-skip
//!
//! Detects missing account discriminator checks, enabling type
//! confusion within the same program's account types. With owner-check
//! passing (the account belongs to the calling program), without a
//! discriminator check the attacker can substitute an account of a
//! **different type owned by the same program**.
//!
//! For each instruction with declared `expected_discriminators`,
//! substitutes a fake account containing identical bytes EXCEPT the
//! first 8 bytes (discriminator), keeping the owner correct. If the
//! instruction succeeds and state changes, report discriminator-skip
//! violation (owner-skip is excluded by design).
//!
//! See `docs/invariants/discriminator-skip.md` for full bug-class
//! background, Anchor-vs-native specifics, and orthogonality discussion.
//!
//! Implementation per `docs/implementation-day3-crucible-internals.md`
//! §7 revised template; substitution pattern matches owner_skip (Day 6)
//! with data[0..8] corruption instead of owner change.

use crucible_test_context::{fuzz_assert, TxOutcome};
use solana_account::Account;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solinv_fuzz::{HasContext, HasInstructionSet};

use super::util::{
    cleanup_temp_account, hash_accounts, hash_accounts_now, restore_accounts, save_accounts,
};

/// Wrong discriminator candidates. Multi-pass: different wrong values
/// catch different bug patterns.
///
/// - Sentinel `0xDEADBEEF...` — catches programs that compare against
///   a hardcoded expected value
/// - All zeros — catches programs that treat default-initialized
///   accounts as valid
/// - All ones — catches programs that use exclusion (e.g.,
///   `disc != [0xFF; 8]` check)
const WRONG_DISCRIMINATORS: &[[u8; 8]] = &[
    [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00],
    [0x00; 8],
    [0xFF; 8],
];

/// Check fixture's instruction set for discriminator-skip vulnerabilities.
///
/// For each instruction × discriminator-checked account index, runs
/// multi-pass substitution with the 3 wrong-discriminator candidates.
/// First pass to succeed reports violation.
pub fn check<F>(fixture: &mut F)
where
    F: HasContext + HasInstructionSet,
{
    let ixs = fixture.instructions();
    for spec in &ixs {
        for (idx, expected) in spec.expected_discriminators.iter().enumerate() {
            let Some(expected_disc) = expected else { continue };

            for wrong_disc in WRONG_DISCRIMINATORS {
                if wrong_disc == expected_disc {
                    continue;
                }
                run_attempt(fixture, spec, idx, *wrong_disc, *expected_disc);
            }
        }
    }
}

/// Single attempt: substitute one fake account with corrupted discriminator.
fn run_attempt<F>(
    fixture: &mut F,
    spec: &solinv_fuzz::InstructionSpec,
    idx: usize,
    wrong_disc: [u8; 8],
    expected_disc: [u8; 8],
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
        restore_accounts(fixture.ctx_mut(), saves);
        return;
    };

    // Need at least 8 bytes to corrupt discriminator
    if real_account.data.len() < 8 {
        restore_accounts(fixture.ctx_mut(), saves);
        return;
    }

    // 3. Build fake data: clone real, overwrite first 8 bytes
    //    KEY ORTHOGONALITY: preserve owner correctness (so owner-skip
    //    is NOT triggered) — only the discriminator-check failure path
    //    can cause this attack to succeed.
    let mut fake_data = real_account.data.clone();
    fake_data[0..8].copy_from_slice(&wrong_disc);

    let fake_pubkey = Pubkey::new_unique();
    let fake_account = Account {
        owner: real_account.owner, // PRESERVE — orthogonality with owner-skip
        data: fake_data,
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

    // 4. Substitute fake into AccountMeta list
    let mut metas = spec.accounts.clone();
    metas[idx].pubkey = fake_pubkey;

    let ix = solana_instruction::Instruction {
        program_id: spec.program_id,
        accounts: metas,
        data: spec.data_sample.clone(),
    };

    // 5. Signers: fee-payer prepended + canonical business signers
    let fee_payer = fixture.fee_payer();
    let mut signer_refs: Vec<&Keypair> = vec![&*fee_payer];
    for kp in &spec.signers {
        if kp.pubkey() != fee_payer.pubkey() {
            signer_refs.push(&**kp);
        }
    }

    // 6. Execute via raw_call
    let result = fixture
        .ctx_mut()
        .raw_call(ix)
        .fee_payer(&*fee_payer)
        .signers(&signer_refs)
        .send();

    // 7. Compute post hash
    let post_hash = hash_accounts_now(fixture.ctx(), pubkeys.iter().copied());

    let succeeded = matches!(result, Ok(TxOutcome::Success { .. }));
    let state_changed = pre_hash != post_hash;

    fuzz_assert!(
        !(succeeded && state_changed),
        "[discriminator-skip:{}] ix {} succeeded with account {} \
         discriminator {:02x?} instead of expected {:02x?}; \
         real pubkey {} → fake pubkey {}",
        spec.program_id,
        spec.name,
        idx,
        wrong_disc,
        expected_disc,
        real_pubkey,
        fake_pubkey,
    );

    // 8. Manual restore of originals + fake-account cleanup
    restore_accounts(fixture.ctx_mut(), saves);
    cleanup_temp_account(fixture.ctx_mut(), &fake_pubkey);
}
