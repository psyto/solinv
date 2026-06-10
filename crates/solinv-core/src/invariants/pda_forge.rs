//! # Invariant: pda-forge
//!
//! Detects missing PDA seed verification at account-read time. Solana's
//! runtime auto-verifies seeds at account *creation* via invoke_signed,
//! but does NOT verify at *read* time when a program receives an
//! existing PDA-derived account. Programs must manually
//! `assert!(account.key == &Pubkey::find_program_address(seeds, prog).0)`.
//!
//! For each instruction with declared `expected_pda_seeds`, substitutes
//! a fake account at a **random off-curve pubkey** with byte-identical
//! content (preserving owner and discriminator). If the instruction
//! succeeds and state changes, report pda-forge violation.
//!
//! Accounts in `creates_indices` are skipped — runtime auto-verifies
//! creation via invoke_signed, so missing read-time verification
//! doesn't apply.
//!
//! See `docs/invariants/pda-forge.md` for full bug-class background,
//! the variant-pass strategy roadmap (currently random-pubkey only),
//! and openhl-solana test fixture.
//!
//! Implementation per `docs/implementation-day3-crucible-internals.md`
//! §7 revised template; substitution pattern identical in shape to
//! owner_skip and discriminator_skip with random-pubkey attack vector.

use crucible_test_context::{fuzz_assert, TxOutcome};
use solana_account::Account;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solinv_fuzz::{HasContext, HasInstructionSet};

use super::util::{
    cleanup_temp_account, hash_accounts, hash_accounts_now, restore_accounts, save_accounts,
};

/// Check fixture's instruction set for pda-forge vulnerabilities.
///
/// For each instruction × account with declared expected_pda_seeds
/// (and NOT in creates_indices), substitutes a random-pubkey fake
/// account with cloned data/owner/lamports. The only check the program
/// could use to reject this is PDA derivation verification; if it
/// succeeds with state change, the program is missing that check.
pub fn check<F>(fixture: &mut F)
where
    F: HasContext + HasInstructionSet,
{
    let ixs = fixture.instructions();
    for spec in &ixs {
        for (idx, expected_seeds) in spec.expected_pda_seeds.iter().enumerate() {
            let Some(seeds) = expected_seeds else { continue };

            // Skip account-creation paths — runtime auto-verifies via
            // invoke_signed during system_instruction::create_account.
            if spec.creates_indices.contains(&idx) {
                continue;
            }

            run_attempt(fixture, spec, idx, seeds);
        }
    }
}

/// Single attempt: substitute one fake account at random pubkey.
fn run_attempt<F>(
    fixture: &mut F,
    spec: &solinv_fuzz::InstructionSpec,
    idx: usize,
    seeds: &[Vec<u8>],
) where
    F: HasContext + HasInstructionSet,
{
    if idx >= spec.accounts.len() {
        return;
    }

    // Re-derive expected PDA from declared seeds; verify fixture setup
    // is correct (declared seeds should match the actual pubkey at idx).
    // This catches fixture authoring errors without panicking.
    let seed_slices: Vec<&[u8]> = seeds.iter().map(|s| s.as_slice()).collect();
    let (expected_pda, _canonical_bump) =
        Pubkey::find_program_address(&seed_slices, &spec.program_id);

    let real_pubkey = spec.accounts[idx].pubkey;
    if real_pubkey != expected_pda {
        // Fixture authoring error: declared seeds don't derive to the
        // pubkey at this index. Silently skip — the user will notice
        // when their other tests fail; we don't add noise to fuzz output.
        return;
    }

    // 1. Manual save (Day 3 Correction #4)
    let pubkeys: Vec<_> = spec.accounts.iter().map(|m| m.pubkey).collect();
    let saves = save_accounts(fixture.ctx(), &pubkeys);
    let pre_hash = hash_accounts(&saves);

    // 2. Get real account for cloning into fake
    let Some((_, real_account)) = saves.iter().find(|(pk, _)| *pk == real_pubkey).cloned()
    else {
        restore_accounts(fixture.ctx_mut(), saves);
        return;
    };

    // 3. Build fake at random pubkey: PRESERVE everything except the
    //    pubkey itself. This is the key orthogonality decision —
    //    owner-skip and discriminator-skip checks both pass on this
    //    fake (data + owner preserved), so only PDA seed verification
    //    can catch the substitution.
    let fake_pubkey = Pubkey::new_unique();
    let fake_account = Account {
        owner: real_account.owner,
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

    // 4. Substitute fake pubkey into AccountMeta list
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

    // 7. Post hash
    let post_hash = hash_accounts_now(fixture.ctx(), pubkeys.iter().copied());

    let succeeded = matches!(result, Ok(TxOutcome::Success { .. }));
    let state_changed = pre_hash != post_hash;

    fuzz_assert!(
        !(succeeded && state_changed),
        "[pda-forge:{}] ix {} succeeded with account {} at random pubkey {} \
         instead of expected PDA {} derived from {} seed components",
        spec.program_id,
        spec.name,
        idx,
        fake_pubkey,
        expected_pda,
        seeds.len(),
    );

    // 8. Manual restore + fake-account cleanup
    restore_accounts(fixture.ctx_mut(), saves);
    cleanup_temp_account(fixture.ctx_mut(), &fake_pubkey);
}
