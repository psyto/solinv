//! # Invariant: account-swap
//!
//! Detects missing context-binding verification — accepting a
//! legitimate account from the wrong context (wrong user / wrong
//! market / wrong epoch). The fourth-line defense after signer-skip,
//! owner-skip, discriminator-skip, and pda-forge.
//!
//! Unlike the preceding 4 Critical invariants (which construct fake
//! accounts), account_swap uses **real alternate PDAs from the fixture**
//! provided via `spec.swap_alternates`. Each alternate is a legitimate
//! account in the fixture (correct owner, discriminator, PDA derivation)
//! but representing a different context. Earlier checks all pass —
//! only the missing context-binding check can cause success.
//!
//! See `docs/invariants/account-swap.md` for full bug-class background,
//! the semantic-vs-syntactic distinction, false-positive analysis
//! (permissionless ixs / shared-context cases), and openhl-solana
//! test fixture (multi-trader + multi-market setup).
//!
//! Implementation per `docs/implementation-day3-crucible-internals.md`
//! §7 revised template; simpler than Days 6-8 because no fake-account
//! construction is needed — alt pubkey is already a real account.

use crucible_test_context::{fuzz_assert, TxOutcome};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solinv_fuzz::{HasContext, HasInstructionSet};

use super::util::{hash_accounts, hash_accounts_now, restore_accounts, save_accounts};

/// Check fixture's instruction set for account-swap vulnerabilities.
///
/// For each instruction × account with declared swap_alternates, tries
/// each alternate pubkey in turn. If the program accepts the alternate
/// (success + state change), it means context-binding verification is
/// missing — the program doesn't check that the account's internal
/// fields reference the correct caller / market / epoch.
pub fn check<F>(fixture: &mut F)
where
    F: HasContext + HasInstructionSet,
{
    let ixs = fixture.instructions();
    for spec in &ixs {
        for (idx, alternates) in spec.swap_alternates.iter().enumerate() {
            for &alt_pubkey in alternates {
                run_attempt(fixture, spec, idx, alt_pubkey);
            }
        }
    }
}

/// Single attempt: substitute one real alternate pubkey for the
/// canonical account at idx.
fn run_attempt<F>(
    fixture: &mut F,
    spec: &solinv_fuzz::InstructionSpec,
    idx: usize,
    alt_pubkey: Pubkey,
) where
    F: HasContext + HasInstructionSet,
{
    if idx >= spec.accounts.len() {
        return;
    }

    let real_pubkey = spec.accounts[idx].pubkey;
    if alt_pubkey == real_pubkey {
        // Same account; not a swap. (Defensive — fixture should not
        // include real in alternates list, but skip gracefully.)
        return;
    }

    // Sanity: alt must exist in ctx. Fixture is supposed to have
    // created it during setup; skip silently if not.
    if fixture.ctx().get_account(&alt_pubkey).is_err() {
        return;
    }

    // 1. Build the full list of pubkeys the modified ix will touch:
    //    canonical accounts with alt substituted at idx. This captures
    //    state changes whether they happen in canonical OR alt account.
    let touched: Vec<Pubkey> = spec
        .accounts
        .iter()
        .enumerate()
        .map(|(i, m)| if i == idx { alt_pubkey } else { m.pubkey })
        .collect();

    // 2. Manual save — includes alt so restore undoes any attack damage
    //    to it (keeps fixture state clean for subsequent invariants).
    let saves = save_accounts(fixture.ctx(), &touched);
    let pre_hash = hash_accounts(&saves);

    // 3. Substitute alt pubkey into AccountMeta list.
    //    NO fake construction — alt is already a real legitimate PDA
    //    in the fixture's state.
    let mut metas = spec.accounts.clone();
    metas[idx].pubkey = alt_pubkey;

    let ix = solana_instruction::Instruction {
        program_id: spec.program_id,
        accounts: metas,
        data: spec.data_sample.clone(),
    };

    // 4. Signers: fee-payer prepended + canonical business signers.
    let fee_payer = fixture.fee_payer();
    let mut signer_refs: Vec<&Keypair> = vec![&*fee_payer];
    for kp in &spec.signers {
        if kp.pubkey() != fee_payer.pubkey() {
            signer_refs.push(&**kp);
        }
    }

    // 5. Execute via raw_call
    let result = fixture
        .ctx_mut()
        .raw_call(ix)
        .fee_payer(&*fee_payer)
        .signers(&signer_refs)
        .send();

    // 6. Post hash on the same touched set
    let post_hash = hash_accounts_now(fixture.ctx(), touched.iter().copied());

    let succeeded = matches!(result, Ok(TxOutcome::Success { .. }));
    let state_changed = pre_hash != post_hash;

    fuzz_assert!(
        !(succeeded && state_changed),
        "[account-swap:{}] ix {} succeeded with account {} swapped \
         from {} to {} (different context, same shape)",
        spec.program_id,
        spec.name,
        idx,
        real_pubkey,
        alt_pubkey,
    );

    // 7. Manual restore of all touched (including alt if attack modified it)
    restore_accounts(fixture.ctx_mut(), saves);
}
