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
                run_attempt(fixture, spec, &[(idx, alt_pubkey)]);
            }
        }
    }
}

/// Slots of one instruction swapped together in a single attempt.
///
/// Some bindings take two accounts to break: a program that trusts the
/// records a caller-chosen program owns rejects a rogue program alone
/// (the record's owner no longer matches) and a rogue record alone (its
/// owner is not the trusted program), but accepts both (#4). A set names
/// each slot index and its alternate; all are substituted at once.
#[derive(Clone, Debug)]
pub struct SwapSet {
    /// The instruction, by `InstructionSpec::name`.
    pub ix: String,
    /// `(account index, alternate pubkey)` for every slot swapped.
    pub swaps: Vec<(usize, Pubkey)>,
}

/// [`check`] for sets of slots that must be swapped together. Call it
/// beside `check` from the same `#[invariant_test]`; a set naming an
/// instruction the fixture does not have is skipped.
pub fn check_sets<F>(fixture: &mut F, sets: &[SwapSet])
where
    F: HasContext + HasInstructionSet,
{
    let ixs = fixture.instructions();
    for set in sets {
        if let Some(spec) = ixs.iter().find(|s| s.name == set.ix) {
            run_attempt(fixture, spec, &set.swaps);
        }
    }
}

/// Single attempt: substitute each real alternate pubkey for the
/// canonical account at its index, all in one instruction.
fn run_attempt<F>(fixture: &mut F, spec: &solinv_fuzz::InstructionSpec, swaps: &[(usize, Pubkey)])
where
    F: HasContext + HasInstructionSet,
{
    if swaps.is_empty() || swaps.iter().any(|&(idx, _)| idx >= spec.accounts.len()) {
        return;
    }
    // One alternate per slot: a repeated index is a malformed set.
    if swaps.iter().enumerate().any(|(i, &(idx, _))| swaps[..i].iter().any(|&(j, _)| j == idx)) {
        return;
    }
    if swaps.iter().any(|&(idx, alt)| alt == spec.accounts[idx].pubkey) {
        // Same account; not a swap. (Defensive — fixture should not
        // include real in alternates list, but skip gracefully.)
        return;
    }

    // Sanity: each alt must exist in ctx. Fixture is supposed to have
    // created it during setup; skip silently if not.
    if swaps.iter().any(|&(_, alt)| fixture.ctx().get_account(&alt).is_err()) {
        return;
    }

    // 1. Build the full list of pubkeys the modified ix will touch:
    //    canonical accounts with alts substituted. This captures state
    //    changes whether they happen in canonical OR alt accounts.
    let alt_at = |i: usize| swaps.iter().find(|&&(idx, _)| idx == i).map(|&(_, alt)| alt);
    let touched: Vec<Pubkey> = spec
        .accounts
        .iter()
        .enumerate()
        .map(|(i, m)| alt_at(i).unwrap_or(m.pubkey))
        .collect();

    // 2. Manual save — includes alt so restore undoes any attack damage
    //    to it (keeps fixture state clean for subsequent invariants).
    let saves = save_accounts(fixture.ctx(), &touched);
    let pre_hash = hash_accounts(&saves);

    // 3. Substitute alt pubkey into AccountMeta list.
    //    NO fake construction — alt is already a real legitimate PDA
    //    in the fixture's state.
    let mut metas = spec.accounts.clone();
    for &(idx, alt) in swaps {
        metas[idx].pubkey = alt;
    }

    // 4. Signers: fee-payer prepended + the business signers the swapped
    //    instruction still asks for. With sigverify on, a keypair whose
    //    slot was swapped out would make signing fail before the program
    //    runs, hiding the result, and an alternate that signs needs its
    //    keypair in `spec.signers`. (Crucible's default, sigverify off,
    //    uses placeholder signatures and needs neither.)
    let fee_payer = fixture.fee_payer();
    let mut signer_refs: Vec<&Keypair> = vec![&*fee_payer];
    for kp in &spec.signers {
        let wanted = metas.iter().any(|m| m.is_signer && m.pubkey == kp.pubkey());
        if kp.pubkey() != fee_payer.pubkey() && wanted {
            signer_refs.push(&**kp);
        }
    }

    let ix = solana_instruction::Instruction {
        program_id: spec.program_id,
        accounts: metas,
        data: spec.data_sample.clone(),
    };

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

    let swapped = swaps
        .iter()
        .map(|&(idx, alt)| format!("{idx} swapped from {} to {alt}", spec.accounts[idx].pubkey))
        .collect::<Vec<_>>()
        .join(", account ");
    fuzz_assert!(
        !(succeeded && state_changed),
        "[account-swap:{}] ix {} succeeded with account {}{} (different context, same shape)",
        spec.program_id,
        spec.name,
        swapped,
        if swaps.len() > 1 { ", together" } else { "" },
    );

    // 7. Manual restore of all touched (including alt if attack modified it)
    restore_accounts(fixture.ctx_mut(), saves);
}
