//! # Invariant: signer-skip
//!
//! Detects missing `is_signer` checks on authorization-required accounts.
//!
//! For each instruction in the fixture's instruction set, for each
//! signer-required account, replay the instruction with the target
//! account's `is_signer = false` AND with that keypair dropped from
//! the signers list. If the instruction succeeds AND state changes
//! occur, report signer-skip violation.
//!
//! See `docs/invariants/signer-skip.md` for full bug-class background,
//! audit-firm context, severity classification, false-positive analysis,
//! and openhl-solana test fixture.
//!
//! Implementation per `docs/implementation-day3-crucible-internals.md`
//! §7 (revised template after internals deep-read).

use crucible_test_context::{fuzz_assert, TxOutcome};
use solana_keypair::Keypair;
use solana_signer::Signer;
use solinv_fuzz::{HasContext, HasInstructionSet};

use super::util::{hash_accounts, hash_accounts_now, restore_accounts, save_accounts};

/// Check fixture's instruction set for signer-skip vulnerabilities.
///
/// Called from inside a user `#[invariant_test]` body alongside other
/// solinv invariants:
///
/// ```ignore
/// #[invariant_test]
/// fn invariant_all(f: &mut MyFixture) {
///     solinv_core::invariants::signer_skip::check(f);
///     // ... other invariants ...
/// }
/// ```
pub fn check<F>(fixture: &mut F)
where
    F: HasContext + HasInstructionSet,
{
    let ixs = fixture.instructions();
    for spec in &ixs {
        for &sig_idx in &spec.signer_indices {
            // Skip optional signers — flipping is not a real bug per
            // signer-skip spec false-positive analysis.
            if spec.optional_signer_indices.contains(&sig_idx) {
                continue;
            }

            // 1. Manual save (Day 3 Correction #4)
            let pubkeys: Vec<_> = spec.accounts.iter().map(|m| m.pubkey).collect();
            let saves = save_accounts(fixture.ctx(), &pubkeys);
            let pre_hash = hash_accounts(&saves);

            // 2. Build mutated ix — flip is_signer on target account
            let mut metas = spec.accounts.clone();
            if sig_idx >= metas.len() {
                // Spec setup error; skip rather than panic
                restore_accounts(fixture.ctx_mut(), saves);
                continue;
            }
            metas[sig_idx].is_signer = false;

            let ix = solana_instruction::Instruction {
                program_id: spec.program_id,
                accounts: metas,
                data: spec.data_sample.clone(),
            };

            // 3. Build signers list with the target business signer
            //    DROPPED but the fee-payer KEPT (Critique 1 fix —
            //    otherwise tx has no fee payer and gets rejected
            //    BEFORE reaching the program's signer check, masking
            //    the bug we're trying to detect).
            let dropped_pubkey = spec.accounts[sig_idx].pubkey;
            let fee_payer = fixture.fee_payer();
            let mut signer_refs: Vec<&Keypair> = vec![&*fee_payer];
            for kp in &spec.signers {
                // Don't double-include fee_payer if it's also in the
                // business signers, and drop the attack target.
                if kp.pubkey() == fee_payer.pubkey() {
                    continue;
                }
                if kp.pubkey() == dropped_pubkey {
                    continue;
                }
                signer_refs.push(&**kp);
            }

            // 4. Execute via raw_call (Day 3 Correction #2)
            //    NOT ctx.program(pid).call().accounts() — that path
            //    overwrites our mutated AccountMeta vec.
            let result = fixture
                .ctx_mut()
                .raw_call(ix)
                .fee_payer(&*fee_payer)
                .signers(&signer_refs)
                .send();

            // 5. Compute post hash
            let post_hash = hash_accounts_now(fixture.ctx(), pubkeys.iter().copied());

            // 6. Detect violation: ix succeeded AND state changed
            //    despite missing signer
            let succeeded = matches!(result, Ok(TxOutcome::Success { .. }));
            let state_changed = pre_hash != post_hash;

            fuzz_assert!(
                !(succeeded && state_changed),
                "[signer-skip:{}] ix {} succeeded with is_signer=false on \
                 account {} (pubkey {}); state hash {} → {}",
                spec.program_id,
                spec.name,
                sig_idx,
                dropped_pubkey,
                pre_hash,
                post_hash,
            );

            // 7. Manual restore (Day 3 Correction #4)
            restore_accounts(fixture.ctx_mut(), saves);
        }
    }
}
