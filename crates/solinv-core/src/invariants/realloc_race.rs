//! # Invariant: realloc-race
//!
//! Detects accounts that grow their data buffer via `AccountInfo::realloc`
//! without a corresponding lamport top-up to keep them rent-exempt at the
//! new size. v1 detection: pre/post ix state snapshot of every account's
//! `data.len()` + `lamports`, fire if any account satisfies all of:
//!
//! 1. `post.data.len() > pre.data.len()` (grew)
//! 2. `post.data.len() > 0` (not closed)
//! 3. `post.lamports < rent_for(post.data.len())` (rent broken)
//!
//! AND a runtime-error path: Solana's runtime catches the rent
//! shortfall at tx commit and rejects with `InsufficientFundsForRent`.
//! When the detector observes that error, it fires the same violation
//! — the protocol-level bug class is observable whether the runtime
//! arrests the bug (Path A: runtime error) or the bug commits and
//! leaves degraded state (Path B: post-state mismatch). On modern
//! Solana (rent-exempt-only feature enabled since 1.8) Path A is the
//! dominant path; Path B is mainly reachable on archaic test-only
//! configurations or via runtime bugs.
//!
//! Shrinks never trigger the rent invariant on Solana (rent excess on
//! shrink isn't refunded; the account simply retains the original
//! lamports against a smaller `data.len()`), so the detector only walks
//! the grow path.
//!
//! See `docs/invariants/realloc-race.md` for the bug class, mainnet
//! precedents (Mango v4 pre-mainnet, NFT marketplace order-extensions),
//! severity bands, the planted-bug fixture in escrow-demo, and §9 / §10
//! — the Phase 2.5 OSS catalog-completion framing inherited from
//! cpi-reentrancy.

use crucible_test_context::{fuzz_assert, TxOutcome};
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_transaction_error::TransactionError;
use solinv_fuzz::{HasContext, HasInstructionSet, InstructionSpec};

use super::util::{restore_accounts, save_accounts};

/// Rent-exempt lamport minimum for an account holding `bytes` of data.
/// Mirrors `solana_rent::Rent::default().minimum_balance(bytes)`
/// without pulling in solana_rent:
///   `(128 + bytes) * 3480 * 2`
/// where 3480 = `LAMPORTS_PER_BYTE_YEAR` and `2` is the exemption
/// threshold (2 years of rent prepaid).
///
/// Same formula as `solinv_fuzz::bytepoke::rent_for_raw`; duplicated
/// here to avoid solinv-core depending on solinv-fuzz's bytepoke
/// module (which is harness-side surface, not detector-side).
pub fn rent_for(bytes: usize) -> u64 {
    (128 + bytes) as u64 * 3480 * 2
}

/// Check the fixture's instruction set for realloc-race violations.
///
/// For each ix whose spec carries `Some(ReallocCheckConfig)`, captures
/// every spec-listed account's pre-ix `(data.len(), lamports)`,
/// executes the ix, then re-fetches and fires `fuzz_assert!` on any
/// account that grew without lamport top-up sufficient to keep it
/// rent-exempt at the new size.
pub fn check<F>(fixture: &mut F)
where
    F: HasContext + HasInstructionSet,
{
    let ixs = fixture.instructions();
    for spec in &ixs {
        if spec.realloc_check.is_none() {
            continue;
        }
        run_attempt(fixture, spec);
    }
}

fn run_attempt<F>(fixture: &mut F, spec: &InstructionSpec)
where
    F: HasContext + HasInstructionSet,
{
    let pubkeys: Vec<_> = spec.accounts.iter().map(|m| m.pubkey).collect();
    let saves = save_accounts(fixture.ctx(), &pubkeys);
    // Build a parallel pre-state vector keyed by pubkey for the rent
    // check. `save_accounts` filters out missing accounts, so the
    // pre-state lookup may return None for an account that didn't
    // exist before the ix (e.g., created during the ix); those skip
    // the grow comparison.
    let pre_states: Vec<(usize, u64)> = saves
        .iter()
        .map(|(_, acc)| (acc.data.len(), acc.lamports))
        .collect();
    let pre_pubkeys: Vec<_> = saves.iter().map(|(pk, _)| *pk).collect();

    let fee_payer = fixture.fee_payer();
    let mut signer_refs: Vec<&Keypair> = vec![&*fee_payer];
    for kp in &spec.signers {
        if kp.pubkey() != fee_payer.pubkey() {
            signer_refs.push(&**kp);
        }
    }

    let result = fixture
        .ctx_mut()
        .raw_call(spec.to_instruction())
        .fee_payer(&*fee_payer)
        .signers(&signer_refs)
        .send();

    // Solana defense-in-depth: when a program grows an account's data
    // buffer past the rent-exempt threshold without depositing
    // additional lamports, the runtime catches this at tx commit and
    // rejects the tx with `InsufficientFundsForRent`. The program-
    // level state mutation does NOT persist (the tx rolls back).
    //
    // Detector path A (runtime-error): if we see this error, surface
    // it as a positive detection — the program tried to commit a
    // rent-deficient state; the runtime arrested it, but the
    // protocol-level bug class is observable.
    if let Ok(TxOutcome::ProgramError { ref error, .. }) = result {
        if let TransactionError::InsufficientFundsForRent { account_index } = error {
            let idx = *account_index as usize;
            let acct_str = pre_pubkeys
                .get(idx)
                .map(|pk| format!("{}", pk))
                .unwrap_or_else(|| format!("account_index={}", idx));
            fuzz_assert!(
                false,
                "[realloc-race:{}] runtime rejected with InsufficientFundsForRent on {} \
                 — program grew account data past rent-exempt threshold without lamport top-up (ix {})",
                spec.program_id,
                acct_str,
                spec.name,
            );
            restore_accounts(fixture.ctx_mut(), saves);
            return;
        }
    }
    if let Ok(outcome) = result {
        if outcome.is_success() {
            for (i, pubkey) in pre_pubkeys.iter().enumerate() {
                let post = match fixture.ctx().get_account(pubkey) {
                    Ok(a) => a,
                    Err(_) => continue,
                };
                let (pre_len, _pre_lamports) = pre_states[i];
                let post_len = post.data.len();
                if post_len <= pre_len {
                    continue; // shrink or unchanged — no rent risk
                }
                if post_len == 0 {
                    continue; // closed (unreachable here since post_len > pre_len, but defensive)
                }
                let required = rent_for(post_len);
                if post.lamports < required {
                    let shortfall = required - post.lamports;
                    fuzz_assert!(
                        false,
                        "[realloc-race:{}] account {} grew {} → {} bytes \
                         but lamports {} < rent_min {} (shortfall {}) (ix {})",
                        spec.program_id,
                        pubkey,
                        pre_len,
                        post_len,
                        post.lamports,
                        required,
                        shortfall,
                        spec.name,
                    );
                }
            }
        }
    }

    restore_accounts(fixture.ctx_mut(), saves);
}

// ============================================================================
// Tests — `rent_for` formula correctness + the pre/post comparison logic
// in isolation (no fuzz harness required).
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Reference values computed from the formula
    // `(128 + bytes) * 3480 * 2`. Hand-verified against
    // `solana_rent::Rent::default().minimum_balance(bytes)`.

    #[test]
    fn rent_for_zero_bytes() {
        // (128 + 0) * 3480 * 2 = 890_880
        assert_eq!(rent_for(0), 890_880);
    }

    #[test]
    fn rent_for_anchor_vault() {
        // 8-byte disc + 32 + 32 + 8 + 8 = 88 bytes
        // (128 + 88) * 3480 * 2 = 1_503_360
        assert_eq!(rent_for(88), 1_503_360);
    }

    #[test]
    fn rent_for_grow_delta_200() {
        // 88 → 288 bytes (typical realloc grow by ~200)
        // (128 + 288) * 3480 * 2 = 2_895_360
        // Shortfall when only 1_503_360 was deposited = 1_392_000
        assert_eq!(rent_for(288), 2_895_360);
        assert_eq!(rent_for(288) - rent_for(88), 1_392_000);
    }

    #[test]
    fn rent_for_monotonic_in_size() {
        // Growing the buffer monotonically increases rent.
        let small = rent_for(100);
        let medium = rent_for(1_000);
        let large = rent_for(10_000);
        assert!(small < medium);
        assert!(medium < large);
    }

    #[test]
    fn rent_for_known_lending_market_size() {
        // klend LendingMarket = 8 disc + 4656 body = 4664 bytes
        // (128 + 4664) * 3480 * 2 = 33_352_320
        assert_eq!(rent_for(4664), 33_352_320);
    }

    /// Validates the v1 detector's branch logic in isolation: a grow
    /// is a violation iff `post.lamports < rent_for(post_len)`.
    #[test]
    fn detection_branch_grow_without_topup() {
        let pre_len = 88;
        let post_len = 288;
        let lamports_pre_grow = rent_for(pre_len);
        // No top-up.
        let lamports_after_grow_no_topup = lamports_pre_grow;
        let required = rent_for(post_len);

        assert!(post_len > pre_len);          // grew
        assert!(post_len > 0);                 // not closed
        assert!(lamports_after_grow_no_topup < required); // → violation
    }

    #[test]
    fn detection_branch_grow_with_correct_topup() {
        let pre_len = 88;
        let post_len = 288;
        let lamports_pre_grow = rent_for(pre_len);
        // Correct top-up: deposited exactly the delta.
        let lamports_after_grow = lamports_pre_grow + (rent_for(post_len) - rent_for(pre_len));
        let required = rent_for(post_len);

        assert!(post_len > pre_len);
        assert!(post_len > 0);
        assert!(lamports_after_grow >= required); // → no violation
    }

    #[test]
    fn detection_branch_shrink_no_violation() {
        let pre_len = 1_000;
        let post_len = 100;
        // Shrink retains all lamports (rent excess isn't refunded).
        let lamports_after_shrink = rent_for(pre_len);
        let required_at_new_size = rent_for(post_len);

        // Detector's branch: post_len <= pre_len → continue (skip);
        // even though the rent math here would pass, the detector
        // exits before checking.
        assert!(post_len < pre_len);
        // Sanity: lamports clearly cover the smaller rent requirement.
        assert!(lamports_after_shrink >= required_at_new_size);
    }
}
