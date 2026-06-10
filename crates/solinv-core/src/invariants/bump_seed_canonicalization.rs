//! # Invariant: bump-seed-canonicalization
//!
//! Detects programs that accept non-canonical PDA bumps. For each
//! ix whose spec carries `Some(BumpSeedCheckConfig)`, iterates each
//! PDA account in `expected_pda_seeds`, finds a non-canonical bump
//! that still yields a valid (off-curve) PDA, substitutes that PDA
//! in the AccountMeta (and optionally patches the ix-data bump byte
//! per `cfg.bump_data_offset`), and fires `fuzz_assert!` if the ix
//! still succeeds.
//!
//! See `docs/invariants/bump-seed-canonicalization.md` for the bug
//! class, mainnet precedents (OtterSec audit findings, Solana docs
//! warning since 2022, Magic Bytes #4 in 2024 top-10), severity
//! bands, the planted-bug fixture in escrow-demo, and §9 / §10 —
//! the Phase 2.5 OSS catalog-completion framing inherited from
//! realloc-race.

use crucible_test_context::{fuzz_assert, TxOutcome};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solinv_fuzz::{HasContext, HasInstructionSet, InstructionSpec};

use super::util::cleanup_temp_account;

/// Check the fixture's instruction set for bump-seed-canonicalization
/// violations.
///
/// For each ix whose spec carries `Some(BumpSeedCheckConfig)`, walks
/// the spec's PDA-derived accounts (those with `expected_pda_seeds[i]
/// = Some(seeds)` and not in `creates_indices`), finds an alt-bump
/// PDA, pre-creates an account at the alt PDA with cloned canonical
/// state, substitutes the alt PDA in the AccountMeta (and optionally
/// patches the ix-data bump byte), and fires if the ix succeeds.
pub fn check<F>(fixture: &mut F)
where
    F: HasContext + HasInstructionSet,
{
    let ixs = fixture.instructions();
    for spec in &ixs {
        if spec.bump_seed_check.is_none() {
            continue;
        }
        run_attempt(fixture, spec);
    }
}

fn run_attempt<F>(fixture: &mut F, spec: &InstructionSpec)
where
    F: HasContext + HasInstructionSet,
{
    let cfg = spec.bump_seed_check.as_ref().unwrap();
    for (idx, expected_seeds) in spec.expected_pda_seeds.iter().enumerate() {
        let Some(seeds) = expected_seeds else {
            continue;
        };
        if spec.creates_indices.contains(&idx) {
            continue;
        }

        let Some((alt_bump, alt_pda)) =
            find_alt_canonical_pda(seeds, &spec.program_id)
        else {
            continue;
        };

        let canonical_pk = spec.accounts[idx].pubkey;
        let canonical_acc = match fixture.ctx().get_account(&canonical_pk) {
            Ok(a) => a,
            Err(_) => continue,
        };

        // Pre-create alt_pda with cloned canonical state.
        if fixture
            .ctx_mut()
            .write_account(&alt_pda, canonical_acc.clone())
            .is_err()
        {
            continue;
        }

        // Build the modified ix.
        let mut ix = spec.to_instruction();
        ix.accounts[idx].pubkey = alt_pda;
        if let Some(offset) = cfg.bump_data_offset {
            if offset < ix.data.len() {
                ix.data[offset] = alt_bump;
            }
        }

        let fee_payer = fixture.fee_payer();
        let mut signer_refs: Vec<&Keypair> = vec![&*fee_payer];
        for kp in &spec.signers {
            if kp.pubkey() != fee_payer.pubkey() {
                signer_refs.push(&**kp);
            }
        }

        let result = fixture
            .ctx_mut()
            .raw_call(ix)
            .fee_payer(&*fee_payer)
            .signers(&signer_refs)
            .send();

        if let Ok(TxOutcome::Success { .. }) = result {
            fuzz_assert!(
                false,
                "[bump-seed-canonicalization:{}] non-canonical bump {} for account {} \
                 accepted (canonical was {}, ix {})",
                spec.program_id,
                alt_bump,
                alt_pda,
                canonical_pk,
                spec.name,
            );
            cleanup_temp_account(fixture.ctx_mut(), &alt_pda);
            return;
        }

        cleanup_temp_account(fixture.ctx_mut(), &alt_pda);
    }
}

/// Given a seed prefix and program ID, find a non-canonical bump
/// that yields a different valid PDA than the canonical bump.
///
/// The canonical bump is the highest bump (from 255 down to 0) where
/// `create_program_address(seeds + [bump])` returns `Ok`. The
/// function iterates lower bumps to find one that also yields `Ok`
/// (i.e., an off-curve point) at a different address. Returns the
/// first such `(alt_bump, alt_pda)` or `None` if no non-canonical
/// alternative exists for these seeds.
///
/// Note: for short seed prefixes most bumps below the canonical yield
/// valid alt PDAs — finding one is typically near-instant. For longer
/// seeds, the search may exhaust without finding an alt; in that case
/// the bug class doesn't apply to that account.
pub fn find_alt_canonical_pda(
    seeds: &[Vec<u8>],
    program_id: &Pubkey,
) -> Option<(u8, Pubkey)> {
    let slices: Vec<&[u8]> = seeds.iter().map(|s| s.as_slice()).collect();
    let (canonical_pda, canonical_bump) =
        Pubkey::find_program_address(&slices, program_id);
    for b in (0..canonical_bump).rev() {
        let bump_slice = [b];
        let mut with_bump = slices.clone();
        with_bump.push(&bump_slice);
        if let Ok(alt_pda) = Pubkey::create_program_address(&with_bump, program_id) {
            if alt_pda != canonical_pda {
                return Some((b, alt_pda));
            }
        }
    }
    None
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(seed: u8) -> Pubkey {
        Pubkey::new_from_array([seed; 32])
    }

    #[test]
    fn find_alt_for_short_seed_succeeds() {
        // Most short seed prefixes produce multiple valid PDAs across
        // the bump range — finding an alt is virtually always possible.
        let seeds = vec![b"vault".to_vec()];
        let program_id = pk(1);
        let result = find_alt_canonical_pda(&seeds, &program_id);
        assert!(result.is_some(), "expected alt bump for short seed");
        let (alt_bump, alt_pda) = result.unwrap();
        let (canonical_pda, canonical_bump) = Pubkey::find_program_address(
            &seeds.iter().map(|s| s.as_slice()).collect::<Vec<_>>(),
            &program_id,
        );
        assert!(alt_bump < canonical_bump);
        assert_ne!(alt_pda, canonical_pda);
    }

    #[test]
    fn find_alt_for_seed_with_pubkey() {
        // Realistic shape: seed prefix + 32-byte pubkey (Solana's
        // canonical user-derived PDA pattern).
        let owner = pk(7);
        let seeds = vec![b"vault".to_vec(), owner.to_bytes().to_vec()];
        let program_id = pk(2);
        let result = find_alt_canonical_pda(&seeds, &program_id);
        assert!(result.is_some(), "expected alt bump for vault PDA shape");
    }

    #[test]
    fn alt_pda_verifiable_via_create_program_address() {
        // The returned alt_pda + alt_bump must round-trip through
        // create_program_address — i.e., the alt PDA is a legitimate
        // PDA, just not the canonical one.
        let seeds = vec![b"pool".to_vec()];
        let program_id = pk(3);
        let (alt_bump, alt_pda) =
            find_alt_canonical_pda(&seeds, &program_id).expect("alt expected");
        let bump_slice = [alt_bump];
        let mut with_bump: Vec<&[u8]> = seeds.iter().map(|s| s.as_slice()).collect();
        with_bump.push(&bump_slice);
        let verified =
            Pubkey::create_program_address(&with_bump, &program_id).expect("valid pda");
        assert_eq!(verified, alt_pda);
    }

    #[test]
    fn alt_bump_lower_than_canonical() {
        // Sanity: any alt_bump returned is strictly less than the
        // canonical bump (the search starts at canonical_bump - 1).
        for prog_seed in 1u8..10u8 {
            let seeds = vec![b"x".to_vec()];
            let program_id = pk(prog_seed);
            if let Some((alt_bump, _)) = find_alt_canonical_pda(&seeds, &program_id) {
                let (_, canonical_bump) = Pubkey::find_program_address(
                    &seeds.iter().map(|s| s.as_slice()).collect::<Vec<_>>(),
                    &program_id,
                );
                assert!(alt_bump < canonical_bump);
            }
        }
    }

    #[test]
    fn find_alt_is_deterministic() {
        // Same inputs → same alt result. Important for replayability
        // of detected violations.
        let seeds = vec![b"vault".to_vec(), pk(11).to_bytes().to_vec()];
        let program_id = pk(4);
        let a = find_alt_canonical_pda(&seeds, &program_id);
        let b = find_alt_canonical_pda(&seeds, &program_id);
        assert_eq!(a, b);
    }
}
