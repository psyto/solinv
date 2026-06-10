//! # Invariant: cu-dos
//!
//! Detects per-ix compute-unit consumption above a user-declared cap,
//! the surface signature for CU-budget DoS bugs (unbounded loops on
//! attacker-controllable inputs, O(n²) algorithms, CPI cascades,
//! storage iteration over growable structures).
//!
//! Detection is a one-line compare: execute the ix unmodified
//! (Crucible's mutator handles boundary biasing on `data_sample`),
//! read `compute_units` off the `TxOutcome::Success` variant, fire
//! if it exceeds `spec.cu_budget`.
//!
//! See `docs/invariants/cu-dos.md` for the bug class, cap selection
//! guidance, severity bands, the escrow-demo planted fixture, and
//! §9 — the pre-committed kill criterion gating Phase 3 expansion
//! after unchecked-math's Day 34 Gate 2 fail.

use crucible_test_context::{fuzz_assert, TxOutcome};
use solana_keypair::Keypair;
use solana_signer::Signer;
use solinv_fuzz::{
    fingerprint_key, HasContext, HasInstructionSet, InstructionSpec, TokenFlowShape,
    TransitionObservation,
};

use super::util::{
    record_transition_fingerprint, restore_accounts, save_accounts,
};

/// Check the fixture's instruction set for cu-dos violations.
///
/// For each ix with a declared `cu_budget`, executes the canonical
/// ix unmodified, reads consumed CU off the Success variant, and
/// fires if the consumption exceeds the cap. Per-ix state is saved
/// and restored around the execution.
pub fn check<F>(fixture: &mut F)
where
    F: HasContext + HasInstructionSet,
{
    let ixs = fixture.instructions();
    for spec in &ixs {
        let Some(budget) = spec.cu_budget else {
            continue;
        };
        run_attempt(fixture, spec, budget);
    }
}

fn run_attempt<F>(fixture: &mut F, spec: &InstructionSpec, budget: u64)
where
    F: HasContext + HasInstructionSet,
{
    let pubkeys: Vec<_> = spec.accounts.iter().map(|m| m.pubkey).collect();
    let saves = save_accounts(fixture.ctx(), &pubkeys);

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

    if let Ok(TxOutcome::Success { compute_units, .. }) = result {
        let fp = fingerprint_key(
            spec,
            TransitionObservation {
                cpi_depth: 0,
                token_flow: TokenFlowShape::Unknown,
            },
        );
        let _is_new = record_transition_fingerprint(fp);
        fuzz_assert!(
            compute_units <= budget,
            "[cu-dos:{}] ix {} consumed {} CU (cap {})",
            spec.program_id,
            spec.name,
            compute_units,
            budget,
        );
    }

    restore_accounts(fixture.ctx_mut(), saves);
}
