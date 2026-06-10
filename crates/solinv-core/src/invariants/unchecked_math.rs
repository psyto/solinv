//! # Invariant: unchecked-math
//!
//! Detects arithmetic overflow / underflow / precision loss reaching
//! protocol-tracked state. Unlike the Critical 5, this invariant does
//! not mutate ix inputs — Crucible's mutator handles boundary biasing
//! on `data_sample`. solinv's contribution is the state-transition
//! sanity check: for each user-declared `StateInvariant` on an ix,
//! capture pre/post-image of the declared fields and verify the
//! invariant holds.
//!
//! See `docs/invariants/unchecked-math.md` for the bug class, mainnet
//! precedents, severity classification, the escrow-demo planted
//! fixture, and §9 — the pre-committed kill criterion gating
//! Phase 3 expansion.

use crucible_test_context::{fuzz_assert, TxOutcome};
use solana_keypair::Keypair;
use solana_signer::Signer;
use solinv_fuzz::{
    fingerprint_key, HasContext, HasInstructionSet, InstructionSpec,
    MonotonicDir, StateInvariant, StateInvariantKind, TransitionObservation,
};

use super::util::{
    read_field_widened, record_transition_fingerprint, restore_accounts, save_accounts,
};

/// Check the fixture's instruction set for unchecked-math violations.
///
/// For each ix that has at least one declared `StateInvariant`, runs
/// one attempt per invariant: save state, read pre-image, execute the
/// canonical ix unmodified (Crucible has already biased
/// `data_sample`), read post-image, check the invariant, restore.
pub fn check<F>(fixture: &mut F)
where
    F: HasContext + HasInstructionSet,
{
    let ixs = fixture.instructions();
    for spec in &ixs {
        for inv in &spec.state_invariants {
            run_attempt(fixture, spec, inv);
        }
    }
}

fn run_attempt<F>(fixture: &mut F, spec: &InstructionSpec, inv: &StateInvariant)
where
    F: HasContext + HasInstructionSet,
{
    let pubkeys: Vec<_> = spec.accounts.iter().map(|m| m.pubkey).collect();
    let saves = save_accounts(fixture.ctx(), &pubkeys);

    let Some(pre) = read_image(fixture, spec, inv) else {
        restore_accounts(fixture.ctx_mut(), saves);
        return;
    };

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

    let succeeded = matches!(result, Ok(TxOutcome::Success { .. }));
    if succeeded {
        let fp = fingerprint_key(spec, TransitionObservation::default());
        let _is_new = record_transition_fingerprint(fp);
        if let Some(post) = read_image(fixture, spec, inv) {
            if let Some(detail) = check_kind(&inv.kind, &pre, &post) {
                fuzz_assert!(
                    false,
                    "[unchecked-math:{}] ix {} violated state invariant '{}': {}",
                    spec.program_id,
                    spec.name,
                    inv.name,
                    detail,
                );
            }
        }
    }

    restore_accounts(fixture.ctx_mut(), saves);
}

fn read_image<F>(fixture: &F, spec: &InstructionSpec, inv: &StateInvariant) -> Option<Vec<u128>>
where
    F: HasContext,
{
    let (offset, size) = field_geom(&inv.kind);
    let mut values = Vec::with_capacity(inv.accounts.len());
    for &acct_idx in &inv.accounts {
        let pk = spec.accounts.get(acct_idx)?.pubkey;
        let acct = fixture.ctx().get_account(&pk).ok()?;
        let v = read_field_widened(&acct.data, offset, size)?;
        values.push(v);
    }
    Some(values)
}

fn field_geom(kind: &StateInvariantKind) -> (usize, usize) {
    match *kind {
        StateInvariantKind::SumConservation {
            field_offset,
            field_size,
            ..
        }
        | StateInvariantKind::Monotonic {
            field_offset,
            field_size,
            ..
        }
        | StateInvariantKind::Bounded {
            field_offset,
            field_size,
            ..
        } => (field_offset, field_size),
    }
}

fn check_kind(kind: &StateInvariantKind, pre: &[u128], post: &[u128]) -> Option<String> {
    match kind {
        StateInvariantKind::SumConservation { tolerance, .. } => {
            let pre_sum: u128 = pre.iter().sum();
            let post_sum: u128 = post.iter().sum();
            let drift = pre_sum.abs_diff(post_sum);
            (drift > *tolerance as u128).then(|| {
                format!(
                    "sum drifted by {drift} (pre {pre_sum}, post {post_sum}, tolerance {tolerance})"
                )
            })
        }
        StateInvariantKind::Monotonic { direction, .. } => {
            for (i, (p, q)) in pre.iter().zip(post.iter()).enumerate() {
                let bad = match direction {
                    MonotonicDir::NonDecreasing => q < p,
                    MonotonicDir::NonIncreasing => q > p,
                };
                if bad {
                    return Some(format!(
                        "account {i} {} (pre {p}, post {q})",
                        direction.violation_word()
                    ));
                }
            }
            None
        }
        StateInvariantKind::Bounded { min, max, .. } => {
            for (i, q) in post.iter().enumerate() {
                if q < min || q > max {
                    return Some(format!("account {i} out of bounds [{min}, {max}]: {q}"));
                }
            }
            None
        }
    }
}

#[cfg(test)]
mod tests {
    //! Direct tests for the pure detection logic (`check_kind`). The
    //! end-to-end pipeline (`check` against a real `TestContext` and
    //! `raw_call`) is exercised via escrow-demo's planted-bug ix
    //! (Day 33+) — system_program transfer can't host these tests
    //! because SystemProgram-owned accounts can't carry the non-empty
    //! data the invariants read.
    use super::*;

    fn sum_kind(tolerance: u64) -> StateInvariantKind {
        StateInvariantKind::SumConservation {
            field_offset: 0,
            field_size: 8,
            tolerance,
        }
    }

    fn mono_kind(direction: MonotonicDir) -> StateInvariantKind {
        StateInvariantKind::Monotonic {
            field_offset: 0,
            field_size: 8,
            direction,
        }
    }

    fn bounded_kind(min: u128, max: u128) -> StateInvariantKind {
        StateInvariantKind::Bounded {
            field_offset: 0,
            field_size: 8,
            min,
            max,
        }
    }

    #[test]
    fn sum_conservation_passes_at_zero_drift() {
        assert!(check_kind(&sum_kind(0), &[100, 50], &[120, 30]).is_none());
    }

    #[test]
    fn sum_conservation_passes_within_tolerance() {
        assert!(check_kind(&sum_kind(2), &[100, 50], &[100, 49]).is_none());
    }

    #[test]
    fn sum_conservation_fires_on_drift_above_tolerance() {
        let msg = check_kind(&sum_kind(2), &[100, 50], &[100, 47]).unwrap();
        assert!(msg.contains("drifted"));
    }

    #[test]
    fn monotonic_non_decreasing_passes_on_increase_or_flat() {
        assert!(check_kind(&mono_kind(MonotonicDir::NonDecreasing), &[10], &[10]).is_none());
        assert!(check_kind(&mono_kind(MonotonicDir::NonDecreasing), &[10], &[20]).is_none());
    }

    #[test]
    fn monotonic_non_decreasing_fires_on_decrease() {
        let msg = check_kind(&mono_kind(MonotonicDir::NonDecreasing), &[10], &[5]).unwrap();
        assert!(msg.contains("decreased"));
    }

    #[test]
    fn monotonic_fires_on_wrap_signature() {
        // u64 underflow signature: pre = small positive, post = near u64::MAX.
        let pre = 5u128;
        let post = u64::MAX as u128 - 4;
        // post > pre numerically, but the NonIncreasing direction catches it.
        let msg = check_kind(&mono_kind(MonotonicDir::NonIncreasing), &[pre], &[post]).unwrap();
        assert!(msg.contains("increased"));
    }

    #[test]
    fn bounded_passes_within_range() {
        assert!(check_kind(&bounded_kind(0, 1000), &[], &[500]).is_none());
        assert!(check_kind(&bounded_kind(0, 1000), &[], &[0]).is_none());
        assert!(check_kind(&bounded_kind(0, 1000), &[], &[1000]).is_none());
    }

    #[test]
    fn bounded_fires_above_max() {
        let msg = check_kind(&bounded_kind(0, 99), &[], &[100]).unwrap();
        assert!(msg.contains("out of bounds"));
    }

    #[test]
    fn bounded_fires_below_min() {
        let msg = check_kind(&bounded_kind(10, 1000), &[], &[5]).unwrap();
        assert!(msg.contains("out of bounds"));
    }

    #[test]
    fn bounded_catches_underflow_wrap_signature() {
        // Realistic underflow: balance was 5, ix did `balance -= 10`,
        // wrap to u64::MAX - 4. Bounded with a sane cap catches it.
        let post = u64::MAX as u128 - 4;
        let msg = check_kind(&bounded_kind(0, 1_000_000_000), &[], &[post]).unwrap();
        assert!(msg.contains("out of bounds"));
    }
}
