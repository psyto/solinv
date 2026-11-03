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
    fingerprint_key, HasContext, HasInstructionSet, InstructionSpec, MonotonicDir, RelOp, RelTerm,
    StateInvariant, StateInvariantKind, TransitionObservation,
};

use super::util::{
    read_field_widened, record_transition_fingerprint, restore_accounts, save_accounts,
    warn_declaration_once,
};
use super::reachability::record_ix_reached;

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
        warn_unreadable(spec, inv, "pre-state");
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

    // A relation that was already false before the ix ran indicts the
    // declaration or the fixture, not the instruction. Firing on it
    // would attribute a pre-existing condition to whatever ix happened
    // to execute next, so the detector stays silent — but says so,
    // because a relation that never holds also never fires, and a
    // permanently-silent invariant looks exactly like a passing one.
    if relation_held_pre(&inv.kind, &pre) == Some(false) {
        warn_declaration_once(
            format!("relation-pre:{}:{}:{}", spec.program_id, spec.name, inv.name),
            &format!(
                "ix {} invariant '{}': relation does not hold in the pre-state \
                 (lhs {}, rhs {}) — it cannot fire until the declaration or the \
                 fixture's initial state is corrected",
                spec.name,
                inv.name,
                pre.first().copied().unwrap_or_default(),
                pre.get(1).copied().unwrap_or_default(),
            ),
        );
    }

    let succeeded = matches!(result, Ok(TxOutcome::Success { .. }));
    if succeeded {
        // Canonical ix accepted — the program's happy path ran. See
        // `reachability` for why only untampered sends are recorded.
        record_ix_reached(&spec.program_id, &spec.name);
        let fp = fingerprint_key(spec, TransitionObservation::default());
        let _is_new = record_transition_fingerprint(fp);
        match read_image(fixture, spec, inv) {
            Some(post) => {
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
            None => warn_unreadable(spec, inv, "post-state"),
        }
    }

    restore_accounts(fixture.ctx_mut(), saves);
}

/// Report a declared field the detector could not read.
///
/// Reaching this means the invariant contributed nothing to the
/// campaign. See `warn_declaration_once` for why that must be loud.
fn warn_unreadable(spec: &InstructionSpec, inv: &StateInvariant, phase: &str) {
    warn_declaration_once(
        format!(
            "unreadable:{}:{}:{}:{}",
            spec.program_id, spec.name, inv.name, phase
        ),
        &format!(
            "ix {} invariant '{}': declared field(s) unreadable in {phase} — offset past \
             the end of account data, an unsupported width, or a missing account. This \
             invariant is checking nothing; a clean run is not evidence. Declaring the \
             layout via solinv_fuzz::AccountSchema and calling validate_len() against \
             real account data catches this at fixture-build time.",
            spec.name, inv.name,
        ),
    );
}

/// Read the fields an invariant declares, as a flat value vector.
///
/// The three uniform kinds produce one value per declared account. A
/// `Relation` instead produces exactly two — the summed left side and
/// the summed right side — so the pre/post comparison flow above works
/// unchanged for every kind.
fn read_image<F>(fixture: &F, spec: &InstructionSpec, inv: &StateInvariant) -> Option<Vec<u128>>
where
    F: HasContext,
{
    if let StateInvariantKind::Relation { lhs, rhs, .. } = &inv.kind {
        let l = sum_terms(fixture, spec, lhs)?;
        let r = sum_terms(fixture, spec, rhs)?;
        return Some(vec![l, r]);
    }

    let (offset, size) = field_geom(&inv.kind)?;
    let mut values = Vec::with_capacity(inv.accounts.len());
    for &acct_idx in &inv.accounts {
        let pk = spec.accounts.get(acct_idx)?.pubkey;
        let acct = fixture.ctx().get_account(&pk).ok()?;
        let v = read_field_widened(&acct.data, offset, size)?;
        values.push(v);
    }
    Some(values)
}

/// Sum one side of a relation.
///
/// Returns `None` if any term is unreadable, or if the sum would
/// exceed `u128` — a wrapped total would compare as a plausible value
/// and defeat the relation it is supposed to establish.
fn sum_terms<F>(fixture: &F, spec: &InstructionSpec, terms: &[RelTerm]) -> Option<u128>
where
    F: HasContext,
{
    let mut acc: u128 = 0;
    for term in terms {
        let v = match *term {
            RelTerm::Const(c) => c,
            RelTerm::Field {
                account,
                field_offset,
                field_size,
            } => {
                let pk = spec.accounts.get(account)?.pubkey;
                let acct = fixture.ctx().get_account(&pk).ok()?;
                read_field_widened(&acct.data, field_offset, field_size)?
            }
        };
        acc = acc.checked_add(v)?;
    }
    Some(acc)
}

/// Uniform `(offset, size)` for the three single-geometry kinds.
/// `Relation` has no single geometry — its terms each carry their own
/// — so it yields `None` and is read by [`sum_terms`] instead.
fn field_geom(kind: &StateInvariantKind) -> Option<(usize, usize)> {
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
        } => Some((field_offset, field_size)),
        StateInvariantKind::Relation { .. } => None,
    }
}

/// Whether a `Relation` held in the pre-state.
///
/// `None` for every other kind — they have no pre-condition gate.
fn relation_held_pre(kind: &StateInvariantKind, pre: &[u128]) -> Option<bool> {
    match kind {
        StateInvariantKind::Relation {
            op, tolerance, ..
        } => {
            let lhs = *pre.first()?;
            let rhs = *pre.get(1)?;
            Some(op.holds(lhs, rhs, *tolerance))
        }
        _ => None,
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
        StateInvariantKind::Relation {
            lhs,
            op,
            rhs,
            tolerance,
        } => {
            // `pre`/`post` are [lhs_sum, rhs_sum] per `read_image`.
            let (lp, rp) = (*pre.first()?, *pre.get(1)?);
            let (lq, rq) = (*post.first()?, *post.get(1)?);

            // Pre-gate: only an ix that *broke* the relation is a
            // finding. See the caller for the diagnostic emitted when
            // the relation was already false.
            if !op.holds(lp, rp, *tolerance) {
                return None;
            }
            if op.holds(lq, rq, *tolerance) {
                return None;
            }
            let tol = if *op == RelOp::Eq && *tolerance != 0 {
                format!(" (tolerance {tolerance})")
            } else {
                String::new()
            };
            Some(format!(
                "relation broken: sum(lhs, {} terms) {} sum(rhs, {} terms){} held pre \
                 ({lp} {} {rp}) but failed post ({lq} vs {rq})",
                lhs.len(),
                op.symbol(),
                rhs.len(),
                tol,
                op.symbol(),
            ))
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

    fn rel_kind(op: RelOp, tolerance: u64) -> StateInvariantKind {
        // Term geometry is irrelevant to `check_kind` — it consumes the
        // already-summed [lhs, rhs] pair from `read_image`. Two terms
        // on the left, one on the right, so the message reports a
        // realistic shape.
        StateInvariantKind::Relation {
            lhs: vec![
                RelTerm::Field {
                    account: 0,
                    field_offset: 0,
                    field_size: 8,
                },
                RelTerm::Field {
                    account: 1,
                    field_offset: 0,
                    field_size: 8,
                },
            ],
            op,
            rhs: vec![RelTerm::Field {
                account: 2,
                field_offset: 0,
                field_size: 8,
            }],
            tolerance,
        }
    }

    #[test]
    fn relation_fires_when_an_ix_breaks_a_relation_that_held() {
        // liquidity + borrowed == total, then the ix loses 10 units.
        let msg = check_kind(&rel_kind(RelOp::Eq, 0), &[100, 100], &[90, 100]).unwrap();
        assert!(msg.contains("relation broken"), "{msg}");
        assert!(msg.contains("held pre"), "{msg}");
    }

    #[test]
    fn relation_passes_when_it_still_holds() {
        assert!(check_kind(&rel_kind(RelOp::Eq, 0), &[100, 100], &[150, 150]).is_none());
    }

    #[test]
    fn relation_stays_silent_when_it_did_not_hold_pre() {
        // Already broken before the ix: not this instruction's doing,
        // so no violation. The caller emits a declaration diagnostic
        // instead — see `relation_held_pre`.
        assert!(check_kind(&rel_kind(RelOp::Eq, 0), &[90, 100], &[80, 100]).is_none());
    }

    #[test]
    fn relation_honors_tolerance_on_eq_only() {
        // Drift of 2 inside a tolerance of 2 is not a violation.
        assert!(check_kind(&rel_kind(RelOp::Eq, 2), &[100, 100], &[98, 100]).is_none());
        // Same drift with an ordering operator ignores tolerance.
        let msg = check_kind(&rel_kind(RelOp::Ge, 0), &[100, 100], &[98, 100]).unwrap();
        assert!(msg.contains("relation broken"), "{msg}");
    }

    #[test]
    fn relation_catches_an_inequality_crossing() {
        // sum(user deposits) <= vault balance, until it doesn't.
        assert!(check_kind(&rel_kind(RelOp::Le, 0), &[50, 100], &[80, 100]).is_none());
        let msg = check_kind(&rel_kind(RelOp::Le, 0), &[50, 100], &[101, 100]).unwrap();
        assert!(msg.contains("<="), "{msg}");
    }

    #[test]
    fn relation_held_pre_reports_only_for_relations() {
        assert_eq!(relation_held_pre(&rel_kind(RelOp::Eq, 0), &[10, 10]), Some(true));
        assert_eq!(relation_held_pre(&rel_kind(RelOp::Eq, 0), &[10, 20]), Some(false));
        assert_eq!(relation_held_pre(&bounded_kind(0, 10), &[5]), None);
    }

    #[test]
    fn field_geom_is_none_for_relation() {
        assert_eq!(field_geom(&bounded_kind(0, 10)), Some((0, 8)));
        assert!(field_geom(&rel_kind(RelOp::Eq, 0)).is_none());
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
