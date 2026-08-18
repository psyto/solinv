//! # Invariant: precondition-skip
//!
//! Detects an instruction succeeding while a declared precondition was
//! false — a dropped or weakened `require!` at the top of a handler.
//!
//! Every other detector in the catalog asks what an instruction did to
//! state. This one asks whether it should have run at all. The
//! distinction matters because the two failure modes look nothing alike
//! from a detector's side: a bad write leaves evidence in the post-state,
//! while a missing guard leaves a *correct-looking* transition that
//! simply should not have happened.
//!
//! ## Why this exists
//!
//! A mutation campaign against `escrow-clean` located the gap
//! empirically. Nine mutants survived; five were `guard-drop` on
//! `require!` statements — timelock comparisons and amount bounds — and
//! no invariant in the catalog modelled that shape. One of the five
//! reproduces exactly the timelock race that `escrow-demo` plants as its
//! flagship bug, which until now was reported as "detected" only because
//! that harness carries a hand-written `fuzz_assert_lt!` over recorded
//! withdraw slots. No detector was finding it.
//!
//! ## Detection
//!
//! For each ix with declared `guards`: capture the pre-state, send the
//! canonical instruction, and if it *succeeded*, evaluate every guard
//! against the captured pre-state. Any guard that was false is a
//! violation.
//!
//! Two ordering decisions carry the whole method:
//!
//! - **Pre-state, not post-state.** `withdraw` moves the very balance
//!   `amount <= vault.amount` constrains, so evaluating afterwards would
//!   test the guard against state the instruction itself changed, and a
//!   correct handler would look like a violation.
//! - **Only on success.** A guard being false is the normal case — it is
//!   what the fuzzer must produce for the check to mean anything. The
//!   violation is a false guard *and* an accepted instruction.
//!
//! ## What it cannot see
//!
//! Guards are declarations, not inferences. An unstated `require!` is
//! invisible here, and a guard stated wrongly reports on correct code.
//! That is the same bargain the rest of the catalog's declared
//! capabilities make, and it is why a clean target's baseline must be
//! silent before any campaign against it means anything.

use crucible_test_context::{fuzz_assert, TxOutcome};
use solana_keypair::Keypair;
use solana_signer::Signer;
use solinv_fuzz::{
    GuardCondition, GuardOperand, HasContext, HasInstructionSet, InstructionSpec,
};

use super::reachability::record_ix_reached;
use super::util::{read_field_widened, restore_accounts, save_accounts};

/// Check the fixture's instruction set for precondition-skip violations.
pub fn check<F>(fixture: &mut F)
where
    F: HasContext + HasInstructionSet,
{
    let ixs = fixture.instructions();
    for spec in &ixs {
        if spec.guards.is_empty() {
            continue;
        }
        run_attempt(fixture, spec);
    }
}

/// One operand's value, read from the pre-state.
///
/// `None` means the operand could not be read — a field offset past the
/// end of an account, or an unsupported width. A guard with an
/// unreadable operand is skipped rather than assumed violated: a
/// declaration that cannot be evaluated is a declaration bug, and firing
/// on it would report the harness as a program defect.
fn operand_value(
    operand: &GuardOperand,
    account_data: &[Option<Vec<u8>>],
    ix_data: &[u8],
    slot: u64,
) -> Option<u128> {
    match operand {
        GuardOperand::Const(v) => Some(*v),
        GuardOperand::Slot => Some(slot as u128),
        GuardOperand::IxData { offset, size } => read_field_widened(ix_data, *offset, *size),
        GuardOperand::Field {
            account_index,
            field_offset,
            field_size,
        } => {
            let data = account_data.get(*account_index)?.as_ref()?;
            read_field_widened(data, *field_offset, *field_size)
        }
    }
}

fn run_attempt<F>(fixture: &mut F, spec: &InstructionSpec)
where
    F: HasContext + HasInstructionSet,
{
    let pubkeys: Vec<_> = spec.accounts.iter().map(|m| m.pubkey).collect();
    let saves = save_accounts(fixture.ctx(), &pubkeys);

    // Everything the guards read, captured before the send.
    let pre_data: Vec<Option<Vec<u8>>> = pubkeys
        .iter()
        .map(|pk| fixture.ctx().get_account(pk).ok().map(|a| a.data.clone()))
        .collect();
    let pre_slot = fixture.ctx().slot();
    let ix_data = spec.data_sample.clone();

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

    if matches!(result, Ok(TxOutcome::Success { .. })) {
        // Canonical ix accepted — the program's happy path ran.
        record_ix_reached(&spec.program_id, &spec.name);

        for guard in &spec.guards {
            report_if_violated(spec, guard, &pre_data, &ix_data, pre_slot);
        }
    }

    restore_accounts(fixture.ctx_mut(), saves);
}

fn report_if_violated(
    spec: &InstructionSpec,
    guard: &GuardCondition,
    pre_data: &[Option<Vec<u8>>],
    ix_data: &[u8],
    pre_slot: u64,
) {
    let (Some(lhs), Some(rhs)) = (
        operand_value(&guard.lhs, pre_data, ix_data, pre_slot),
        operand_value(&guard.rhs, pre_data, ix_data, pre_slot),
    ) else {
        return;
    };

    fuzz_assert!(
        guard.op.holds(lhs, rhs),
        "[precondition-skip:{}] ix {} succeeded while '{}' did not hold \
         ({} {} {} is false)",
        spec.program_id,
        spec.name,
        guard.name,
        lhs,
        guard.op.symbol(),
        rhs,
    );
}

#[cfg(test)]
mod tests {
    use solinv_fuzz::{GuardOp, GuardOperand};

    use super::*;

    fn field(offset: usize) -> GuardOperand {
        GuardOperand::Field {
            account_index: 0,
            field_offset: offset,
            field_size: 8,
        }
    }

    fn account(values: &[u64]) -> Vec<Option<Vec<u8>>> {
        let mut data = Vec::new();
        for v in values {
            data.extend_from_slice(&v.to_le_bytes());
        }
        vec![Some(data)]
    }

    #[test]
    fn reads_a_field_a_slot_and_a_constant() {
        let data = account(&[7, 9]);
        assert_eq!(operand_value(&field(0), &data, &[], 3), Some(7));
        assert_eq!(operand_value(&field(8), &data, &[], 3), Some(9));
        assert_eq!(operand_value(&GuardOperand::Slot, &data, &[], 3), Some(3));
        assert_eq!(
            operand_value(&GuardOperand::Const(42), &data, &[], 3),
            Some(42)
        );
    }

    #[test]
    fn reads_an_instruction_argument_past_the_sighash() {
        let mut ix_data = vec![0u8; 8];
        ix_data.extend_from_slice(&1234u64.to_le_bytes());
        let operand = GuardOperand::IxData {
            offset: 8,
            size: 8,
        };
        assert_eq!(operand_value(&operand, &[], &ix_data, 0), Some(1234));
    }

    #[test]
    fn an_unreadable_operand_yields_none_rather_than_zero() {
        // Zero would be a plausible-looking value that silently makes
        // `amount > 0` guards read as violated on correct programs.
        let data = account(&[1]);
        assert_eq!(operand_value(&field(64), &data, &[], 0), None);
        assert_eq!(operand_value(&field(0), &[], &[], 0), None);
        let bad_width = GuardOperand::Field {
            account_index: 0,
            field_offset: 0,
            field_size: 4,
        };
        assert_eq!(operand_value(&bad_width, &data, &[], 0), None);
    }

    #[test]
    fn operators_compare_as_named() {
        assert!(GuardOp::Lt.holds(1, 2));
        assert!(!GuardOp::Lt.holds(2, 2));
        assert!(GuardOp::Le.holds(2, 2));
        assert!(GuardOp::Ge.holds(2, 2));
        assert!(!GuardOp::Gt.holds(2, 2));
        assert!(GuardOp::Eq.holds(2, 2));
        assert!(GuardOp::Ne.holds(1, 2));
    }

    // The timelock case, evaluated the way the detector does it: a
    // withdraw at slot 10 against unlock_slot 10 is a violation of
    // `slot < unlock_slot` — and it is exactly the boundary the escrow
    // planted bug turns on, `<=` where `<` was meant.
    #[test]
    fn the_timelock_boundary_is_the_case_that_separates_them() {
        let vault = account(&[10]); // unlock_slot = 10
        let unlock = operand_value(&field(0), &vault, &[], 0).unwrap();
        for (slot, expected) in [(9u64, true), (10, false), (11, false)] {
            let now = operand_value(&GuardOperand::Slot, &vault, &[], slot).unwrap();
            assert_eq!(
                GuardOp::Lt.holds(now, unlock),
                expected,
                "slot {slot} vs unlock {unlock}"
            );
        }
    }
}
