# Invariant: precondition-skip

Tier: High. Status: implemented, Gate 1 passed on `escrow-clean`.

## 1. Bug class

A handler guards its entry with a condition — a timelock, a balance
bound, an authority state, a lifecycle flag — and the guard is missing,
weakened, or ordered wrongly. The instruction then succeeds in a state
where the protocol's own rules say it should not have.

The other ten invariants in the catalog ask what an instruction *did*
to state. This one asks whether it was allowed to run. The distinction
is not academic: the two failure modes look different from a detector's
side. A bad write leaves evidence in the post-state, and a
post-state-comparison detector finds it. A missing guard leaves a
*correct-looking* transition — the arithmetic is right, the accounts
are right, the discriminator is right — that simply should not have
happened. Nothing in the post-state distinguishes an early withdrawal
from a legitimate one.

Concrete shapes:

| Shape | Example |
|---|---|
| Timelock boundary | `require!(slot < unlock_slot)` written as `<=`, letting the depositor drain at the unlock slot and race the beneficiary |
| Balance bound | `require!(amount <= vault.amount)` dropped, so the debit runs against whatever the caller asked for |
| Non-empty / non-zero | `require!(amount > 0)` dropped, allowing no-op instructions that still emit events or advance counters |
| Lifecycle flag | an ix that should only run once, or only after initialization, with no state check |

The timelock shape is the one worth naming, because a boundary error
there is a *race*, not a rejected transaction. Both parties' code
paths are legal at the boundary slot, and which one lands is a matter
of ordering.

## 2. Why this invariant exists

It was located empirically rather than proposed. A mutation campaign
against `examples/escrow-demo/programs/escrow-clean` produced nine
survivors; triage put five of them in one bucket — `guard-drop` on
`require!` statements, timelocks and amount bounds — and no invariant
in the catalog modelled that shape. Nothing could have killed them.

One of the five reproduces exactly the timelock race that
`escrow-demo` plants as its flagship bug. That bug had been reported as
detected since Phase 1, and it was: the escrow harness carries a
hand-written `fuzz_assert_lt!` over recorded withdraw slots. **No
detector in the catalog was finding it.** The mutation campaign is what
separated "the harness catches this" from "solinv catches this".

## 3. Detection algorithm

For each instruction with declared `guards`:

1. Capture the pre-state: the data of every account in the spec, the
   current slot, and the instruction data.
2. Send the canonical instruction.
3. If it **succeeded**, evaluate every guard against the captured
   pre-state.
4. Any guard that evaluates false is a violation.

Two ordering decisions carry the whole method.

**Pre-state, not post-state.** `withdraw` moves the very balance that
`amount <= vault.amount` constrains. Evaluating afterwards would test
the guard against state the instruction itself changed, and a correct
handler would look like a violation on every successful call.

**Only on success.** A guard being false is the normal case — it is
precisely what the fuzzer has to produce for the check to mean
anything. The violation is the conjunction: a false guard *and* an
accepted instruction.

## 4. Capability

```rust
pub struct GuardCondition {
    pub name: String,          // surfaced in the violation message
    pub lhs: GuardOperand,
    pub op: GuardOp,           // Lt | Le | Gt | Ge | Eq | Ne
    pub rhs: GuardOperand,
}

pub enum GuardOperand {
    Field { account_index: usize, field_offset: usize, field_size: usize },
    Slot,
    IxData { offset: usize, size: usize },
    Const(u128),
}
```

`Slot` is the operand that makes timelocks expressible; `IxData` is the
one that makes argument bounds expressible. Widths follow the same 8/16
rule as `StateInvariant`, and Anchor arguments start at offset 8, after
the sighash.

Declared on `InstructionSpec.guards`. Empty = opt out.

```rust
guards: vec![
    guard("withdraw only strictly before unlock",
          GuardOperand::Slot, GuardOp::Lt, vault_field(UNLOCK_SLOT_OFFSET)),
    guard("withdraw no more than the vault holds",
          arg_amount(), GuardOp::Le, vault_field(AMOUNT_OFFSET)),
],
```

## 5. False-positive risks and mitigations

**A wrong declaration reports on correct code.** This is the dominant
risk and it is not hypothetical — during development, declaring
`initialize`'s payer as the fixture's `fee_payer` produced 19998
`signer-skip` findings against a correct program, because the fee payer
signs the transaction whatever its `AccountMeta` says. The same class
of mistake in a guard offset or operator produces the same kind of
noise.

Mitigation is procedural rather than algorithmic: **the baseline must
be silent.** A clean target's unmutated run has to report nothing
before any campaign against it means anything, and a non-empty baseline
is a defect in the declaration to fix, never a number to subtract.

**An unreadable operand is skipped, not assumed violated.** A field
offset past the end of an account, or an unsupported width, yields
`None` and the guard does not fire. Defaulting to `0` would be worse
than skipping: it is a plausible-looking value that makes every
`amount > 0` guard read as violated on correct programs.

**Unstated guards are invisible.** The detector checks what was
declared. This is the same bargain the rest of the catalog's declared
capabilities make.

## 6. Severity classification

Follows the guard, not the mechanism:

| Guard shape | Typical severity |
|---|---|
| Timelock / vesting boundary | **Critical** — direct fund loss, and a race rather than a rejection |
| Balance or collateral bound | **Critical** — over-withdrawal is the canonical drain |
| Authority / lifecycle flag | High — depends what the flag gates |
| Non-zero / non-empty | Low to Medium — usually a griefing or accounting-noise surface |

## 7. Test fixture

`examples/escrow-demo/programs/escrow-clean`, which declares five
guards across `deposit`, `withdraw` and `claim`.

Gate 1, measured:

- **Baseline silent.** The unmutated program reports zero violations
  across all eleven detectors, guards included.
- **Timelock mutant killed.** Applying `guard-drop@…lib.rs:73#1`, which
  deletes `require!(clock.slot < vault.unlock_slot)`, produces 2090
  findings in a 30-second run:
  `ix withdraw succeeded while 'withdraw only strictly before unlock'`.

The mutant is the fixture. That is the point of building the invariant
from a mutation campaign rather than from a hand-written planted bug:
the bug is generated by an operator, not chosen by the person writing
the detector, so it cannot be shaped to fit.

## 8. References

- Mutation campaign record:
  [`examples/escrow-demo/campaigns/`](../../examples/escrow-demo/campaigns/)
- Design note: [`docs/mutation-testing.md`](../mutation-testing.md)
- Implementation:
  `crates/solinv-core/src/invariants/precondition_skip.rs`

## 9. Experiment design and kill criterion

Committed before the post-implementation campaign was run.

**Question.** Does declaring guards close the gap the campaign located,
or does it only appear to?

**Prediction.** The three guards whose falsity the fuzzer can reach —
`withdraw`'s timelock and balance bound, `claim`'s timelock — are
killed. The two `amount > 0` guards on `deposit` and `claim` may not
be: the detector sends `data_sample`, a fixed value, so nothing varies
the argument to zero.

**Outcome if the two survive.** That is a reachability limit, not a
detector blind spot, and it should be reported as such rather than
counted against sensitivity. The fix would be varying `data_sample`
across the guard boundary, which is a separate change.

**What would falsify the invariant's value.** If the timelock mutant
survived, or if the baseline stopped being silent, the declaration
mechanism does not work and the invariant should not ship.

### Result

Three of five killed; the baseline stayed silent. Campaign score rose
from 28.6% to 83.3% after exclusions, every kill by the predicted
invariant.

The prediction was half right, and wrong in an instructive way.

| Mutant | Guard | Predicted | Actual |
|---|---|---|---|
| `:73` | withdraw timelock | killed | **killed** |
| `:95` | claim timelock | killed | **killed** |
| `:97` | claim `vault.amount > 0` | at risk | **killed** |
| `:74` | withdraw balance bound | killed | survived |
| `:44` | deposit `amount > 0` | at risk | survived |

The two `amount > 0` guards were predicted to share a fate and did not,
because they are not the same guard. `:97` reads a *state* field, and
the fuzzer can empty a vault, so the condition becomes false and the
mutation is caught. `:44` reads an *instruction argument*, and the
detector sends a fixed `data_sample`, so the condition is never false.
The relevant axis was operand source, not the shape of the comparison —
which the prediction had not separated.

`:74` survived for a third reason again: dropping
`amount > 0 && amount <= vault.amount` leaves the bound enforced by the
handler's own `checked_sub`, which returns `None` and errors. Excluded
as equivalent.

So of the two survivors, one is equivalent and one is a reachability
limit fixable by varying `data_sample` across the guard boundary.
Neither is a sensitivity failure, which is what §9 was asking about.

## 10. Honest framing

This invariant is narrower than its name suggests. It checks
*declared, expressible* preconditions: comparisons between two unsigned
scalars drawn from account data, the slot, instruction data, or a
constant. Real guards are often none of those — `has_one` relations,
signer identity, cross-account consistency, multi-clause boolean
conditions. A conjunction can be declared as several guards, but a
disjunction cannot be declared at all in v1.

It also inherits mutation testing's reachability problem in a sharper
form. A guard is only checkable when the fuzzer can reach a state where
it is false. For a timelock that means advancing the slot past unlock,
which the escrow fixture does via an explicit action; for a protocol
without such an action, the guard is declared and never exercised, and
a silent run says nothing. The reachability ledger is what keeps that
distinction visible.
