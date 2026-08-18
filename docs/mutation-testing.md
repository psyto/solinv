# Mutation testing for Solana programs

Design note for `solinv-mutate`.

## 1. What it measures — and what it explicitly does not

A mutation campaign plants a known bug class in a program's source,
runs the invariant catalog against it, and records whether the detector
that was supposed to catch it did.

**It does not find bugs.** Every bug in a campaign is one this crate
planted. Nothing a campaign produces is a vulnerability, and nothing it
produces is submittable to a bug bounty. What it produces is a number
per detector per program.

That number is the half of solinv's calibration argument that is
currently missing. The published result today is:

> 0 violations across 3 invariant classes × 3 protocols × ~150K
> executions — the detectors are sensitive to planted bugs and silent
> against well-engineered production code.

The sensitivity half of that claim rests on `examples/escrow-demo`, and
escrow-demo is not Raydium. A silent run on production code is evidence
only if the *same harness on that same program* demonstrably kills
planted bugs. Mutation testing is how that gets measured instead of
assumed.

It is also the experiment that distinguishes two explanations of the
null result which the current data cannot separate:

- **the bug classes are defended** — the Critical-5 are on every Solana
  audit checklist, so hardened mainnet code has been reviewed against
  exactly this list
- **the targets are unrepresentative** — n=3, all native, all
  high-profile; the thinner tail (Anchor 0.27–0.29: klend, Sanctum,
  Marinade) is depth-gated and untested

If mutants injected into Raydium die, the detectors work and the target
was genuinely clean → widen the target set. If they survive, the
detectors have a blind spot on real code → fix the detectors. The two
lead to opposite roadmaps, which is why this is worth running before
extending the catalog.

## 2. The denominator is the design

The naive score is `killed / total`. On Solana that is actively
misleading, because many mutants are never *executed*: the harness may
not drive the mutated instruction, the path may be gated behind state
the fuzzer has not built up, or the mutant may not compile.

solinv has already measured this effect from the other direction:
`bump-seed-canonicalization` detects its planted bug at roughly 2%
because the substitution attack requires the canonical vault to exist
first. Reachability, not detector sensitivity, sets that rate. A
campaign that counts unreached mutants as survivors inherits the
confound wholesale and reports working detectors as broken.

So:

```
score = killed / (killed + survived)
```

`not_reached`, `build_failed` and `harness_error` are excluded and
reported as first-class figures next to the headline, never folded in
and never omitted. Two consequences worth stating:

- **No score when nothing was reached.** `Score::score` is
  `Option<f64>`, not `0.0`. A campaign with no evidence has no score;
  reporting zero would be indistinguishable from total detector
  failure.
- **`Inconclusive` is a real outcome.** A gate with only PASS and FAIL
  forces a verdict on a campaign that produced nothing. A run reaching
  fewer than `min_reached` mutants reports `INCONCLUSIVE` — the same
  discipline as the §9 gates, where the honest outcome of an
  under-powered experiment is "we did not learn", not "it failed".

Attribution is tracked separately: a mutant killed by an *unexpected*
invariant is still dead, but it means the coverage came from somewhere
the operator did not predict, which is worth knowing before crediting
the detector that was supposed to catch it.

That field earned its place on the first campaign that ran end to end.
It scored 17 of 17 killed, gate PASS, and the line beneath the headline
read **0 killed by the predicted invariant, 17 by another**. Sixteen
were credited to `cu-dos`, a detector with no bearing on a signer
weakening or a `checked_add` rewrite. See §2.2.

### 2.1 The target has to be correct before you mutate it

Mutation testing asks whether a detector notices a bug you just
introduced. The question is only answerable if the program was clean
beforehand, and `examples/escrow-demo`'s `escrow` is the opposite of
clean by construction: every detector in the catalog has a handler
built to trip it. Measured on the unmutated program, a scoring run
produces 7202 `cu-dos` and 796 `unchecked-math` findings before a
single line is mutated. Every mutant therefore "kills" something, and
the score is an artifact.

`examples/escrow-demo/programs/escrow-clean` exists for this: the same
escrow with the timelock comparison corrected and all nine `unsafe_*`
handlers removed. Four handlers, all meant to be correct. Its defining
property is verified rather than assumed — the scoring run on the
unmutated program reports nothing at all.

A harness for a mutation target is mostly its declarations.
`expected_owners`, `expected_discriminators`, `expected_pda_seeds` and
`signer_indices` tell the Critical 5 what the program is supposed to
enforce; a mutation that removes an enforcement is caught only if a
declaration said the enforcement was there. When a declaration is
wrong, the baseline stops being silent, which is the intended failure
mode: declaring `initialize`'s payer to be the fixture's `fee_payer`
produced 19998 `signer-skip` findings on correct code, because the fee
payer signs the transaction whatever its `AccountMeta` says, so
clearing its `is_signer` flag removed nothing. A non-empty baseline on
a clean target is a defect to fix, never a number to subtract.

### 2.2 A kill has to be caused by the mutation

Even so, the campaign runner does subtract. It runs the scoring test
against the unmutated program first and removes that detector set from
every mutant's, because a detector already firing beforehand cannot be
evidence that a mutation was caught. Without this the classifier
credits any violation at all, which is how 17 of 17 happened.

The runner also warns at startup when a mutant's predicted killer is
already firing. Those mutants are unscoreable on that target rather
than merely hard to kill, and that is worth knowing before spending a
rebuild on each of them.

### 2.3 Equivalent mutants

Some mutations compile, run, and cannot misbehave. No detector could
have caught them, and counting them as survivors understates the
detectors by however many there are. On escrow-clean, four of nine
survivors were of this kind — two `Signer<'info>` weakenings on
handlers whose bodies invoke a CPI that re-imposes the signature
requirement, and two `checked_*` → `wrapping_*` rewrites whose overflow
is unreachable behind an intact guard or beyond the fixture's balances.

`solinv mutate exclude --plan P --mutant ID --reason "..."` records
one. The exclusion is post-hoc by nature — you cannot know a mutant is
equivalent until you have watched it survive — which is exactly the
reasoning the §9 pre-commit discipline exists to constrain. Three
things hold it in place:

- **The reason is mandatory**, and is expected to be an argument, not a
  label.
- **The report prints the pre-exclusion score** next to the adjusted
  one and lists every exclusion with its reason, so the arithmetic can
  be checked against the argument.
- **Only survivors can be excluded.** Excluding a killed mutant would
  shrink the numerator, turning a triage tool into a way to launder a
  score upward. Ids absent from the results are rejected too, so a typo
  cannot read as an applied exclusion.

### How `not_reached` is actually determined

A denominator that excludes unreached mutants is worthless unless
something can identify them, and "the run was silent" cannot: a
detector that was never asked and one that was asked and said nothing
produce identical output. Two halves make the distinction:

- **`solinv mutate plan` records each mutant's `enclosing_fn`** — the
  innermost declaration above the mutation site, `fn` or `struct`,
  whichever comes later. A struct resolves through the handler taking
  it as its `Context<..>`. That indirection is not decoration: on an
  Anchor program the most productive operator matches inside a
  `#[derive(Accounts)]` struct, and every such struct sits *below* the
  last handler in the file, so a nearest-`fn` rule attributes all of
  them to whichever handler happens to be last. A struct no handler
  names resolves to `None` — excluding the mutant beats crediting it to
  a function that never touches it.
- **`solinv-core::invariants::reachability` records instruction names**
  when a canonical instruction succeeds, emitting
  `[solinv][reached] ix=<name>` under `SOLINV_REACHABILITY=1`. The
  recording happens in the fixture's `action_*` methods, which already
  send those instructions and already know whether they landed — no
  added traffic, no perturbed state.

  Hanging it off the detectors instead, as the first implementation
  did, does not work. Only the four that send untampered instructions
  can record at all, and each drives only the instructions carrying the
  declaration it needs; the Critical 5 send *tampered* instructions
  expecting rejection, which says nothing about the happy path. On
  escrow the ledger could vouch for exactly three instructions, none of
  which any mutant sat in, and all 17 scored `not_reached`. Reachability
  is a property of the campaign, not of a detector.

**Killing and reaching cannot share a run.** The fuzzer stops an
iteration at its first violation, and on a target with planted bugs
that is the first action — 1653 of the iterations in a 30s scoring run
executed exactly one. Nothing is ever deposited before something tries
to withdraw, so every state-dependent instruction fails against an
empty vault and reads as unreachable. So a campaign runs two tests per
mutant: the scoring test, and an assertion-free `invariant_reachability`
whose sequences run to full length. Measured on escrow: 4 of 9
instructions reached by the scoring run, 9 of 9 by the reachability
run. Reachability is the union.

`run_mutation_campaign.sh` joins the two by name. **The join is sound in
one direction only.** If the enclosing function's instruction never
executed, the mutation certainly did not — a valid negative. The
converse fails: the instruction may have run without taking the
mutated branch. So a mutant whose instruction *did* run is classified
`survived`, never promoted to killed-or-excluded on that evidence.
Mutants with no `enclosing_fn`, or whose name matches no instruction,
are likewise `survived`. Every ambiguity resolves against the detector,
which is the direction an honest score errs in.

One guard worth naming, because its absence was a live bug: a run that
emits no `[reached]` line at all is `harness_error`, checked *before*
reachability and before the `survived` fallback. A harness that never
started is silent in exactly the way a harness that found nothing is
silent. The first campaign to run end to end scored 0.0% over 17
reached mutants because `crucible` had exited immediately every time —
it resolves its harness under `./fuzz/<program>/` relative to the
working directory, the campaign ran from the repo root, and the runner
threw the exit code away with `|| true`. An empty log has no violations
in it, so all 17 fell through to `survived`, and a configuration
mistake was reported as seventeen detector blind spots.

The fallback for "no evidence" has to be its own outcome, not whichever
outcome happens to be adjacent. Two further guards follow from the same
thought:

- **A baseline build-and-run before any mutant.** The unmutated program
  must emit at least one `[reached]` line or the campaign refuses to
  start. This turns a 17-rebuild failure into a 30-second one.
- **Instructions the plan needs but the baseline never reaches are
  named at startup**, with the mutant count for each, while the number
  can still inform the decision to spend the build time.

## 3. Operators

Nine operators, each modelling a bug class solinv already has a
detector and a spec for, and each naming the invariant expected to kill
it. Run `solinv mutate operators` for the current table.

Patterns neutralize a *condition* (`!x.is_signer` → `false`) rather
than deleting the guard block. Deleting a block needs brace matching,
which text patterns do badly; neutralizing leaves the code compiling
and the guard dead — the same bug with far fewer mutants that simply
fail to build. Build failures are not free: each one is compute spent
to learn nothing.

**Coverage is partial and the reports say so.** v1 reaches 6 of 10
catalog invariants. Not covered: `cu-dos`, `cpi-reentrancy`,
`realloc-race`, `account-swap`. Each needs a structural rather than
textual mutation — inflate a loop bound past a CU budget, introduce a
call cycle, drop a lamport top-up adjacent to a `realloc`, rebind an
account to a foreign context. Those want an AST-level engine (v2). A
mutation score that quietly omitted four detectors would read as a
verdict on all ten, so `UNCOVERED_INVARIANTS` is printed in every
campaign summary.

Text-based mutation is a v1 decision, not a claim of superiority.
`cargo-mutants` does AST-level mutation well; solinv's value-add is the
Solana-specific operator catalog and the reachability-aware
denominator, not the mutation engine.

## 4. Running one

```bash
solinv mutate operators

solinv mutate plan \
  --target escrow-clean \
  --src examples/escrow-demo/programs/escrow-clean/src/lib.rs \
  --out plan.json \
  --statement "If fewer than 80% of reached mutants die, the detectors \
               have a blind spot on this shape of code." \
  --min-score 0.8 --min-reached 8

./scripts/run_mutation_campaign.sh plan.json \
  examples/escrow-demo/programs/escrow-clean/Cargo.toml \
  escrow_clean examples/escrow-demo results.json

solinv mutate score --plan plan.json --results results.json
```

The fourth argument is the directory *containing* `fuzz/<target>/`, not
the harness directory. `crucible -C` is honoured when building the
harness but not when locating the built binary, so the runner has to
run from there.

The kill criterion is supplied at `plan` time, before any mutant runs.
That is the §9 pre-commit discipline applied to the campaign itself: it
is what stops a disappointing score from being reinterpreted afterwards.
`plan` also warns when a plan holds fewer mutants than its own
`min_reached`, since such a run is inconclusive before it starts.

## 5. Cost

One `cargo build-sbf` per mutant dominates. That cost is a tax, not an
asset — worth attacking with mutant schemata (all mutations compiled
into one binary behind a runtime selector) rather than tolerating.

One caveat if schemata is adopted: it changes the binary, so CU figures
from a schemata build cannot feed `cu-dos` or the differential CU
surface. Those need per-mutant builds. Deciding this before building
the harness avoids discarding a campaign's measurements afterwards.

## 6. Status

Implemented, unit-tested, and run. 46 tests in `solinv-mutate`
(operator patterns, mutant generation, `enclosing_fn` resolution
including the Anchor struct case, stale-plan rejection, scoring, gate
outcomes, equivalent-mutant exclusion, report rendering) and 4 in
`solinv-core::invariants::reachability`.

### First campaign — escrow-clean

11 mutants, all reached, no build failures, no harness errors.

| | Score | Killed | Reached | Gate |
|---|---|---|---|---|
| Raw | 18.2% | 2 | 11 | FAIL |
| After excluding 4 equivalent mutants | 28.6% | 2 | 7 | **INCONCLUSIVE** |

The honest headline is the second row. Removing the equivalent mutants
drops the denominator below the committed `min_reached` of 8, and a
campaign this small cannot support an 80% claim in either direction.
Both numbers are printed by `mutate score`; neither replaces the other.

Both kills were by the invariant the operator predicted — the
attribution line that read 0-of-17 on `escrow` reads 2-of-2 here.

The nine survivors are worth more than the score. Triaged:

- **Four equivalent**, excluded with reasons in
  [`examples/escrow-demo/campaigns/escrow-clean-plan.json`](../examples/escrow-demo/campaigns/escrow-clean-plan.json).
  Two `Signer<'info>` → `AccountInfo<'info>` weakenings on `initialize`
  and `deposit`, whose handler bodies invoke CPIs that require the
  signature anyway; two `checked_*` → `wrapping_*` rewrites that cannot
  wrap. The pattern is exact: the same mutation *is* killed on
  `withdraw` and `claim`, which move lamports directly rather than
  through a CPI. Anchor's `Signer` constraint is redundant on a handler
  that transfers from that account.
- **Five uncovered.** All `guard-drop` on `require!` statements —
  timelock comparisons and amount bounds. These are real bugs; solinv
  has no invariant that models temporal ordering or business-logic
  bounds, so nothing could have caught them.

That second group is the finding. Dropping the guard at
`escrow-clean/src/lib.rs:73` reproduces the exact timelock race that
`escrow` plants as its flagship bug — and solinv does not detect it.
The reason `escrow` reports that bug as caught is that its harness
carries a hand-written `fuzz_assert_lt!` over the recorded withdraw
slots, not that any detector in the catalog found it. A temporal /
ordering invariant is the gap this campaign located.

### What this does not yet establish

No campaign has been run against a real protocol, and this one
exercised two detectors, not ten: escrow-clean's four handlers yield
mutants whose predicted killers are `signer-skip` and `unchecked-math`
only. A four-handler timelock escrow does not contain the shapes the
other eight detect.

What escrow-clean established is that the instrument reports what it
measures — a claim that failed twice before it held. It says nothing
about Raydium, which is the experiment in §1 and still ahead.
