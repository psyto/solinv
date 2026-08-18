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

`not_reached` and `build_failed` are excluded and reported as
first-class figures next to the headline, never folded in and never
omitted. Two consequences worth stating:

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

### How `not_reached` is actually determined

A denominator that excludes unreached mutants is worthless unless
something can identify them, and "the run was silent" cannot: a
detector that was never asked and one that was asked and said nothing
produce identical output. Two halves make the distinction:

- **`solinv mutate plan` records each mutant's `enclosing_fn`** — the
  nearest function declaration above the mutation site.
- **`solinv-core::invariants::reachability` records instruction names**
  when a *canonical* (untampered) instruction executes successfully,
  emitting `[solinv][reached] ix=<name>` under `SOLINV_REACHABILITY=1`.
  Only the four detectors that send untampered instructions
  (`unchecked-math`, `cu-dos`, `cpi-reentrancy`, `realloc-race`)
  contribute; the five Critical detectors deliberately send tampered
  instructions expecting rejection, which says nothing about whether
  the happy path ran.

`run_mutation_campaign.sh` joins the two by name. **The join is sound in
one direction only.** If the enclosing function's instruction never
executed, the mutation certainly did not — a valid negative. The
converse fails: the instruction may have run without taking the
mutated branch. So a mutant whose instruction *did* run is classified
`survived`, never promoted to killed-or-excluded on that evidence.
Mutants with no `enclosing_fn`, or whose name matches no instruction,
are likewise `survived`. Every ambiguity resolves against the detector,
which is the direction an honest score errs in.

One guard worth naming: the script requires at least one `[reached]`
line before it will classify anything as `not_reached`. A run that
emitted none means the ledger is not wired up, not that nothing
executed, and inferring reachability from that would empty the
denominator on a misconfiguration — turning a broken campaign into a
vacuous pass.

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
  --target escrow-demo \
  --src examples/escrow-demo/programs/escrow/src/lib.rs \
  --out plan.json \
  --statement "If fewer than 80% of reached mutants die, the detectors \
               have a blind spot on this shape of code." \
  --min-score 0.8 --min-reached 10

./scripts/run_mutation_campaign.sh plan.json \
  examples/escrow-demo/programs/escrow/Cargo.toml escrow results.json

solinv mutate score --plan plan.json --results results.json
```

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

Implemented and unit-tested — 38 tests in `solinv-mutate` (operator
patterns, mutant generation, `enclosing_fn` extraction, stale-plan
rejection, scoring, gate outcomes, report rendering) and 4 in
`solinv-core::invariants::reachability`.

The CLI has been exercised end-to-end on `examples/escrow-demo` source:
17 mutants planned across 6 handlers, `enclosing_fn` resolved correctly
for every one, `apply` verified to produce exactly one changed hunk,
and scoring verified against a synthetic result set covering all four
outcomes.

**No real campaign has been run.** `run_mutation_campaign.sh` is
syntax-checked but has not been executed against a live build, so no
mutation score for any target exists yet, and the reachability join has
never been exercised against real `[solinv][reached]` output. Until
that happens this crate is tooling, not evidence.

The intended order is escrow-demo first, then Raydium. escrow-demo is
not the interesting target — it is the calibration of the instrument.
Its planted bugs are known to be detected 7/7, so a run there that
produces a low score indicts the harness or the script rather than the
detectors, and it costs a fraction of what learning the same thing on
Raydium would. Only once the instrument is known to produce a signal
does the Raydium experiment in §1 mean anything.
