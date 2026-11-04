# solinv — catch the Anchor account check a change drops

Some of Solana's largest losses came down to one account nobody checked:
[Wormhole](https://www.certik.com/blog/wormhole-bridge-exploit-incident-analysis) (Feb 2022,
~$320M) never verified that the instructions sysvar was the real one;
[Cashio](https://halborn.com/explained-the-cashio-hack-march-2022/) (Mar 2022, ~$48M) never
validated a `mint` field, so a chain of fake accounts passed;
[Crema](https://halborn.com/explained-the-crema-finance-hack-july-2022/) (Jul 2022, ~$8.8M) let a
fake tick account past its owner check. In Anchor each of those checks is one type or one
`#[account(...)]` line, enforced only while it is written down — and a refactor that loosens
`Account<'info, Vault>` to `UncheckedAccount` or deletes a `has_one` fails no test. As more
programs are written and refactored by AI coding agents, that kind of change gets more common and
easier to miss: it compiles, the tests the agent wrote pass, and a one-line deletion is easy to skim
past in a large generated diff.

**solinv tells you when that happens, on the pull request, before it merges** — and maps where a
program's hand-written account checks are, and fuzzes them with the attack each check exists to
stop. Apache-2.0.

## Pick a tool

| I want to… | Use |
|---|---|
| fail a pull request that removes an account check, with a note on the line | the `psyto/solinv` GitHub Action, or `solinv diff --base-src <before> --head-src <after>` |
| see which instructions need a hand-checked account, before writing any harness | `solinv idl target/idl/<program>.json --src programs/<program>/src` |
| get a paste-ready spec for one instruction | `solinv idl <idl> --rust <ix>` |
| fill an `InstructionSpec` from the IDL and fixture state instead of by hand | `solinv_fuzz::Idl` → `.spec()` → `.infer_from_state()` / `.infer_candidates()` |
| check a signer is really required | `solinv_core::invariants::signer_skip::check` |
| check an account's owner program / type tag is really checked | `owner_skip::check` / `discriminator_skip::check` |
| check a PDA can't be forged, or swapped for another user's | `pda_forge::check` / `account_swap::check` / `bump_seed_canonicalization::check` |
| check a `require!` guard can't be skipped | `precondition_skip::check` + `InstructionSpec.guards` |
| catch wrapped arithmetic on named fields | `unchecked_math::check` + `AccountSchema` |
| cap compute units, or catch re-entry / under-funded `realloc` | `cu_dos` / `cpi_reentrancy` / `realloc_race` |
| measure whether the detectors would catch a bug you plant | `solinv mutate plan` → `apply` → `score` |
| check two programs behave the same (Anchor → Pinocchio rewrite) | `solinv_fuzz::check_pair_equivalent` |

## Quickstart

From a fresh clone, no Solana toolchain. First, a change that drops a check — the demo vault
loosened to `UncheckedAccount` and its `has_one` deleted
([the file](examples/escrow-demo/diff/drop-a-check/lib.rs)):

```bash
git clone https://github.com/psyto/solinv && cd solinv
cargo run -q -p solinv-cli -- diff \
    --base-src examples/escrow-demo/programs/escrow-clean/src \
    --head-src examples/escrow-demo/diff/drop-a-check
```
```
solinv diff: 2 removed check(s), 0 warning(s)
REMOVED withdraw.vault (examples/escrow-demo/diff/drop-a-check/lib.rs:153): was Account, now UncheckedAccount: Anchor no longer checks its owner and type
REMOVED withdraw.vault (examples/escrow-demo/diff/drop-a-check/lib.rs:153): `has_one = depositor` removed: it no longer has to match `depositor`
```

It exits 1, so CI fails. In a pull request the same findings appear as annotations on the changed
line — [the demo pull request](https://github.com/psyto/solinv/pull/2) makes this change to the real program and fails with both,
on line 146.

Second, the map of a whole program — which instructions have hand-checked accounts:

```bash
cargo run -q -p solinv-cli -- idl examples/escrow-demo/idl/escrow.json \
    --src examples/escrow-demo/programs/escrow/src
```
```
program Esrcw11111111111111111111111111111111111111 — 12 instructions, account types: Vault

S signer  W writable  P pda seeds  A fixed address  · nothing declared  U unchecked in source  T typed in source  t typed, identity not fixed by a constraint
…
unsafe_set_amount_from_source   ! no signer, writes an unconstrained slot
   0 source               U
   1 target           W   t
…
unsafe_withdraw   ! no signer, writes an unconstrained slot
   0 vault            W   U
   1 depositor        W   U

7 slots are UncheckedAccount / AccountInfo in source: their checks are hand-written, which is where the Critical 5 can find something.
! 1 writable typed accounts have no declared constraint fixing which account they are (no seeds, address, has_one, associated_token:: or .key() comparison; the handler body is not read). Unless the handler checks the key, a caller may pass any account of the type: expected for their own token accounts, a hole for a vault, escrow or pool the program owns. account-swap candidates: unsafe_set_amount_from_source.target
3 instruction(s) with no signer write an unconstrained slot: unsafe_set_amount_from_source, unsafe_withdraw_with_bump, unsafe_withdraw
Start there: either they are meant to be permissionless, or an authority check is missing.
```

`U` marks an `UncheckedAccount` / `AccountInfo`, whose owner and type checks are hand-written; `T`
a typed account Anchor checks. `t` is a typed account whose identity no declared constraint fixes:
Anchor checks that it is *a* `Vault`, not *which* one, so unless the handler compares its key, a
caller can pass their own. Without `--src` the IDL alone cannot tell these apart. The three
flagged instructions are the demo program's three planted account-validation bugs. To fuzz them, see
[fuzz the planted-bug demo](#quickstart--escrow-demo) (needs the Crucible CLI and `cargo build-sbf`).

## Does it work?

| Claim | Evidence |
|---|---|
| A removed check fails the PR | The demo above; [the demo pull request](https://github.com/psyto/solinv/pull/2) |
| No noise on code that keeps its checks | Comparing Jito tip-payment, tip-distribution and Raydium cp-swap with themselves: 0 reports. Reformatting a constraint or renaming its error: 0 reports (tested) |
| The fuzz detectors catch a check that is removed | Mutation test on the clean escrow: of the removed checks the harness reached, 5 of 6 were caught, each by the detector predicted for it — after setting aside 5 mutations that cannot change behaviour, each argued in the [report](examples/escrow-demo/campaigns/escrow-clean-report.md) (5 of 11 before) |
| …but not every kind yet | On Raydium's native AMM, 0 of 18: its guards compare values computed inside the handler, which a declaration cannot name ([why](#mutation-testing--measuring-detector-power-on-a-real-target)) |
| It is quiet on audited code | Three production programs fuzzed to a first result: 0 findings, the expected answer ([details](docs/idl-specs.md#measured-on-production-programs)) |

## Use it in your own project

On every pull request (`.github/workflows/solinv.yml`):

```yaml
on: pull_request
jobs:
  account-checks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: psyto/solinv@f5267c8f23c3b21bc8f2b54308bcbd52824da806
        with:
          program-src: programs/my_program/src
```

It installs solinv at that commit, compares the program's source with the pull request's base,
and fails the job when a check is removed. The first run compiles solinv (about 2 minutes on
`ubuntu-latest` for the demo pull request); later runs restore it from the cache (the whole job took 7 seconds on a re-run). No Solana
toolchain, no build of your program.

The CLI (not on crates.io yet; pin a commit):

```bash
cargo install --git https://github.com/psyto/solinv --rev 6ebc1ca651e3 solinv-cli
```

In your Crucible fuzz harness:

```toml
[dependencies]
solinv-fuzz = { git = "https://github.com/psyto/solinv", rev = "6ebc1ca651e362df67e75ab9836692fc0940697c" }
solinv-core = { git = "https://github.com/psyto/solinv", rev = "6ebc1ca651e362df67e75ab9836692fc0940697c" }
crucible-test-context = { git = "https://github.com/asymmetric-research/crucible", tag = "v0.1.0" }
```
```rust
let spec = Idl::from_json(include_str!("../idl/my_program.json"))?
    .spec("deposit", program_id)?
    .account("vault", vault)
    .signer("depositor", Arc::clone(&depositor))
    .args(&50_000u64.to_le_bytes())
    .build()?
    .infer_from_state(|pk| ctx.get_account(pk).ok())     // facts
    .infer_candidates(|pk| ctx.get_account(pk).ok())     // leads, logged
    .into_spec();
```

Return the specs from `HasInstructionSet::instructions()` and call the detectors from an
`#[invariant_test]`, e.g. `solinv_core::invariants::signer_skip::check(fixture)`. Full walk-through:
[start from your IDL](#start-from-your-idl) and [integration](#integration--adopting-solinv-on-your-own-program).
Both install lines above were checked from GitHub at that rev, not from a local clone.

Trying it on a program of your own for the first time? [`docs/try-solinv.md`](docs/try-solinv.md) is a
one-page walk-through, with what to time and what to send back.

## How it compares

- **Anchor's own checks** enforce what is declared. solinv watches the declarations: it notices
  when one disappears, and maps where nothing is declared and the check is hand-written.
- **Linters and static analyzers** flag patterns in one version. `solinv diff` compares two
  versions and names what changed; the fuzz detectors send the attack and report only if it lands.
- **An audit** checks the code once. solinv keeps the audited checks in place afterwards; it does
  not replace one.

## How light it is

- **One dependency in your harness.** solinv runs inside Crucible and inherits its sBPF execution,
  coverage and scheduling; it adds detectors and spec-building, not an engine. No validator, no RPC.
- **The IDL writes the account half of the spec, and the source narrows what to read.** On the
  production programs below, `--src` cut the slots to review from 29 to 5 (tip-distribution),
  34 to 14 (tip-payment) and 108 to 30 (cp-swap). What you still write is the fixture: the
  accounts that must exist before an instruction can run, and one action per instruction.
- **Measured on three production Anchor programs** (2026-11-03, fixture written by someone who
  knows solinv): Jito tip-payment 6 min and tip-distribution 6 min to a first Crucible result,
  Raydium cp-swap 11 min (its admin key is hard-coded, so setup writes the config account directly).
  All three came back clean — the expected answer for audited code; the use is catching a check that a
  later change drops, in CI. What slowed each one down is in
  [`docs/idl-specs.md`](docs/idl-specs.md#measured-on-production-programs).

## How the pieces fit

Sibling to [pinocchio-bench](https://github.com/psyto/pinocchio-bench) — the public CU-measurement
leaderboard comparing Anchor vs Pinocchio across 13 DeFi hot paths.


Existing Solana fuzzers (Crucible, [Trident](https://github.com/Ackee-Blockchain/trident))
provide coverage-guided execution and snapshot infrastructure. They
ask the user to declare what counts as a bug. Solinv ships that
declaration as a library:

1. **Pre-built Solana invariants — 11 in the catalog**, each tested
   end-to-end against planted bugs and clean against hardened
   production code: **Critical 5** (signer-skip, owner-skip,
   discriminator-skip, pda-forge, account-swap) + **High 6**
   (unchecked-math, cu-dos, cpi-reentrancy, realloc-race,
   bump-seed-canonicalization, precondition-skip). Each
   ships with a 10-section spec doc, Gate 1 planted-bug acceptance,
   and Gate 2 production-target calibration evidence.
2. **Honest calibration data** — production code is mostly clean.
   Solinv publishes the null results alongside the catalog so the
   detectors' sensitivity is auditable rather than implied. As of
   the 5-invariant calibration sweep on Raydium AMM SwapV2:
   **168,531 executions / 0 violations** across 5 distinct detection
   mechanisms.
3. **Pre-commit kill-criterion methodology** — every invariant ships
   with a §9 pre-committed experiment design (Gate 1 + Gate 2 binary
   outcomes) and a §10 honest framing of any decision overrides. The
   methodology has been empirically tested across 5 invariants × Day
   34 / 38 / 58 / 59 / 60 result docs.
4. **Layer-of-responsibility framing** — each bug class is mapped to
   what Solana's runtime defends against vs what the protocol must
   own. See [the catalog summary table](#layer-of-responsibility-scale)
   below.
5. **Bytepoke helper API** — `solinv-fuzz::bytepoke` provides
   reusable Anchor-discriminator + sighash + byte-offset writers +
   `AnchorAccountBuilder`, for pre-writing deep account state directly
   instead of reaching it through the program's own instructions.
6. **Disclosure templates** — Immunefi / Sherlock / direct-to-protocol
   markdown templates with field-by-field guidance + a worked example
   from solinv's own planted-bug detection.
7. **Field schemas + relation invariants** — state invariants name
   `pool.total_deposits` instead of byte offset 40, and can assert
   relations across accounts (`liquidity + borrowed == total`). A wrong
   offset used to fail *silently*; it now fails at declaration time.
   See [field schemas](#field-schemas--naming-fields-instead-of-counting-bytes).
8. **Mutation testing** — `solinv-mutate` plants known Solana bug
   classes in a program's source and measures which detectors kill
   them, with a denominator that excludes mutants nothing ever reached.
   See [mutation testing](#mutation-testing--measuring-detector-power-on-a-real-target).
9. **Differential equivalence + checkable findings** — a three-surface
   oracle for "do these two programs behave the same?" (written state,
   accept/reject *and reason*, compute units), and a finding format that
   identifies every input by digest and states plainly whether it
   carries them. See
   [differential equivalence](#differential-equivalence--do-two-programs-behave-the-same)
   below.
10. **Specs from an Anchor IDL** — `solinv-fuzz::idl` builds the
    account-validation half of an `InstructionSpec` from the IDL plus
    the fixture's post-setup state, and `solinv idl` maps a program's
    unsigned writers before any fixture exists — with `--src`, also
    which slots are `UncheckedAccount` / `AccountInfo` in source.
    Expectations the IDL does not make are kept apart as
    *candidates*: leads to confirm, not facts. See
    [start from your IDL](#start-from-your-idl).
11. **The checks a change removes** — `solinv diff` compares two
    versions of a program's source slot by slot (no build): a typed
    account loosened to `UncheckedAccount`, a signer no longer
    required, a `seeds` / `address` / `owner` / `has_one` /
    `constraint` deleted (constraints compared by expression), plus
    warnings for moved checks, type changes, optional accounts and new
    unsigned writers. `action.yml` runs it on pull requests with
    annotations on the line. Design and limits:
    [`docs/diff.md`](docs/diff.md).

Engine performance is **not** the wedge — solinv runs on Crucible and
inherits its sBPF coverage and libafl scheduling.

## Layer-of-responsibility scale

| Invariant | Solana runtime defense | Protocol responsibility |
|---|---|---|
| unchecked-math | none | total |
| cu-dos | per-tx 200K CU cap | total within cap |
| cpi-reentrancy | writable-account locks (same-account only) | partial (different-account / proxy paths) |
| realloc-race | near-total (rent check at tx commit) | intent only |
| bump-seed-canonicalization | none | total (use `find_program_address` + store canonical bump) |
| signer-skip | none (Anchor framework helps for `Signer<'info>`) | total for raw `AccountInfo` |
| owner-skip | none (Anchor framework helps for typed `Account<'info, T>`) | total for `UncheckedAccount` |
| discriminator-skip | none | total |
| pda-forge | none at read-time (runtime checks `invoke_signed` only) | total |
| account-swap | none | total |
| precondition-skip | none | total (the runtime has no notion of a protocol's entry conditions) |

The scale anchors solinv's value-add: detectors target precisely the
layer Solana's runtime doesn't own, where the protocol's
responsibility is total or near-total.

## Paired with pinocchio-bench

[psyto/pinocchio-bench](https://github.com/psyto/pinocchio-bench) is
the public CU-measurement leaderboard comparing Anchor 0.32.1 vs
Pinocchio 0.11.1 across 13 representative DeFi hot paths (W0-W12:
no-op through perp `open_position`). Two scaling laws now hold across
the dataset:

| Dimension | Marginal Anchor overhead |
| --------- | ----------------------- |
| Per additional mutable zero-copy account | ~329 CU |
| Per additional CPI hop | ~1,968 CU |

Pinocchio-bench answers _"how much CU is on the table?"_. Solinv
answers _"can a Pinocchio rewrite preserve the original program's
behavior?"_ — see [differential equivalence](#differential-equivalence--do-two-programs-behave-the-same)
below. The leaderboard lists 5-6 invariants per workload that a
fuzzer "would attach" for each surface (orderbook tick insert, AMM
constant-product, lending refresh, vault NAV, oracle publish, perp
margin); solinv is the framework that actually attaches them.

## Differential equivalence — do two programs behave the same?

Invariants ask whether a program violates a property. A rewrite, a
refactor or an optimization asks something else: whether the new
version still does what the old one did.

On Ethereum a differential runner can diff against a commitment — the
state root, the receipts trie. **Solana publishes no equivalent**, so
there is nothing to compare except the other run, and the definition of
"same outcome" is a choice the tool makes rather than something the
chain hands you. Get it wrong and you don't get an error, you get
silent false confidence.

Solinv spells the oracle out as three surfaces — chosen because they
are where a rewrite is most likely to break, **not** because they
exhaust what a caller can observe:

| Surface | Type | Fault when |
|---|---|---|
| Written account state | `BodyDivergence` | any byte of the compared body differs |
| Accept/reject **and the reason** | `ParityDivergence` | decisions differ, or both reject *for different reasons* |
| Compute units consumed | `CuComparison` | the rewrite consumed **more** than the original |

Two of these are easy to omit and expensive to omit:

- **Rejection reasons are ABI.** A caller branching on `6001` behaves
  differently against a rewrite returning `6002` — yet a boolean
  accept/reject check calls that agreement, because both sides
  "failed". Comparing the custom code alone is still not enough: every
  builtin `ProgramError` reports *no* code, so two different builtins
  compare equal. `ParityDivergence::check_outcomes` compares a
  normalized reason (`custom:6001`, `builtin:InvalidArgument`).
- **CU is consensus-relevant.** Two runs writing byte-identical state at
  different CU are not equivalent: the dearer one can exceed the
  transaction limit and fail where the other succeeds. Only a
  *regression* is a fault — for a rewrite the two sides are supposed to
  disagree, in one direction. (`CuComparison::from_outcomes` can record
  the figure per action; the harnesses call `regression` only, so what
  they retain is the verdict, not a CU series.)

A harness that checks written state alone will pass a rewrite that
changed its rejection reasons or got slower.

What these three do **not** cover, stated plainly because a differential
that quietly under-checks is worse than one that admits its scope:
account lamports / owner / executable flags, accounts written but not
declared as a pair, instruction return data, and emitted logs. Passing
all three narrows where a divergence can hide; it does not prove
equivalence.

A fourth condition is a precondition rather than a surface: a probe
whose `send()` failed never reached the program. `SendFailure` reports
it — including the case where *both* sides failed, since a symmetric
failure still produced no evidence. Nothing diverges when nothing
executes, so a silently skipped send failure turns a broken harness
into a clean run, which is the worst result a differential can give.

### Findings that someone else can check

A finding that only says *what* diverged is an assertion.
`solinv-disclose` packages it with its inputs — identified by digest,
and carried outright when the producer supplies them:

```
# Divergence report — amm-diff (raydium-amm swap)

- **Sides**: `anchor` (left) vs `pinocchio` (right)
- **Verdict**: DIVERGED
- **Claim digest**: `9fbd48ca…` (schema v2, build-scoped — contains a
  builtin rejection token whose text depends on the producing toolchain)
- **Reproducible**: NOT FROM THIS REPORT ALONE — the inputs are
  identified by digest, not carried. Obtain them independently, verify
  them against the hashes below, then re-execute.
  - Not carried: anchor program bytes, pinocchio program bytes,
    `pool` account data, encoding for action `swap(100, 0)`,
    the execution context and signer policy

## Where they parted

- [recorded] `swap` CU: 12400 → 3900 (-8500)
- **[fault]** `swap(100, 0)` outcome diverged: left rejected (custom:6001),
  right rejected (builtin:InvalidArgument)
```

…followed by tables for each side's `.so` and every account's pre-state
and metadata (owner, lamports, executable, rent epoch), the activated
feature set, the execution context — runtime, clock, and how signatures
are to be satisfied — and the action sequence with its account metas.

Program IDs are upgradeable, so an ID names a slot in time rather than a
binary; the feature set matters because Solana's runtime semantics are
gated by flags that activate at epoch boundaries, which makes "same
instruction, same accounts" two different executions on two different
days.

**A digest identifies; it does not deliver.** A hash lets a reader
confirm that bytes they already hold are the right ones — it cannot
hand them those bytes. So the bundle is graded four ways:
`InputsCarried` (every input the bundle models travels with it, intact,
with a stated execution context), `IdentifiedOnly` (inputs are named by
digest and must be obtained elsewhere), `Incomplete` (the comparison is
not even defined), and `Corrupt` (carried bytes contradict their own
digest). Every report this repository can produce today is
`IdentifiedOnly`, and says so in its header rather than inviting a
reproduction it cannot support.

The top verdict is deliberately *not* called reproducible. A published
report can never carry signing material, and it states rather than
carries the runtime conditions — so what it promises is that nothing
the model covers is missing or corrupt, and that the reader knows which
environment to reconstruct.

The claim digest pins **the finding** — excluding tool provenance, so a
crate release does not change it — and is bound to a schema version
carried inside the hashed payload. It does not attest that the claim is
*true*; no hash can. Confirming a finding means re-running the inputs.
The digest makes the claim immutable; re-execution makes it true or
false.

`solinv-disclose` depends on serde and sha2 and nothing else: finding a
divergence needs Crucible, LiteSVM and the Solana crates, but *checking
a report about one* should not.

Design rationale, API walkthrough and current gaps:
[`docs/differential-equivalence.md`](docs/differential-equivalence.md).

All six differential harnesses under
`examples/pinocchio-bench-fuzz/fuzz/` (`amm-diff`, `matching-diff`,
`oracle-diff`, `perp-diff`, `refresh-diff`, `vault-diff`) check all
three surfaces and report probes that produced no evidence, with CU
non-regression as its own `*_cu_no_regression_only` variant so a
performance finding is never reported as a behavioural one. Each
invariant runs its probes once and hands the result to the evaluators,
since the probes mutate fixture state.

`amm-diff` emits its findings as reports: `SOLINV_REPORT=<prefix>`
writes the canonical JSON and the Markdown view on the first
divergence, and `SOLINV_REPORT_INLINE=1` carries the program bytes and
account pre-state rather than only naming them. The other five
harnesses still leave a finding as a log line.

## Field schemas — naming fields instead of counting bytes

A state invariant reads a little-endian integer at a byte offset.
Declaring that offset by hand is the most error-prone part of adopting
solinv, and it fails in the worst possible way: **silently**. The
detector reads eight bytes belonging to some other field, they move
plausibly, nothing fires, and the campaign reports a clean run. A
harness checking the wrong bytes is indistinguishable from one that
found no bug — which matters more here than elsewhere, because solinv's
headline result *is* a null result.

`AccountSchema` moves the layout into a single checkable declaration:

```rust
let pool = AccountSchema::anchor("Pool")   // cursor starts past the 8-byte disc
    .field("authority", 32)                // declared for its offset only
    .field("total_deposits", 8)
    .field("total_borrows", 8);

pool.validate_len(account.data.len())?;    // check the claim against reality

let inv = pool.monotonic(
    "deposits grow", vec![0], "total_deposits", MonotonicDir::NonDecreasing,
)?;
```

| Mistake | Before | After |
|---|---|---|
| Offset off by one field | silent wrong read | `UnknownField`, listing the real names |
| Asserting on a 32-byte pubkey | silent truncation | `UnreadableWidth` |
| Layout drifted from the program | silent wrong read | `ShortAccount` from `validate_len` |

`StateInvariantKind::Relation` adds the shape the other three kinds
cannot express — two sides, each a sum of terms, compared with `==`,
`<=`, `<`, `>=` or `>`:

```rust
relation(
    "liquidity + borrowed == total",
    vec![reserve.term(0, "liquidity")?, reserve.term(0, "borrowed")?],
    RelOp::Eq,
    vec![reserve.term(0, "total")?],
    0,
)?
```

A relation fires only when it **held before the ix and failed after**:
one that was already false indicts the declaration, not the
instruction. Because a relation that never holds also never fires, that
case is *reported* rather than dropped — as are unreadable fields, once
per site, un-gated by any env var. A harness that is silently checking
nothing has to say so by default.

The grammar stays deliberately closed (integers plus an operator), so a
candidate invariant can be validated before it ever executes. Ratios
are not expressible in v1; that is a stated limit, not an oversight.
Design rationale: [`docs/invariants/field-schema.md`](docs/invariants/field-schema.md).

## Mutation testing — measuring detector power on a real target

`solinv-mutate` plants a known bug class in a program's source, runs
the catalog against it, and records whether the detector that was
supposed to catch it did. **It does not find bugs** — every bug in a
campaign is one the tool planted, and nothing it produces is
submittable anywhere.

What it produces is the missing half of the calibration argument. The
sensitivity claim behind "0 violations on production code" currently
rests on `examples/escrow-demo`, and escrow-demo is not Raydium. A
silent run is evidence only if the same harness on that same program
demonstrably kills planted bugs.

The denominator is the design:

```
score = killed / (killed + survived)      # reached mutants only
```

`not_reached` and `build_failed` are excluded and reported next to the
headline, never folded in. solinv already measured why this matters
from the other direction — `bump-seed-canonicalization` detects its
planted bug at ~2% because reachability, not sensitivity, sets the
rate. Two consequences: a campaign that reached nothing has **no**
score rather than 0%, and a run below its committed `min_reached`
reports `INCONCLUSIVE` rather than FAIL.

Identifying unreached mutants needs evidence, since a silent run and an
unasked detector look identical. Plans record each mutant's
`enclosing_fn`; the fixture's `action_*` methods emit
`[solinv][reached] ix=<name>` under `SOLINV_REACHABILITY=1` when a
canonical instruction lands; the campaign script joins them. The join is
sound in one direction only — an instruction that never ran proves the
mutation never ran, but an instruction that ran does not prove the
mutated *branch* did — so every ambiguity resolves to `survived`,
erring against the detector.

Three findings shaped the runner, each of them a wrong number it
produced first:

- **A run with no evidence is `harness_error`, not `survived`.** The
  first campaign scored 0.0% over 17 reached mutants; `crucible` had
  in fact exited immediately every time, and an empty log has no
  violations in it. A baseline build-and-run now gates the campaign.
- **A kill has to be caused by the mutation.** The next campaign
  scored 17 of 17, gate PASS — with 0 killed by the predicted
  invariant. The unmutated program was already producing 7202
  violations. The runner now measures the baseline's detector set and
  subtracts it.
- **The target has to be correct before you mutate it.** Which is why
  `escrow-clean` exists: escrow with the timelock fixed and every
  `unsafe_*` handler removed, verified to produce no violations at all
  before mutation.

```bash
solinv mutate operators                    # 9 operators, 6 of 10 invariants
solinv mutate plan --target escrow-clean \
  --src examples/escrow-demo/programs/escrow-clean/src/lib.rs \
  --out plan.json --statement "..." --min-score 0.8 --min-reached 8
./scripts/run_mutation_campaign.sh plan.json \
  examples/escrow-demo/programs/escrow-clean/Cargo.toml \
  escrow_clean examples/escrow-demo results.json
solinv mutate score --plan plan.json --results results.json
```

The kill criterion is committed at `plan` time, before any mutant runs
— the §9 pre-commit discipline applied to the campaign itself.

**Campaigns on escrow-clean**, before and after the invariant the
first one located:

| Run | Raw | After exclusions | Gate |
|---|---|---|---|
| Before `precondition-skip` | 18.2% (2/11) | 28.6% (2/7) | INCONCLUSIVE |
| After | 45.5% (5/11) | **83.3% (5/6)** | PASS |

Every kill in both runs was by the invariant its operator predicted.
Read the PASS sceptically: it rests on six mutants, and `min_reached`
was set to 6 after the first run had shown how many exclusions to
expect — choosing the bar with that knowledge is what §9 pre-commitment
exists to prevent. This is calibration of the instrument, not a
detector clearing a gate.

The first run's nine survivors are what made it worth running. Four
were equivalent mutants — an Anchor `Signer` constraint is redundant on
a handler whose body invokes a CPI that requires the signature anyway,
and the same mutation *is* killed on the two handlers that move
lamports directly. The other five were `require!` guards on timelocks
and amount bounds, which **no invariant in the catalog modelled**. That
bucket became [`precondition-skip`](docs/invariants/precondition-skip.md),
the eleventh invariant — the first solinv located with its own tooling
rather than taking from a write-up. Three of the five now die,
including the timelock race `escrow-demo` plants as its flagship bug,
which until now read as detected only because that harness carries a
hand-written assertion.

One honest survivor remains: `deposit`'s `amount > 0`. The guard is
real and the mutation removes it, but the detector sends a fixed
`data_sample` and never varies the argument to zero. That is a
reachability limit, not a blind spot, and the distinction decides what
work would fix it.

**First campaign on production code — raydium-amm:** 21 mutants inside
the two swap handlers, baseline silent. **0 killed of 18 reached —
FAIL, conclusively.** Three causes, and only one of them is a blind
spot:

- **The operator set was Anchor-only.** raydium-amm has zero
  `require!` and zero `Signer<'info>`; its 212 error returns are all
  `if cond { return Err(..) }`. The catalog could not mutate a native
  program at all, so every score before this one measured Anchor code
  specifically. `native-guard-neutralize` fixes that — 129 matches in
  raydium's processor.rs.
- **Most survivors are guards the invariant cannot express.**
  `precondition-skip` compares pre-state values; a production AMM
  guards on *computed intermediates* (`swap_amount_out <
  minimum_amount_out`), which no pre-state declaration can name. Real
  limit of the design, invisible on a four-handler escrow.
- **The campaign was mis-specified.** 15 of 18 mutants predicted
  `precondition-skip` and the raydium harness declares no guards — the
  detector was switched off on the target it was being scored against.

One finding replicated: neutralizing raydium's `!is_signer` check opens
nothing, because that account is the authority of the `token_transfer`
CPI. Same redundancy as escrow-clean's `deposit`, found independently
on production code.

v1 operators reach 7 of the 11 catalog invariants; `cu-dos`,
`cpi-reentrancy`, `realloc-race` and `account-swap` need structural
rather than textual mutation and are named in every campaign summary so
a score is never mistaken for a verdict on all ten. This campaign
exercised two of them — a four-handler escrow does not contain the
shapes the rest detect. Design note:
[`docs/mutation-testing.md`](docs/mutation-testing.md).

## Quickstart — escrow-demo

Fuzz the planted-bug demo end to end.

```bash
# Install Crucible CLI (one-time)
git clone https://github.com/asymmetric-research/crucible ~/src/crucible
cargo install --path ~/src/crucible/crates/crucible-fuzz-cli

# Build the planted-bug program (one planted bug per High-tier invariant
# + the Critical-5 acceptance fixture)
cd examples/escrow-demo
cargo build-sbf --tools-version v1.52 --manifest-path programs/escrow/Cargo.toml

# And the clean twin, which mutation campaigns target. It must produce
# NO violations before mutation — that is the property being relied on.
cargo build-sbf --tools-version v1.52 \
  --manifest-path programs/escrow-clean/Cargo.toml
crucible run escrow_clean invariant_all --release --timeout 30

# Run each invariant in isolation
for inv in signer_skip owner_skip discriminator_skip pda_forge account_swap \
           unchecked_math cu_dos cpi_reentrancy realloc_race \
           bump_seed_canonicalization; do
    crucible run escrow invariant_${inv}_only --release --timeout 30
done
```

Each campaign reports its respective invariant's violation against the
planted bug. Detection rates range from ~2% (`bump-seed-canonicalization`'s
substitution attack requires the canonical vault to exist first; state
buildup gates reachability) to ~99% (deterministic mechanisms like
`unchecked-math` / `cu-dos` / `realloc-race`). See
[`examples/escrow-demo/README.md`](examples/escrow-demo/README.md)
for per-variant detection numbers and the combined acceptance variant.

## Calibration dataset

The 5 High-tier invariants tested under apples-to-apples Gate 2
conditions against Raydium AMM SwapV2:

| Invariant | Mechanism | Executions | Violations |
|---|---|---:|---:|
| unchecked-math | state mutation (Bounded) | 15,380 | 0 |
| cu-dos | per-ix CU consumption | 25,650 | 0 |
| cpi-reentrancy | CPI call-tree logs | 27,573 | 0 |
| realloc-race | runtime err + post-state | 24,381 | 0 |
| bump-seed-canonicalization | alt-PDA substitution | 75,547 | 0 |
| **Total** | | **168,531** | **0** |

5 distinct detection mechanisms × 1 hardened production target × 0
violations. Edge saturation 629/14,696 identical across all 5 runs —
additional time would not have changed the outcome. The dataset is
the empirical backbone of solinv's "honest tested-and-found-nothing"
framing. Full per-Gate methodology in
[`docs/phase5-day60-bump-seed-canonicalization-gates.md`](docs/phase5-day60-bump-seed-canonicalization-gates.md).

## Invariant catalog (11 invariants)

The catalog targets Solana's distinctive account model and
runtime-specific bug surfaces.

| # | Tier | Name | Bug class | Spec |
|---|---|---|---|---|
| 1 | Critical | signer-skip | missing `is_signer` on authorization-required account | [`docs/invariants/signer-skip.md`](docs/invariants/signer-skip.md) |
| 2 | Critical | owner-skip | missing `account.owner == expected_program` check | [`docs/invariants/owner-skip.md`](docs/invariants/owner-skip.md) |
| 3 | Critical | discriminator-skip | missing Anchor account discriminator check | [`docs/invariants/discriminator-skip.md`](docs/invariants/discriminator-skip.md) |
| 4 | Critical | pda-forge | PDA seed not verified at read time, attacker forges arbitrary PDA | [`docs/invariants/pda-forge.md`](docs/invariants/pda-forge.md) |
| 5 | Critical | account-swap | wrong-context PDA — missing context-binding check | [`docs/invariants/account-swap.md`](docs/invariants/account-swap.md) |
| 6 | High | unchecked-math | arithmetic overflow / wrap reaching protocol state | [`docs/invariants/unchecked-math.md`](docs/invariants/unchecked-math.md) |
| 7 | High | cu-dos | single ix consumes >limit CU → permanent DoS | [`docs/invariants/cu-dos.md`](docs/invariants/cu-dos.md) |
| 8 | High | cpi-reentrancy | CPI cycle through caller program → state-coherence break (Mango v3 class) | [`docs/invariants/cpi-reentrancy.md`](docs/invariants/cpi-reentrancy.md) |
| 9 | High | realloc-race | data buffer grown past rent-exempt threshold without lamport top-up | [`docs/invariants/realloc-race.md`](docs/invariants/realloc-race.md) |
| 10 | High | bump-seed-canonicalization | non-canonical PDA bump accepted; alt-PDA substitution attack | [`docs/invariants/bump-seed-canonicalization.md`](docs/invariants/bump-seed-canonicalization.md) |
| 11 | High | precondition-skip | ix succeeds while a declared entry guard was false — dropped timelock or bound | [`docs/invariants/precondition-skip.md`](docs/invariants/precondition-skip.md) |

Invariant 11 was located by a mutation campaign rather than proposed:
five survivors on `escrow-clean` were dropped `require!` guards that
nothing in the catalog modelled, one of which reproduces the timelock
race `escrow-demo` plants as its flagship bug — a bug that read as
"detected" only because that harness carries a hand-written assertion.
See [mutation testing](#mutation-testing--measuring-detector-power-on-a-real-target).

Medium tier (roadmap, not yet specced): close-reopen,
sysvar-manipulation, permissionless-misuse, rent-exemption,
account-init-race.

Each implemented invariant ships with:
- A spec doc under `docs/invariants/` (8 sections + a §9 pre-committed
  kill criterion for the gated experiments)
- Reference implementation under `crates/solinv-core/src/invariants/`
- Planted-bug fixture in `examples/escrow-demo/`
- Regression tests covering both detect-pair (when in-tree) and
  non-detect baseline

## Validated targets

| Target | Class | Result |
|---|---|---|
| `examples/escrow-demo` | planted bugs across 5 handlers, 7 invariants | 7/7 planted bugs detected end-to-end ([Day 13 Critical 5/5](docs/implementation-day13-owner-skip-unmask-CRITICAL-COMPLETE.md), Day 33 unchecked-math + Day 37 cu-dos Gate 1) |
| `examples/raydium-amm-fuzz` | Native production AMM, 5 invariants × SwapBaseInV2 + OutV2 | 25,383 attacks → **0 violations** ([Day 21](docs/phase2-day21-raydium-extension.md)) |
| `examples/slumlord-fuzz` | Native flash-loan program (Igneous Labs) | 86,391 exec × 5 invariants → **0 violations** ([Day 43](docs/phase4-day43-slumlord-result.md)) |
| Raydium SwapV2 + unchecked-math | High-tier, Gate 2 | 0 violations / 15K exec ([Day 34](docs/phase3-day34-unchecked-math-gate2.md)) |
| Raydium SwapV2 + cu-dos | High-tier, Gate 2 | 0 violations / 25K exec ([Day 38](docs/phase3-day38-cu-dos-gate2.md)) |

**On hardened production code: 0 violations across 3 invariant classes
× 3 protocols × ~150K total executions.** This is the empirical
calibration result: solinv's invariants are sensitive to planted bugs
and silent against well-engineered production code. The dataset is
preserved as the project's published-honest baseline.

## Reachability status

Solinv inherits Crucible's LiteSVM (currently v0.9.1) for in-process
program execution. Different program classes have different reachability:

| Program class | Reachability | Examples |
|---|---|---|
| Native (any `solana-program` 1.16+) | ✅ works | Raydium AMM, Slumlord, Save (ex-Solend), Jito restaking |
| Anchor 1.0+ | ✅ works | escrow-demo |
| Anchor 0.31 + Solana 2.x | ⚠️ builds clean, runtime untested | Meteora DAMM v2, Jito workspace SDK |
| Anchor 0.28 | ✅ for Sanctum unstake's deployed binary (`solana program dump`): `init` and later instructions run. Our local build of it (solana-program 1.14.20, platform-tools v1.37/v1.39) faulted on the `init` CPI, on a real validator too. Other 0.28 programs untested | Sanctum unstake |
| Anchor 0.27, 0.29 | ⚠️ untested with the deployed binary (klend's harness targets its source build) | klend |
| Pre-Anchor / `solana-program 1.10` | ⚠️ the source does not build with any toolchain we tried; the deployed binary is untested | Wormhole bridge |

**Fuzz the binary the protocol deployed.** `solana program dump -u m <program id> out.so`
gets it. An earlier diagnosis blamed LiteSVM for Sanctum unstake's (Anchor 0.28)
`init` failure; the real cause was our rebuild of its solana-program 1.14 source
with new platform-tools
(see [`docs/phase5-day61-h1-was-the-build.md`](docs/phase5-day61-h1-was-the-build.md)).

The `solinv-fuzz::bytepoke` module (Anchor discriminator + sighash helpers,
byte-offset writers, `AnchorAccountBuilder`) is still there for pre-writing deep
state directly instead of reaching it through the program's own instructions.
The klend example uses it.
See [`docs/phase5-day57-bytepoke-helper.md`](docs/phase5-day57-bytepoke-helper.md)
for the helper API.

## Architecture

```
solinv/
├── crates/
│   ├── solinv-core/       # 7 implemented invariants + regression tests
│   ├── solinv-fuzz/       # Crucible re-exports + HasContext/HasInstructionSet traits
│   │                      #   + bytepoke + differential equivalence oracle
│   │                      #   + AccountSchema (named fields) + Relation
│   │                      #   + idl (Anchor IDL → InstructionSpec, candidates)
│   ├── solinv-mutate/     # Mutation operators, campaign planning, and
│   │                      #   reachability-aware scoring (serde+regex only,
│   │                      #   no Crucible/Solana)
│   ├── solinv-cheat/      # LiteSVM cheatcode wrappers
│   ├── solinv-corpus/     # Yellowstone gRPC seeder (scaffold)
│   ├── solinv-disclose/   # Divergence findings as checkable evidence
│   │                      #   (serde+sha2 only, no Crucible/Solana);
│   │                      #   platform formatters pending
│   └── solinv-cli/        # `solinv` binary — idl, diff (+ source.rs: declared
│                          #   account types and #[account] constraints; diff.rs:
│                          #   what a change removes), mutate, score (+ scaffolds:
│                          #   init, check, fuzz, corpus, disclose)
├── examples/
│   ├── escrow-demo/             # planted-bug acceptance fixture (7 invariants)
│   │   ├── diff/drop-a-check/   # escrow-clean with one check dropped (diff quickstart)
│   │   └── idl/                 # IDLs of both programs, for `--features idl_specs`
│   ├── raydium-amm-fuzz/        # Native production AMM (validated clean)
│   ├── slumlord-fuzz/           # Native flash-loan (validated clean)
│   ├── klend-fuzz/              # Anchor 0.29 (source build; ReserveConfig setup incomplete)
│   ├── sanctum-unstake-fuzz/    # Anchor 0.28 (mainnet binary, init reachable)
│   ├── targets.phase4.toml      # target-scoring config (10 protocols)
│   └── target-scoring.example.toml  # config schema reference
├── docs/
│   ├── invariants/                  # per-invariant 8-section specs
│   │   └── field-schema.md          # named fields + relation invariants
│   ├── idl-specs.md                 # IDL → spec: facts vs candidates, limits
│   ├── diff.md                      # what `solinv diff` reports, and its limits
│   ├── mutation-testing.md          # operator catalog + scoring rationale
│   ├── differential-equivalence.md  # oracle rationale + report format
│   ├── disclosure-template-*.md     # Immunefi / Sherlock / generic templates
│   ├── research-*.md                # research deliverables
│   ├── harness-pattern-raw-call.md  # reusable Anchor-version-independent harness
│   └── (implementation logs)        # Day-by-day audit trail of engineering decisions
├── action.yml                       # GitHub Action: solinv diff on pull requests
├── scripts/                         # bandit allocation, metrics, mutation campaigns,
│                                    #   idl-specs-parity.sh (hand vs IDL specs)
└── logs/                            # per-campaign fuzz logs (gitignored)
```

## Start from your IDL

```bash
anchor build                                   # writes target/idl/<program>.json
solinv idl target/idl/my_program.json          # where to point the Critical 5
solinv idl target/idl/my_program.json --src programs/my_program/src  # + declared types
solinv idl target/idl/my_program.json --rust deposit   # binding stub for one ix
```

Reads the Anchor 0.30+ IDL format. A legacy (pre-0.30) IDL is rejected
with the fix: convert it with
`anchor idl convert <path> -p <program id> -o <out>` (`-p` is needed
when the IDL has no `metadata.address`; klend's does not). Shank IDLs
from native programs are not supported. `solinv idl` needs no fixture. It lists every
instruction's slots as the IDL declares them and names the instructions
with **no signer that write a slot the IDL leaves unconstrained** —
either deliberately permissionless, or missing an authority check. On
escrow-demo's planted program those are exactly its three planted
account-validation bugs.

The IDL cannot tell a typed `Account<'info, T>` from an
`UncheckedAccount` (Anchor strips the `/// CHECK:` line from `docs`), so
without source every unconstrained slot counts the same. `--src` reads
each field's declared type from the `#[derive(Accounts)]` structs and
marks slots `U` (`UncheckedAccount` / `AccountInfo`: owner and type
checks are hand-written) or `T` (one of Anchor's typed wrappers). A typed
data account (`Account`, `AccountLoader`, `InterfaceAccount`) that no
`seeds`, `address`, `has_one`, `associated_token::*` or `.key()`
comparison identifies — on it, or on
another slot naming it — and that `init` does not create, is marked
`t`: Anchor checks its owner and type, not which account it is, so it
is where `account-swap` should look. It is a candidate list, not a
verdict: `seeds`, `address`, `has_one`, `associated_token::authority` and each
`&&` clause of a constraint comparing a `.key()` (not an `||`, where
one branch can pass alone) count when they
name another account of the instruction or an upper-case constant
(`seeds` of literals alone too), not an instruction argument the caller
picks, and what a comparison says is not checked; a key
comparison in the handler body is not read (Jito
tip-distribution's `upload_merkle_root` checks there), nor is the fact
that a type only ever exists at one PDA. A tie to another account
counts even when that account is itself the caller's choice (the pool
or sale the instruction acts on): whether a caller can create a matching
pair depends on who can create the type, which the map does not read —
`account-swap` with both slots swapped is the test for that. The reader is a line reader,
not a parser: a slot typed by a type alias, a struct name
defined twice, or a field type split over lines is left unplaced and
counted as not found — never guessed. On the production programs
measured that narrows the review a lot: Jito tip-distribution 29
unconstrained slots → 5 unchecked, tip-payment 34 → 14, Raydium cp-swap
108 → 30, with every slot placed. Writable `t` slots: tip-distribution 4
(a `Config` that `initialize` creates at a PDA, and tip-distribution
accounts the handler checks or any caller may migrate by design),
cp-swap 22 (admin-chosen configs and the
caller's own token accounts — its vaults are tied by `constraint`), and
20 on an Anchor 0.30 program of our own, among them the vaults behind
four real holes ([#3](https://github.com/psyto/solinv/issues/3)).

Building a spec, `system_program` and `associated_token_program` are
bound by name when the IDL gives no address, and listed in
`IdlSpec::defaulted()`. Nothing else is guessed: a program's own account
may be called `clock`, and `token_program` may be SPL Token or
Token-2022. A spec whose program id differs from the
IDL's `address` gets an `unresolved()` entry: the loaded `.so` must
declare that id, or Anchor rejects every instruction with
`DeclaredProgramIdMismatch` — usually a `.so` built with different
features than the IDL.

In the fixture, the stub becomes the spec:

```rust
let spec = idl.spec("deposit", program_id)?
    .account("vault", vault_pda)
    .signer("depositor", Arc::clone(&depositor))
    .args(&50_000u64.to_le_bytes())
    .build()?
    .infer_from_state(|pk| ctx.get_account(pk).ok())   // after setup()
    .infer_candidates(|pk| ctx.get_account(pk).ok())
    .into_spec();
```

The IDL supplies the account list, signers, PDA seeds and instruction
data. `infer_from_state` adds facts: owner and discriminator of each
seeded slot, and which seeded accounts the instruction creates.

That alone finds nothing on Anchor. What the IDL declares, Anchor
already enforces (`signer: true` is a `Signer<'info>`, `pda.seeds` is a
`seeds = [...]` constraint), so the spec only asks the program to
honour checks its own macros generated. Bugs live where the IDL is
silent. `infer_candidates` proposes checks for those slots from what
the fixture put there — a program-owned account with an IDL
discriminator (owner + discriminator); a seed pattern from elsewhere in
the IDL that re-derives the slot's address (pda seeds); on an
instruction with no signer that writes program state, a slot whose
pubkey that state stores (signer) — and lists each in
`IdlSpec::candidates()`.

**Candidates are leads, not facts.** They describe what the fixture
passed, not what the instruction must require: a correct permissionless
crank that pays a stored `beneficiary` matches the signer rule. Confirm
a finding on a candidate slot against the program's intent before
reporting it. Findings do not carry that provenance themselves, so log
`IdlSpec::candidate_log()` when building the spec (the escrow-demo
harnesses do): a finding whose instruction and account index match a
`[SOLINV_CANDIDATES]` line is a lead. Account-data seeds, seeds under
another program, non-8-byte discriminators, and seed patterns that
could not be evaluated for a typed slot are listed in
`IdlSpec::unresolved()`.

Still hand-written: `swap_alternates`, state invariants and guards —
semantic, not in any IDL. Composite accounts are named by dotted path
(`"group_a.authority"`), or by leaf name when it is unique.

`scripts/idl-specs-parity.sh` runs escrow-demo's detectors with the
hand-written specs and with `--features idl_specs`, and exits non-zero
unless every planted row matches across modes and the clean twin
reports nothing. Last run (seed 1,
20 s per planted run, 60 s clean): the same detector fired on the same
instruction in both modes for all five of the Critical 5, and the clean
twin stayed at 0 under `invariant_all`.

## Integration — adopting solinv on your own program

Implement two traits on a fixture that already works under Crucible.
For an Anchor program, build the `InstructionSpec`s from the IDL
([start from your IDL](#start-from-your-idl)) and hand-write only the
semantic fields; the full literal below is what that fills in, and is
still the route for native and Pinocchio programs:

```rust
use solinv_fuzz::{HasContext, HasInstructionSet, InstructionSpec};

impl HasContext for MyFixture {
    fn ctx(&self) -> &TestContext { &self.ctx }
    fn ctx_mut(&mut self) -> &mut TestContext { &mut self.ctx }
    fn program_ids(&self) -> Vec<Pubkey> { vec![self.program_id] }
    fn fee_payer(&self) -> Arc<Keypair> { Arc::clone(&self.fee_payer) }
}

impl HasInstructionSet for MyFixture {
    fn instructions(&self) -> Vec<InstructionSpec> {
        vec![InstructionSpec {
            program_id: self.program_id,
            name: "my_ix".into(),
            accounts: vec![/* AccountMeta list */],
            signer_indices: vec![/* indices that must be signers */],
            expected_owners: vec![/* per-account expected owner (or None) */],
            expected_discriminators: vec![/* Anchor disc bytes (or None) */],
            expected_pda_seeds: vec![/* PDA seeds (or None) */],
            // ... see InstructionSpec docs for all 14 fields ...
        }]
    }
}
```

Then call invariants from a single `#[invariant_test]`:

```rust
#[invariant_test]
fn invariant_all(fixture: &mut MyFixture) {
    solinv_core::invariants::signer_skip::check(fixture);
    solinv_core::invariants::owner_skip::check(fixture);
    solinv_core::invariants::discriminator_skip::check(fixture);
    solinv_core::invariants::pda_forge::check(fixture);
    solinv_core::invariants::account_swap::check(fixture);
    solinv_core::invariants::unchecked_math::check(fixture);
    solinv_core::invariants::cu_dos::check(fixture);
}
```

Anchor IDLs auto-fill four of the five Critical-tier fields
(`signer_indices`, `expected_owners`, `expected_discriminators`,
`expected_pda_seeds`); only `swap_alternates` requires manual
context-binding declaration. Native programs declare manually.

Per-invariant attack vectors and false-positive risks are documented
under `docs/invariants/<name>.md` §3 + §5.

## Target scoring + bandit allocation

The CLI ranks bug-bounty / audit targets via a TOML scoring config:

```bash
./target/release/solinv score --config examples/targets.phase4.toml --top 10
./target/release/solinv score --config examples/targets.phase4.toml --top 10 --reachable-only
```

Each target carries a `status` field (`ready` / `exhausted` / `gated`
/ `unverified`) + free-form note, so the rank output reflects what's
actually fuzzable today, not just what scores high in the abstract.

For per-invariant signal-rate tracking across campaigns, solinv emits
machine-readable bandit metrics:

```bash
SOLINV_BANDIT_METRICS=1 crucible run <target> <invariant> --release --timeout 30
# emits: [solinv][bandit] invariant=... dt_sec=... delta_fp=... fp_per_sec=...
```

The `scripts/recommend_bandit_allocation.sh` and
`scripts/bandit_decide.sh` helpers convert log lines into deterministic
allocation decisions (`70/30`, `50/50`, or `early-stop`). Policy:
[`docs/day3-bandit-allocation-policy.md`](docs/day3-bandit-allocation-policy.md).

## Disclosure templates

`docs/disclosure-template-{immunefi,sherlock,generic}.md` each pair a
field-by-field submission template (matching the platform's expected
form shape) with a worked example built from solinv's own
`escrow-demo` planted-bug detection.

When a real finding does emerge during dogfooding, the templates make
it directly submittable without a from-scratch write-up.

These are human-authored submissions for **invariant** findings —
severity argument, impact narrative, remediation. The machine-generated
evidence for **differential** findings is `solinv-disclose`'s
`DivergenceReport` (above). They are complementary: the template is what
a triage team reads, the report is what they re-run. Wiring the report
into the platform-specific templates is not implemented yet.

## Methodology — pre-commit kill criteria

Every gated invariant ships with a §9 in its spec doc that pre-commits
the experiment's binary outcome before any code runs. Two such gates
have already fired in practice:

- [Day 34 (unchecked-math)](docs/phase3-day34-unchecked-math-gate2.md) — Gate 2 FAIL on Raydium, binding pivot
- [Day 38 (cu-dos)](docs/phase3-day38-cu-dos-gate2.md) — Gate 2 FAIL on Raydium, binding pivot across High tier

This is the methodology contribution as much as the catalog: gated
experiments with binary outcomes, documented in the spec at write-time,
honored at result-time. The pre-commit prevents "let me try one more
thing" drift after a negative result.

## Build + test

```bash
cargo check --workspace               # verify scaffold (~5s)
cargo test  --workspace               # all crates (273 tests)
cargo test  -p solinv-core            # invariant regression tests
cargo test  -p solinv-fuzz            # bytepoke + differential oracle + schema + idl
cargo test  -p solinv-mutate          # operators + mutants + scoring (no Solana deps)
cargo test  -p solinv-disclose        # divergence reports (no Solana deps)
cargo build --release                 # build CLI binary
./target/release/solinv --help
./scripts/idl-specs-parity.sh         # needs crucible + escrow-demo .so files
```

CLI surface:

```
solinv idl <idl.json>                        # account-validation map + unsigned writers
solinv idl <idl.json> --src <program src>    # + U/T/t: unchecked, typed, typed but untied
solinv diff --base-src <before> --head-src <after>  # checks a change removes; exit 1 if any
solinv diff … --format github                # the same, as Actions annotations
solinv idl <idl.json> --rust <ix|all>        # SpecBuilder stub to paste into a fixture
solinv init                                  # scaffold a solinv harness (not yet implemented)
solinv check <target>                        # run invariant checks
solinv fuzz <target>                         # run coverage-guided fuzzer
solinv score --config targets.toml           # rank targets by ROI proxy score
solinv corpus fetch --rpc URL --program-id   # ingest mainnet corpus (scaffold)
solinv disclose <bug-id>                     # generate disclosure report (scaffold)
solinv mutate operators                      # list the mutation operator catalog
solinv mutate plan --target T --src F ...    # plan a campaign + commit its kill criterion
solinv mutate apply --plan P --mutant ID     # write one mutant's patched source
solinv mutate score --plan P --results R     # score a completed campaign
```

## Contributing

PRs welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the
detector / harness / calibration contribution shapes, code style,
and PR process. Security vulnerabilities go via
[`SECURITY.md`](SECURITY.md) (not regular issues).

Sibling project [pinocchio-bench](https://github.com/psyto/pinocchio-bench)
is the public CU leaderboard — adopt solinv on top of a Pinocchio
rewrite to verify behavioral equivalence with the original Anchor
program.

## License

Apache-2.0 — see [`LICENSE-APACHE`](LICENSE-APACHE).

Dependency stack stays MIT/Apache-2.0 clean (Crucible MIT, LiteSVM
Apache-2.0); AGPL deps are avoided so downstream commercial users
aren't polluted.
