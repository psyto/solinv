# Differential equivalence — the oracle, and the report

Solinv's invariant catalog answers *"does this program violate a
property?"*. The differential surface answers a different question:
*"do these two programs behave the same?"* — the question a Pinocchio
rewrite, a refactor, or an optimization has to answer before it ships.

This doc covers what "the same" has to mean on Solana, and what a
finding has to carry to be checkable by someone who wasn't there.

- Harness-side API: `crates/solinv-fuzz/src/differential.rs`
- Report-side API: `crates/solinv-disclose/src/`

## Why the oracle has to be hand-built here

On Ethereum a differential runner has something to diff *against*. The
state root commits to post-state; the receipts trie commits to logs and
status. Two clients that disagree produce two different roots, and the
disagreement is visible without anyone deciding in advance what to
compare.

Solana publishes no equivalent. There is no state root you can prove an
account against, and no receipt trie. So there is nothing to compare
except the other run, and **the definition of "same outcome" is a
choice the tool makes**, not something the chain hands you. Getting
that definition wrong doesn't produce an error — it produces silent
false confidence.

That framing also explains why this module's types are the shape they
are: the comparison target has to travel with the finding, because
nothing on-chain can reconstruct it later.

## The three surfaces

Three of the things a caller can observe, chosen because they are where
a rewrite is most likely to break. **They are not the whole observable
surface** — see "What is not compared" below.

| # | Surface | Type | Fault when |
|---|---|---|---|
| 1 | Written account state | `BodyDivergence` | any byte of the compared body differs |
| 2 | Accept/reject **and the reason** | `ParityDivergence` | decisions differ, or both reject for different reasons |
| 3 | Compute units consumed | `CuComparison` | the rewrite consumed *more* than the original |

### 1. Written state

`check_pair_equivalent` / `check_all_pairs` over a declared set of
`DiffAccountPair`s. Each pair names the two accounts, the body length
to compare, and the per-side prefix to strip (Anchor's 8-byte
discriminator vs Pinocchio's bare body). The divergence is reported to
the first differing byte, with the compared length as context —
"byte 0 of 6664" and "byte 6663 of 6664" are very different findings.

### 2. The decision, and its reason

A boolean accept/reject comparison **cannot see reason divergence**:
two sides that both reject look like agreement. A program's rejection
reasons are part of its observable ABI — a caller branching on `6001`
behaves differently against a rewrite that returns `6002`, even though
both "failed".

Comparing the custom error code is necessary but still not sufficient.
`TxOutcome::error_code()` returns `None` for *every* builtin
`ProgramError`, so two sides rejecting with `InvalidArgument` and
`AccountDataTooSmall` would both report "no code" and compare equal.
That is the likeliest place for a divergence to hide in this repository,
because the Pinocchio bench rewrites return builtins exclusively.

`SideResult` therefore carries a normalized reason — `custom:6001`,
`builtin:InvalidArgument` — and `ParityDivergence::check_outcomes`
compares that. The reason is a **comparison token**, meaningful only
against another token from the same build; it is not a stable wire
identifier.

### 3. Cost

CU is not cosmetic on Solana. It is consensus-relevant: two runs that
write byte-identical state at different CU are not equivalent, because
the dearer one can exceed the transaction limit and fail in production
where the other succeeds. A harness that checks only surface (1) will
pass a rewrite that got slower.

`CuComparison::from_outcomes` therefore records the figure on every
compared action, not only on disagreement. For a rewrite the two sides are *supposed* to
disagree, in one direction — that difference is the measurement the
whole exercise exists to produce, and it is what
[pinocchio-bench](https://github.com/psyto/pinocchio-bench) publishes.
It becomes a fault in exactly one case, a regression, for which
`CuComparison::regression` is the gating constructor. Note what the
harnesses actually do: they call `regression` only, which **discards
the measurement on every non-regressing action**. What they retain is
the verdict, not a per-action CU series.

`None` on a side means that side never reached a successful execution,
so the runtime reported no CU figure.

## What is not compared

Naming the gaps, because a differential that quietly under-checks is
worse than one that admits its scope:

- **Account metadata** — lamports, owner, and the executable flag are
  all caller-observable and none are compared. Only declared body byte
  ranges are.
- **Undeclared accounts** — an account written by one side but absent
  from `diff_pairs()` is invisible.
- **Return data and logs** — both observable, neither compared.
- **Rejection reasons beyond the first differing probe** — a harness
  stops at the first violation.

A run that passes all three surfaces has narrowed where a divergence
could be hiding. It has not proved equivalence.

## Probes that produced no evidence

`send()` returning `Err` is a harness-level failure — bad signer set,
unloaded account, malformed instruction — not a statement about program
behaviour. It is nonetheless reported, by `SendFailure`, rather than
skipped: a harness whose sends are all failing would otherwise run to
completion and declare itself clean. **Nothing diverges when nothing
executes**, which makes an unreported send failure the most dangerous
possible result — a broken harness that looks like a passing one.

## From finding to report

The harness-side types are tuned for the fuzz worker: `Display` strings
destined for `fuzz_assert!`, `anchor`/`pino` in the field names. That is
the right shape for the person watching the run and the wrong shape for
everyone else.

`solinv-disclose` is the other half. `From` conversions turn each
finding into a `solinv_disclose::Divergence`: serializable, hashable,
and **side-neutral** — the two executions are `left` and `right`, and
what they were is carried as data in `Sides`. The generality is
load-bearing rather than decorative, because the same record has to
serve:

- an Anchor program vs its Pinocchio rewrite (solinv today),
- a program at commit N vs commit N+1 (refactor regression),
- the `.so` deployed on mainnet vs a local build (post-mortem
  reconstruction),
- a venue's published number vs an independent recomputation.

### The reproduction bundle

A report that only says *what* diverged is an assertion. One that
carries the inputs is evidence: the reader re-executes and reaches the
same place, instead of taking the finder's word.

`ReproBundle` carries what re-execution actually needs:

| Field | Why it is required |
|---|---|
| `programs[].code` | Program IDs are upgradeable — an ID names a slot in time, not a binary. The artifact pins the bytes that ran. |
| `accounts[].pre_state` + owner/lamports | Same reason, for state. Account metadata is part of the state, not decoration. |
| `feature_set` | Solana runtime semantics are gated by flags that activate at epoch boundaries. Same instruction + same accounts can be two different executions on two different days. Without this the comparison target is undefined. |
| `actions` | The minimal instruction sequence reaching the divergence. |
| `slot` | Which mainnet snapshot the accounts were cloned from, when the fixture came from a real pool. |

### A digest identifies; it does not deliver

The distinction that a boolean `is_reproducible()` got wrong: a SHA-256
lets a reader confirm that bytes they already hold are the right ones.
It cannot hand them those bytes. A bundle carrying only digests
describes what must be supplied out of band — it is not, by itself,
enough to re-execute anything, and must not announce otherwise.

`ReproBundle::completeness()` is therefore three-valued:

| value | meaning |
|---|---|
| `SelfContained` | program bytes, account pre-state with metadata, and encoded instructions all travel with the report. Re-execute from this alone. |
| `IdentifiedOnly` | everything is *named* — digests, program IDs, labels — but the bytes do not travel. Obtain them independently, verify against the hashes, then re-run. |
| `Incomplete` | something required to define the comparison at all is absent. |

**Every report this repository can currently produce is
`IdentifiedOnly`.** No harness populates inline artifacts or encoded
instruction data yet. The rendered header says so.

Hashing is part of the spec, not an implementation detail: `sha256_hex`
is exported so a third party recomputing digests hashes the same way
rather than guessing the encoding.

### What the digests do and do not do

Two are exposed. `claim_digest()` covers the semantic finding — schema
version, subject, sides, inputs, divergences — and **excludes
provenance**, so two runs that found the same thing agree even if one
was produced by a newer build. `digest()` covers the whole report,
tool stamp included, and will change on a crate release even when the
finding did not.

Both are SHA-256 over compact JSON with fields in struct declaration
order, no maps, so no key-ordering ambiguity. The honest scope: **that
guarantee holds for one schema version.** Adding a field, reordering
declarations, or a change in `serde_json` formatting all change the
bytes. `SCHEMA_VERSION` is carried inside the hashed payload so a
mismatch is diagnosable — it is not a stable cross-version wire format.

Neither attests that the claim is true. No hash can. Confirming a
finding means re-running the bundle and arriving at the same
divergence: the digest makes the claim immutable, re-execution makes it
true or false.

### Rendered output

```
# Divergence report — amm-diff (raydium-amm swap)

- **Sides**: `anchor` (left) vs `pinocchio` (right)
- **Verdict**: DIVERGED
- **Report digest**: `9fbd48ca…`
- **Reproducible**: yes — re-run the bundle below and compare

## Where they parted

- [recorded] `swap` CU: 12400 → 3900 (-8500)
- **[fault]** `swap(100, 0)` outcome diverged: left rejected (6001), right rejected (6002)
```

…followed by the program / account hash tables and the action sequence.
Note the two prefixes: the CU saving is `[recorded]` because it is the
goal, and only the error-code divergence is a `[fault]`.

## Relationship to the disclosure templates

`docs/disclosure-template-{immunefi,sherlock,generic}.md` are
human-authored submissions for **invariant** findings — severity
argument, impact narrative, remediation. `DivergenceReport` is the
machine-generated evidence for **differential** findings.

They are complementary, not alternatives: the templates are what a
triage team reads, the report is what they re-run. Wiring the report
into the platform-specific templates is not done yet — see Status.

## Status

**Implemented**

- All three oracle surfaces, with `From` conversions into the report
  types (`solinv-fuzz`, 29 tests).
- Adoption across all six differential harnesses
  (`examples/pinocchio-bench-fuzz/fuzz/{amm,matching,oracle,perp,refresh,vault}-diff`):
  each drives its probe actions through `probe_actions`, which returns
  the raw `TxOutcome`s instead of collapsing them to booleans, then
  applies `check_outcomes` for parity and exposes CU non-regression as
  its own `*_cu_no_regression_only` invariant variant.
- `Divergence` / `ReproBundle` / `DivergenceReport`, canonical
  encoding, digest, Markdown rendering (`solinv-disclose`,
  23 tests + 5 doctests).

**Not implemented**

- **No harness emits a report yet.** All six differential harnesses
  under `examples/pinocchio-bench-fuzz/fuzz/` now check all three
  surfaces (see below), but the `DivergenceReport` conversions are not
  wired into any of them — a finding still leaves the fuzz worker as a
  `fuzz_assert!` log line, not as a reproducible bundle.
- The `TxOutcome` adapters (`check_outcomes`, `from_outcomes`,
  `regression`) are untested — constructing a `TxOutcome` needs
  `Signature` / `InnerInstructionsList` / `TransactionReturnData`,
  which are not `solinv-fuzz` dependencies. The decision logic is
  factored into `check_codes` and tested there; the adapters are
  one-line forwarding.
- No signing. The digest pins the claim; binding it to an identity
  (ed25519 receipt) is not in this crate.
- Bounty-platform-specific formatters, severity classification,
  economic impact estimation, and remediation-pattern lookup are still
  unimplemented — the Markdown rendering is generic and not shaped to
  any platform's submission template.
- The `.so` bytes and account pre-state are hashed by whoever builds
  the bundle; nothing yet captures them automatically from a running
  harness.
