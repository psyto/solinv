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
| `accounts[].pre_state` + owner / lamports / **executable** | Same reason, for state. The metadata is part of the state, not decoration — `executable` decides whether the runtime treats the account as a program, so an account restored without it is not the account that ran. |
| `feature_set` | Solana runtime semantics are gated by flags that activate at epoch boundaries. Same instruction + same accounts can be two different executions on two different days. Without this the comparison target is undefined. |
| `actions` | The minimal instruction sequence reaching the divergence. A label describes a step; only `ActionRef::encoded` — whose base64 must actually decode — lets anyone replay it. |
| `slot` | Which mainnet snapshot the accounts were cloned from, when the fixture came from a real pool. |

### A digest identifies; it does not deliver

The distinction that a boolean `is_reproducible()` got wrong: a SHA-256
lets a reader confirm that bytes they already hold are the right ones.
It cannot hand them those bytes. A bundle carrying only digests
describes what must be supplied out of band — it is not, by itself,
enough to re-execute anything, and must not announce otherwise.

`ReproBundle::completeness()` is therefore four-valued:

| value | meaning |
|---|---|
| `InputsCarried` | every input the bundle *models* travels with it and matches its own declared length and digest: program bytes, account pre-state with full metadata (owner, lamports, executable, rent epoch), decodable instruction encodings, a feature set, and a stated execution context and signer policy. |
| `IdentifiedOnly` | everything is *named* — digests, program IDs, labels — but the bytes do not travel. Obtain them independently, verify against the hashes, then re-run. |
| `Incomplete` | something required to define the comparison at all is absent. |
| `Corrupt` | a carried payload contradicts its own declared length or digest. Worse than absent: the bundle asserts it holds the inputs and the assertion is false. Checked first, so no other verdict can mask it. |

`InputsCarried` is only granted after every carried payload is decoded
and re-hashed, and every encoded action is decoded. Trusting a payload
because the same report also states its digest would repeat, one level
down, exactly the mistake the digest/deliver distinction exists to
prevent — and so would trusting a `data_base64` field that no reader
can turn back into an instruction.

Base64 is accepted in **canonical form only**: padding must terminate
the stream, the discarded bits of a short final quantum must be zero,
and the string must re-encode to itself. This is stricter than
decodability, and the reason is the digest rather than the payload —
the SHA-256 covers the decoded bytes, but the base64 *string* is what
gets hashed into the claim. Two encodings of one payload would pass
every integrity check while producing two different claim digests for
one finding.

### Reading a report back

`serde_json::from_slice` does not validate the schema number: it will
accept a document declaring any version whose shape happens to fit,
silently reinterpreting it under this build's meaning.
`DivergenceReport::from_json` is the path that checks, and is what
should be used wherever a report is treated as evidence.

**Every report this repository can currently produce is
`IdentifiedOnly`.** No harness populates inline artifacts, encoded
instruction data, or an execution context yet. The rendered header
says so.

### `InputsCarried` is not "replayable"

The verdict was called `SelfContained` for three revisions, rendered as
"re-execute from this alone", and that was never true. Each revision
found another layer being trusted rather than carried: first the bytes
behind a digest, then the integrity of those bytes, then the
decodability of an instruction encoding — and then the things the model
does not represent at all.

Two of those are structural rather than oversights:

- **Signing material.** Action metas carry `is_signer` flags, but a
  published report must never carry keys. `SignerPolicy` therefore
  states how signatures are to be satisfied — `SigverifyDisabled` for a
  LiteSVM-backed harness, or `KeysSuppliedOutOfBand` naming the signers
  a reader has to bring.
- **Runtime conditions.** Sysvars beyond the clock, the exact runtime
  build, and any program-owned account the fixture never declared are
  *stated* (`ExecutionContext.runtime`, `clock_slot`) rather than
  carried.

So the verdict now claims only what it can: nothing the model covers is
missing or corrupt, and the reader has been told which environment to
reconstruct. That is the strongest honest claim available to a document
you publish.

Hashing is part of the spec, not an implementation detail: `sha256_hex`
is exported so a third party recomputing digests hashes the same way
rather than guessing the encoding.

### What the digests do and do not do

Two are exposed. `claim_digest()` covers the semantic finding — schema
version, subject, sides, inputs, divergences — and **excludes
provenance**, so two runs that found the same thing agree even if one
was produced by a newer build. `digest()` covers the whole report,
tool stamp included, and will change on a crate release even when the
finding did not. The claim is a real nested field rather than a
projection maintained by hand, so the two cannot silently drift apart.

**The cross-release promise has a hole, and the report says where.** A
rejection reason naming a builtin `ProgramError` is a `Debug` rendering
— correct for comparing two sides inside one process, which is what it
is produced for, but its *text* belongs to the toolchain rather than to
the finding. When such a token is inside the hashed payload, the digest
inherits that instability. `claim_digest_is_portable()` returns `false`
in exactly that case, and the rendered header labels the digest
`build-scoped`. Custom codes (`custom:6001`) are unaffected — a `u32`
is stable.

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

…followed by the program table and the account table — each row stating
whether its bytes are carried, and flagging `**CORRUPT**` if a carried
payload fails its own digest — then the execution context (runtime,
clock, and how signatures are to be satisfied; here, *not stated*), then
the action sequence with each action's account metas. Instruction data
past 44 base64 characters is elided toward the serialized JSON, which is
what a reader replays from.

Note the two prefixes: the CU saving is `[recorded]` because it is the
goal, and only the reason divergence is a `[fault]`. And note that the
digest is labelled build-scoped: the finding names a builtin
`ProgramError`, whose text comes from the toolchain rather than from the
finding.

The sample above is real output, regenerated against the current
renderer rather than transcribed by hand.

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
  types (`solinv-fuzz`, 31 tests).
- Adoption across all six differential harnesses
  (`examples/pinocchio-bench-fuzz/fuzz/{amm,matching,oracle,perp,refresh,vault}-diff`):
  each drives its probe actions through `probe_actions`, which returns
  the raw `TxOutcome`s instead of collapsing them to booleans, then
  applies `check_outcomes` for parity and exposes CU non-regression as
  its own `*_cu_no_regression_only` invariant variant.
- `Divergence` / `ReproBundle` / `DivergenceReport`, canonical
  encoding, digest, Markdown rendering (`solinv-disclose`,
  55 tests + 6 doctests).

**Not implemented**

- **No harness emits a report yet.** All six differential harnesses
  under `examples/pinocchio-bench-fuzz/fuzz/` check all three surfaces
  and report probes that produced no evidence, but the
  `DivergenceReport` conversions are not wired into any of them — a
  finding still leaves the fuzz worker as a `fuzz_assert!` log line,
  not as a bundle.
- **Nothing populates a fully carried bundle.** Every report this
  repository can currently produce is `IdentifiedOnly`. The inline
  carrier, account metadata, instruction encoding, execution context and
  signer policy all exist and are tested; no producer fills them in.
- The `TxOutcome` adapters (`check_outcomes`, `from_outcomes`,
  `regression`) are thin forwarding over tested decision logic and are
  not themselves covered — constructing a `TxOutcome` needs
  `Signature` / `InnerInstructionsList` / `TransactionReturnData`,
  which are not `solinv-fuzz` dependencies.
- `SendFailure` is unit-tested but has never fired in a campaign: no
  send has failed in any of the six harnesses, so the reporting path is
  not exercised end to end.
- Builtin-reason parity has not been run against the W9 and W10
  harnesses, whose recorded campaigns predate it.
- No signing. The digest pins the claim; binding it to an identity
  (ed25519 receipt) is not in this crate.
- Bounty-platform-specific formatters, severity classification,
  economic impact estimation, and remediation-pattern lookup are still
  unimplemented — the Markdown rendering is generic and not shaped to
  any platform's submission template.
- The `.so` bytes and account pre-state are hashed by whoever builds
  the bundle; nothing yet captures them automatically from a running
  harness.
