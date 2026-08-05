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

A caller of a Solana program can observe three things. All three are
part of the contract, so all three belong in the oracle.

| # | Surface | Type | Fault when |
|---|---|---|---|
| 1 | Written account state | `BodyDivergence` | any byte of the compared body differs |
| 2 | Accept/reject **and the reason** | `ParityDivergence` | decisions differ, or both reject with different error codes |
| 3 | Compute units consumed | `CuComparison` | the rewrite consumed *more* than the original |

### 1. Written state

`check_pair_equivalent` / `check_all_pairs` over a declared set of
`DiffAccountPair`s. Each pair names the two accounts, the body length
to compare, and the per-side prefix to strip (Anchor's 8-byte
discriminator vs Pinocchio's bare body). The divergence is reported to
the first differing byte, with the compared length as context —
"byte 0 of 6664" and "byte 6663 of 6664" are very different findings.

### 2. The decision, and its reason

`ParityDivergence::check` compares booleans only, and therefore **cannot
see reason divergence**: two sides that both reject look like agreement.
That is a real hole, because a program's custom error codes are part of
its observable ABI — a caller branching on `6001` behaves differently
against a rewrite that returns `6002`, even though both "failed".

`check_outcomes` (or `check_codes`, over plain values) closes it: sides
agree only when they made the same decision *and* reported the same
error code. Prefer it wherever the harness has the `TxOutcome`s.

### 3. Cost

CU is not cosmetic on Solana. It is consensus-relevant: two runs that
write byte-identical state at different CU are not equivalent, because
the dearer one can exceed the transaction limit and fail in production
where the other succeeds. A harness that checks only surface (1) will
pass a rewrite that got slower.

`CuComparison` is therefore **recorded on every compared action, not
only on disagreement**. For a rewrite the two sides are *supposed* to
disagree, in one direction — that difference is the measurement the
whole exercise exists to produce, and it is what
[pinocchio-bench](https://github.com/psyto/pinocchio-bench) publishes.
It becomes a fault in exactly one case, a regression, for which
`CuComparison::regression` is the gating constructor.

`None` on a side means that side never reached a successful execution,
so the runtime reported no CU figure. That asymmetry is flagged by the
accompanying `ParityDivergence`, not here.

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
| `programs[].code_sha256` | Program IDs are upgradeable — an ID names a slot in time, not a binary. The hash pins the bytes that ran. |
| `accounts[].pre_state_sha256` | Same reason, for state. |
| `feature_set` | Solana runtime semantics are gated by flags that activate at epoch boundaries. Same instruction + same accounts can be two different executions on two different days. Without this the comparison target is undefined. |
| `actions` | The minimal instruction sequence reaching the divergence. |
| `slot` | Which mainnet snapshot the accounts were cloned from, when the fixture came from a real pool. |

`is_reproducible()` / `missing()` make an incomplete bundle say so.
A report that can't be reproduced renders with **`Reproducible: NO`**
and the list of gaps at the top, rather than presenting itself as
checkable.

Hashing is part of the spec, not an implementation detail: `sha256_hex`
is exported so a third party recomputing digests hashes the same way
rather than guessing the encoding.

### What the digest does and does not do

`DivergenceReport::digest()` is SHA-256 over a canonical encoding
(compact JSON, struct declaration order, no maps so no ordering
ambiguity). It pins **the claim** — inputs, sides, and asserted
divergences — so a finding can be quoted, referenced across a bounty
thread, or later signed without ambiguity about which version is meant.

It does **not** attest that the claim is true. No hash can. Confirming a
finding means re-running the bundle and arriving at the same
divergence. That division is deliberate: the digest makes the claim
immutable, re-execution makes it true or false.

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
- `Divergence` / `ReproBundle` / `DivergenceReport`, canonical
  encoding, digest, Markdown rendering (`solinv-disclose`,
  23 tests + 5 doctests).

**Not implemented**

- **No harness emits a report yet, and none has adopted the two new
  checks.** Six differential harnesses live under
  `examples/pinocchio-bench-fuzz/fuzz/` — `amm-diff`, `matching-diff`,
  `oracle-diff`, `perp-diff`, `refresh-diff`, `vault-diff`. All of them
  currently call `check_pair_equivalent` / `check_all_pairs` plus the
  boolean `ParityDivergence::check`, so all six still carry both holes:
  a rewrite that changes an error code or regresses on CU passes.
  Adopting `check_codes` / `CuComparison` and emitting a
  `DivergenceReport` is a change in this repository, per harness.
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
