# solinv

**Solana-aware invariant fuzzing framework.** A library + plugin on
top of [Crucible](https://github.com/asymmetric-research/crucible)
that ships Solana-specific bug-class detectors as auto-invariants, so
audit firms and protocol teams don't have to hand-author every
`fuzz_assert!` themselves.

Apache-2.0 licensed. Sibling to
[pinocchio-bench](https://github.com/psyto/pinocchio-bench) — the
public CU-measurement leaderboard comparing Anchor vs Pinocchio
across 13 DeFi hot paths.

## What this is

Existing Solana fuzzers (Crucible, [Trident](https://github.com/Ackee-Blockchain/trident))
provide coverage-guided execution and snapshot infrastructure. They
ask the user to declare what counts as a bug. Solinv ships that
declaration as a library:

1. **Pre-built Solana invariants — catalog 10/10** end-to-end against
   planted bugs and clean against hardened production code:
   **Critical 5** (signer-skip, owner-skip, discriminator-skip,
   pda-forge, account-swap) + **High 5** (unchecked-math, cu-dos,
   cpi-reentrancy, realloc-race, bump-seed-canonicalization). Each
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
   `AnchorAccountBuilder` so adopting solinv on an Anchor 0.x program
   (where the LiteSVM/Anchor ABI mismatch blocks init paths) takes
   minutes instead of hours.
6. **Disclosure templates** — Immunefi / Sherlock / direct-to-protocol
   markdown templates with field-by-field guidance + a worked example
   from solinv's own planted-bug detection.
7. **Differential equivalence + reproducible reports** — a three-surface
   oracle for "do these two programs behave the same?" (written state,
   accept/reject *and reason*, compute units), and a finding format that
   carries the inputs needed to re-execute it. See
   [differential equivalence](#differential-equivalence--do-two-programs-behave-the-same)
   below.

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

Solinv spells the oracle out as three surfaces, all of them observable
by a caller and therefore all of them load-bearing:

| Surface | Type | Fault when |
|---|---|---|
| Written account state | `BodyDivergence` | any byte of the compared body differs |
| Accept/reject **and the reason** | `ParityDivergence` | decisions differ, or both reject with *different error codes* |
| Compute units consumed | `CuComparison` | the rewrite consumed **more** than the original |

Two of these are easy to omit and expensive to omit:

- **Error codes are ABI.** A caller branching on `6001` behaves
  differently against a rewrite returning `6002` — yet a boolean
  accept/reject check calls that agreement, because both sides
  "failed". `ParityDivergence::check_outcomes` compares the reason too.
- **CU is consensus-relevant.** Two runs writing byte-identical state at
  different CU are not equivalent: the dearer one can exceed the
  transaction limit and fail where the other succeeds. `CuComparison` is
  recorded on every action rather than only on disagreement — for a
  rewrite the CU difference is the measurement the work exists to
  produce, and only a *regression* is a fault.

A harness that checks written state alone will pass a rewrite that
changed its error codes or got slower.

### Findings that someone else can check

A finding that only says *what* diverged is an assertion. `solinv-disclose`
packages it with the inputs needed to re-execute it:

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

…followed by SHA-256 of each side's `.so`, of every account's
pre-state, the activated feature set, and the action sequence. Program
IDs are upgradeable, so an ID names a slot in time rather than a
binary; the feature set matters because Solana's runtime semantics are
gated by flags that activate at epoch boundaries, which makes "same
instruction, same accounts" two different executions on two different
days. An incomplete bundle renders as **`Reproducible: NO`** with the
list of gaps, rather than presenting itself as checkable.

The report digest pins **the claim**, so a finding can be quoted or
referenced without ambiguity about which version is meant. It does not
attest that the claim is *true* — no hash can. Confirming a finding
means re-running the bundle. The digest makes the claim immutable;
re-execution makes it true or false.

`solinv-disclose` depends on serde and sha2 and nothing else: finding a
divergence needs Crucible, LiteSVM and the Solana crates, but *checking
a report about one* should not.

Design rationale, API walkthrough and current gaps:
[`docs/differential-equivalence.md`](docs/differential-equivalence.md).

All six differential harnesses under
`examples/pinocchio-bench-fuzz/fuzz/` (`amm-diff`, `matching-diff`,
`oracle-diff`, `perp-diff`, `refresh-diff`, `vault-diff`) check all
three surfaces, with CU non-regression as its own
`*_cu_no_regression_only` variant so a performance finding is never
reported as a behavioural one. **Emitting reports is still pending** —
a finding leaves the fuzz worker as a log line, not yet as a
reproducible bundle.

## Quickstart — escrow-demo (catalog 10/10)

```bash
# Install Crucible CLI (one-time)
git clone https://github.com/asymmetric-research/crucible ~/src/crucible
cargo install --path ~/src/crucible/crates/crucible-fuzz-cli

# Build the planted-bug program (one planted bug per High-tier invariant
# + the Critical-5 acceptance fixture)
cd examples/escrow-demo
cargo build-sbf --tools-version v1.52 --manifest-path programs/escrow/Cargo.toml

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

## Invariant catalog (10/10 complete)

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
| Anchor 0.27-0.29 | ⛔ runtime depth-gated (H1 ABI mismatch) | klend, Sanctum unstake, Marinade |
| Pre-Anchor / `solana-program 1.10` | ⛔ build-gated (toolchain too old) | Wormhole bridge |

**Byte-poke pattern unblocks Anchor 0.x post-init reachability**
without requiring a LiteSVM fork. The `solinv-fuzz::bytepoke` module
provides reusable Anchor discriminator + sighash helpers + byte-offset
writers + an `AnchorAccountBuilder`. Adopting solinv on a
depth-gated Anchor 0.x program: pre-write the target accounts via
the byte-poke API (skipping the broken init→CPI path), then fuzz
the post-init attack surface directly. The klend (Anchor 0.29) and
sanctum-unstake (Anchor 0.28) example harnesses demonstrate the
pattern. See
[`docs/phase4-day47-a1-dig.md`](docs/phase4-day47-a1-dig.md) for the
H1 diagnosis and
[`docs/phase5-day57-bytepoke-helper.md`](docs/phase5-day57-bytepoke-helper.md)
for the helper API + usage.

## Architecture

```
solinv/
├── crates/
│   ├── solinv-core/       # 7 implemented invariants + regression tests
│   ├── solinv-fuzz/       # Crucible re-exports + HasContext/HasInstructionSet traits
│   │                      #   + bytepoke + differential equivalence oracle
│   ├── solinv-cheat/      # LiteSVM cheatcode wrappers
│   ├── solinv-corpus/     # Yellowstone gRPC seeder (scaffold)
│   ├── solinv-disclose/   # Reproducible divergence reports (serde+sha2 only,
│   │                      #   no Crucible/Solana); platform formatters pending
│   └── solinv-cli/        # `solinv` binary — score, init, check, fuzz, corpus, disclose
├── examples/
│   ├── escrow-demo/             # planted-bug acceptance fixture (7 invariants)
│   ├── raydium-amm-fuzz/        # Native production AMM (validated clean)
│   ├── slumlord-fuzz/           # Native flash-loan (validated clean)
│   ├── klend-fuzz/              # Anchor 0.29 (depth-gated, unblocks after fork)
│   ├── sanctum-unstake-fuzz/    # Anchor 0.28 (depth-gated, unblocks after fork)
│   ├── targets.phase4.toml      # target-scoring config (10 protocols)
│   └── target-scoring.example.toml  # config schema reference
├── docs/
│   ├── invariants/                  # per-invariant 8-section specs
│   ├── differential-equivalence.md  # oracle rationale + report format
│   ├── disclosure-template-*.md     # Immunefi / Sherlock / generic templates
│   ├── research-*.md                # research deliverables
│   ├── harness-pattern-raw-call.md  # reusable Anchor-version-independent harness
│   └── (implementation logs)        # Day-by-day audit trail of engineering decisions
├── scripts/                         # bandit allocation + metrics aggregation
└── logs/                            # per-campaign fuzz logs (gitignored)
```

## Integration — adopting solinv on your own program

Implement two traits on a fixture that already works under Crucible:

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
cargo test  --workspace               # all crates (119 tests)
cargo test  -p solinv-core            # invariant regression tests
cargo test  -p solinv-fuzz            # bytepoke + differential oracle
cargo test  -p solinv-disclose        # divergence reports (no Solana deps)
cargo build --release                 # build CLI binary
./target/release/solinv --help
```

CLI surface:

```
solinv init                                  # scaffold a solinv harness
solinv check <target>                        # run invariant checks
solinv fuzz <target>                         # run coverage-guided fuzzer
solinv score --config targets.toml           # rank targets by ROI proxy score
solinv corpus fetch --rpc URL --program-id   # ingest mainnet corpus (scaffold)
solinv disclose <bug-id>                     # generate disclosure report (scaffold)
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
