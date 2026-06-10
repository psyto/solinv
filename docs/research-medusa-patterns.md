# Medusa Design Patterns → solinv Portability

Date: 2026-05-24
Status: Week 2 validation item #4

## Verdict

**Top 5 Medusa patterns to port to solinv** (all clean-room reimplemented to avoid AGPL contamination):

1. Aspect-level shrinker (3-pass: drop-failed → shorten → per-aspect)
2. Three-tier test-case taxonomy (`assert_*` / `property_*` / `optimize_*`)
3. Background corpus pruner (periodic re-run on cloned chain)
4. Per-entry corpus weighting (`mutationChooserWeight`)
5. Replayable failure artifacts (`{UnixNano}-{UUID}.json`)

Everything else either already in Crucible/LibAFL or EVM-specific.

## Critical license constraint

**Medusa AGPL-3.0. Echidna AGPL-3.0.** Direct code lifts = AGPL contamination of solinv.

**Mitigation:** clean-room reimplement from architectural notes. Cite Medusa as design inspiration only, copy zero lines. Foundry (MIT/Apache-2.0) is safer to study side-by-side.

## Medusa architecture summary

Top-level (Go, default branch `master`, last push 2026-05-14, ~474 stars):
- `chain/` — geth-backed `TestChain` + cheatcodes
- `compilation/` — Solidity build
- `fuzzing/` — the brain
- `cmd/`, `events/`, `logging/`

`fuzzing/` decomposes:
- `fuzzer.go` — `Fuzzer` struct with `ctx`, workers, corpus, metrics, testCases, Hooks, Events. `Start()` builds baseValueSet → `ChainSetupFunc` → `spawnWorkersLoop()` (goroutines coordinated via `threadReserveChannel` + `availableWorkerSlotQueue`). Termination: `Timeout`, `TestLimit`, ctx cancel
- `fuzzer_worker.go` — per-worker loop (~L633): drain shrink requests → generate sequence → `testNextCallSequence()` → `CheckSequenceCoverageAndUpdate()`. Recycled on `WorkerResetLimit` to bound state growth
- `fuzzer_worker_sequence_generator.go` — `CallSequenceGenerator`. New vs mutation chosen by `NewSequenceProbability`. Corpus path = `WeightedRandomChooser` over 8 strategies (corpus head/tail × prepend/splice × mutated/unmodified)
- `fuzzer_worker_shrinking.go` — three passes in sequence: `removeReverts`, `shortenSequence`, `shrinkAllTransactions` (per-tx aspect: args/value/gas-price/block-delay). **Final tx never touched**
- `corpus/` — JSON files in `call_sequences/` and `test_results/` named `{UnixNano}-{UUID}.json`. `addCallSequence(weight *big.Int)` supports per-entry weights
- `corpus_pruner.go` — runs every `PruneFrequency` minutes on cloned chain with coverage tracer
- `coverage/coverage_maps.go` — **edge markers** (srcPC → destPC) + special XOR for revert/return/enter. Hit count 0→non-zero = new coverage. **No AFL bucketing** (less granular than LibAFL — solinv stays with LibAFL)
- `valuegeneration/mutator.go` — **typed mutations**: `MutateAddress/Bool/Integer/String/Bytes/FixedBytes/Array` + AST + Slither seed constants

## 12-pattern portability table

| # | Pattern | Class | solinv action |
|---|---|---|---|
| 1 | Coverage-guided scheduler with energy assignment | NOT NEEDED | Crucible/LibAFL covers; Medusa's is just weighted random anyway |
| 2 | Stateful multi-call sequences | PORTABLE | `Vec<CallMessage>` → `Vec<Action>` (Crucible already has this) |
| 3 | Handler functions (Foundry pattern) | PORTABLE+MOD | Solana: Rust harness module exposing instruction builders with pre-conditions (PDA derivation, signer setup, account funding). High value |
| 4 | Shrinker / minimization | **PORTABLE** | Medusa 3-pass = cleanest reference. Crucible has minimization; solinv adds aspect-level (account list, lamports, ix data field, sysvar clock delay) |
| 5 | Crash bucket deduplication | PORTABLE+MOD | Solana: key by `{program_id, ix_disc, error_code}` (vs Medusa's `{contract, method}`) |
| 6 | Property vs assertion vs optimization invariants | **PORTABLE+MOD** | 3-tier model: `assert_*` (panic/log-scan), `property_*` (view returning bool), `optimize_*` (max-finding). Function-prefix discovery = lightest API |
| 7 | Mutation strategies (byte vs typed) | NOT NEEDED | Crucible already does typed mutation on `Action` |
| 8 | Corpus management / interesting input prioritization | PARTIAL | LibAFL provides scheduler; **borrow Medusa's corpus pruner** as separate task |
| 9 | Time-budget execution | PORTABLE | `Timeout`, `TestLimit`, `ShrinkLimit`, `CallSequenceLength`, `WorkerResetLimit` config schema = direct lift |
| 10 | Parallel worker coordination | PORTABLE+MOD | Goroutines → tokio/rayon. LibAFL multi-core LLMP already inherited. Defer to LibAFL |
| 11 | Replay / regression suite generation | **PORTABLE** | Serializable `Vec<Action>` + RNG seed + slot/clock state. Trivial. Turns every crash into `cargo test`-able regression |
| 12 | Coverage report output formats | PORTABLE+MOD | LCOV reusable. sBPF→source needs DWARF (covered by sbpf-coverage research) |

## Top 5 implementation priorities

### 1. Aspect-level shrinker
Source: `fuzzing/fuzzer_worker_shrinking.go` (L1-L300).

3-pass design:
- **Pass 1**: drop-failed-ix (remove instructions that reverted)
- **Pass 2**: shorten-sequence (remove non-failing tail)
- **Pass 3**: per-ix-aspect shrink (account selection, instruction data fields, lamports, clock-delay)

**Invariant**: always preserve the last instruction (it's the one triggering the bug).

solinv crate: `solinv-fuzz` shrinker module.

### 2. Three-tier test-case taxonomy
Source: `fuzzing/test_case_assertion.go`, `test_case_property.go`, `test_case_optimization.go`.

API:
- `#[solinv_assert]` on `fn` — panic-style; passes if no log scan match or `InstructionError::ProgramFailedToComplete`
- `#[solinv_property]` on `fn(&Fixture) -> bool` — passes if returns true; reads via view ix
- `#[solinv_optimize]` on `fn(&Fixture) -> i64` — maximize objective

Discovery via prefix at `onFuzzerStarting()` time, no manual registration.

### 3. Background corpus pruner
Source: `fuzzing/corpus/corpus_pruner.go`.

Periodic task (`PruneFrequency` minutes) that:
1. Clones LiteSVM
2. Re-runs corpus with coverage tracer
3. Drops sequences that no longer add edges

Critical for long Phase 1 campaigns where corpus accumulates degenerate dupes.

### 4. Per-entry corpus weighting
Source: `corpus.go::addCallSequence(weight *big.Int)`.

Cheap layer on top of LibAFL scheduler:
- Bias toward sequences hitting **rare edges**
- Bias toward recently-failing-then-shrunk sequences (regression candidates)

### 5. Replayable failure artifacts
Source: `fuzzing/test_results/{UnixNano}-{UUID}.json`.

Schema:
```json
{
  "program_id": "...",
  "actions": [...],
  "signers": [...],
  "sysvar_clock": {...},
  "sysvar_slot": "...",
  "rng_seed": "..."
}
```

Trivial to add. Every crash becomes `cargo test`-able regression.

## EVM-specific patterns → Solana equivalents

| Medusa (EVM) | Solana equivalent |
|---|---|
| Solidity panic codes (`0x01/0x11/0x12`) | Scan `TransactionResult` for `InstructionError::ProgramFailedToComplete`, Anchor error codes from `program.log`, BPF VM aborts |
| Geth `WorkerResetLimit` for MemoryDB OOM | `AccountsDb` size threshold reset |
| Slither AST seeding | **Anchor IDL constants + `declare_id!` pubkeys + sysvar pubkeys + `1`/`u64::MAX`/`LAMPORTS_PER_SOL`** — strong analogue, implement it |
| Cheatcodes (`chain/cheat_code_contract.go`) | LiteSVM native (warp clock, lamports, rent-exempt, sysvar override) — expose via `solinv-cheat` module |
| Block timestamp / `MaxBlockTimestampDelay` | Solana slot / `Clock` sysvar advancement bound |
| `fail_on_revert` (Foundry) | `fail_on_program_error` config flag; default true for assertions, false for property-only |

## Risks

1. **License**: Medusa + Echidna AGPL-3.0. Clean-room reimplement only. Foundry MIT/Apache-2.0 safer for code lifts
2. **Language barrier (Go → Rust)**: Medusa uses goroutines + channels + `sync.Mutex`. Rust port → `tokio` async OR `crossbeam` channels + `parking_lot::Mutex`. LibAFL already wraps these
3. **Crucible alignment**: Need confirm Crucible exposes (a) sequence corpus with weight injection, (b) post-call invariant hook, (c) replayable seed plumbing. If not → upstream Crucible PRs OR solinv-side wrapping
4. **Coverage representation mismatch**: Medusa per-marker hit-counts < LibAFL AFL-bucketed bitmap. Don't downgrade — stay with LibAFL
5. **No JSON coverage in Medusa**: solinv should emit JSON in addition to LCOV (Medusa's omission)

## Sources

- [crytic/medusa](https://github.com/crytic/medusa) (AGPL-3.0, Go)
- [crytic/echidna](https://github.com/crytic/echidna) (AGPL-3.0, Haskell)
- [Unleashing Medusa — ToB blog 2025-02-14](https://blog.trailofbits.com/2025/02/14/unleashing-medusa-fast-and-scalable-smart-contract-fuzzing/)
- [Foundry Invariant Testing book page](https://book.getfoundry.sh/forge/invariant-testing)
- [RareSkills: Invariant Testing in Foundry](https://rareskills.io/post/invariant-testing-solidity)
- [solidity-fuzzing-comparison benchmarks](https://github.com/devdacian/solidity-fuzzing-comparison)
