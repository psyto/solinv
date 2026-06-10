# Phase 1 Day 1 — Crucible Hands-On Validation

Date: 2026-05-25
Status: ✅ ALL DAY-1 GOALS MET

## Outcomes

| Day 1 goal | Status | Evidence |
|---|---|---|
| Clone Crucible v0.1.0 | ✅ | `research/crucible` at tag `v0.1.0` (commit `689e63a`) |
| Verify toolchain | ✅ | cargo 1.95.0, cargo-build-sbf 3.1.14, platform-tools v1.52, solana-cli 3.1.14 (Agave) |
| Install `crucible` CLI | ✅ | `cargo install --path crates/crucible-fuzz-cli --locked` (15.20s build) |
| Build escrow program (SBF) | ✅ | 35.83s, outputs `target/deploy/escrow.so` |
| Run fuzzer | ✅ | 2,080 exec/sec single-thread, found planted bug in seconds |
| Generate LCOV | ✅ | `coverage/coverage.lcov` written, 3719 lines + 780 branches reported |

## Throughput observed

Single-thread on this machine: **2,080 exec/sec**. Per Crucible blog post the multicore scaling is near-linear with `-j N` so 16 cores should reach ~30k exec/sec. (Crucible blog claims 67k on 12 cores; mileage will vary by harness complexity.)

## Coverage observed (escrow example, 30s fuzz + 24 corpus inputs)

- **419 / 3,512 edges (11.9%)**
- **390 / 1,756 branches (22.2%)**

Bytecode-level coverage by default. LCOV output uses synthetic source file name (`program_af1e4b0a930d8e03.bpf`) and synthetic function names (`fn_0`, `fn_53`, etc.). Real source-level mapping requires the 3-binary workflow (deferred to Day 2).

## Bug detection

Planted bug (slot `<=` should be `<`) detected within seconds of starting fuzz. Sample violation output:

```
=== FUZZ SEQUENCE (4 executed, 4 skipped) ===
  1. advance_slots(slots=10) -> OK
  2. deposit(amount=65536) -> OK
  3. deposit(amount=254722) -> OK
  4. withdraw(amount=256) -> OK [VIOLATION]
[FUZZ_FINDING] withdraw at slot 10 should have been rejected (unlock_slot = 10)
```

Shrinker auto-minimizes to 3-4 action reproductions. Multiple independent crashes recorded (108-111 within 30 sec).

## Two-step coverage workflow (validated)

```bash
# Step 1: fuzz to build corpus (no --coverage, full speed)
crucible run escrow invariant_escrow --release --timeout 15 --corpus-out ./corpus
# → corpus/ contains 24 input files

# Step 2: replay corpus with --coverage (single pass, generates LCOV)
crucible run escrow invariant_escrow --release --coverage --corpus-in ./corpus
# → coverage/coverage.lcov written
```

`--coverage` ALONE without `--corpus-in` errors out (`Error: --coverage requires --corpus-in`). The two-step workflow is the documented pattern.

## CLI surface confirmed

```
crucible init           Create a new fuzz harness for a program
crucible run            Run a fuzz test
crucible list           List available fuzz tests (program_name positional)
crucible show           View/replay crashes
crucible tmin           Minimize a crash to smallest reproducing action sequence
crucible cmin           Minimize corpus to smallest set preserving coverage
```

`crucible list` does NOT take test name (only program_name). `crucible show <program> <test> <crash-id>` for inspection. `crucible tmin <program> <test> <crash-id>` for shrinking.

## LCOV format observed

Standard LCOV:

```
TN:fuzzer
SF:program_af1e4b0a930d8e03.bpf
FN:1,fn_0
FN:54,fn_53
...
DA:<pc>,<count>
...
BRDA:<line>,<block>,<branch>,<taken>
...
end_of_record
```

Per docs/coverage.md, source-level mapping would replace `SF:` with real paths (`/path/programs/escrow/src/lib.rs`) and `DA:` line numbers would be Rust source lines instead of PCs.

## Day 1 strategic learnings

1. **Crucible CLI is small and fast to install** (15 sec for cargo install). Acceptable user friction
2. **Escrow example build time is short** (~36s) — within hackathon-attention-span
3. **Fuzzer throughput on M-series Mac single thread** = 2k exec/sec; multi-core scaling makes solinv viable on solo dev hardware
4. **Default bytecode-level coverage** is sufficient for "track coverage growth" metric; source-level needs 3-binary setup (~30 min extra setup per program)
5. **Coverage requires corpus replay** — implies solinv-corpus crate should make corpus persistence first-class, not optional
6. **CLI subcommand names match research expectations** — `run / list / show / tmin / cmin`. `init` mentioned in docs but we didn't test (Day 2)

## Day 1 → Day 2-3 readiness

All Day 1 success criteria met. Day 2-3 can proceed:

- **Day 2**: Set up 3-binary workflow on escrow → confirm source-level LCOV maps to Rust files
- **Day 3**: Read `crucible-fuzz-macro/src/coverage.rs` to understand bitmap shape; read `crucible-invariant-macro/src/lib.rs` for `#[fuzz_fixture]` / `#[invariant_test]` API
- **Day 4-5**: Start `solinv-fuzz` crate — re-export Crucible + define `HasContext` / `HasInstructionSet` capability traits

No surprises encountered. Tool stack works as research notes predicted.

## Risks / friction observed (small)

| Item | Note |
|---|---|
| `crucible --version` not supported | Minor UX gap. `--help` works |
| `--coverage` alone errors | Need `--corpus-in` always. Document in solinv harness guide |
| Build warnings in escrow harness | Cosmetic (`unused_mut`); doesn't block functionality |
| First-time install brings dep chain | ~20 deps compiled; acceptable for tooling |

None are blockers. All expected per Crucible v0.1.0's "API may change" disclaimer.

## Next session

Day 2 plan:
1. Modify escrow's `Cargo.toml` with `[profile.release] opt-level = 1, debug = 2, strip = false`
2. Rebuild with `cargo build-sbf --debug --tools-version v1.52`
3. Run coverage with `--symbols target/sbpf-solana-solana/release/escrow.so`
4. Confirm LCOV uses real Rust source paths
5. Maybe install `lcov` (`brew install lcov`) + `genhtml` for HTML report visualization
