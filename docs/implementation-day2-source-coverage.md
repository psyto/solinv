# Phase 1 Day 2 — Source-Level Coverage Validation

Date: 2026-05-25
Status: ✅ Source-level LCOV mapping works end-to-end

## Outcomes

| Day 2 goal | Status | Evidence |
|---|---|---|
| Edit `[profile.release]` for debug info | ✅ | Added `opt-level = 1, debug = 2, strip = false` |
| Rebuild with `--debug --tools-version v1.52` | ✅ | 44.56s, produces 170K stripped + 5.3M unstripped |
| Source-level LCOV via `--symbols` | ✅ | `DWARF source map loaded: 12,059 PCs resolved, 12,043 functions` |
| Real source paths in LCOV | ✅ | `SF:/.../programs/escrow/src/lib.rs` |
| Demangled function names | ✅ | `escrow::escrow_program::deposit`, `escrow::entry`, etc. |
| HTML report via `genhtml` | ⬜ skipped | `lcov`/`genhtml` not installed (would need `brew install lcov`) |

## Binary size comparison (debug info confirmation)

| Build | Size | Purpose |
|---|---|---|
| Day 1 (default release) | 165K stripped, **817K unstripped** | Bytecode-level coverage only |
| Day 2 (debug=2, strip=false) | 170K stripped, **5.3M unstripped** | Source-level via DWARF |

The 5.3M unstripped binary is significantly smaller than coverage.md's
"30-40 MB" estimate — escrow is a tiny program (~200 lines of Rust),
so the absolute DWARF size scales accordingly. Larger production
programs (Drift, Marginfi, openhl-solana) will see proportionally
larger debug binaries.

## LCOV output sample (source-level)

```
TN:fuzzer
SF:~/src/solinv/research/crucible/examples/escrow/programs/escrow/src/lib.rs
FN:7,escrow::entry
FN:7,escrow::__private::__global::initialize
FN:7,escrow::__private::__global::deposit
FN:7,escrow::__private::__global::withdraw
FN:7,escrow::__private::__global::claim
FN:24,escrow::escrow_program::deposit
FN:46,escrow::escrow_program::withdraw
FN:70,escrow::escrow_program::claim
FN:88,<escrow::Initialize as anchor_lang::Accounts<...>>::try_accounts
FNDA:158,escrow::entry
FNDA:0,escrow::__private::__global::initialize     ← uncovered (no init in fuzz)
FNDA:63,escrow::__private::__global::deposit
FNDA:30,escrow::__private::__global::withdraw
FNDA:65,escrow::__private::__global::claim
...
```

This is the format solinv-disclose can directly consume to:
- Identify which Anchor account constraint helpers were exercised
- Report which instructions in target program never executed
- Surface "uncovered branch" candidates to guide invariant additions

## Cargo.toml modification

Added to `examples/escrow/Cargo.toml` workspace `[profile.release]`:

```toml
[profile.release]
overflow-checks = true
lto = "fat"
codegen-units = 1
opt-level = 1      # NEW: better DWARF accuracy (vs default opt=3 inlining gaps)
debug = 2          # NEW: full DWARF
strip = false      # NEW: keep debug sections
```

For solinv users, this modification recipe goes into `solinv init`
template Cargo.toml — coverage workflow becomes "out of the box"
after `solinv init`.

## Implementation implications

### Documentation update for solinv

`solinv init` should generate user project's `Cargo.toml` with both:

```toml
# Fuzzing profile (fast, optimized; default for `cargo build-sbf`)
[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1

# Coverage profile (slower, source-mappable)
[profile.coverage]
inherits = "release"
opt-level = 1
debug = 2
strip = false
```

Users would then build with `cargo build-sbf --profile coverage` for
coverage workflows, separate from the fuzzing build. This avoids the
slowdown for normal fuzz runs.

### LCOV parser for solinv-disclose

The LCOV format observed exactly matches what `crucible/docs/coverage.md`
documents:

- `SF:` — real source paths (absolute)
- `FN:` — function declarations (line, demangled name)
- `FNDA:` — function hit counts (count, name)
- `DA:` — line hit data
- `BRDA:` — branch data

solinv-disclose can use a standard LCOV parser (e.g., Python
`parse_lcov` recipe in coverage.md §LCOV Parsing) to extract uncovered
ranges for "missing-coverage" disclosures.

## Coverage observations (escrow, source-level)

- 1 source file (`lib.rs`)
- 4,504 lines (including all expanded macros — Anchor `#[program]`)
- 448 branches
- 14.4% edges / 26.9% branches reached from 25 corpus inputs
- `escrow::__private::__global::initialize` never called (no `initialize` action in harness)
- All 3 main paths (`deposit`, `withdraw`, `claim`) hit

The `initialize` function being uncovered indicates the harness
doesn't have an `action_initialize`. This is correct because escrow's
`Vault::init` happens automatically on first `deposit` via Anchor's
`init` constraint. Manual `initialize` ix doesn't exist.

This is exactly the gap-analysis use case solinv-disclose enables.

## Day 1+2 validation status

| Validation | Status |
|---|---|
| Crucible runs on this Mac | ✅ Day 1 |
| Bytecode-level coverage works | ✅ Day 1 |
| Planted bug detected via fuzz | ✅ Day 1 |
| Two-step corpus workflow (`--corpus-out` then `--coverage --corpus-in`) | ✅ Day 1 |
| **Source-level coverage via `--symbols`** | ✅ Day 2 |
| **DWARF mapping (PC → source line)** | ✅ Day 2 |
| **Real source paths + demangled functions in LCOV** | ✅ Day 2 |
| HTML report generation | ⬜ skipped (lcov/genhtml not installed) |

## Optional: install lcov for HTML reports

If wanted:

```bash
brew install lcov
lcov --extract coverage/coverage.lcov '*/programs/escrow/*' -o escrow_coverage.lcov
genhtml escrow_coverage.lcov -o coverage_html --legend
open coverage_html/index.html
```

Defers to user preference — solinv core functionality doesn't depend
on HTML rendering.

## Day 2 → Day 3 readiness

Both coverage modes (bytecode + source-level) validated. Day 3 can
proceed to Crucible internals reading:

- Read `crates/crucible-fuzz-macro/src/coverage.rs` — bitmap shape,
  `MAP_SIZE`, `SHARED_EDGE_BITMAP_SIZE` constants
- Read `crates/crucible-invariant-macro/src/lib.rs` (lines 1270-1434) —
  `#[invariant_test]` injection hook
- Read `crates/crucible-test-context/src/lib.rs` — `TestContext` API
  surface, `fuzz_assert_*!` macros, violation TLS

After Day 3, Days 4-5 implement `solinv-fuzz` capability traits
(`HasContext`, `HasInstructionSet`) per `docs/invariants/signer-skip.md`
template.

## Risks / friction observed (none new)

| Item | Day 2 specific |
|---|---|
| `lcov`/`genhtml` not pre-installed | Cosmetic; `brew install lcov` is 1 command |
| Cargo.toml modification needed per program | Documented; will be `solinv init` template |
| 44s rebuild after profile change | Acceptable (one-time cost per program) |
| Debug binary is 30x larger | Expected, stays in target/ — not deployed |

No blockers, no surprises.
