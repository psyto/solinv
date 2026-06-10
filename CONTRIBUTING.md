# Contributing to solinv

Thanks for considering a contribution. solinv is a Solana-aware
invariant fuzzing framework built as a plugin layer on top of
[Crucible](https://github.com/asymmetric-research/crucible). The
maintainers' priority is the **invariant catalog** + **honest
calibration data**: contributions that grow either are most
welcome.

## Quick links

- Bug class spec template: [`docs/invariants/cu-dos.md`](docs/invariants/cu-dos.md) (10-section format)
- Existing detectors: [`crates/solinv-core/src/invariants/`](crates/solinv-core/src/invariants/)
- Example harnesses: [`examples/`](examples/)
- Calibration dataset: [`docs/phase5-day60-bump-seed-canonicalization-gates.md`](docs/phase5-day60-bump-seed-canonicalization-gates.md) §"Phase 2.5 cumulative calibration dataset"
- Security disclosure: [`SECURITY.md`](SECURITY.md)

## Ways to contribute

### 1. Add a new invariant (highest leverage)

Each invariant ships as a triple:

1. **Spec doc** at `docs/invariants/<name>.md` following the
   10-section template (Bug class / Mainnet precedent / Detection
   algorithm / Capability trait / FP risks / Severity / Test
   fixture / References / **§9 pre-commit experiment design** /
   **§10 honest framing**). The §9 + §10 sections are not optional —
   they encode the methodology that distinguishes solinv from a
   collection of detectors. See [`cpi-reentrancy.md`](docs/invariants/cpi-reentrancy.md)
   §10 for the framing template.
2. **Implementation** at `crates/solinv-core/src/invariants/<name>.rs`
   following the existing pattern (free `check` function that takes
   `&mut F: HasContext + HasInstructionSet`, opt-in via
   `Option<Config>` field on `InstructionSpec`, unit tests for any
   pure logic). Cu-dos and realloc-race are the cleanest templates.
3. **Planted-bug fixture in escrow-demo + Gate 1** (must fire within
   30s of `crucible run`) + **production-target Gate 2** (record the
   result whether positive or null — null is the expected and
   publishable Phase 2.5 outcome).

PRs proposing only a spec without the impl, or only the impl without
a Gate 1, are welcome but reviewers will ask for the missing piece
before merging.

### 2. Add a new example harness

Each harness is one target protocol. Existing examples:

- `escrow-demo` — planted-bug fixture for self-validation (Anchor 1.0)
- `raydium-amm-fuzz` — Native production AMM (calibration source)
- `slumlord-fuzz` — Native flash-loan
- `klend-fuzz` — Anchor 0.29 lending (byte-poke pattern)
- `sanctum-unstake-fuzz` — Anchor 0.28 LST unstake (byte-poke)
- `pinocchio-bench-fuzz` — Pinocchio-vs-Anchor differential

A new harness needs:
1. `fuzz/<name>/` directory with `Cargo.toml` + `src/main.rs`.
2. `setup()` that loads the target's `.so` via `ctx.add_program`.
3. `HasContext` + `HasInstructionSet` impls on the fixture.
4. At least one `#[invariant_test]` entry.
5. A `README.md` documenting how to build the target program.

External `.so` paths use `env!()` so users can point at their own
checkout: `env!("RAYDIUM_AMM_SO", "set ...")`. See
[`examples/raydium-amm-fuzz/`](examples/raydium-amm-fuzz/) as the
canonical template.

### 3. Run calibration on a new protocol

The Phase 2.5 calibration dataset (5 invariants × Raydium ×
~168K exec × 0 violations) anchors solinv's "honest tested-and-
found-nothing" framing. Extending it to more protocols (Save,
Jito-restaking, Marginfi, etc.) is highly valuable — each protocol
adds an evidence row.

Process:
1. Build the target as an example harness (per #2).
2. Run each invariant for the documented Gate 2 budget (2 campaigns
   × 4 workers × 30s).
3. Submit the results as a `docs/phase*-<protocol>-calibration.md`
   doc following the Day 58 / 59 / 60 template.

### 4. Bytepoke helper extensions

`solinv-fuzz::bytepoke` houses the Anchor 0.x byte-poke primitives.
Open follow-ups:
- `mirror!` macro wrapping `#[repr(C)] struct + offset_of!`.
- Field-aware account builder API.
- Coverage of additional Anchor account discriminator/sighash
  patterns beyond the 8-byte sha256 prefix.

### 5. Documentation, typos, READMEs

All welcome. Keep prose technical and avoid marketing claims that
can't be reproduced via `crucible run`.

## Development setup

```bash
git clone https://github.com/psyto/solinv.git
cd solinv

# Install Crucible CLI (one-time)
git clone https://github.com/asymmetric-research/crucible ~/src/crucible
cargo install --path ~/src/crucible/crates/crucible-fuzz-cli

# Workspace build
cargo build --workspace
cargo test --workspace

# Run escrow-demo example
cd examples/escrow-demo
cargo build-sbf --tools-version v1.52 --manifest-path programs/escrow/Cargo.toml
crucible run escrow invariant_signer_skip_only --release --timeout 30
```

## Code style

- `cargo fmt --all` before committing.
- `cargo clippy --workspace --all-targets` — keep new code warning-free.
- Tests: prefer unit tests for pure logic (log parsers, math helpers, etc.)
  + Gate 1 acceptance for detector correctness on planted bugs.
- Comments are sparse and load-bearing: explain WHY, not WHAT.
  Reference issue numbers / mainnet precedents / spec sections
  rather than restating the code's surface.

## Commit style

- Subject line ≤ 70 chars.
- Body explains the WHY, links the relevant `docs/invariants/<name>.md`
  section if applicable, references prior Day N docs for methodology
  precedent.
- Sign-off via `git commit -s` if your employer requires it.
- Co-authorship lines welcome (`Co-Authored-By: ...`).

## PR process

1. Open an issue first if the work is ≥1 day of effort, so reviewers
   can sanity-check direction.
2. Branch from `main`. Rebase rather than merge to keep history flat.
3. PRs should be reviewable in one sitting (~500 lines diff for code,
   ~1000 for docs).
4. CI runs `cargo build --workspace`, `cargo test --workspace`, plus
   any planted-bug Gate 1 tests added by the PR.
5. Reviewer turnaround target: 5 business days. Bug fixes may merge
   faster.

## Adding a planted-bug fixture

The planted-bug pattern is solinv's correctness gate. Every
detector ships with at least one planted-bug fixture in
`escrow-demo` (or its own dedicated example crate for complex
shapes). See [`examples/escrow-demo/programs/escrow/src/lib.rs`](examples/escrow-demo/programs/escrow/src/lib.rs)
for the canonical layout — each `unsafe_*` ix is annotated with
the invariant it validates + the bug shape it exercises.

When adding one:
1. Document the bug shape in a `// ----- PLANTED BUG for ... -----`
   comment block, including the real-world analogue.
2. Use deterministic-detection patterns (e.g., `wrapping_*`
   arithmetic rather than `unchecked_*` which the SBF runtime
   panics on with `overflow-checks = true`).
3. Cap fuzz-derived inputs so the ix succeeds reliably (so the
   detector's re-execution lands on the Success branch).
4. Stamp the spec's relevant field (`cu_budget: Some(N)`,
   `bump_seed_check: Some({...})`, etc.) on the harness's
   `InstructionSpec` literal so the detector enrolls the ix.

## Phase 2.5 catalog status

The current catalog is **10/10** complete (Critical 5 + High 5):
signer-skip, owner-skip, discriminator-skip, pda-forge, account-swap,
unchecked-math, cu-dos, cpi-reentrancy, realloc-race,
bump-seed-canonicalization.

Future expansion candidates (Medium tier):
- close-reopen
- sysvar-manipulation
- permissionless-misuse
- rent-exemption
- account-init-race

See [`docs/research-summary.md`](docs/research-summary.md) for the
historical catalog framing.

## Code of conduct

Be kind, be specific. Report bad behavior via the maintainer email
in [`SECURITY.md`](SECURITY.md).
