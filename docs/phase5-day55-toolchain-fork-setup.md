# Phase 5 Day 55 — toolchain fork: setup + first experiment

Date: 2026-05-28
Phase: 2.5 (OSS audit-accelerator), toolchain fork stage (Day 55-68 plan)
Goal: resolve the Anchor 0.x ↔ LiteSVM 0.9.1 H1 ABI mismatch
(`docs/phase4-day47-a1-dig.md`) so the Anchor 0.27-0.29 production
universe (klend, Sanctum, Marinade, etc.) becomes reachable.

## Infrastructure set up (Day 55)

1. **Local LiteSVM fork**: `~/src/litesvm-fork` — cloned at tag v0.9.1
   (matches the version Crucible v0.1.0 pulls transitively). Editable
   working copy; the actual `litesvm` crate is at
   `~/src/litesvm-fork/crates/litesvm`.

2. **Cargo patch wiring** — `[patch.crates-io] litesvm = { path = ... }`
   added to:
   - `~/src/solinv/Cargo.toml` (workspace root — for the solinv crates)
   - `examples/sanctum-unstake-fuzz/fuzz/sanctum-unstake/Cargo.toml`
     (the H1 reproduction + fix-verification harness; opt-out workspace
     so it needs its own patch entry)

   Verified: both rebuild against the fork cleanly. The patch overrides
   the crates.io litesvm that crucible-test-context (git dep) would
   otherwise resolve.

3. **Reproduction target**: Sanctum unstake harness (Anchor 0.28).
   `crucible run sanctum_unstake invariant_sanctum_unstake_smoke` against
   the vanilla fork reproduces the exact Day 46-47 baseline: 1.4% edges
   (206/15012), 0% ok rate, create_pool soft-fails inside Anchor's
   `#[account(init, mint::authority, mint::decimals)]` constraint with
   "Access violation at 0xFFFFFFFFFFFFFFFF size 32".

**Dev loop**: edit `~/src/litesvm-fork/.../lib.rs` → `cargo build
--release` the Sanctum harness → `crucible run ... --timeout 5` → check
ok rate / edges / error. ~10s per iteration after first build.

## Experiment 1 — is H1 feature-gated? (NO)

**Hypothesis**: `into_basic()` uses `FeatureSet::all_enabled()`, turning
on Solana 3.x features Anchor 0.28 (Solana 1.16-era) doesn't expect.
If a feature toggles the failing codepath, disabling it fixes H1.

**Test**: swapped `FeatureSet::all_enabled()` → `FeatureSet::default()`
(all features off) in the fork's `into_basic()`, rebuilt Sanctum
harness, ran smoke.

**Result**: **IDENTICAL failure.** 1.4% edges, 0% ok, same access
violation. Disabling every feature flag changed nothing.

**Conclusion**: H1 is **not feature-gated.** Reverted to
`all_enabled()` (the working baseline; `default()` risks breaking
basic program loading anyway). This rules out the cheapest fix path —
there is no "disable feature X" one-liner.

## Remaining hypotheses (deeper, Day 56+)

With feature-gating ruled out, the H1 access violation is most likely
one of:

- **H1b — AccountInfo memory-layout ABI difference.** Anchor 0.28's
  bundled `solana-program` (1.16-era) assumes a specific in-VM memory
  layout for `AccountInfo` (data ptr, owner ptr, lamports ptr offsets).
  LiteSVM 0.9.1 emulates the Solana 3.x runtime, which may serialize
  the account region differently. When Anchor's macro-generated
  validation reads `account.owner` (a 32-byte Pubkey — matches the
  "size 32" in the error) through the old offset, it dereferences a
  bad address. The 0xFFFF... (= near u64::MAX) address is consistent
  with a pointer computed from a wrong/negative offset.
  → Fix would require LiteSVM to present accounts in the layout the
  old solana-program expects — a compatibility shim, not a config.

- **H1c — BPF loader version mismatch.** LiteSVM loads programs under
  a loader version (v2 vs v3 / upgradeable) that may differ from what
  Anchor 0.28's entrypoint macro expects. Affects how the program's
  input region is laid out at invocation.

- **H1d — syscall ABI difference.** A syscall (e.g.
  `sol_get_account_info` or the CPI account-passing path) behaves
  differently across runtime versions in a way that corrupts the
  account region mid-validation.

H1b is the leading candidate given the "size 32" Pubkey-read signature
and the crash-during-account-validation timing (5802 CU, before any
CPI logs).

## Revised effort estimate

The Day 47 estimate was "1-2 weeks LiteSVM-internals patching". Day 55
experiment 1 sharpens this **upward**: since H1 isn't a feature toggle,
the fix likely requires either:

- a per-account memory-layout compatibility shim in LiteSVM's account
  loading path (deep, runtime-internals work), OR
- running an older solana-program-runtime version inside LiteSVM for
  Anchor 0.x programs (very deep, possibly architecturally infeasible
  within LiteSVM 0.9.1), OR
- pinning the whole stack to an older LiteSVM that natively ran the
  Solana 1.16 runtime (loses Crucible v0.1.0 compatibility — would
  need a Crucible fork too)

Realistic revised estimate: **2-4 weeks minimum, with non-trivial risk
that a clean fix isn't achievable without a Crucible-level downgrade.**
This is worth surfacing to the Phase 2.5 plan — the toolchain fork is
the riskiest line item, and a time-box + kill criterion (à la the
Phase 3 §9 methodology) is warranted before sinking weeks into it.

## Next experiment (Day 56)

Before committing to a shim, cheaply test H1c/H1b discrimination:

1. **Build a trivial Anchor 0.28 hello-world** (single ix, single
   `#[account(mut)] data: Account<'info, Foo>`, no mint/init CPI).
   Run it under the fork. If even a bare `Account<'info, Foo>` read
   trips H1 → confirms H1b (account-layout), the most fundamental.
   If only the mint-init CPI path trips it → narrows to H1c/H1d
   (CPI / loader-specific).

2. Cross-check against the Day 51 finding that Anchor 0.31 *builds*
   clean — does Anchor 0.31 also *run* clean? If 0.31 runs but 0.28
   doesn't, the boundary is a specific solana-program version bump
   between 0.28 and 0.31, which narrows the shim target.

The Day 56 experiment is cheap (a 30-line hello-world Anchor program +
minimal harness) and would discriminate between "deep but bounded
shim" (H1c/d) and "fundamental layout incompatibility" (H1b). That
discrimination should gate whether the toolchain fork proceeds or the
Phase 2.5 plan pivots to "ship with Native + Anchor 1.0+ support only".

## Pre-commit time-box (proposed, à la Phase 3 §9)

Toolchain fork should not be open-ended. Proposed kill criterion:

- **Gate A (Day 56-58)**: discriminate H1b vs H1c/d via the
  hello-world experiment. If H1b (fundamental layout) → the shim is
  likely infeasible within LiteSVM 0.9.1; pivot to "Native + Anchor
  1.0+ only" launch scope.
- **Gate B (Day 59-65)**: if H1c/d (bounded), attempt the shim. If a
  working Anchor 0.28 run isn't achieved by Day 65, time-box expires →
  pivot to Native + Anchor 1.0+ launch scope + document the Anchor 0.x
  gap as a known limitation + contributor invitation.

This keeps the toolchain fork from becoming an open-ended sink, and
preserves a clean launch path (Native + Anchor 1.0+ is already a
shippable OSS artifact) even if the fork fails.

## Files touched Day 55

- `~/src/litesvm-fork/` — new local fork (NOT in solinv repo; external
  like raydium-amm / slumlord / sanctum-unstake clones)
- `Cargo.toml` (solinv root) — `[patch.crates-io]` litesvm entry
- `examples/sanctum-unstake-fuzz/fuzz/sanctum-unstake/Cargo.toml` —
  same patch entry
- `docs/phase5-day55-toolchain-fork-setup.md` (this doc)

Note: the fork itself lives outside the solinv repo, so the patch
paths are machine-local (absolute paths to ~/src/litesvm-fork). Before
public launch this needs to become either a git submodule, a published
fork crate, or an upstreamed Crucible patch — tracked as a launch-prep
item.
