//! # solinv invariants
//!
//! Per Day 3 internals deep-read, each invariant follows the same
//! detection pattern (`docs/implementation-day3-crucible-internals.md` §1
//! Corrections):
//!
//! 1. Manual save: `get_account()` each account in `spec.accounts`
//! 2. Compute pre program-state hash
//! 3. Mutate accounts per invariant's attack vector
//! 4. Execute via `ctx.raw_call(Instruction { ... }).signers(&...).send()`
//!    (NOT Anchor `ProgramBuilder.accounts()` — that overwrites
//!    AccountMeta vec)
//! 5. Compute post hash
//! 6. `fuzz_assert!(!(success && state_changed), "violation msg")`
//! 7. Manual restore: `write_account()` each saved account back
//!    (NOT `restore_snapshot()` — that restores ALL dirty accounts)
//!
//! First-violation-wins TLS means multiple invariants chained in one
//! `#[invariant_test]` body produce at most one violation per iteration;
//! 5 bugs → 5 violation messages observed across a fuzz campaign.

pub mod signer_skip;
pub mod owner_skip;
pub mod discriminator_skip;
pub mod pda_forge;
pub mod account_swap;

// Critical tier 5/5 implemented (2026-05-25).
//
// High tier — Phase 3 gated experiments closed Day 38; reopened Day 58
// under Phase 2.5 OSS catalog-completion framing (committed Day 52,
// see docs/invariants/cpi-reentrancy.md §10).
//   Day 31-34: unchecked_math. Gate 1 PASS, Gate 2 FAIL on Raydium.
//   Day 35-38: cu_dos. Second gated experiment per Day 34 follow-on +
//   docs/invariants/cu-dos.md §9 + §10. Two-fail outcome binds the
//   pivot across the Phase 3 extraction frame.
//   Day 58: cpi_reentrancy under Phase 2.5 catalog frame. Detection via
//   TxOutcome.logs CPI call-tree reconstruction.
//   Day 59: realloc_race under Phase 2.5 catalog frame. Detection via
//   pre/post-ix data.len()+lamports state snapshot vs rent_for(post_len).
//   Day 60: bump_seed_canonicalization under Phase 2.5 catalog frame.
//   Detection via alt-PDA substitution from non-canonical bump.
//   Catalog 10/10 complete (Critical 5 + High 5).
pub mod unchecked_math;
pub mod cu_dos;
pub mod cpi_reentrancy;
pub mod realloc_race;
pub mod bump_seed_canonicalization;

/// Shared utilities for invariant implementations.
pub(crate) mod util;

/// Number of unique state-transition fingerprints seen in this process.
pub fn unique_transition_fingerprint_count() -> usize {
    util::unique_transition_fingerprint_count()
}

/// Clear accumulated state-transition fingerprints.
pub fn reset_transition_fingerprints() {
    util::reset_transition_fingerprints();
}

/// Run one invariant check and, when enabled, emit transition-signal rate.
///
/// Enable via:
/// - `SOLINV_BANDIT_METRICS=1`
/// - or `SOLINV_BANDIT_METRICS=true`
///
/// Output example:
/// `[solinv][bandit] invariant=unchecked-math dt_sec=0.012 delta_fp=3 fp_per_sec=250.000`
pub fn run_with_transition_metrics<R>(invariant: &str, f: impl FnOnce() -> R) -> R {
    let enabled = std::env::var("SOLINV_BANDIT_METRICS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !enabled {
        return f();
    }

    let before = unique_transition_fingerprint_count();
    let started = std::time::Instant::now();
    let out = f();
    let elapsed = started.elapsed().as_secs_f64();
    let after = unique_transition_fingerprint_count();
    let delta = after.saturating_sub(before);
    let rate = if elapsed > 0.0 {
        delta as f64 / elapsed
    } else {
        0.0
    };
    eprintln!(
        "[solinv][bandit] invariant={} dt_sec={:.3} delta_fp={} fp_per_sec={:.3}",
        invariant, elapsed, delta, rate
    );
    out
}

#[cfg(test)]
mod regression_tests;
