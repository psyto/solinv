//! # solinv-core
//!
//! Solana-aware invariant library. Auto-detected invariants for common
//! Solana program bug classes that audit firms currently check by hand.
//!
//! Catalog target (17 baseline + 3 stretch). See `docs/invariants/`
//! for per-invariant specifications.
//!
//! Critical tier (5/5 specified, implementation in progress):
//! - signer-skip, owner-skip, discriminator-skip, pda-forge, account-swap
//!
//! High tier (5, pending):
//! - cpi-reentrancy, cu-dos, unchecked-math, realloc-race, token-2022-hook
//!
//! Medium tier (5-7, pending):
//! - close-reopen, sysvar-manipulation, permissionless-misuse,
//!   rent-exemption, account-init-race
//!
//! Each invariant is a free function `check<F>(fixture: &mut F)` where
//! `F: HasContext + HasInstructionSet` (from solinv-fuzz capability
//! module). Designed to be called from inside a user-written
//! `#[invariant_test]` body alongside Crucible's macros.

pub mod invariants;
pub mod trace;

#[cfg(test)]
mod tests {
    #[test]
    fn smoke() {
        // Placeholder smoke test
    }
}
