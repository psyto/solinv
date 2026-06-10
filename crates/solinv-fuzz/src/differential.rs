//! # Differential equivalence helpers
//!
//! Reusable building blocks for "Anchor↔Pinocchio rewrite" harnesses.
//! Three of these live next to [pinocchio-bench](https://github.com/psyto/pinocchio-bench)
//! today (`matching-diff`, `amm-diff`, `refresh-diff`); this module
//! extracts the shape they share.
//!
//! ## What a differential harness does
//!
//! Loads both `.so` files into one `TestContext`, drives the same
//! fuzz-derived action through each, and after every action asserts
//! that the corresponding account pairs hold byte-identical body
//! content (excluding per-side discriminator prefixes).
//!
//! ## What this module provides
//!
//! - [`DiffAccountPair`] — declarative pair description (which two
//!   pubkeys, what body size, what per-side offset to strip).
//! - [`BodyDivergence`] / [`ParityDivergence`] — structured failure
//!   reports the harness passes into `fuzz_assert!` after a check fires.
//! - [`check_pair_equivalent`] / [`ParityDivergence::check`] — pure
//!   functions returning `Option<Divergence>` for the harness to decide
//!   whether to escalate to a fuzz violation.
//! - [`DifferentialFixture`] trait + [`check_all_pairs`] — optional
//!   sugar for fixtures that want to declare their pair set once and
//!   walk it from a single helper call.
//!
//! ## Why a `fuzz_assert!`-free API
//!
//! `fuzz_assert!` is a macro from `crucible_fuzzer` that is only sound
//! when called from the harness binary (the fuzz worker context).
//! Library code that calls it from inside a free function loses control
//! of where the violation is attributed in libafl's per-iteration
//! reporting. So this module returns `Option<Divergence>` types and the
//! harness call-site does `if let Some(d) = ... { fuzz_assert!(false, "{}", d); }`
//! — keeping macro invocation in the binary while reusing the data.

use crucible_test_context::TestContext;
use solana_pubkey::Pubkey;

/// A pair of accounts holding semantically-equivalent state across an
/// Anchor↔Pinocchio rewrite pair. Body content (`body_size` bytes,
/// reading from each side's `_offset`) must be byte-identical after
/// every action that both sides accepted.
///
/// Common offset patterns:
///
/// - **Anchor zero-copy + Pinocchio raw**: Anchor side carries the
///   8-byte account discriminator at offset 0; Pinocchio side starts
///   the body at offset 0. Use [`DiffAccountPair::anchor_disc_8`].
/// - **SPL Token accounts on both sides**: SPL Token Program owns both,
///   the format is identical, no discriminator on either side. Use
///   [`DiffAccountPair::raw`].
/// - **Custom offsets**: build the struct directly when one or both
///   sides has a non-standard layout prefix.
#[derive(Clone, Debug)]
pub struct DiffAccountPair {
    /// Human-readable label surfaced in divergence reports
    /// (e.g. `"pool"`, `"user_src"`, `"obligation"`).
    pub label: &'static str,
    pub anchor: Pubkey,
    /// Bytes to skip on the Anchor side before the body begins.
    /// Typically `8` (Anchor account discriminator).
    pub anchor_offset: usize,
    pub pino: Pubkey,
    /// Bytes to skip on the Pinocchio side. Typically `0`.
    pub pino_offset: usize,
    /// Body length to compare, in bytes.
    pub body_size: usize,
}

impl DiffAccountPair {
    /// Anchor side has the standard 8-byte account discriminator;
    /// Pinocchio side has no prefix. Common pattern for zero-copy
    /// state accounts.
    pub fn anchor_disc_8(
        label: &'static str,
        anchor: Pubkey,
        pino: Pubkey,
        body_size: usize,
    ) -> Self {
        Self {
            label,
            anchor,
            anchor_offset: 8,
            pino,
            pino_offset: 0,
            body_size,
        }
    }

    /// Neither side has a prefix; bytes are compared starting at
    /// offset 0 on both. Used for SPL Token accounts (Token Program
    /// owns both, layout is identical regardless of which Rust
    /// program wrapped the transfer).
    pub fn raw(label: &'static str, anchor: Pubkey, pino: Pubkey, body_size: usize) -> Self {
        Self {
            label,
            anchor,
            anchor_offset: 0,
            pino,
            pino_offset: 0,
            body_size,
        }
    }
}

/// A state-body divergence between the two sides of a `DiffAccountPair`.
/// Returned by [`check_pair_equivalent`]; consumed by the harness as
/// the message argument to `fuzz_assert!`.
#[derive(Clone, Debug)]
pub struct BodyDivergence {
    pub label: String,
    pub first_byte: usize,
    pub anchor_byte: u8,
    pub pino_byte: u8,
    /// Total body size compared. Helps the reader gauge how much of
    /// the body was checked (e.g. "byte 0 of 6664" pinpoints the
    /// first byte; "byte 6663 of 6664" implies almost everything matched).
    pub body_size: usize,
}

impl std::fmt::Display for BodyDivergence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} body divergence at byte {} (of {}): anchor=0x{:02x} pino=0x{:02x}",
            self.label, self.first_byte, self.body_size, self.anchor_byte, self.pino_byte,
        )
    }
}

/// An execution-result mismatch between Anchor and Pinocchio sides
/// on a single instruction execution.
#[derive(Clone, Debug)]
pub struct ParityDivergence {
    pub label: String,
    pub anchor_ok: bool,
    pub pino_ok: bool,
}

impl ParityDivergence {
    /// Constructor that returns `None` when the two sides agreed (no
    /// divergence to report) and `Some(div)` when they disagreed.
    pub fn check(label: &str, anchor_ok: bool, pino_ok: bool) -> Option<Self> {
        if anchor_ok == pino_ok {
            None
        } else {
            Some(ParityDivergence {
                label: label.to_string(),
                anchor_ok,
                pino_ok,
            })
        }
    }
}

impl std::fmt::Display for ParityDivergence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "execution-parity divergence on {}: anchor={} pino={}",
            self.label, self.anchor_ok, self.pino_ok,
        )
    }
}

/// Read both sides of a pair into `(anchor_body, pino_body)` slices
/// of length `pair.body_size`, stripping each side's declared offset.
///
/// Returns `None` (fail-soft) when either account is missing from the
/// `TestContext` or sizes are insufficient — this happens routinely
/// during early fuzz iterations before all setup is complete and
/// shouldn't escalate to a violation.
pub fn read_pair_bodies(
    ctx: &TestContext,
    pair: &DiffAccountPair,
) -> Option<(Vec<u8>, Vec<u8>)> {
    let a = ctx.get_account(&pair.anchor).ok()?;
    let p = ctx.get_account(&pair.pino).ok()?;
    if a.data.len() < pair.anchor_offset + pair.body_size {
        return None;
    }
    if p.data.len() < pair.pino_offset + pair.body_size {
        return None;
    }
    Some((
        a.data[pair.anchor_offset..pair.anchor_offset + pair.body_size].to_vec(),
        p.data[pair.pino_offset..pair.pino_offset + pair.body_size].to_vec(),
    ))
}

/// Check whether a pair has byte-equivalent body content.
/// Returns `None` if equivalent (or unreadable — fail-soft);
/// `Some(BodyDivergence)` pinpointing the first differing byte otherwise.
pub fn check_pair_equivalent(
    ctx: &TestContext,
    pair: &DiffAccountPair,
) -> Option<BodyDivergence> {
    let (a, p) = read_pair_bodies(ctx, pair)?;
    let first_byte = a.iter().zip(p.iter()).position(|(x, y)| x != y)?;
    Some(BodyDivergence {
        label: pair.label.to_string(),
        first_byte,
        anchor_byte: a[first_byte],
        pino_byte: p[first_byte],
        body_size: pair.body_size,
    })
}

/// Fixture that declares an Anchor-vs-Pinocchio differential surface.
///
/// Implementing this trait gives the harness one-call access to
/// [`check_all_pairs`] for body-equivalence over the full declared set.
/// Execution parity is intentionally kept harness-side since
/// instruction construction varies across surfaces.
pub trait DifferentialFixture: super::HasContext {
    fn anchor_program_id(&self) -> Pubkey;
    fn pino_program_id(&self) -> Pubkey;
    fn diff_pairs(&self) -> Vec<DiffAccountPair>;
}

/// Walk every pair declared by a [`DifferentialFixture`] and return
/// the first body-divergence found, if any. Useful as the body of a
/// `#[invariant_test]` variant that wants the full equivalence check
/// in one call.
pub fn check_all_pairs<F: DifferentialFixture>(fixture: &F) -> Option<BodyDivergence> {
    for pair in fixture.diff_pairs() {
        if let Some(div) = check_pair_equivalent(fixture.ctx(), &pair) {
            return Some(div);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parity_check_agrees() {
        assert!(ParityDivergence::check("ix", true, true).is_none());
        assert!(ParityDivergence::check("ix", false, false).is_none());
    }

    #[test]
    fn parity_check_disagrees() {
        let div = ParityDivergence::check("swap(100, 0)", true, false).unwrap();
        assert_eq!(div.label, "swap(100, 0)");
        assert!(div.anchor_ok);
        assert!(!div.pino_ok);
    }

    #[test]
    fn body_divergence_display_pinpoints() {
        let div = BodyDivergence {
            label: "pool".to_string(),
            first_byte: 16,
            anchor_byte: 0x42,
            pino_byte: 0x00,
            body_size: 24,
        };
        assert!(div.to_string().contains("byte 16 (of 24)"));
        assert!(div.to_string().contains("0x42"));
        assert!(div.to_string().contains("0x00"));
    }

    #[test]
    fn anchor_disc_8_offsets_correctly() {
        let pair = DiffAccountPair::anchor_disc_8(
            "test",
            Pubkey::new_from_array([1u8; 32]),
            Pubkey::new_from_array([2u8; 32]),
            16,
        );
        assert_eq!(pair.anchor_offset, 8);
        assert_eq!(pair.pino_offset, 0);
        assert_eq!(pair.body_size, 16);
    }

    #[test]
    fn raw_pair_zero_offsets() {
        let pair = DiffAccountPair::raw(
            "spl_token",
            Pubkey::new_from_array([1u8; 32]),
            Pubkey::new_from_array([2u8; 32]),
            165,
        );
        assert_eq!(pair.anchor_offset, 0);
        assert_eq!(pair.pino_offset, 0);
    }
}
