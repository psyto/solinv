//! # Differential equivalence helpers
//!
//! Reusable building blocks for "Anchor↔Pinocchio rewrite" harnesses —
//! the fuzz-side counterpart to
//! [pinocchio-bench](https://github.com/psyto/pinocchio-bench), which
//! measures how much CU such a rewrite saves. Six harnesses under
//! `examples/pinocchio-bench-fuzz/fuzz/` share this shape today
//! (`amm-diff`, `matching-diff`, `oracle-diff`, `perp-diff`,
//! `refresh-diff`, `vault-diff`); this module extracts it.
//!
//! ## What a differential harness does
//!
//! Loads both `.so` files into one `TestContext`, drives the same
//! fuzz-derived action through each, and after every action asserts
//! that the corresponding account pairs hold byte-identical body
//! content (excluding per-side discriminator prefixes).
//!
//! ## What "same outcome" has to mean here
//!
//! On Ethereum a differential can diff against a commitment — the state
//! root, the receipts trie. Solana publishes no such thing, so there is
//! nothing to compare against except the other run, and the oracle has
//! to be spelled out by hand.
//!
//! Three surfaces are covered here:
//!
//! 1. **Written state** — [`check_pair_equivalent`]. Byte-identical
//!    account *bodies*, over the pairs a fixture declares.
//! 2. **The decision, and its reason** — [`ParityDivergence`]. Not just
//!    accepted vs rejected, and not just the custom error code: every
//!    builtin `ProgramError` reports no code, so the normalized reason
//!    is what actually distinguishes two rejections. See [`SideResult`].
//! 3. **Cost** — [`CuComparison`]. CU is consensus-relevant, so two
//!    runs writing identical bytes at different CU are not equivalent;
//!    the dearer one can hit the transaction limit and fail.
//!
//! **These three are not the whole observable surface.** A caller can
//! also see account lamports, owner and executable flags, instruction
//! return data, emitted logs, and any account written by one side but
//! not declared as a pair. None of those are compared here. The three
//! covered surfaces are the ones a rewrite is most likely to break,
//! not an exhaustive definition of equivalence — a harness passing all
//! three has narrowed the space of possible divergence, not closed it.
//!
//! A fourth condition is not a surface but a precondition:
//! [`SendFailure`] reports probes that never reached the program on one
//! or both sides. Nothing diverges when nothing executes, so an
//! unreported send failure turns a broken harness into a clean run.
//!
//! ## What this module provides
//!
//! - [`DiffAccountPair`] — declarative pair description (which two
//!   pubkeys, what body size, what per-side offset to strip).
//! - [`SideResult`] — one side's observable result: accepted, or
//!   rejected with a normalized reason.
//! - [`BodyDivergence`] / [`ParityDivergence`] / [`CuComparison`] /
//!   [`SendFailure`] — structured findings the harness passes into
//!   `fuzz_assert!` after a check fires.
//! - [`check_pair_equivalent`] / [`ParityDivergence::check_outcomes`] /
//!   [`CuComparison::regression`] / [`SendFailure::check`] — pure
//!   functions returning `Option<..>` for the harness to decide whether
//!   to escalate to a fuzz violation.
//! - [`DifferentialFixture`] trait + [`check_all_pairs`] — optional
//!   sugar for fixtures that want to declare their pair set once and
//!   walk it from a single helper call.
//! - `From` conversions into [`solinv_disclose::Divergence`], so a
//!   finding can leave the fuzz worker as a structured record rather
//!   than a log line. See the bridge section at the bottom of the file.
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

use crucible_test_context::{TestContext, TxOutcome};
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

/// One side's execution result, reduced to the parts a caller can
/// observe: whether it was accepted, and if not, *why*.
///
/// The `reason` is the load-bearing field. Comparing only
/// [`TxOutcome::error_code`] is not enough, because that returns `None`
/// for every builtin `ProgramError` — so two sides rejecting with
/// `InvalidArgument` and `AccountDataTooSmall` would both report "no
/// code" and compare equal. That matters concretely here: the Pinocchio
/// bench rewrites return *only* builtins, so a code-only comparison is
/// blind to divergence anywhere within the side it is most likely to
/// occur.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SideResult {
    pub ok: bool,
    /// Custom program error code, when the runtime reported one.
    pub error_code: Option<u32>,
    /// Normalized rejection reason — `None` when accepted.
    ///
    /// This is a **comparison token**, not a stable wire identifier: it
    /// is only meaningful when compared against another token produced
    /// by the same build, which is exactly how it is used. Do not
    /// persist it and expect it to match a future toolchain.
    pub reason: Option<String>,
}

impl SideResult {
    /// Reduce a [`TxOutcome`] to the observable result.
    pub fn from_outcome(outcome: &TxOutcome) -> Self {
        match outcome {
            TxOutcome::Success { .. } => Self {
                ok: true,
                error_code: None,
                reason: None,
            },
            TxOutcome::ProgramError {
                error, error_code, ..
            } => Self {
                ok: false,
                error_code: *error_code,
                reason: Some(match error_code {
                    // A custom code fully identifies the rejection.
                    Some(code) => format!("custom:{code}"),
                    // No custom code — the builtin variant IS the
                    // reason, and must be compared as such.
                    None => format!("builtin:{error:?}"),
                }),
            },
        }
    }

    /// Accepted.
    pub fn accepted() -> Self {
        Self {
            ok: true,
            error_code: None,
            reason: None,
        }
    }

    /// Rejected with an Anchor-style custom error code.
    pub fn custom(code: u32) -> Self {
        Self {
            ok: false,
            error_code: Some(code),
            reason: Some(format!("custom:{code}")),
        }
    }

    /// Rejected with a builtin `ProgramError` variant, named by `tag`.
    pub fn builtin(tag: impl std::fmt::Display) -> Self {
        Self {
            ok: false,
            error_code: None,
            reason: Some(format!("builtin:{tag}")),
        }
    }

    fn render(&self) -> String {
        match (&self.ok, &self.reason) {
            (true, _) => "accepted".to_string(),
            (false, Some(r)) => format!("rejected({r})"),
            (false, None) => "rejected".to_string(),
        }
    }
}

/// An execution-result mismatch between Anchor and Pinocchio sides
/// on a single instruction execution.
///
/// Sides agree only when they made the same accept/reject decision
/// **and**, on rejection, rejected for the same reason — custom code
/// against custom code, builtin variant against builtin variant. A
/// program's rejection reasons are part of its observable ABI: a caller
/// branching on `6001` behaves differently against a rewrite that
/// returns `6002`, or that returns a builtin instead.
#[derive(Clone, Debug)]
pub struct ParityDivergence {
    pub label: String,
    pub anchor: SideResult,
    pub pino: SideResult,
}

impl ParityDivergence {
    /// Compare two reduced results.
    ///
    /// ```
    /// use solinv_fuzz::{ParityDivergence, SideResult};
    ///
    /// // Both reject, both without a custom code — but for different
    /// // builtin reasons. A code-only comparison calls this agreement.
    /// let d = ParityDivergence::check(
    ///     "swap",
    ///     &SideResult::builtin("InvalidArgument"),
    ///     &SideResult::builtin("AccountDataTooSmall"),
    /// );
    /// assert!(d.is_some());
    /// ```
    pub fn check(label: &str, anchor: &SideResult, pino: &SideResult) -> Option<Self> {
        if anchor == pino {
            return None;
        }
        Some(ParityDivergence {
            label: label.to_string(),
            anchor: anchor.clone(),
            pino: pino.clone(),
        })
    }

    /// Convenience over two [`TxOutcome`]s.
    ///
    /// ```ignore
    /// if let Some(d) = ParityDivergence::check_outcomes("swap", &a, &p) {
    ///     fuzz_assert!(false, "{}", d);
    /// }
    /// ```
    pub fn check_outcomes(label: &str, anchor: &TxOutcome, pino: &TxOutcome) -> Option<Self> {
        Self::check(
            label,
            &SideResult::from_outcome(anchor),
            &SideResult::from_outcome(pino),
        )
    }
}

impl std::fmt::Display for ParityDivergence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "execution-parity divergence on {}: anchor={} pino={}",
            self.label,
            self.anchor.render(),
            self.pino.render(),
        )
    }
}

/// A transaction that never reached the program on at least one side.
///
/// `send()` returning `Err` is a harness-level failure — bad signer
/// set, unloaded account, malformed instruction — not a statement about
/// program behaviour. It must still be **reported**: treating it as a
/// skipped probe lets a harness whose sends are all failing run to
/// completion and declare itself clean, which is the worst possible
/// outcome for a differential. Nothing diverges when nothing executes.
#[derive(Clone, Debug)]
pub struct SendFailure {
    pub label: String,
    /// Error text from the Anchor side, when its `send()` failed.
    pub anchor_error: Option<String>,
    pub pino_error: Option<String>,
}

impl SendFailure {
    /// `Some` when either side failed to submit. Both-sides failure is
    /// included deliberately: a symmetric failure is still a probe that
    /// produced no evidence, and a campaign built entirely from them is
    /// vacuous.
    pub fn check<T, E: std::fmt::Display>(
        label: &str,
        anchor: &Result<T, E>,
        pino: &Result<T, E>,
    ) -> Option<Self> {
        let anchor_error = anchor.as_ref().err().map(|e| e.to_string());
        let pino_error = pino.as_ref().err().map(|e| e.to_string());
        if anchor_error.is_none() && pino_error.is_none() {
            return None;
        }
        Some(SendFailure {
            label: label.to_string(),
            anchor_error,
            pino_error,
        })
    }
}

impl std::fmt::Display for SendFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let side = |e: &Option<String>| match e {
            Some(msg) => format!("send failed ({msg})"),
            None => "sent".to_string(),
        };
        write!(
            f,
            "probe produced no evidence on {}: anchor={} pino={}",
            self.label,
            side(&self.anchor_error),
            side(&self.pino_error),
        )
    }
}

/// Compute units consumed by each side of a rewrite pair on one action.
///
/// Unlike the other two types in this module this is **not primarily a
/// violation detector** — it is a measurement. A Pinocchio rewrite is
/// undertaken to make CU go down, so the two sides are expected to
/// disagree, in one direction. Recording that difference is the output
/// the exercise exists to produce.
///
/// It becomes a fault in one case: when the rewrite consumed *more*
/// than the original. [`Self::regression`] is the gating constructor
/// for harnesses that want to fail on that.
///
/// CU is not cosmetic on Solana. It is consensus-relevant: two runs
/// that write byte-identical state but consume different CU can still
/// end differently in production, because the more expensive one can
/// exceed the transaction limit and fail. A differential that checks
/// only account bytes will call such a pair equivalent when it is not.
///
/// `None` on a side means that side did not reach a successful
/// execution, so the runtime reported no CU figure — the accompanying
/// [`ParityDivergence`] is where that asymmetry gets flagged.
#[derive(Clone, Debug)]
pub struct CuComparison {
    pub label: String,
    pub anchor_cu: Option<u64>,
    pub pino_cu: Option<u64>,
}

impl CuComparison {
    /// Record both sides unconditionally. Use on every compared action.
    pub fn record(label: &str, anchor_cu: Option<u64>, pino_cu: Option<u64>) -> Self {
        Self {
            label: label.to_string(),
            anchor_cu,
            pino_cu,
        }
    }

    /// Record from the two [`TxOutcome`]s directly.
    pub fn from_outcomes(label: &str, anchor: &TxOutcome, pino: &TxOutcome) -> Self {
        Self::record(label, anchor.compute_units(), pino.compute_units())
    }

    /// `pino - anchor`, when both sides reported a figure. Negative
    /// means the rewrite is cheaper — the intended direction.
    pub fn delta(&self) -> Option<i64> {
        match (self.anchor_cu, self.pino_cu) {
            (Some(a), Some(p)) => Some(p as i64 - a as i64),
            _ => None,
        }
    }

    /// Percentage of the original's CU that the rewrite saved.
    /// Negative on a regression.
    pub fn saved_pct(&self) -> Option<f64> {
        match (self.anchor_cu, self.pino_cu) {
            (Some(a), Some(p)) if a > 0 => Some((a as f64 - p as f64) / a as f64 * 100.0),
            _ => None,
        }
    }

    /// Whether the rewrite consumed more than the original.
    pub fn is_regression(&self) -> bool {
        matches!(self.delta(), Some(d) if d > 0)
    }

    /// Gating constructor: `Some` only when the rewrite regressed, so a
    /// harness can escalate it the same way it escalates the other
    /// divergence types.
    ///
    /// **This discards the measurement on every non-regressing action.**
    /// The six differential harnesses call only this, so despite the
    /// type's framing as a recording, what they retain today is the
    /// regression verdict — not a CU figure per action. Use
    /// [`Self::from_outcomes`] to keep every measurement.
    pub fn regression(label: &str, anchor: &TxOutcome, pino: &TxOutcome) -> Option<Self> {
        let cmp = Self::from_outcomes(label, anchor, pino);
        cmp.is_regression().then_some(cmp)
    }
}

impl std::fmt::Display for CuComparison {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.anchor_cu, self.pino_cu) {
            (Some(a), Some(p)) => {
                let verb = if p > a { "regressed" } else { "saved" };
                write!(
                    f,
                    "CU on {}: anchor={} pino={} ({} {} CU)",
                    self.label,
                    a,
                    p,
                    verb,
                    (p as i64 - a as i64).abs(),
                )
            }
            (a, p) => write!(
                f,
                "CU on {}: anchor={:?} pino={:?} (a side did not complete)",
                self.label, a, p,
            ),
        }
    }
}

// ---------------------------------------------------------------------
// Bridge to solinv-disclose
//
// The types above are tuned for the harness: `Display` strings destined
// for `fuzz_assert!`, Anchor/Pinocchio in the field names. The disclose
// types are tuned for everyone else: serializable, hashable, and
// side-neutral. These conversions are the seam between "found it" and
// "here is the finding, go check it yourself".
// ---------------------------------------------------------------------

impl From<&BodyDivergence> for solinv_disclose::Divergence {
    fn from(d: &BodyDivergence) -> Self {
        solinv_disclose::Divergence::Body {
            label: d.label.clone(),
            first_byte: d.first_byte,
            left_byte: d.anchor_byte,
            right_byte: d.pino_byte,
            body_size: d.body_size,
        }
    }
}

impl From<&ParityDivergence> for solinv_disclose::Divergence {
    fn from(d: &ParityDivergence) -> Self {
        solinv_disclose::Divergence::Parity {
            label: d.label.clone(),
            left_ok: d.anchor.ok,
            right_ok: d.pino.ok,
            left_error: d.anchor.error_code,
            right_error: d.pino.error_code,
            left_reason: d.anchor.reason.clone(),
            right_reason: d.pino.reason.clone(),
        }
    }
}

impl From<&CuComparison> for solinv_disclose::Divergence {
    fn from(c: &CuComparison) -> Self {
        solinv_disclose::Divergence::Cu {
            label: c.label.clone(),
            left_cu: c.anchor_cu,
            right_cu: c.pino_cu,
        }
    }
}

/// Read both sides of a pair into `(anchor_body, pino_body)` slices
/// of length `pair.body_size`, stripping each side's declared offset.
///
/// Returns `None` (fail-soft) when either account is missing from the
/// `TestContext` or sizes are insufficient — this happens routinely
/// during early fuzz iterations before all setup is complete and
/// shouldn't escalate to a violation.
pub fn read_pair_bodies(ctx: &TestContext, pair: &DiffAccountPair) -> Option<(Vec<u8>, Vec<u8>)> {
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
pub fn check_pair_equivalent(ctx: &TestContext, pair: &DiffAccountPair) -> Option<BodyDivergence> {
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
    fn identical_results_agree() {
        assert!(
            ParityDivergence::check("ix", &SideResult::accepted(), &SideResult::accepted())
                .is_none()
        );
        assert!(ParityDivergence::check(
            "ix",
            &SideResult::custom(6001),
            &SideResult::custom(6001)
        )
        .is_none());
        assert!(ParityDivergence::check(
            "ix",
            &SideResult::builtin("InvalidArgument"),
            &SideResult::builtin("InvalidArgument")
        )
        .is_none());
    }

    #[test]
    fn accept_vs_reject_diverges() {
        let div = ParityDivergence::check(
            "swap(100, 0)",
            &SideResult::accepted(),
            &SideResult::custom(6001),
        )
        .unwrap();
        assert_eq!(div.label, "swap(100, 0)");
        assert!(div.anchor.ok);
        assert!(!div.pino.ok);
        assert!(div.to_string().contains("anchor=accepted"), "{div}");
        assert!(
            div.to_string().contains("pino=rejected(custom:6001)"),
            "{div}"
        );
    }

    #[test]
    fn both_rejected_with_different_codes_diverge() {
        let div =
            ParityDivergence::check("swap", &SideResult::custom(6001), &SideResult::custom(6002))
                .expect("different rejection reasons must diverge");
        assert_eq!(div.anchor.error_code, Some(6001));
        assert_eq!(div.pino.error_code, Some(6002));
    }

    #[test]
    fn both_rejected_with_different_builtins_diverge() {
        // Neither side reports a custom code, so `error_code` is None on
        // both. Comparing codes alone would call this agreement — and
        // this is the common case, because the Pinocchio rewrites return
        // builtins exclusively.
        let anchor = SideResult::builtin("InvalidArgument");
        let pino = SideResult::builtin("AccountDataTooSmall");
        assert_eq!(anchor.error_code, None);
        assert_eq!(pino.error_code, None);

        let div = ParityDivergence::check("swap", &anchor, &pino)
            .expect("different builtin reasons must diverge");
        assert!(div.to_string().contains("builtin:InvalidArgument"), "{div}");
        assert!(
            div.to_string().contains("builtin:AccountDataTooSmall"),
            "{div}"
        );
    }

    #[test]
    fn custom_and_builtin_rejections_diverge() {
        assert!(ParityDivergence::check(
            "swap",
            &SideResult::custom(6001),
            &SideResult::builtin("InvalidArgument")
        )
        .is_some());
    }

    #[test]
    fn send_failure_on_either_side_is_reported() {
        let ok = || Ok::<&str, &str>("outcome");
        // Modelled with a stand-in payload; only the Err arm is inspected.
        let one_side = SendFailure::check("swap", &ok(), &Err::<&str, &str>("blockhash expired"))
            .expect("a one-sided send failure must be reported, not skipped");
        assert!(one_side.anchor_error.is_none());
        assert_eq!(one_side.pino_error.as_deref(), Some("blockhash expired"));
        assert!(
            one_side.to_string().contains("pino=send failed"),
            "{one_side}"
        );

        let err = |m: &'static str| Err::<&str, &str>(m);
        let both = SendFailure::check("swap", &err("a"), &err("b"))
            .expect("a symmetric send failure still produced no evidence");
        assert!(both.anchor_error.is_some() && both.pino_error.is_some());
    }

    #[test]
    fn no_send_failure_when_both_sides_submitted() {
        let ok = || Ok::<&str, &str>("outcome");
        assert!(SendFailure::check("swap", &ok(), &ok()).is_none());
    }

    #[test]
    fn cu_saving_is_measured_not_faulted() {
        let cmp = CuComparison::record("swap", Some(12_400), Some(3_900));
        assert_eq!(cmp.delta(), Some(-8_500));
        assert!(!cmp.is_regression());
        assert!((cmp.saved_pct().unwrap() - 68.548).abs() < 0.01);
        assert!(cmp.to_string().contains("saved 8500 CU"), "{cmp}");
    }

    #[test]
    fn cu_regression_is_flagged() {
        let cmp = CuComparison::record("swap", Some(3_900), Some(12_400));
        assert_eq!(cmp.delta(), Some(8_500));
        assert!(cmp.is_regression());
        assert!(cmp.saved_pct().unwrap() < 0.0);
        assert!(cmp.to_string().contains("regressed 8500 CU"), "{cmp}");
    }

    #[test]
    fn cu_with_an_incomplete_side_has_no_delta() {
        let cmp = CuComparison::record("swap", Some(3_900), None);
        assert_eq!(cmp.delta(), None);
        assert!(!cmp.is_regression());
        assert!(cmp.to_string().contains("did not complete"), "{cmp}");
    }

    #[test]
    fn body_divergence_converts_to_a_disclosable_finding() {
        let div = BodyDivergence {
            label: "pool".to_string(),
            first_byte: 16,
            anchor_byte: 0x42,
            pino_byte: 0x00,
            body_size: 6664,
        };
        let finding: solinv_disclose::Divergence = (&div).into();
        assert!(finding.is_fault());
        assert!(finding.headline().contains("byte 16 of 6664"));
    }

    #[test]
    fn parity_divergence_carries_its_reasons_into_the_finding() {
        let div = ParityDivergence::check(
            "swap",
            &SideResult::custom(6001),
            &SideResult::builtin("InvalidArgument"),
        )
        .unwrap();
        let finding: solinv_disclose::Divergence = (&div).into();
        assert!(finding.is_fault());
        match finding {
            solinv_disclose::Divergence::Parity {
                left_error,
                right_error,
                left_reason,
                right_reason,
                ..
            } => {
                assert_eq!(left_error, Some(6001));
                // The builtin side has no code — the reason is what
                // carries the divergence across the boundary.
                assert_eq!(right_error, None);
                assert_eq!(left_reason.as_deref(), Some("custom:6001"));
                assert_eq!(right_reason.as_deref(), Some("builtin:InvalidArgument"));
            }
            other => panic!("expected a parity finding, got {other:?}"),
        }
    }

    #[test]
    fn cu_saving_converts_to_a_recorded_non_fault_finding() {
        let cmp = CuComparison::record("swap", Some(12_400), Some(3_900));
        let finding: solinv_disclose::Divergence = (&cmp).into();
        assert!(!finding.is_fault(), "a CU saving is the goal, not a defect");
        assert!(finding.headline().contains("-8500"));
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
