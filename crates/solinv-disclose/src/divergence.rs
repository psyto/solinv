//! # divergence — implementation-neutral record of where two runs parted
//!
//! [`solinv_fuzz::differential`] finds divergences between an Anchor
//! program and its Pinocchio rewrite. That is one instance of a more
//! general shape: **two executions that were supposed to agree, and
//! the exact place they didn't.**
//!
//! The types here deliberately do *not* know about Anchor or Pinocchio.
//! The two executions are `left` and `right`, and what they were is
//! carried as data in [`Sides`]. That keeps the same record usable when
//! the pair is:
//!
//! - an Anchor program vs its Pinocchio rewrite (solinv today),
//! - a program at commit N vs commit N+1 (refactor regression),
//! - the `.so` deployed on mainnet vs a local build (post-mortem
//!   reconstruction),
//! - a venue's published number vs an independent recomputation
//!   (protocol-level soundness checking).
//!
//! On Solana this generality matters more than it would on Ethereum,
//! because there is no state root or receipt trie to diff against. The
//! comparison target is never a commitment — it is always another run.
//! So the record of *what was compared* has to travel with the finding.
//!
//! ## Faults vs recorded facts
//!
//! Not every divergence is a defect. A compute-unit difference is the
//! entire point of a Pinocchio rewrite: the sides are *supposed* to
//! disagree, in one direction. [`Divergence::is_fault`] encodes that —
//! body and parity divergences are always faults, a CU difference is a
//! fault only when the right side got *worse*.

use serde::{Deserialize, Serialize};

/// Human names for the two executions being compared.
///
/// Carried as data so a report is readable without knowing which
/// harness produced it.
///
/// ```
/// use solinv_disclose::Sides;
///
/// let s = Sides::anchor_pinocchio();
/// assert_eq!(s.left, "anchor");
/// assert_eq!(s.right, "pinocchio");
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sides {
    pub left: String,
    pub right: String,
}

impl Sides {
    pub fn new(left: impl Into<String>, right: impl Into<String>) -> Self {
        Self {
            left: left.into(),
            right: right.into(),
        }
    }

    /// The Anchor↔Pinocchio rewrite pair — the shape
    /// `solinv-fuzz::differential` harnesses drive today.
    pub fn anchor_pinocchio() -> Self {
        Self::new("anchor", "pinocchio")
    }

    /// A before/after pair of the same program, identified by revision.
    pub fn revisions(before: impl Into<String>, after: impl Into<String>) -> Self {
        Self::new(before, after)
    }
}

/// One place where two executions that should have agreed did not.
///
/// The variants cover the three oracles a Solana differential run can
/// actually observe. There is no state root to compare, so "same
/// outcome" has to be spelled out as: same written bytes, same
/// accept/reject decision (and same reason), same cost.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Divergence {
    /// Account state written by the two sides differs, pinpointed to
    /// the first differing byte of the compared body.
    Body {
        /// Which account pair diverged (e.g. `"pool"`, `"obligation"`).
        label: String,
        /// Offset of the first differing byte, within the compared body.
        first_byte: usize,
        left_byte: u8,
        right_byte: u8,
        /// Total body length compared — context for how far the two
        /// sides agreed before parting.
        body_size: usize,
    },

    /// The two sides disagreed on whether the instruction was accepted,
    /// or rejected it for different reasons.
    ///
    /// The error codes matter: a program's custom error code is part of
    /// its observable ABI. Two sides that both reject, but with
    /// different codes, have diverged in a way a caller can see —
    /// even though both "failed".
    Parity {
        label: String,
        left_ok: bool,
        right_ok: bool,
        /// Custom program error code, when the side rejected with one.
        left_error: Option<u32>,
        right_error: Option<u32>,
    },

    /// Compute units consumed by each side.
    ///
    /// Recorded on every compared action, not only on disagreement —
    /// for a rewrite this is the measurement the whole exercise exists
    /// to produce. `None` means that side did not reach a successful
    /// execution, so no CU figure was reported.
    ///
    /// CU is consensus-relevant on Solana: two runs that write
    /// identical bytes but consume different CU can still end
    /// differently in production, because the more expensive one can
    /// hit the transaction limit and fail.
    Cu {
        label: String,
        left_cu: Option<u64>,
        right_cu: Option<u64>,
    },
}

impl Divergence {
    /// Which comparison surface this divergence was found on.
    pub fn label(&self) -> &str {
        match self {
            Divergence::Body { label, .. }
            | Divergence::Parity { label, .. }
            | Divergence::Cu { label, .. } => label,
        }
    }

    /// Whether this divergence is a defect, as opposed to a recorded
    /// measurement.
    ///
    /// Body and parity divergences are always defects. A CU difference
    /// is a defect only when the right side consumed *more* than the
    /// left — a rewrite that costs more than the original has failed at
    /// the thing it was for.
    ///
    /// ```
    /// use solinv_disclose::Divergence;
    ///
    /// let win = Divergence::Cu {
    ///     label: "swap".into(),
    ///     left_cu: Some(12_400),
    ///     right_cu: Some(3_900),
    /// };
    /// assert!(!win.is_fault());
    ///
    /// let regression = Divergence::Cu {
    ///     label: "swap".into(),
    ///     left_cu: Some(3_900),
    ///     right_cu: Some(12_400),
    /// };
    /// assert!(regression.is_fault());
    /// ```
    pub fn is_fault(&self) -> bool {
        match self {
            Divergence::Body { .. } => true,
            Divergence::Parity { .. } => true,
            Divergence::Cu {
                left_cu: Some(l),
                right_cu: Some(r),
                ..
            } => r > l,
            // One side never produced a CU figure — that asymmetry is
            // reported by the accompanying Parity divergence, not here.
            Divergence::Cu { .. } => false,
        }
    }

    /// One-line summary, used as the headline in rendered reports.
    pub fn headline(&self) -> String {
        match self {
            Divergence::Body {
                label,
                first_byte,
                left_byte,
                right_byte,
                body_size,
            } => format!(
                "`{label}` state diverged at byte {first_byte} of {body_size}: \
                 left=0x{left_byte:02x} right=0x{right_byte:02x}"
            ),
            Divergence::Parity {
                label,
                left_ok,
                right_ok,
                left_error,
                right_error,
            } => {
                let render = |ok: &bool, err: &Option<u32>| match (ok, err) {
                    (true, _) => "accepted".to_string(),
                    (false, Some(code)) => format!("rejected ({code})"),
                    (false, None) => "rejected".to_string(),
                };
                format!(
                    "`{label}` outcome diverged: left {}, right {}",
                    render(left_ok, left_error),
                    render(right_ok, right_error)
                )
            }
            Divergence::Cu {
                label,
                left_cu,
                right_cu,
            } => match (left_cu, right_cu) {
                (Some(l), Some(r)) if r > l => {
                    format!("`{label}` CU regressed: {l} → {r} (+{})", r - l)
                }
                (Some(l), Some(r)) => {
                    format!("`{label}` CU: {l} → {r} (-{})", l - r)
                }
                (l, r) => format!("`{label}` CU: left={l:?} right={r:?}"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(first_byte: usize) -> Divergence {
        Divergence::Body {
            label: "pool".into(),
            first_byte,
            left_byte: 0x42,
            right_byte: 0x00,
            body_size: 6664,
        }
    }

    #[test]
    fn body_divergence_is_always_a_fault() {
        assert!(body(16).is_fault());
    }

    #[test]
    fn body_headline_pinpoints_the_byte() {
        let h = body(16).headline();
        assert!(h.contains("byte 16 of 6664"), "{h}");
        assert!(h.contains("0x42"), "{h}");
        assert!(h.contains("0x00"), "{h}");
    }

    #[test]
    fn cu_improvement_is_recorded_but_not_a_fault() {
        let d = Divergence::Cu {
            label: "swap".into(),
            left_cu: Some(12_400),
            right_cu: Some(3_900),
        };
        assert!(!d.is_fault());
        assert!(d.headline().contains("-8500"), "{}", d.headline());
    }

    #[test]
    fn cu_regression_is_a_fault() {
        let d = Divergence::Cu {
            label: "swap".into(),
            left_cu: Some(3_900),
            right_cu: Some(12_400),
        };
        assert!(d.is_fault());
        assert!(d.headline().contains("+8500"), "{}", d.headline());
    }

    #[test]
    fn cu_with_a_missing_side_is_not_itself_a_fault() {
        let d = Divergence::Cu {
            label: "swap".into(),
            left_cu: Some(3_900),
            right_cu: None,
        };
        assert!(!d.is_fault());
    }

    #[test]
    fn both_rejected_with_different_codes_is_a_fault() {
        let d = Divergence::Parity {
            label: "swap(100, 0)".into(),
            left_ok: false,
            right_ok: false,
            left_error: Some(6001),
            right_error: Some(6002),
        };
        assert!(d.is_fault());
        let h = d.headline();
        assert!(h.contains("rejected (6001)"), "{h}");
        assert!(h.contains("rejected (6002)"), "{h}");
    }

    #[test]
    fn divergence_round_trips_through_json() {
        let d = body(16);
        let encoded = serde_json::to_string(&d).unwrap();
        assert!(encoded.contains(r#""kind":"body""#), "{encoded}");
        let decoded: Divergence = serde_json::from_str(&encoded).unwrap();
        assert_eq!(d, decoded);
    }
}
