//! # report — a divergence finding in a form someone else can check
//!
//! A [`DivergenceReport`] is one comparison run, packaged so that a
//! reader who was not there can (a) see exactly where the two sides
//! parted, and (b) re-execute and confirm it.
//!
//! ## What the digest does and does not do
//!
//! [`DivergenceReport::digest`] is a SHA-256 over a canonical encoding
//! of the report. It pins **the claim** — the inputs, the sides, and
//! the divergences asserted — so the finding can be referenced, quoted
//! in a bounty submission, or later signed without ambiguity about
//! which version is meant.
//!
//! It does *not* attest that the claim is true. Nothing in a hash can
//! do that. Confirming the finding means re-running the bundle and
//! arriving at the same divergence. That is the intended division of
//! labour: the digest makes the claim immutable, re-execution makes it
//! true or false.
//!
//! ## Canonical encoding
//!
//! The canonical form is compact JSON (no whitespace) with fields in
//! struct declaration order, produced by `serde_json` over the typed
//! structs — no maps, so no ordering ambiguity. A third party
//! recomputing the digest serializes the same structs the same way and
//! hashes the bytes with SHA-256.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::divergence::{Divergence, Sides};
use crate::repro::{sha256_hex, ReproBundle};

/// What produced the report, so a stale finding can be traced back to
/// the tool version that made it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolStamp {
    pub name: String,
    pub version: String,
}

impl ToolStamp {
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
        }
    }

    /// This crate, at its compiled version.
    pub fn this_crate() -> Self {
        Self::new("solinv-disclose", env!("CARGO_PKG_VERSION"))
    }
}

/// One differential comparison run, its findings, and everything
/// needed to reproduce it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DivergenceReport {
    pub tool: ToolStamp,
    /// What the run was called (e.g. the harness or campaign name).
    pub subject: String,
    pub sides: Sides,
    pub bundle: ReproBundle,
    pub divergences: Vec<Divergence>,
}

impl DivergenceReport {
    pub fn new(subject: impl Into<String>, sides: Sides, bundle: ReproBundle) -> Self {
        Self {
            tool: ToolStamp::this_crate(),
            subject: subject.into(),
            sides,
            bundle,
            divergences: Vec::new(),
        }
    }

    pub fn with_divergence(mut self, divergence: Divergence) -> Self {
        self.divergences.push(divergence);
        self
    }

    pub fn with_divergences(mut self, divergences: impl IntoIterator<Item = Divergence>) -> Self {
        self.divergences.extend(divergences);
        self
    }

    /// Divergences that are defects, as opposed to recorded
    /// measurements. See [`Divergence::is_fault`].
    pub fn faults(&self) -> impl Iterator<Item = &Divergence> {
        self.divergences.iter().filter(|d| d.is_fault())
    }

    pub fn has_fault(&self) -> bool {
        self.divergences.iter().any(|d| d.is_fault())
    }

    /// Canonical bytes the digest is taken over. See the module docs
    /// for the encoding rules.
    pub fn canonical_json(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Lowercase-hex SHA-256 over [`Self::canonical_json`].
    ///
    /// Two reports carrying the same claim produce the same digest
    /// regardless of how they were built:
    ///
    /// ```
    /// use solinv_disclose::{Divergence, DivergenceReport, ReproBundle, Sides};
    ///
    /// let d = Divergence::Body {
    ///     label: "pool".into(),
    ///     first_byte: 16,
    ///     left_byte: 0x42,
    ///     right_byte: 0x00,
    ///     body_size: 6664,
    /// };
    ///
    /// let built_one_at_a_time = DivergenceReport::new(
    ///     "amm-diff", Sides::anchor_pinocchio(), ReproBundle::new(),
    /// ).with_divergence(d.clone());
    ///
    /// let built_in_bulk = DivergenceReport::new(
    ///     "amm-diff", Sides::anchor_pinocchio(), ReproBundle::new(),
    /// ).with_divergences([d]);
    ///
    /// assert_eq!(
    ///     built_one_at_a_time.digest().unwrap(),
    ///     built_in_bulk.digest().unwrap(),
    /// );
    /// ```
    pub fn digest(&self) -> Result<String> {
        Ok(sha256_hex(&self.canonical_json()?))
    }

    /// Render as Markdown, for a bug-bounty submission or a public
    /// finding log.
    ///
    /// The verdict line is deliberately blunt about reproducibility: a
    /// report whose bundle is incomplete says so at the top rather than
    /// presenting itself as checkable.
    pub fn to_markdown(&self) -> String {
        let digest = self
            .digest()
            .unwrap_or_else(|_| "<report could not be encoded>".to_string());

        let mut out = String::new();
        out.push_str(&format!("# Divergence report — {}\n\n", self.subject));
        out.push_str(&format!(
            "- **Sides**: `{}` (left) vs `{}` (right)\n",
            self.sides.left, self.sides.right
        ));
        out.push_str(&format!(
            "- **Verdict**: {}\n",
            if self.has_fault() {
                "DIVERGED"
            } else {
                "no divergence"
            }
        ));
        out.push_str(&format!("- **Report digest**: `{digest}`\n"));

        if self.bundle.is_reproducible() {
            out.push_str("- **Reproducible**: yes — re-run the bundle below and compare\n");
        } else {
            out.push_str(&format!(
                "- **Reproducible**: NO — bundle is missing {}\n",
                self.bundle.missing().join(", ")
            ));
        }

        out.push_str("\n## Where they parted\n\n");
        if self.divergences.is_empty() {
            out.push_str("Nothing recorded.\n");
        } else {
            for d in &self.divergences {
                out.push_str(&format!(
                    "- {} {}\n",
                    if d.is_fault() {
                        "**[fault]**"
                    } else {
                        "[recorded]"
                    },
                    d.headline()
                ));
            }
        }

        out.push_str("\n## Reproduction\n\n");
        if let Some(fs) = &self.bundle.feature_set {
            out.push_str(&format!("Feature set: `{fs}`\n\n"));
        }
        if let Some(slot) = self.bundle.slot {
            out.push_str(&format!("Account snapshot cloned at slot `{slot}`\n\n"));
        }

        if !self.bundle.programs.is_empty() {
            out.push_str("| side | program id | code sha256 |\n");
            out.push_str("|---|---|---|\n");
            for p in &self.bundle.programs {
                out.push_str(&format!(
                    "| {} | `{}` | `{}` |\n",
                    p.side, p.program_id, p.code_sha256
                ));
            }
            out.push('\n');
        }

        if !self.bundle.accounts.is_empty() {
            out.push_str("| account | pubkey | len | pre-state sha256 |\n");
            out.push_str("|---|---|---|---|\n");
            for a in &self.bundle.accounts {
                out.push_str(&format!(
                    "| {} | `{}` | {} | `{}` |\n",
                    a.label, a.pubkey, a.len, a.pre_state_sha256
                ));
            }
            out.push('\n');
        }

        if !self.bundle.actions.is_empty() {
            out.push_str("Action sequence:\n\n```\n");
            for (i, action) in self.bundle.actions.iter().enumerate() {
                out.push_str(&format!("{}. {}\n", i + 1, action));
            }
            out.push_str("```\n");
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repro::ProgramRef;

    fn body_divergence() -> Divergence {
        Divergence::Body {
            label: "pool".into(),
            first_byte: 16,
            left_byte: 0x42,
            right_byte: 0x00,
            body_size: 6664,
        }
    }

    fn cu_win() -> Divergence {
        Divergence::Cu {
            label: "swap".into(),
            left_cu: Some(12_400),
            right_cu: Some(3_900),
        }
    }

    fn reproducible_bundle() -> ReproBundle {
        ReproBundle::new()
            .with_program(ProgramRef::from_code("anchor", "Anch111", b"a"))
            .with_program(ProgramRef::from_code("pinocchio", "Pino111", b"p"))
            .with_feature_set("mainnet-beta@epoch-812")
            .with_action("swap(100, 0)")
    }

    fn report() -> DivergenceReport {
        DivergenceReport::new("amm-diff", Sides::anchor_pinocchio(), reproducible_bundle())
    }

    #[test]
    fn clean_run_recording_only_a_cu_win_has_no_fault() {
        let r = report().with_divergence(cu_win());
        assert!(!r.has_fault());
        assert_eq!(r.faults().count(), 0);
        assert!(r.to_markdown().contains("**Verdict**: no divergence"));
    }

    #[test]
    fn body_divergence_makes_the_verdict_diverged() {
        let r = report().with_divergences([cu_win(), body_divergence()]);
        assert!(r.has_fault());
        assert_eq!(r.faults().count(), 1);
        assert!(r.to_markdown().contains("**Verdict**: DIVERGED"));
    }

    #[test]
    fn digest_is_stable_across_identical_reports() {
        assert_eq!(
            report()
                .with_divergence(body_divergence())
                .digest()
                .unwrap(),
            report()
                .with_divergence(body_divergence())
                .digest()
                .unwrap(),
        );
    }

    #[test]
    fn digest_changes_when_the_claim_changes() {
        let base = report()
            .with_divergence(body_divergence())
            .digest()
            .unwrap();
        let moved = report()
            .with_divergence(Divergence::Body {
                label: "pool".into(),
                first_byte: 17,
                left_byte: 0x42,
                right_byte: 0x00,
                body_size: 6664,
            })
            .digest()
            .unwrap();
        assert_ne!(base, moved);
    }

    #[test]
    fn digest_changes_when_the_inputs_change() {
        let base = report()
            .with_divergence(body_divergence())
            .digest()
            .unwrap();

        let other_binary = DivergenceReport::new(
            "amm-diff",
            Sides::anchor_pinocchio(),
            ReproBundle::new()
                .with_program(ProgramRef::from_code("anchor", "Anch111", b"a"))
                // Same claim, different Pinocchio build — must not
                // share a digest with the run above.
                .with_program(ProgramRef::from_code("pinocchio", "Pino111", b"p2"))
                .with_feature_set("mainnet-beta@epoch-812")
                .with_action("swap(100, 0)"),
        )
        .with_divergence(body_divergence())
        .digest()
        .unwrap();

        assert_ne!(base, other_binary);
    }

    #[test]
    fn digest_is_64_hex_chars() {
        let d = report().digest().unwrap();
        assert_eq!(d.len(), 64);
        assert!(d
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
    }

    #[test]
    fn incomplete_bundle_is_flagged_in_the_rendered_report() {
        let r = DivergenceReport::new("amm-diff", Sides::anchor_pinocchio(), ReproBundle::new())
            .with_divergence(body_divergence());
        let md = r.to_markdown();
        assert!(md.contains("**Reproducible**: NO"), "{md}");
        assert!(md.contains("the activated feature set"), "{md}");
    }

    #[test]
    fn markdown_carries_the_divergence_point_and_both_binaries() {
        let md = report().with_divergence(body_divergence()).to_markdown();
        assert!(md.contains("byte 16 of 6664"), "{md}");
        assert!(md.contains("**[fault]**"), "{md}");
        assert!(md.contains("| anchor | `Anch111` |"), "{md}");
        assert!(md.contains("| pinocchio | `Pino111` |"), "{md}");
        assert!(md.contains("swap(100, 0)"), "{md}");
    }

    #[test]
    fn report_round_trips_through_json() {
        let r = report().with_divergences([cu_win(), body_divergence()]);
        let encoded = serde_json::to_string(&r).unwrap();
        let decoded: DivergenceReport = serde_json::from_str(&encoded).unwrap();
        assert_eq!(r, decoded);
        assert_eq!(r.digest().unwrap(), decoded.digest().unwrap());
    }
}
