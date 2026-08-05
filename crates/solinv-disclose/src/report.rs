//! # report — a divergence finding in a form someone else can check
//!
//! A [`DivergenceReport`] is one comparison run, packaged so that a
//! reader who was not there can (a) see exactly where the two sides
//! parted, and (b) re-execute and confirm it.
//!
//! ## What the digests do and do not do
//!
//! Two are exposed, and the difference matters.
//!
//! [`DivergenceReport::claim_digest`] covers the **semantic finding** —
//! schema version, subject, sides, inputs, divergences — and excludes
//! provenance. Two runs that found the same thing agree here even if
//! one was produced by a newer build of this crate.
//!
//! [`DivergenceReport::digest`] covers the **entire report**, tool
//! stamp included. Use it to name one exact artifact; expect it to
//! change on a crate release even when nothing about the finding did.
//!
//! Neither attests that the finding is *true*. No hash can. Confirming
//! it means re-running the bundle and arriving at the same divergence:
//! the digest makes the claim immutable, re-execution makes it true or
//! false.
//!
//! ## The canonical encoding, precisely
//!
//! The canonical form is compact JSON (no whitespace), fields in struct
//! declaration order, produced by `serde_json` over the typed structs —
//! no maps, so no key-ordering ambiguity.
//!
//! The honest scope of that guarantee: **it holds for one schema
//! version.** Adding a field, reordering declarations, or a change in
//! `serde_json`'s number or escape formatting all change the bytes and
//! therefore the digest. That is why [`SCHEMA_VERSION`] is carried
//! inside the hashed payload — a reader who computes a different digest
//! can tell whether they are looking at a different finding or merely a
//! different schema. It is *not* a stable cross-version wire format,
//! and a report should not be treated as one.
//!
use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::divergence::{Divergence, Sides};
use crate::repro::{sha256_hex, Completeness, ReproBundle};

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

/// Version of the report schema the canonical encoding is bound to.
///
/// Bumped whenever a field is added, removed, or reordered in
/// [`DivergenceReport`] or anything it contains. Carried inside the
/// hashed payload so a digest mismatch is diagnosable.
pub const SCHEMA_VERSION: u32 = 1;

/// One differential comparison run, its findings, and the inputs it
/// ran on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DivergenceReport {
    /// See [`SCHEMA_VERSION`].
    pub schema: u32,
    pub tool: ToolStamp,
    /// What the run was called (e.g. the harness or campaign name).
    pub subject: String,
    pub sides: Sides,
    pub bundle: ReproBundle,
    pub divergences: Vec<Divergence>,
}

/// The provenance-free view of a report, used by
/// [`DivergenceReport::claim_digest`]. Field order mirrors
/// [`DivergenceReport`] minus `tool`.
#[derive(Serialize)]
struct Claim<'a> {
    schema: u32,
    subject: &'a str,
    sides: &'a Sides,
    bundle: &'a ReproBundle,
    divergences: &'a [Divergence],
}

impl DivergenceReport {
    pub fn new(subject: impl Into<String>, sides: Sides, bundle: ReproBundle) -> Self {
        Self {
            schema: SCHEMA_VERSION,
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

    /// Canonical bytes of the whole report. See the module docs for the
    /// encoding rules and the scope of their guarantee.
    pub fn canonical_json(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Canonical bytes of the finding alone, excluding provenance.
    pub fn claim_json(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&Claim {
            schema: self.schema,
            subject: &self.subject,
            sides: &self.sides,
            bundle: &self.bundle,
            divergences: &self.divergences,
        })?)
    }

    /// Lowercase-hex SHA-256 over [`Self::canonical_json`] — names one
    /// exact report, tool stamp included.
    pub fn digest(&self) -> Result<String> {
        Ok(sha256_hex(&self.canonical_json()?))
    }

    /// Lowercase-hex SHA-256 over [`Self::claim_json`] — names the
    /// finding, and survives a release of this crate.
    ///
    /// ```
    /// use solinv_disclose::{DivergenceReport, ReproBundle, Sides, ToolStamp};
    ///
    /// let mut a = DivergenceReport::new("amm-diff", Sides::anchor_pinocchio(), ReproBundle::new());
    /// let mut b = a.clone();
    /// b.tool = ToolStamp::new("solinv-disclose", "99.0.0");
    ///
    /// // Same finding, different build.
    /// assert_eq!(a.claim_digest().unwrap(), b.claim_digest().unwrap());
    /// assert_ne!(a.digest().unwrap(), b.digest().unwrap());
    ///
    /// // A different finding parts ways under both.
    /// a.subject = "other".into();
    /// assert_ne!(a.claim_digest().unwrap(), b.claim_digest().unwrap());
    /// ```
    pub fn claim_digest(&self) -> Result<String> {
        Ok(sha256_hex(&self.claim_json()?))
    }

    /// Render as Markdown, for a bug-bounty submission or a public
    /// finding log.
    ///
    /// The header is deliberately blunt about what the reader can do
    /// with it: a bundle that only names its inputs says so, instead of
    /// inviting a reproduction it cannot support.
    pub fn to_markdown(&self) -> String {
        let digest = self
            .claim_digest()
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
        out.push_str(&format!(
            "- **Claim digest**: `{digest}` (schema v{})\n",
            self.schema
        ));

        match self.bundle.completeness() {
            Completeness::SelfContained => out.push_str(
                "- **Reproducible**: yes — every input travels with this \
                 report; re-execute and compare\n",
            ),
            Completeness::IdentifiedOnly => {
                out.push_str(
                    "- **Reproducible**: NOT FROM THIS REPORT ALONE — the inputs \
                     are identified by digest, not carried. Obtain them \
                     independently, verify them against the hashes below, then \
                     re-execute.\n",
                );
                out.push_str(&format!(
                    "  - Not carried: {}\n",
                    self.bundle.not_carried().join(", ")
                ));
            }
            Completeness::Incomplete => out.push_str(&format!(
                "- **Reproducible**: NO — the bundle does not even define a \
                 comparison; missing {}\n",
                self.bundle.missing().join(", ")
            )),
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

        out.push_str("\n## Inputs\n\n");
        if let Some(fs) = &self.bundle.feature_set {
            out.push_str(&format!("Feature set: `{fs}`\n\n"));
        }
        if let Some(slot) = self.bundle.slot {
            out.push_str(&format!("Account snapshot cloned at slot `{slot}`\n\n"));
        }

        if !self.bundle.programs.is_empty() {
            out.push_str("| side | program id | code sha256 | bytes carried |\n");
            out.push_str("|---|---|---|---|\n");
            for p in &self.bundle.programs {
                out.push_str(&format!(
                    "| {} | `{}` | `{}` | {} |\n",
                    p.side,
                    p.program_id,
                    p.code.sha256(),
                    if p.code.is_carried() { "yes" } else { "no" },
                ));
            }
            out.push('\n');
        }

        if !self.bundle.accounts.is_empty() {
            out.push_str("| account | pubkey | len | owner | lamports | pre-state sha256 | bytes carried |\n");
            out.push_str("|---|---|---|---|---|---|---|\n");
            for a in &self.bundle.accounts {
                let dash = "—".to_string();
                out.push_str(&format!(
                    "| {} | `{}` | {} | {} | {} | `{}` | {} |\n",
                    a.label,
                    a.pubkey,
                    a.pre_state.len(),
                    a.owner.clone().unwrap_or_else(|| dash.clone()),
                    a.lamports.map(|l| l.to_string()).unwrap_or(dash),
                    a.pre_state.sha256(),
                    if a.pre_state.is_carried() {
                        "yes"
                    } else {
                        "no"
                    },
                ));
            }
            out.push('\n');
        }

        if !self.bundle.actions.is_empty() {
            out.push_str("Action sequence:\n\n```\n");
            for (i, action) in self.bundle.actions.iter().enumerate() {
                out.push_str(&format!(
                    "{}. {}{}\n",
                    i + 1,
                    action.label,
                    match (&action.program_id, &action.data_base64) {
                        (Some(pid), Some(data)) => format!("  [program {pid} data {data}]"),
                        _ => "  [not encoded — description only]".to_string(),
                    }
                ));
            }
            out.push_str("```\n");
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repro::{ActionRef, ProgramRef};

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

    fn identified_bundle() -> ReproBundle {
        ReproBundle::new()
            .with_program(ProgramRef::from_code("anchor", "Anch111", b"a"))
            .with_program(ProgramRef::from_code("pinocchio", "Pino111", b"p"))
            .with_feature_set("mainnet-beta@epoch-812")
            .with_action(ActionRef::described("swap(100, 0)"))
    }

    fn report() -> DivergenceReport {
        DivergenceReport::new("amm-diff", Sides::anchor_pinocchio(), identified_bundle())
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
    fn one_sided_cu_alone_cannot_render_a_clean_verdict() {
        // Guards the gap where a report carrying only a half-executed CU
        // record, with no parity record to accompany it, announced "no
        // divergence" for a run in which one side never ran.
        let r = report().with_divergence(Divergence::Cu {
            label: "swap".into(),
            left_cu: Some(3_900),
            right_cu: None,
        });
        assert!(r.has_fault());
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
                .with_action(ActionRef::described("swap(100, 0)")),
        )
        .with_divergence(body_divergence())
        .digest()
        .unwrap();

        assert_ne!(base, other_binary);
    }

    #[test]
    fn claim_digest_survives_a_tool_release_but_full_digest_does_not() {
        let a = report().with_divergence(body_divergence());
        let mut b = a.clone();
        b.tool = ToolStamp::new("solinv-disclose", "99.0.0");
        assert_eq!(a.claim_digest().unwrap(), b.claim_digest().unwrap());
        assert_ne!(a.digest().unwrap(), b.digest().unwrap());
    }

    #[test]
    fn schema_version_is_inside_the_hashed_payload() {
        let a = report();
        let mut b = a.clone();
        b.schema = SCHEMA_VERSION + 1;
        assert_ne!(a.claim_digest().unwrap(), b.claim_digest().unwrap());
    }

    #[test]
    fn digest_is_64_hex_chars() {
        for d in [report().digest().unwrap(), report().claim_digest().unwrap()] {
            assert_eq!(d.len(), 64);
            assert!(d
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
        }
    }

    #[test]
    fn digest_only_bundle_does_not_advertise_reproducibility() {
        let md = report().with_divergence(body_divergence()).to_markdown();
        assert!(md.contains("NOT FROM THIS REPORT ALONE"), "{md}");
        assert!(md.contains("Not carried:"), "{md}");
        // The per-artifact column must agree with the header.
        assert!(md.contains("| anchor | `Anch111` |"), "{md}");
        assert!(md.contains("not encoded — description only"), "{md}");
    }

    #[test]
    fn incomplete_bundle_is_flagged_in_the_rendered_report() {
        let r = DivergenceReport::new("amm-diff", Sides::anchor_pinocchio(), ReproBundle::new())
            .with_divergence(body_divergence());
        let md = r.to_markdown();
        assert!(md.contains("does not even define a"), "{md}");
        assert!(md.contains("the activated feature set"), "{md}");
    }

    #[test]
    fn self_contained_bundle_advertises_reproducibility() {
        use crate::repro::AccountRef;
        let r = DivergenceReport::new(
            "amm-diff",
            Sides::anchor_pinocchio(),
            ReproBundle::new()
                .with_program(ProgramRef::with_code_inline("anchor", "Anch111", b"a"))
                .with_program(ProgramRef::with_code_inline("pinocchio", "Pino111", b"p"))
                .with_account(
                    AccountRef::with_data_inline("pool", "Pool111", &[0u8; 24])
                        .with_metadata("Owner111", 5_000_000, false),
                )
                .with_feature_set("mainnet-beta@epoch-812")
                .with_action(ActionRef::encoded("swap", "Anch111", &[1, 2], vec![])),
        )
        .with_divergence(body_divergence());
        let md = r.to_markdown();
        assert!(md.contains("**Reproducible**: yes"), "{md}");
        assert!(
            md.contains("| pool | `Pool111` | 24 | Owner111 | 5000000 |"),
            "{md}"
        );
    }

    #[test]
    fn markdown_carries_the_divergence_point() {
        let md = report().with_divergence(body_divergence()).to_markdown();
        assert!(md.contains("byte 16 of 6664"), "{md}");
        assert!(md.contains("**[fault]**"), "{md}");
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
