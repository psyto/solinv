//! # solinv-disclose
//!
//! Turns a differential finding into something a third party can check.
//!
//! A fuzz harness that finds a divergence holds it as a formatted
//! string on its way into `fuzz_assert!` — enough for the person
//! watching the run, not enough for anyone else. This crate is the
//! other half: the finding as **data**, with the inputs that produced
//! it, in a form that survives leaving the machine it was found on.
//!
//! ```
//! use solinv_disclose::{
//!     ActionRef, Divergence, DivergenceReport, ProgramRef, ReproBundle, Sides,
//! };
//!
//! let report = DivergenceReport::new(
//!     "amm-diff",
//!     Sides::anchor_pinocchio(),
//!     ReproBundle::new()
//!         .with_program(ProgramRef::from_code("anchor", "Anch111", b"..."))
//!         .with_program(ProgramRef::from_code("pinocchio", "Pino111", b"..."))
//!         .with_feature_set("mainnet-beta@epoch-812")
//!         .with_action(ActionRef::described("swap(100, 0)")),
//! )
//! .with_divergence(Divergence::Body {
//!     label: "pool".into(),
//!     first_byte: 16,
//!     left_byte: 0x42,
//!     right_byte: 0x00,
//!     body_size: 6664,
//! });
//!
//! assert!(report.has_fault());
//! assert!(report.to_markdown().contains("byte 16 of 6664"));
//! let _digest = report.claim_digest().unwrap();  // pins the finding
//!
//! // `from_code` names the binary by digest without carrying it, so the
//! // report says so rather than inviting a reproduction it can't support.
//! assert!(!report.bundle().is_self_contained());
//! ```
//!
//! ## Why this is a separate, dependency-light crate
//!
//! Finding a divergence needs Crucible, LiteSVM and the Solana crates.
//! *Checking a report about one* should not. This crate depends on
//! serde and sha2 and nothing else, so a consumer that only wants to
//! read, verify the digest of, or re-render a finding can do so without
//! pulling in the fuzzing stack — including consumers outside this
//! repository.
//!
//! The types are correspondingly implementation-neutral: the two
//! executions are `left` and `right`, never "Anchor" and "Pinocchio".
//! See [`divergence`] for why that generality is load-bearing rather
//! than decorative.
//!
//! ## Status
//!
//! Implemented: the divergence record ([`Divergence`]), the input
//! bundle ([`ReproBundle`]) with a three-valued
//! [`Completeness`][repro::Completeness] judgement, and the report with
//! its canonical encoding, claim/report digests and Markdown rendering
//! ([`DivergenceReport`]).
//!
//! Not implemented yet: bounty-platform-specific formatters (Immunefi,
//! Sherlock, native protocol programs), severity classification,
//! economic impact estimation, and remediation-pattern lookup. The
//! Markdown rendering is generic — it is not yet shaped to any
//! platform's submission template.
//!
//! No harness populates a self-contained bundle today. Every report
//! this repository can currently produce is
//! [`IdentifiedOnly`][repro::Completeness::IdentifiedOnly]: it names
//! its inputs by digest without carrying them, and renders accordingly.

pub mod divergence;
pub mod report;
pub mod repro;

pub use divergence::{Divergence, Sides};
pub use report::{Claim, DivergenceReport, ToolStamp, SCHEMA_VERSION};
pub use repro::{
    sha256_hex, AccountRef, ActionRef, Artifact, Completeness, ProgramRef, ReproBundle,
};
