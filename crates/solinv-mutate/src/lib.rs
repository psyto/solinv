//! # solinv-mutate
//!
//! Mutation testing for Solana programs: plant a known bug class in a
//! program's source, run the invariant catalog against it, and record
//! whether the detector that was supposed to catch it did.
//!
//! ## What this measures, and what it does not
//!
//! It measures **detector power on a specific target**. It does not
//! find bugs. Nothing in a mutation campaign is a vulnerability — the
//! bugs are the ones this crate planted. What a campaign produces is a
//! number per detector per program, which is the thing solinv's
//! calibration story is currently missing: the catalog is known to be
//! sensitive against `examples/escrow-demo`, and escrow-demo is not
//! Raydium. A run that reports 0 violations on production code is
//! evidence only if the same harness demonstrably kills planted bugs
//! *in that same program*.
//!
//! ## Structure
//!
//! - [`operator`] — the Solana bug-class catalog as source rewrites,
//!   each naming the invariant expected to kill it
//! - [`mutant`] — locating sites and emitting one mutant per site
//! - [`score`] — reachability-aware scoring and a pre-committed kill
//!   criterion
//!
//! The crate depends on serde, regex and nothing else: planning and
//! scoring a campaign is text and arithmetic, and should not require
//! building Crucible, LiteSVM or the Solana toolchain. The same edge
//! direction as `solinv-disclose`.
//!
//! ## What the caller supplies
//!
//! Executing a mutant needs a Solana build (`cargo build-sbf`) and a
//! fuzzing run, both of which are environment-specific and neither of
//! which belongs in a library. The intended flow is:
//!
//! 1. `solinv mutate plan` → a [`score::Campaign`] as JSON, with the
//!    kill criterion committed before anything runs
//! 2. for each mutant: `solinv mutate apply` → patched source → build →
//!    run the invariant harness → record a [`score::MutantResult`]
//! 3. `solinv mutate score` → a [`score::CampaignReport`]
//!
//! `scripts/run_mutation_campaign.sh` drives steps 2–3 for the
//! escrow-demo layout and is the reference for adapting it to another
//! target.
//!
//! ## Cost
//!
//! One `cargo build-sbf` per mutant is the dominant cost, and it is a
//! tax rather than an asset — worth attacking with mutant schemata
//! (all mutations compiled into one binary behind a runtime selector)
//! before it is worth tolerating. One caveat if that is done: schemata
//! changes the binary, so CU figures from a schemata build cannot feed
//! `cu-dos` or the differential CU surface. Those need per-mutant
//! builds.

pub mod mutant;
pub mod operator;
pub mod score;

pub use mutant::{apply, digest, generate, generate_with, Mutant};
pub use operator::{by_id, catalog, covered_invariants, MutationOperator, Tier, UNCOVERED_INVARIANTS};
pub use score::{
    per_invariant, Campaign, CampaignReport, EquivalentMutant, GateOutcome, KillCriterion,
    MutantOutcome, MutantResult, Score,
};
