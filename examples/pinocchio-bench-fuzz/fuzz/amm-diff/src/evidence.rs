//! # evidence — turning a divergence into something a third party can check
//!
//! The harness already knows how to *find* a divergence. This module is
//! the other half of the loop: writing one out as a
//! [`solinv_disclose::DivergenceReport`] instead of a `fuzz_assert!`
//! log line that dies with the worker.
//!
//! ## Why it is off by default and fires once
//!
//! The W8 pair diverges on essentially every probe — a 20s campaign
//! produced 5,998 violations across 5,999 executions. A harness that
//! wrote a report per violation would emit thousands of near-identical
//! files and dominate the run's wall-clock.
//!
//! So emission is opt-in through `SOLINV_REPORT`, following the
//! `SOLINV_BANDIT_METRICS` convention already in `solinv-core`, and a
//! [`Once`] guarantees at most one report per process. The first
//! divergence is the one that gets recorded; the campaign's own counters
//! remain the measure of *how often*, which is the question a report was
//! never the right shape to answer.
//!
//! ## What the report can and cannot claim
//!
//! By default the bundle names its inputs by SHA-256 without carrying
//! them, which grades `IdentifiedOnly` — a reader must obtain the `.so`
//! files independently and verify them against the digests. Setting
//! `SOLINV_REPORT_INLINE=1` carries the program bytes and account
//! pre-state in the report itself, which is what `InputsCarried`
//! requires. The anchor `.so` is ~200 KB, so that is a deliberate
//! choice rather than the default.

use std::sync::Once;

use solinv_disclose::DivergenceReport;

static EMITTED: Once = Once::new();

fn flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Path prefix reports are written to, when set.
///
/// `SOLINV_REPORT=/tmp/w8` writes `/tmp/w8.json` (canonical, what a
/// reader verifies) and `/tmp/w8.md` (the human view).
pub fn target() -> Option<String> {
    std::env::var("SOLINV_REPORT")
        .ok()
        .filter(|p| !p.is_empty())
}

/// Whether to carry program bytes and account pre-state in the report
/// rather than only naming them by digest.
pub fn inline_artifacts() -> bool {
    flag("SOLINV_REPORT_INLINE")
}

/// Write the report, at most once per process.
///
/// Failures are reported to stderr and otherwise swallowed: a harness
/// that cannot write its evidence has still found the divergence, and
/// aborting the campaign over a filesystem problem would lose the run
/// as well as the report.
pub fn emit(build: impl FnOnce() -> DivergenceReport) {
    let Some(prefix) = target() else {
        return;
    };
    EMITTED.call_once(|| {
        let report = build();
        let json = match report.canonical_json() {
            Ok(bytes) => bytes,
            Err(e) => {
                eprintln!("[solinv][report] could not encode: {e}");
                return;
            }
        };
        for (path, bytes) in [
            (format!("{prefix}.json"), json),
            (format!("{prefix}.md"), report.to_markdown().into_bytes()),
        ] {
            if let Err(e) = std::fs::write(&path, &bytes) {
                eprintln!("[solinv][report] could not write {path}: {e}");
                return;
            }
        }
        let digest = report
            .claim_digest()
            .unwrap_or_else(|_| "<unencodable>".to_string());
        eprintln!(
            "[solinv][report] wrote {prefix}.json + {prefix}.md \
             claim_digest={digest} completeness={:?} portable={}",
            report.bundle().completeness(),
            report.claim_digest_is_portable(),
        );
    });
}
