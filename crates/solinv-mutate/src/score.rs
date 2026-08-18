//! # Scoring — with a denominator that admits what it excludes
//!
//! The naive mutation score is `killed / total`. On Solana that number
//! is actively misleading, because a large share of mutants are never
//! *executed*: the harness may not drive the mutated instruction, the
//! path may be gated behind state the fuzzer has not built up, or the
//! mutant may not compile at all. Counting those as survivors reports a
//! detector as weak when the campaign simply never asked it anything.
//!
//! solinv has already measured this effect from the other direction:
//! `bump-seed-canonicalization` detects its planted bug at roughly 2%
//! because the substitution attack requires the canonical vault to
//! exist first, so reachability — not detector sensitivity — sets the
//! rate. A mutation campaign that ignores reachability inherits that
//! confound wholesale.
//!
//! So the denominator here is **reached mutants only**:
//!
//! ```text
//! score = killed / (killed + survived)
//! ```
//!
//! with `not_reached` and `build_failed` reported as first-class
//! figures rather than folded in. A score computed over three reached
//! mutants out of two hundred is not a strong result, and the report
//! must make that impossible to miss — which is what
//! [`KillCriterion::min_reached`] enforces.
//!
//! ## Why there is an `Inconclusive` outcome
//!
//! A gate with only PASS and FAIL forces a verdict on a campaign that
//! produced no evidence. [`GateOutcome::Inconclusive`] exists so a run
//! that reached too few mutants reports as such instead of as a
//! detector failure — the same discipline as the §9 pre-committed kill
//! criteria in `docs/invariants/`, where the honest outcome of an
//! under-powered experiment is "we did not learn", not "it failed".

use crate::mutant::Mutant;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// What happened to one mutant when the campaign ran it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum MutantOutcome {
    /// An invariant fired. `by` is the invariant that reported it,
    /// which is not always the one the operator expected.
    Killed { by: String },
    /// The mutated code executed and no invariant fired.
    Survived,
    /// The mutated line was never executed — no evidence either way.
    NotReached,
    /// The mutant did not compile. Excluded from the score: a mutant
    /// that cannot run tells you nothing about a detector.
    BuildFailed { reason: String },
    /// The harness itself failed to run, or ran and produced no
    /// evidence of having executed anything. Excluded from the score.
    ///
    /// This variant exists because its absence was a live bug. A
    /// harness that never started looks, from the outside, exactly like
    /// one that ran and found nothing: no violations on stdout either
    /// way. Folding that case into `Survived` turned a misconfigured
    /// campaign into a confident report of detector blind spots. The
    /// fallback for "no evidence" must be its own outcome, not the
    /// outcome that happens to be adjacent.
    HarnessError { reason: String },
}

/// One mutant's result, as reported by the campaign runner.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MutantResult {
    pub mutant_id: String,
    /// Invariant the plan expected to kill this mutant.
    pub expected_killer: String,
    #[serde(flatten)]
    pub outcome: MutantOutcome,
}

impl MutantResult {
    /// Whether this mutant was reached — i.e. contributes to the
    /// denominator.
    pub fn is_reached(&self) -> bool {
        matches!(
            self.outcome,
            MutantOutcome::Killed { .. } | MutantOutcome::Survived
        )
    }

    /// Whether the invariant that killed it is the one the operator
    /// predicted. `false` for survivors and unreached mutants.
    pub fn killed_as_expected(&self) -> bool {
        match &self.outcome {
            MutantOutcome::Killed { by } => by == &self.expected_killer,
            _ => false,
        }
    }
}

/// Aggregate outcome counts and the resulting score.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Score {
    pub killed: usize,
    /// Of `killed`, how many were killed by the predicted invariant.
    pub killed_by_expected: usize,
    /// Of `killed`, how many by some other invariant. Not a failure —
    /// but it means the coverage came from somewhere unplanned, which
    /// is worth knowing before attributing it.
    pub killed_by_other: usize,
    pub survived: usize,
    pub not_reached: usize,
    pub build_failed: usize,
    /// Mutants whose run produced no evidence at all. Non-zero means
    /// the campaign is partly measuring itself rather than the target.
    pub harness_error: usize,
    /// `killed + survived` — reached mutants only.
    pub denominator: usize,
    /// `killed / denominator`. `None` when nothing was reached: a
    /// campaign with no evidence has no score, and reporting 0.0 would
    /// be indistinguishable from a total detector failure.
    pub score: Option<f64>,
}

impl Score {
    /// Tally a set of results.
    pub fn tally(results: &[MutantResult]) -> Self {
        let mut s = Score {
            killed: 0,
            killed_by_expected: 0,
            killed_by_other: 0,
            survived: 0,
            not_reached: 0,
            build_failed: 0,
            harness_error: 0,
            denominator: 0,
            score: None,
        };
        for r in results {
            match &r.outcome {
                MutantOutcome::Killed { .. } => {
                    s.killed += 1;
                    if r.killed_as_expected() {
                        s.killed_by_expected += 1;
                    } else {
                        s.killed_by_other += 1;
                    }
                }
                MutantOutcome::Survived => s.survived += 1,
                MutantOutcome::NotReached => s.not_reached += 1,
                MutantOutcome::BuildFailed { .. } => s.build_failed += 1,
                MutantOutcome::HarnessError { .. } => s.harness_error += 1,
            }
        }
        s.denominator = s.killed + s.survived;
        s.score = (s.denominator > 0).then(|| s.killed as f64 / s.denominator as f64);
        s
    }

    /// Total mutants considered, including those excluded from the
    /// denominator.
    pub fn total(&self) -> usize {
        self.denominator + self.not_reached + self.build_failed + self.harness_error
    }

    /// Share of mutants that produced no evidence. The figure that
    /// says how much of a campaign was wasted compute.
    pub fn excluded_fraction(&self) -> f64 {
        let total = self.total();
        if total == 0 {
            return 0.0;
        }
        (self.not_reached + self.build_failed + self.harness_error) as f64 / total as f64
    }
}

/// Per-invariant breakdown — the actual deliverable of a campaign.
///
/// A single headline score averages over detectors with very different
/// power. What a reader wants is which detector killed what, on this
/// target.
pub fn per_invariant(results: &[MutantResult]) -> BTreeMap<String, Score> {
    let mut grouped: BTreeMap<String, Vec<MutantResult>> = BTreeMap::new();
    for r in results {
        grouped
            .entry(r.expected_killer.clone())
            .or_default()
            .push(r.clone());
    }
    grouped
        .into_iter()
        .map(|(k, v)| (k, Score::tally(&v)))
        .collect()
}

/// A kill criterion, pre-committed before the campaign runs.
///
/// Mirrors the §9 structure in `docs/invariants/`: the binary outcome
/// is written down first so a disappointing result cannot be
/// re-interpreted after the fact.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct KillCriterion {
    /// Prose statement of what this campaign is testing and what each
    /// outcome would mean. Written before the run.
    pub statement: String,
    /// Minimum score over reached mutants for a PASS.
    pub min_score: f64,
    /// Minimum reached mutants for the run to be conclusive at all.
    pub min_reached: usize,
}

impl KillCriterion {
    /// Evaluate a tallied score against this criterion.
    pub fn evaluate(&self, score: &Score) -> GateOutcome {
        if score.denominator < self.min_reached {
            return GateOutcome::Inconclusive {
                reached: score.denominator,
                required: self.min_reached,
            };
        }
        // `denominator >= min_reached >= 1` here, so a score exists.
        let value = score.score.unwrap_or(0.0);
        if value >= self.min_score {
            GateOutcome::Pass {
                score: value,
                reached: score.denominator,
            }
        } else {
            GateOutcome::Fail {
                score: value,
                reached: score.denominator,
            }
        }
    }
}

/// Verdict of a pre-committed criterion.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "gate", rename_all = "snake_case")]
pub enum GateOutcome {
    Pass { score: f64, reached: usize },
    Fail { score: f64, reached: usize },
    /// Too few mutants reached for the run to mean anything. Not a
    /// failure of the detectors — a failure of the campaign to ask.
    Inconclusive { reached: usize, required: usize },
}

impl GateOutcome {
    /// Single word for a summary line.
    pub fn label(&self) -> &'static str {
        match self {
            GateOutcome::Pass { .. } => "PASS",
            GateOutcome::Fail { .. } => "FAIL",
            GateOutcome::Inconclusive { .. } => "INCONCLUSIVE",
        }
    }
}

/// A planned campaign: the mutants, and the criterion committed to
/// before running them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Campaign {
    /// Target name, e.g. `raydium-amm`.
    pub target: String,
    pub criterion: KillCriterion,
    pub mutants: Vec<Mutant>,
    /// Mutants ruled equivalent — the mutation compiles and runs but
    /// cannot produce incorrect behaviour, so no detector could have
    /// caught it and its survival says nothing about detector power.
    #[serde(default)]
    pub equivalent: Vec<EquivalentMutant>,
}

/// A mutant excluded from the denominator by human triage.
///
/// Equivalent mutants are the standing tax on mutation testing: on
/// escrow-clean, three of nine survivors were mutations that cannot
/// misbehave — a `checked_sub` whose underflow is unreachable behind an
/// intact guard, an Anchor `Signer` constraint made redundant by the
/// system-transfer CPI underneath it. Counted as survivors they push
/// the score below what the detectors are actually worth.
///
/// The exclusion is post-hoc by nature: you cannot know a mutant is
/// equivalent until you have seen it survive. That is exactly the shape
/// of reasoning the §9 pre-commit discipline exists to constrain, so
/// two things are non-negotiable here. The `reason` is required and
/// must be an argument, not a label. And the report prints the raw
/// score alongside the adjusted one, with every exclusion and its
/// reason listed, so a reader can check the arithmetic against the
/// argument rather than taking the adjusted number on trust.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EquivalentMutant {
    pub mutant_id: String,
    /// Why this mutation cannot produce incorrect behaviour.
    pub reason: String,
}

/// A completed campaign.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CampaignReport {
    pub target: String,
    pub criterion: KillCriterion,
    pub score: Score,
    pub per_invariant: BTreeMap<String, Score>,
    pub gate: GateOutcome,
    /// Catalog invariants no operator can produce a mutant for.
    pub uncovered_invariants: Vec<String>,
    /// Mutant ids that survived — the list worth reading.
    pub survivors: Vec<String>,
    /// The score over every result, before equivalent mutants are
    /// removed. Always rendered next to the adjusted one: an exclusion
    /// a reader cannot see is an exclusion they cannot check.
    pub raw_score: Score,
    /// The exclusions applied, with the argument for each.
    pub excluded_as_equivalent: Vec<EquivalentMutant>,
}

impl CampaignReport {
    /// Build a report from a campaign's results.
    pub fn build(campaign: &Campaign, results: &[MutantResult]) -> Self {
        let raw_score = Score::tally(results);

        // Only exclusions naming a mutant that actually survived are
        // honoured. Declaring a killed mutant equivalent would quietly
        // shrink the numerator, and declaring an absent one is a stale
        // plan — neither should silently change a score.
        let survived_ids: BTreeSet<&str> = results
            .iter()
            .filter(|r| matches!(r.outcome, MutantOutcome::Survived))
            .map(|r| r.mutant_id.as_str())
            .collect();
        let excluded_as_equivalent: Vec<EquivalentMutant> = campaign
            .equivalent
            .iter()
            .filter(|e| survived_ids.contains(e.mutant_id.as_str()))
            .cloned()
            .collect();

        let excluded_ids: BTreeSet<&str> = excluded_as_equivalent
            .iter()
            .map(|e| e.mutant_id.as_str())
            .collect();
        let scored: Vec<MutantResult> = results
            .iter()
            .filter(|r| !excluded_ids.contains(r.mutant_id.as_str()))
            .cloned()
            .collect();

        let score = Score::tally(&scored);
        let gate = campaign.criterion.evaluate(&score);
        let survivors = scored
            .iter()
            .filter(|r| matches!(r.outcome, MutantOutcome::Survived))
            .map(|r| r.mutant_id.clone())
            .collect();
        CampaignReport {
            target: campaign.target.clone(),
            criterion: campaign.criterion.clone(),
            score,
            per_invariant: per_invariant(&scored),
            gate,
            uncovered_invariants: crate::operator::UNCOVERED_INVARIANTS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            survivors,
            raw_score,
            excluded_as_equivalent,
        }
    }

    /// Render the report as Markdown.
    ///
    /// The excluded counts and the uncovered-invariant list are printed
    /// unconditionally, next to the headline number rather than in a
    /// footnote. A score that silently omits what it did not measure
    /// reads as a verdict on everything.
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("# Mutation campaign — {}\n\n", self.target));

        let headline = match self.score.score {
            Some(v) => format!("{:.1}%", v * 100.0),
            None => "n/a (nothing reached)".to_string(),
        };
        out.push_str(&format!(
            "- **Gate**: {}\n- **Score**: {} ({} killed / {} reached)\n",
            self.gate.label(),
            headline,
            self.score.killed,
            self.score.denominator,
        ));
        out.push_str(&format!(
            "- **Excluded from the denominator**: {} not reached, {} failed to build, \
             {} harness error ({:.0}% of {} mutants produced no evidence)\n",
            self.score.not_reached,
            self.score.build_failed,
            self.score.harness_error,
            self.score.excluded_fraction() * 100.0,
            self.score.total(),
        ));
        out.push_str(&format!(
            "- **Attribution**: {} killed by the predicted invariant, {} by another\n",
            self.score.killed_by_expected, self.score.killed_by_other,
        ));
        out.push_str(&format!(
            "- **Not covered by any v1 operator**: {}\n",
            self.uncovered_invariants.join(", ")
        ));

        // Placed above everything else a reader would act on. A harness
        // that did not run does not weaken any number below — it
        // removes their subject.
        if self.score.harness_error > 0 {
            out.push_str(&format!(
                "\n> **{} of {} mutants produced no evidence that the harness ran.** \
                 Fix the harness before reading anything below as a statement about \
                 the detectors: a run that never started and a run that found nothing \
                 are the same silence.\n",
                self.score.harness_error,
                self.score.total(),
            ));
        }

        if !self.excluded_as_equivalent.is_empty() {
            let raw = match self.raw_score.score {
                Some(v) => format!("{:.1}%", v * 100.0),
                None => "n/a".to_string(),
            };
            out.push_str(&format!(
                "- **Before excluding equivalent mutants**: {} ({} killed / {} reached)\n",
                raw, self.raw_score.killed, self.raw_score.denominator,
            ));
        }

        out.push_str("\n## Pre-committed criterion\n\n");
        out.push_str(&format!("> {}\n\n", self.criterion.statement));
        out.push_str(&format!(
            "PASS requires score ≥ {:.2} over ≥ {} reached mutants.\n",
            self.criterion.min_score, self.criterion.min_reached
        ));
        if let GateOutcome::Inconclusive { reached, required } = &self.gate {
            out.push_str(&format!(
                "\n**The run did not reach that bar**: {reached} of {required} required \
                 mutants executed. This is not evidence that the detectors are weak — \
                 it is evidence the campaign never asked them.\n"
            ));
        }

        out.push_str("\n## Per invariant\n\n");
        out.push_str(
            "| Invariant | Killed | Reached | Score | Not reached | Build failed | \
             Harness error |\n",
        );
        out.push_str("|---|---:|---:|---:|---:|---:|---:|\n");
        for (inv, s) in &self.per_invariant {
            let cell = match s.score {
                Some(v) => format!("{:.0}%", v * 100.0),
                None => "n/a".to_string(),
            };
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} |\n",
                inv,
                s.killed,
                s.denominator,
                cell,
                s.not_reached,
                s.build_failed,
                s.harness_error,
            ));
        }

        if !self.survivors.is_empty() {
            out.push_str("\n## Survivors\n\n");
            out.push_str(
                "Mutants that executed and that no invariant caught. Each is either a \
                 detector blind spot or a bug class the catalog does not model.\n\n",
            );
            for id in &self.survivors {
                out.push_str(&format!("- `{id}`\n"));
            }
        }

        if !self.excluded_as_equivalent.is_empty() {
            out.push_str("\n## Excluded as equivalent\n\n");
            out.push_str(
                "Mutants ruled incapable of producing incorrect behaviour, and so \
                 removed from the denominator. Each exclusion raises the score, so \
                 each one is stated with its argument — check them.\n\n",
            );
            for e in &self.excluded_as_equivalent {
                out.push_str(&format!("- `{}`\n  - {}\n", e.mutant_id, e.reason));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn res(id: &str, expected: &str, outcome: MutantOutcome) -> MutantResult {
        MutantResult {
            mutant_id: id.to_string(),
            expected_killer: expected.to_string(),
            outcome,
        }
    }

    fn killed(by: &str) -> MutantOutcome {
        MutantOutcome::Killed { by: by.to_string() }
    }

    #[test]
    fn denominator_excludes_unreached_and_unbuildable() {
        let results = vec![
            res("a", "signer-skip", killed("signer-skip")),
            res("b", "signer-skip", MutantOutcome::Survived),
            res("c", "signer-skip", MutantOutcome::NotReached),
            res(
                "d",
                "signer-skip",
                MutantOutcome::BuildFailed {
                    reason: "type error".into(),
                },
            ),
        ];
        let s = Score::tally(&results);
        assert_eq!(s.denominator, 2, "only killed + survived count");
        assert_eq!(s.score, Some(0.5));
        assert_eq!(s.not_reached, 1);
        assert_eq!(s.build_failed, 1);
        assert_eq!(s.total(), 4);
        assert_eq!(s.excluded_fraction(), 0.5);
    }

    #[test]
    fn nothing_reached_yields_no_score_rather_than_zero() {
        let results = vec![
            res("a", "cu-dos", MutantOutcome::NotReached),
            res("b", "cu-dos", MutantOutcome::NotReached),
        ];
        let s = Score::tally(&results);
        assert_eq!(s.denominator, 0);
        assert_eq!(s.score, None, "no evidence must not read as total failure");
    }

    #[test]
    fn attribution_separates_expected_from_incidental_kills() {
        let results = vec![
            res("a", "signer-skip", killed("signer-skip")),
            res("b", "signer-skip", killed("owner-skip")),
        ];
        let s = Score::tally(&results);
        assert_eq!(s.killed, 2);
        assert_eq!(s.killed_by_expected, 1);
        assert_eq!(s.killed_by_other, 1);
        assert_eq!(s.score, Some(1.0), "an unexpected killer is still a kill");
    }

    #[test]
    fn per_invariant_groups_by_expected_killer() {
        let results = vec![
            res("a", "signer-skip", killed("signer-skip")),
            res("b", "signer-skip", MutantOutcome::Survived),
            res("c", "unchecked-math", killed("unchecked-math")),
        ];
        let by = per_invariant(&results);
        assert_eq!(by["signer-skip"].score, Some(0.5));
        assert_eq!(by["unchecked-math"].score, Some(1.0));
    }

    fn criterion() -> KillCriterion {
        KillCriterion {
            statement: "If fewer than 80% of reached Critical-5 mutants are killed on \
                        Raydium, the detectors have a blind spot on production code."
                .into(),
            min_score: 0.8,
            min_reached: 10,
        }
    }

    #[test]
    fn gate_passes_at_or_above_the_committed_score() {
        let mut s = Score::tally(&[]);
        s.killed = 8;
        s.survived = 2;
        s.denominator = 10;
        s.score = Some(0.8);
        assert!(matches!(criterion().evaluate(&s), GateOutcome::Pass { .. }));
    }

    #[test]
    fn gate_fails_below_it() {
        let mut s = Score::tally(&[]);
        s.killed = 7;
        s.survived = 3;
        s.denominator = 10;
        s.score = Some(0.7);
        assert!(matches!(criterion().evaluate(&s), GateOutcome::Fail { .. }));
    }

    #[test]
    fn an_underpowered_run_is_inconclusive_not_failed() {
        // A perfect score over 3 mutants must not read as PASS, and a
        // poor one over 3 must not read as FAIL.
        let mut s = Score::tally(&[]);
        s.killed = 3;
        s.denominator = 3;
        s.score = Some(1.0);
        assert!(matches!(
            criterion().evaluate(&s),
            GateOutcome::Inconclusive { reached: 3, required: 10 }
        ));

        let mut poor = Score::tally(&[]);
        poor.killed = 0;
        poor.survived = 3;
        poor.denominator = 3;
        poor.score = Some(0.0);
        assert!(matches!(
            criterion().evaluate(&poor),
            GateOutcome::Inconclusive { .. }
        ));
    }

    fn campaign() -> Campaign {
        Campaign {
            target: "raydium-amm".into(),
            criterion: criterion(),
            mutants: Vec::new(),
            equivalent: Vec::new(),
        }
    }

    fn campaign_excluding(ids_and_reasons: &[(&str, &str)]) -> Campaign {
        Campaign {
            equivalent: ids_and_reasons
                .iter()
                .map(|(id, reason)| EquivalentMutant {
                    mutant_id: id.to_string(),
                    reason: reason.to_string(),
                })
                .collect(),
            ..campaign()
        }
    }

    #[test]
    fn an_equivalent_mutant_leaves_the_denominator() {
        let results = vec![
            res("a", "signer-skip", killed("signer-skip")),
            res("b", "signer-skip", MutantOutcome::Survived),
        ];
        let r = CampaignReport::build(
            &campaign_excluding(&[("b", "underflow unreachable behind an intact guard")]),
            &results,
        );
        assert_eq!(r.score.denominator, 1);
        assert_eq!(r.score.score, Some(1.0));
        assert_eq!(r.raw_score.denominator, 2, "the raw score keeps every result");
        assert_eq!(r.raw_score.score, Some(0.5));
        assert!(r.survivors.is_empty(), "an excluded mutant is not a survivor");
    }

    #[test]
    fn the_report_shows_the_score_the_exclusions_replaced() {
        let results = vec![
            res("a", "signer-skip", killed("signer-skip")),
            res("b", "signer-skip", MutantOutcome::Survived),
        ];
        let md = CampaignReport::build(
            &campaign_excluding(&[("b", "the CPI underneath already requires the signature")]),
            &results,
        )
        .to_markdown();
        assert!(md.contains("Before excluding equivalent mutants"), "{md}");
        assert!(md.contains("50.0%"), "the pre-exclusion score must survive: {md}");
        assert!(md.contains("## Excluded as equivalent"), "{md}");
        assert!(
            md.contains("the CPI underneath already requires the signature"),
            "the argument for an exclusion must be printed with it: {md}"
        );
    }

    #[test]
    fn only_survivors_can_be_excluded() {
        // Excluding a killed mutant would shrink the numerator, turning
        // a triage tool into a way to launder a bad score upward.
        let results = vec![
            res("a", "signer-skip", killed("signer-skip")),
            res("b", "signer-skip", MutantOutcome::Survived),
        ];
        let r = CampaignReport::build(
            &campaign_excluding(&[("a", "not a survivor"), ("ghost", "not in the results")]),
            &results,
        );
        assert!(r.excluded_as_equivalent.is_empty());
        assert_eq!(r.score.denominator, 2);
        assert_eq!(r.score.killed, 1);
    }

    #[test]
    fn report_states_exclusions_and_gaps_in_the_headline() {
        let results = vec![
            res("a", "signer-skip", killed("signer-skip")),
            res("b", "signer-skip", MutantOutcome::Survived),
            res("c", "owner-skip", MutantOutcome::NotReached),
        ];
        let md = CampaignReport::build(&campaign(), &results).to_markdown();
        assert!(md.contains("Excluded from the denominator"), "{md}");
        assert!(md.contains("not reached"), "{md}");
        assert!(md.contains("Not covered by any v1 operator"), "{md}");
        assert!(md.contains("cu-dos"), "uncovered list must be named: {md}");
    }

    fn harness_error(reason: &str) -> MutantOutcome {
        MutantOutcome::HarnessError {
            reason: reason.to_string(),
        }
    }

    #[test]
    fn harness_errors_stay_out_of_the_denominator() {
        let results = vec![
            res("a", "signer-skip", killed("signer-skip")),
            res("b", "signer-skip", MutantOutcome::Survived),
            res("c", "signer-skip", harness_error("crucible exited 1")),
        ];
        let s = Score::tally(&results);
        assert_eq!(s.harness_error, 1);
        assert_eq!(s.denominator, 2, "a failed harness is not a survivor");
        assert_eq!(s.score, Some(0.5));
        assert_eq!(s.total(), 3, "excluded mutants still count as attempted");
    }

    #[test]
    fn a_campaign_of_only_harness_errors_scores_nothing() {
        // The regression this variant exists for: before it, these three
        // were `Survived` and the report read 0% over 3 reached — a
        // confident verdict on detectors that were never invoked.
        let results = vec![
            res("a", "signer-skip", harness_error("no fuzz/ directory")),
            res("b", "signer-skip", harness_error("no fuzz/ directory")),
            res("c", "unchecked-math", harness_error("no fuzz/ directory")),
        ];
        let s = Score::tally(&results);
        assert_eq!(s.denominator, 0);
        assert_eq!(s.score, None, "no evidence must not render as 0%");
        assert!((s.excluded_fraction() - 1.0).abs() < f64::EPSILON);

        let md = CampaignReport::build(&campaign(), &results).to_markdown();
        assert!(md.contains("no evidence that the harness ran"), "{md}");
        assert!(md.contains("nothing reached"), "{md}");
        assert!(
            !md.contains("## Survivors"),
            "a harness failure must not be reported as a blind spot: {md}"
        );
    }

    #[test]
    fn report_lists_survivors() {
        let results = vec![res("b", "signer-skip", MutantOutcome::Survived)];
        let r = CampaignReport::build(&campaign(), &results);
        assert_eq!(r.survivors, vec!["b".to_string()]);
        assert!(r.to_markdown().contains("## Survivors"));
    }

    #[test]
    fn report_explains_an_inconclusive_gate() {
        let results = vec![res("a", "signer-skip", killed("signer-skip"))];
        let md = CampaignReport::build(&campaign(), &results).to_markdown();
        assert!(md.contains("INCONCLUSIVE"), "{md}");
        assert!(md.contains("never asked"), "{md}");
    }

    #[test]
    fn results_round_trip_through_json() {
        let results = vec![
            res("a", "signer-skip", killed("signer-skip")),
            res("b", "signer-skip", MutantOutcome::Survived),
            res(
                "c",
                "owner-skip",
                MutantOutcome::BuildFailed {
                    reason: "mismatched types".into(),
                },
            ),
        ];
        let json = serde_json::to_string(&results).unwrap();
        let back: Vec<MutantResult> = serde_json::from_str(&json).unwrap();
        assert_eq!(results, back);
    }
}
