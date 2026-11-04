//! solinv CLI - main entry point
//!
//! Sub-commands:
//! - `solinv init`              scaffold a solinv project
//! - `solinv check <target>`    run invariant checks
//! - `solinv fuzz <target>`     run coverage-guided fuzzer
//! - `solinv corpus fetch ...`  ingest mainnet corpus
//! - `solinv disclose <id>`     generate bug bounty disclosure

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::Deserialize;
use std::{fs, path::PathBuf};

use solinv_static::{diff, source};

#[derive(Parser)]
#[command(
    name = "solinv",
    version,
    about = "Solana-aware invariant fuzzing framework"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a solinv project in the current directory
    Init,
    /// Run invariant checks against a target program
    Check {
        /// Target program path
        target: String,
    },
    /// Run coverage-guided fuzzer against a target program
    Fuzz {
        /// Target program path
        target: String,
    },
    /// Manage mainnet corpus
    Corpus {
        #[command(subcommand)]
        action: CorpusAction,
    },
    /// Generate a disclosure report for a found bug
    Disclose {
        /// Bug identifier
        bug_id: String,
    },
    /// Plan, apply and score a mutation-testing campaign
    Mutate {
        #[command(subcommand)]
        action: MutateAction,
    },
    /// Show an Anchor IDL's account-validation surface, and which
    /// instructions to point the Critical 5 at first
    Idl {
        /// Anchor IDL JSON, e.g. target/idl/my_program.json
        path: PathBuf,
        /// Print a `SpecBuilder` binding stub for this instruction
        /// (`all` for every instruction)
        #[arg(long)]
        rust: Option<String>,
        /// Program source (file or directory): read each slot's
        /// declared type, so typed accounts are told apart from
        /// UncheckedAccount / AccountInfo
        #[arg(long)]
        src: Option<PathBuf>,
    },
    /// Name the account checks a change removes: compares two versions
    /// of an Anchor program's source (no build needed)
    Diff {
        /// The program source before the change (file or directory)
        #[arg(long, requires = "head_src", conflicts_with_all = ["base_idl", "head_idl"])]
        base_src: Option<PathBuf>,
        /// The program source after the change
        #[arg(long, requires = "base_src", conflicts_with_all = ["base_idl", "head_idl"])]
        head_src: Option<PathBuf>,
        /// The Anchor IDL before the change (e.g. the audited build), instead
        /// of source. Sees fewer checks: signer, seeds, address, has_one
        #[arg(long, requires = "head_idl")]
        base_idl: Option<PathBuf>,
        /// The Anchor IDL after the change (e.g. `anchor idl fetch <program>`)
        #[arg(long, requires = "base_idl")]
        head_idl: Option<PathBuf>,
        /// `text`, or `github` for Actions annotations on the changed lines
        #[arg(long, default_value = "text")]
        format: String,
        /// Exit 0 even when checks were removed
        #[arg(long)]
        no_fail: bool,
    },
    /// Score and rank bug bounty targets
    Score {
        /// Path to target scoring config (.json or .toml)
        #[arg(long)]
        config: PathBuf,
        /// Show top-N targets
        #[arg(long, default_value_t = 10)]
        top: usize,
        /// Emit machine-readable JSON output
        #[arg(long)]
        json: bool,
        /// Filter to targets with status="ready" only (drops exhausted/gated/unverified)
        #[arg(long)]
        reachable_only: bool,
    },
}

#[derive(Subcommand)]
enum MutateAction {
    /// List the mutation operator catalog and the invariants it does
    /// not reach
    Operators {
        /// Emit machine-readable JSON output
        #[arg(long)]
        json: bool,
    },
    /// Generate a campaign plan from program sources.
    ///
    /// The kill criterion is supplied here, before any mutant runs —
    /// the §9 pre-commit discipline applied to the campaign itself.
    Plan {
        /// Target name recorded in the plan, e.g. `raydium-amm`
        #[arg(long)]
        target: String,
        /// Rust source files to mutate. Repeat the flag per file.
        #[arg(long = "src", required = true)]
        srcs: Vec<PathBuf>,
        /// Where to write the campaign JSON
        #[arg(long)]
        out: PathBuf,
        /// Pre-committed statement of what this campaign tests and
        /// what each outcome would mean
        #[arg(long)]
        statement: String,
        /// Minimum kill rate over reached mutants for a PASS
        #[arg(long, default_value_t = 0.8)]
        min_score: f64,
        /// Minimum reached mutants for the run to be conclusive
        #[arg(long, default_value_t = 10)]
        min_reached: usize,
        /// Keep only mutants inside these functions. Repeat per name.
        ///
        /// The reachability join works at instruction granularity: a
        /// mutant is credited as reached when the ledger saw its
        /// enclosing function run as an instruction. Code in a helper
        /// the handler calls therefore reads as unreached even though
        /// it executed. Planning a whole native crate produces mostly
        /// such mutants — 324 across raydium-amm, of which a harness
        /// driving two instructions can speak to a couple of dozen —
        /// and each one still costs a full SBF rebuild to exclude.
        #[arg(long = "only-fn")]
        only_fns: Vec<String>,
    },
    /// Write the mutated source for one mutant in a plan
    Apply {
        /// Campaign JSON produced by `plan`
        #[arg(long)]
        plan: PathBuf,
        /// Mutant id to apply
        #[arg(long)]
        mutant: String,
        /// Where to write the patched file (defaults to stdout)
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Record a mutant as equivalent, excluding it from the score.
    ///
    /// For a mutation that compiles and runs but cannot produce
    /// incorrect behaviour, so no detector could have caught it. The
    /// reason is mandatory and is printed in the report next to the
    /// adjusted score — an exclusion nobody can check is an exclusion
    /// that flatters the number.
    Exclude {
        /// Campaign JSON produced by `plan`
        #[arg(long)]
        plan: PathBuf,
        /// Mutant id to exclude
        #[arg(long)]
        mutant: String,
        /// Why this mutation cannot produce incorrect behaviour
        #[arg(long)]
        reason: String,
    },
    /// Score a completed campaign
    Score {
        /// Campaign JSON produced by `plan`
        #[arg(long)]
        plan: PathBuf,
        /// Results JSON — an array of MutantResult
        #[arg(long)]
        results: PathBuf,
        /// Emit machine-readable JSON instead of Markdown
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum CorpusAction {
    /// Fetch corpus from mainnet via Yellowstone gRPC
    Fetch {
        #[arg(long)]
        rpc: String,
        #[arg(long)]
        program_id: String,
        #[arg(long)]
        since_slot: Option<u64>,
    },
}

#[derive(Debug, Deserialize)]
struct ScoringConfig {
    weights: ScoringWeights,
    targets: Vec<TargetInput>,
}

#[derive(Debug, Deserialize)]
struct ScoringWeights {
    tvl: f64,
    change_velocity: f64,
    permissionless_surface: f64,
    complexity: f64,
    audit_maturity: f64,
}

#[derive(Debug, Deserialize)]
struct TargetInput {
    name: String,
    tvl: f64,
    change_velocity: f64,
    permissionless_surface: f64,
    complexity: f64,
    audit_maturity: f64,
    /// Toolchain reachability flag. One of:
    ///  - `"ready"`      — reachable + fresh + not yet exhausted
    ///  - `"exhausted"`  — reachable but tested clean already (no marginal value)
    ///  - `"gated"`      — blocked: no usable binary (the source does not build and the deployed one has not been made to fit), or nothing to write a harness from (no source or IDL)
    ///  - `"unverified"` — reachability not yet confirmed (default if omitted)
    #[serde(default = "default_status")]
    status: String,
    /// Optional one-line note explaining reachability status.
    #[serde(default)]
    note: String,
}

fn default_status() -> String {
    "unverified".to_string()
}

#[derive(Debug, serde::Serialize)]
struct TargetScore {
    rank: usize,
    name: String,
    score: f64,
    tvl: f64,
    change_velocity: f64,
    permissionless_surface: f64,
    complexity: f64,
    audit_maturity: f64,
    status: String,
    note: String,
}

fn parse_scoring_config(path: &PathBuf) -> Result<ScoringConfig> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read config file: {}", path.display()))?;
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or_default();
    match ext {
        "json" => serde_json::from_str(&raw).context("invalid JSON scoring config"),
        "toml" => toml::from_str(&raw).context("invalid TOML scoring config"),
        _ => anyhow::bail!(
            "unsupported config extension for {} (use .json or .toml)",
            path.display()
        ),
    }
}

fn compute_scores(cfg: ScoringConfig) -> Vec<TargetScore> {
    let mut scored: Vec<_> = cfg
        .targets
        .into_iter()
        .map(|t| {
            let score = cfg.weights.tvl * t.tvl
                + cfg.weights.change_velocity * t.change_velocity
                + cfg.weights.permissionless_surface * t.permissionless_surface
                + cfg.weights.complexity * t.complexity
                - cfg.weights.audit_maturity * t.audit_maturity;
            (t, score)
        })
        .collect();

    scored.sort_by(|a, b| b.1.total_cmp(&a.1));
    scored
        .into_iter()
        .enumerate()
        .map(|(idx, (t, score))| TargetScore {
            rank: idx + 1,
            name: t.name,
            score,
            tvl: t.tvl,
            change_velocity: t.change_velocity,
            permissionless_surface: t.permissionless_surface,
            complexity: t.complexity,
            audit_maturity: t.audit_maturity,
            status: t.status,
            note: t.note,
        })
        .collect()
}

fn run_mutate(action: MutateAction) -> Result<()> {
    use solinv_mutate::{
        apply, catalog, generate, Campaign, CampaignReport, EquivalentMutant, KillCriterion,
        MutantResult,
        UNCOVERED_INVARIANTS,
    };

    match action {
        MutateAction::Operators { json } => {
            let ops = catalog();
            if json {
                // The operator table is `&'static str` throughout, so
                // render it explicitly rather than deriving Serialize
                // on a type whose whole point is being a const catalog.
                let rows: Vec<_> = ops
                    .iter()
                    .map(|op| {
                        serde_json::json!({
                            "id": op.id,
                            "description": op.description,
                            "expected_killer": op.expected_killer,
                            "tier": op.tier,
                            "rationale": op.rationale,
                        })
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "operators": rows,
                        "uncovered_invariants": UNCOVERED_INVARIANTS,
                    }))?
                );
            } else {
                println!("id\texpected killer\tdescription");
                for op in &ops {
                    println!("{}\t{}\t{}", op.id, op.expected_killer, op.description);
                }
                println!(
                    "\n{} operators. Not reachable by any v1 operator: {}",
                    ops.len(),
                    UNCOVERED_INVARIANTS.join(", ")
                );
            }
        }

        MutateAction::Plan {
            target,
            srcs,
            out,
            statement,
            min_score,
            min_reached,
            only_fns,
        } => {
            let mut sources = Vec::with_capacity(srcs.len());
            for path in &srcs {
                let contents = fs::read_to_string(path)
                    .with_context(|| format!("failed to read source: {}", path.display()))?;
                sources.push((path.display().to_string(), contents));
            }
            let mut mutants = generate(&sources)?;
            if !only_fns.is_empty() {
                let before = mutants.len();
                mutants.retain(|m| {
                    m.enclosing_fn
                        .as_deref()
                        .is_some_and(|f| only_fns.iter().any(|w| w == f))
                });
                println!(
                    "--only-fn kept {} of {before} mutants across {} function(s)",
                    mutants.len(),
                    only_fns.len()
                );
                for f in &only_fns {
                    if !mutants.iter().any(|m| m.enclosing_fn.as_deref() == Some(f)) {
                        println!("warning: no mutants in '{f}' — misspelled, or nothing to mutate");
                    }
                }
            }
            let campaign = Campaign {
                target,
                criterion: KillCriterion {
                    statement,
                    min_score,
                    min_reached,
                },
                mutants,
                equivalent: Vec::new(),
            };
            fs::write(&out, serde_json::to_string_pretty(&campaign)?)
                .with_context(|| format!("failed to write plan: {}", out.display()))?;

            // Say up front whether the plan can even satisfy its own
            // criterion — a plan with fewer mutants than min_reached is
            // inconclusive before it starts.
            let n = campaign.mutants.len();
            println!("planned {n} mutants for {} -> {}", campaign.target, out.display());
            if n < min_reached {
                println!(
                    "warning: the plan holds {n} mutants but the criterion needs {min_reached} \
                     reached ones. Even a perfect run would be INCONCLUSIVE — widen the \
                     source set or lower --min-reached before spending build time."
                );
            }
        }

        MutateAction::Apply { plan, mutant, out } => {
            let campaign: Campaign = serde_json::from_str(
                &fs::read_to_string(&plan)
                    .with_context(|| format!("failed to read plan: {}", plan.display()))?,
            )
            .context("invalid campaign JSON")?;
            let m = campaign
                .mutants
                .iter()
                .find(|m| m.id == mutant)
                .with_context(|| format!("no mutant '{mutant}' in {}", plan.display()))?;
            let contents = fs::read_to_string(&m.file)
                .with_context(|| format!("failed to read mutated file: {}", m.file))?;
            let patched = apply(&contents, m)?;
            match out {
                Some(path) => {
                    fs::write(&path, patched)
                        .with_context(|| format!("failed to write: {}", path.display()))?;
                    println!("{} -> {}", m.id, path.display());
                }
                None => print!("{patched}"),
            }
        }

        MutateAction::Exclude {
            plan,
            mutant,
            reason,
        } => {
            if reason.trim().is_empty() {
                anyhow::bail!("--reason must say why the mutation cannot misbehave");
            }
            let mut campaign: Campaign = serde_json::from_str(
                &fs::read_to_string(&plan)
                    .with_context(|| format!("failed to read plan: {}", plan.display()))?,
            )
            .context("invalid campaign JSON")?;

            // Refuse an id the plan does not contain. Silently accepting
            // one would let a typo read as an applied exclusion.
            if !campaign.mutants.iter().any(|m| m.id == mutant) {
                anyhow::bail!("no mutant `{mutant}` in {}", plan.display());
            }
            if let Some(existing) = campaign.equivalent.iter_mut().find(|e| e.mutant_id == mutant) {
                existing.reason = reason;
                println!("updated the reason for {mutant}");
            } else {
                campaign.equivalent.push(EquivalentMutant {
                    mutant_id: mutant.clone(),
                    reason,
                });
                println!("excluded {mutant} as equivalent");
            }
            fs::write(&plan, serde_json::to_string_pretty(&campaign)?)
                .with_context(|| format!("failed to write plan: {}", plan.display()))?;
        }

        MutateAction::Score {
            plan,
            results,
            json,
        } => {
            let campaign: Campaign = serde_json::from_str(
                &fs::read_to_string(&plan)
                    .with_context(|| format!("failed to read plan: {}", plan.display()))?,
            )
            .context("invalid campaign JSON")?;
            let results: Vec<MutantResult> = serde_json::from_str(
                &fs::read_to_string(&results)
                    .with_context(|| format!("failed to read results: {}", results.display()))?,
            )
            .context("invalid results JSON")?;
            let report = CampaignReport::build(&campaign, &results);
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print!("{}", report.to_markdown());
            }
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Init => {
            println!("solinv init: not yet implemented");
        }
        Commands::Check { target } => {
            println!("solinv check {target}: not yet implemented");
        }
        Commands::Fuzz { target } => {
            println!("solinv fuzz {target}: not yet implemented");
        }
        Commands::Corpus { action } => match action {
            CorpusAction::Fetch {
                rpc,
                program_id,
                since_slot,
            } => {
                println!(
                    "solinv corpus fetch --rpc {rpc} --program-id {program_id} \
                     --since-slot {since_slot:?}: not yet implemented"
                );
            }
        },
        Commands::Disclose { bug_id } => {
            println!("solinv disclose {bug_id}: not yet implemented");
        }
        Commands::Mutate { action } => run_mutate(action)?,
        Commands::Diff { base_src, head_src, base_idl, head_idl, format, no_fail } => {
            let changes = match (base_src, head_src, base_idl, head_idl) {
                (Some(base_src), Some(head_src), None, None) => {
                    let base = source::SourceKinds::read(&base_src)?;
                    let head = source::SourceKinds::read(&head_src)?;
                    if base.is_empty() {
                        anyhow::bail!(
                            "no #[derive(Accounts)] field under {} could be matched to an instruction",
                            base_src.display()
                        );
                    }
                    diff::diff(&base, &head)
                }
                (None, None, Some(base_idl), Some(head_idl)) => {
                    let read = |p: &PathBuf| -> Result<solinv_static::idl::Idl> {
                        let raw = fs::read_to_string(p)
                            .with_context(|| format!("failed to read IDL: {}", p.display()))?;
                        Ok(solinv_static::idl::Idl::from_json_any(&raw)?.0)
                    };
                    solinv_static::idl_diff::diff_idl(&read(&base_idl)?, &read(&head_idl)?)
                }
                _ => anyhow::bail!("pass --base-src and --head-src, or --base-idl and --head-idl"),
            };
            match format.as_str() {
                "github" => {
                    print!("{}", diff::render_github(&changes));
                    eprint!("{}", diff::render_text(&changes));
                }
                "text" => print!("{}", diff::render_text(&changes)),
                other => anyhow::bail!("unknown --format {other} (text or github)"),
            }
            let removed = changes.iter().any(|c| c.severity == diff::Severity::Regression);
            if removed && !no_fail {
                std::process::exit(1);
            }
        }
        Commands::Idl { path, rust, src } => {
            let raw = fs::read_to_string(&path)
                .with_context(|| format!("failed to read IDL: {}", path.display()))?;
            let (idl, legacy) = solinv_fuzz::Idl::from_json_any(&raw)?;
            if legacy {
                eprintln!("note: legacy (pre-0.30) IDL, read as `anchor idl convert` would convert it");
            }
            match rust.as_deref() {
                None => match src {
                    Some(dir) => {
                        let kinds = source::SourceKinds::read(&dir)?;
                        if kinds.is_empty() {
                            eprintln!(
                                "solinv idl: no #[derive(Accounts)] field under {} could be \
                                 matched to an instruction; the report below is IDL-only",
                                dir.display()
                            );
                        }
                        print!(
                            "{}",
                            idl.report_with_bound(
                                |ix, path| kinds.get(ix, path),
                                |ix, path| !kinds.unbound(ix, path)
                            )
                        );
                    }
                    None => print!("{}", idl.report()),
                },
                Some("all") => {
                    for ix in &idl.instructions {
                        println!("{}", ix.rust_bindings());
                    }
                }
                Some(name) => print!("{}", idl.instruction(name)?.rust_bindings()),
            }
        }
        Commands::Score {
            config,
            top,
            json,
            reachable_only,
        } => {
            let cfg = parse_scoring_config(&config)?;
            let scores = compute_scores(cfg);
            let filtered: Vec<_> = if reachable_only {
                scores.into_iter().filter(|s| s.status == "ready").collect()
            } else {
                scores
            };
            // Re-rank in display order after filtering so the printed rank
            // is contiguous and reflects the post-filter ordering. The
            // original rank field stays in JSON output for traceability.
            let shown: Vec<_> = filtered.into_iter().take(top).collect();
            if json {
                println!("{}", serde_json::to_string_pretty(&shown)?);
            } else {
                println!("rank\tscore\tstatus    \tname\tnote");
                for row in shown {
                    let note = if row.note.is_empty() { "—" } else { row.note.as_str() };
                    println!(
                        "{}\t{:.3}\t{:<10}\t{}\t{}",
                        row.rank, row.score, row.status, row.name, note
                    );
                }
            }
        }
    }
    Ok(())
}
