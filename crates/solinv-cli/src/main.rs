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
    ///  - `"gated"`      — depth-gated by toolchain (e.g. Anchor 0.x ↔ LiteSVM 0.9.1 H1)
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
