//! # Invariant: cpi-reentrancy
//!
//! Detects CPI cycles where a program is invoked again before its
//! outer handler returns. Reads `TxOutcome.logs` after each ix
//! execution, parses the Solana runtime's `Program <pid> invoke
//! [<depth>]` / `success` / `failed` log lines into a sequence of
//! CPI events, walks the events maintaining a running call stack,
//! and fires `fuzz_assert!` if any program id appears at two depths
//! simultaneously (modulo `CpiReentrancyConfig.allowlist`).
//!
//! See `docs/invariants/cpi-reentrancy.md` for the bug class,
//! mainnet precedents (Mango v3 insurance fund $114M), severity
//! bands, the planted-bug fixture design, and §9 / §10 — the Phase
//! 2.5 OSS catalog-completion framing that legitimately reopens
//! this work post-Day-38.

use crucible_test_context::fuzz_assert;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solinv_fuzz::{HasContext, HasInstructionSet, InstructionSpec};

use super::util::{restore_accounts, save_accounts};

/// Check the fixture's instruction set for cpi-reentrancy violations.
///
/// For each ix whose spec carries `Some(CpiReentrancyConfig)`,
/// executes the ix unmodified, walks the resulting `TxOutcome.logs`
/// to reconstruct the CPI call tree, and fires a violation if the
/// spec's `program_id` (or any other program — see "Detection
/// scope" below) appears at two different stack depths.
///
/// Detection scope: v1 fires on ANY program appearing twice, not
/// only the spec's `program_id`. Rationale: the cycle is the bug
/// regardless of which program closes it. The
/// `CpiReentrancyConfig.allowlist` lets users silence intentional
/// cycles per program.
pub fn check<F>(fixture: &mut F)
where
    F: HasContext + HasInstructionSet,
{
    let ixs = fixture.instructions();
    for spec in &ixs {
        if spec.cpi_reentrancy.is_none() {
            continue;
        }
        run_attempt(fixture, spec);
    }
}

fn run_attempt<F>(fixture: &mut F, spec: &InstructionSpec)
where
    F: HasContext + HasInstructionSet,
{
    let pubkeys: Vec<_> = spec.accounts.iter().map(|m| m.pubkey).collect();
    let saves = save_accounts(fixture.ctx(), &pubkeys);

    let fee_payer = fixture.fee_payer();
    let mut signer_refs: Vec<&Keypair> = vec![&*fee_payer];
    for kp in &spec.signers {
        if kp.pubkey() != fee_payer.pubkey() {
            signer_refs.push(&**kp);
        }
    }

    let result = fixture
        .ctx_mut()
        .raw_call(spec.to_instruction())
        .fee_payer(&*fee_payer)
        .signers(&signer_refs)
        .send();

    if let Ok(outcome) = result {
        let logs = outcome.logs();
        let events = parse_cpi_events(logs);
        let allowlist = spec
            .cpi_reentrancy
            .as_ref()
            .map(|c| c.allowlist.as_slice())
            .unwrap_or(&[]);
        if let Some(reentry) = detect_reentry(&events, allowlist) {
            fuzz_assert!(
                false,
                "[cpi-reentrancy:{}] program {} re-entered at depths {}/{} (ix {})",
                spec.program_id,
                reentry.pid,
                reentry.outer_depth,
                reentry.inner_depth,
                spec.name,
            );
        }
    }

    restore_accounts(fixture.ctx_mut(), saves);
}

// ============================================================================
// Log parser + re-entry detector — free functions so unit tests can
// hand-craft `Vec<String>` fixtures without spinning up a fuzz harness.
// ============================================================================

/// One CPI transition extracted from `TxOutcome.logs`. `depth` is the
/// invoke-depth reported by the Solana runtime; outermost user-issued
/// ix is depth 1, the first nested CPI is depth 2, and so on
/// (MAX_CPI_DEPTH = 4 currently).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CpiEvent {
    Invoke { pid: Pubkey, depth: u32 },
    Success { pid: Pubkey },
    Failed { pid: Pubkey },
}

/// A detected re-entry. `pid` appeared at `outer_depth` and again at
/// `inner_depth` (deeper) without an intervening `Success` / `Failed`
/// closing the outer frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reentry {
    pub pid: Pubkey,
    pub outer_depth: u32,
    pub inner_depth: u32,
}

/// Parse a slice of Solana runtime log lines into a `Vec<CpiEvent>`.
///
/// Recognized line shapes (matched at line start, after trimming):
/// - `Program <BASE58_PID> invoke [<DEPTH>]`
/// - `Program <BASE58_PID> success`
/// - `Program <BASE58_PID> failed: <REASON>` (also `failed.` and
///   anything starting with `failed`)
///
/// Other lines (`Program log: ...`, `Program <PID> consumed <N> of
/// <M> compute units`, blank lines, malformed lines) are silently
/// skipped. The parser is fail-soft — it never panics on malformed
/// input.
pub fn parse_cpi_events(logs: &[String]) -> Vec<CpiEvent> {
    let mut out = Vec::new();
    for line in logs {
        let trimmed = line.trim();
        if !trimmed.starts_with("Program ") {
            continue;
        }
        // Strip "Program " prefix.
        let rest = &trimmed["Program ".len()..];
        // Split into (pid, verb-and-args).
        let Some((pid_str, tail)) = rest.split_once(' ') else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<Pubkey>() else {
            continue;
        };
        if let Some(depth_str) = tail.strip_prefix("invoke [") {
            if let Some(depth_str) = depth_str.strip_suffix(']') {
                if let Ok(depth) = depth_str.parse::<u32>() {
                    out.push(CpiEvent::Invoke { pid, depth });
                }
            }
        } else if tail == "success" {
            out.push(CpiEvent::Success { pid });
        } else if tail.starts_with("failed") {
            out.push(CpiEvent::Failed { pid });
        }
        // Otherwise: "consumed N of M compute units", "log: ...",
        // or other unrelated text — skip.
    }
    out
}

/// Walk a sequence of CPI events maintaining the active call stack;
/// return the first detected re-entry (any pid appearing twice in
/// the stack without an intervening pop) or `None` if no cycle.
///
/// `allowlist` programs are allowed to re-enter — their cycles do
/// not fire a violation.
///
/// The parser may produce unbalanced sequences under log truncation
/// (heavy CPI fills the LiteSVM log buffer); the walker tolerates
/// unbalanced pops by no-op'ing them. An unmatched invoke at end-of-
/// stream is also tolerated (returns `None` if no cycle was seen
/// before the truncation).
pub fn detect_reentry(events: &[CpiEvent], allowlist: &[Pubkey]) -> Option<Reentry> {
    let mut stack: Vec<(Pubkey, u32)> = Vec::new();
    for event in events {
        match event {
            CpiEvent::Invoke { pid, depth } => {
                if !allowlist.contains(pid) {
                    if let Some(&(_, outer_depth)) =
                        stack.iter().find(|(p, _)| p == pid)
                    {
                        return Some(Reentry {
                            pid: *pid,
                            outer_depth,
                            inner_depth: *depth,
                        });
                    }
                }
                stack.push((*pid, *depth));
            }
            CpiEvent::Success { .. } | CpiEvent::Failed { .. } => {
                stack.pop();
            }
        }
    }
    None
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(seed: u8) -> Pubkey {
        Pubkey::new_from_array([seed; 32])
    }

    fn logline_invoke(pid: &Pubkey, depth: u32) -> String {
        format!("Program {} invoke [{}]", pid, depth)
    }
    fn logline_success(pid: &Pubkey) -> String {
        format!("Program {} success", pid)
    }
    fn logline_failed(pid: &Pubkey) -> String {
        format!("Program {} failed: custom program error 0x1", pid)
    }
    fn logline_log() -> String {
        "Program log: side info".to_string()
    }
    fn logline_consumed(pid: &Pubkey, n: u64) -> String {
        format!("Program {} consumed {} of 200000 compute units", pid, n)
    }

    // ---------- parser tests ----------

    #[test]
    fn parse_single_invoke_success() {
        let a = pk(1);
        let logs = vec![
            logline_invoke(&a, 1),
            logline_log(),
            logline_consumed(&a, 1234),
            logline_success(&a),
        ];
        let events = parse_cpi_events(&logs);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0], CpiEvent::Invoke { pid: a, depth: 1 });
        assert_eq!(events[1], CpiEvent::Success { pid: a });
    }

    #[test]
    fn parse_failed_variants() {
        let a = pk(1);
        let logs = vec![
            logline_invoke(&a, 1),
            logline_failed(&a),
        ];
        let events = parse_cpi_events(&logs);
        assert_eq!(events[1], CpiEvent::Failed { pid: a });
    }

    #[test]
    fn parse_skips_malformed_lines() {
        let a = pk(1);
        let logs = vec![
            "garbage line".to_string(),
            "Program NOT_A_PUBKEY invoke [1]".to_string(),
            "Program ".to_string(),       // truncated
            logline_invoke(&a, 1),
            "Program {} invoke [not_a_number]".to_string(),
            logline_success(&a),
        ];
        let events = parse_cpi_events(&logs);
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn parse_handles_deep_chain() {
        let a = pk(1);
        let b = pk(2);
        let c = pk(3);
        let logs = vec![
            logline_invoke(&a, 1),
            logline_invoke(&b, 2),
            logline_invoke(&c, 3),
            logline_success(&c),
            logline_success(&b),
            logline_success(&a),
        ];
        let events = parse_cpi_events(&logs);
        assert_eq!(events.len(), 6);
    }

    // ---------- detect_reentry tests ----------

    #[test]
    fn no_cycle_no_violation() {
        let a = pk(1);
        let events = vec![
            CpiEvent::Invoke { pid: a, depth: 1 },
            CpiEvent::Success { pid: a },
        ];
        assert_eq!(detect_reentry(&events, &[]), None);
    }

    #[test]
    fn direct_a_to_b_to_a_fires() {
        let a = pk(1);
        let b = pk(2);
        let events = vec![
            CpiEvent::Invoke { pid: a, depth: 1 },
            CpiEvent::Invoke { pid: b, depth: 2 },
            CpiEvent::Invoke { pid: a, depth: 3 },
            CpiEvent::Success { pid: a },
            CpiEvent::Success { pid: b },
            CpiEvent::Success { pid: a },
        ];
        let r = detect_reentry(&events, &[]).expect("re-entry should fire");
        assert_eq!(r.pid, a);
        assert_eq!(r.outer_depth, 1);
        assert_eq!(r.inner_depth, 3);
    }

    #[test]
    fn indirect_multi_hop_a_b_c_a_fires() {
        let a = pk(1);
        let b = pk(2);
        let c = pk(3);
        let events = vec![
            CpiEvent::Invoke { pid: a, depth: 1 },
            CpiEvent::Invoke { pid: b, depth: 2 },
            CpiEvent::Invoke { pid: c, depth: 3 },
            CpiEvent::Invoke { pid: a, depth: 4 },
        ];
        let r = detect_reentry(&events, &[]).expect("re-entry should fire");
        assert_eq!(r.pid, a);
        assert_eq!(r.outer_depth, 1);
        assert_eq!(r.inner_depth, 4);
    }

    #[test]
    fn sibling_invocations_no_cycle() {
        // A→B (returns), A→C — same pid (A) appears twice but only at
        // depth 1 each time, no nesting.
        let a = pk(1);
        let b = pk(2);
        let c = pk(3);
        let events = vec![
            CpiEvent::Invoke { pid: a, depth: 1 },
            CpiEvent::Invoke { pid: b, depth: 2 },
            CpiEvent::Success { pid: b },
            CpiEvent::Invoke { pid: c, depth: 2 },
            CpiEvent::Success { pid: c },
            CpiEvent::Success { pid: a },
        ];
        assert_eq!(detect_reentry(&events, &[]), None);
    }

    #[test]
    fn allowlist_silences_intentional_reentry() {
        let a = pk(1);
        let b = pk(2);
        let events = vec![
            CpiEvent::Invoke { pid: a, depth: 1 },
            CpiEvent::Invoke { pid: b, depth: 2 },
            CpiEvent::Invoke { pid: a, depth: 3 },
        ];
        // Without allowlist: fires.
        assert!(detect_reentry(&events, &[]).is_some());
        // With A allowlisted: silent.
        assert_eq!(detect_reentry(&events, &[a]), None);
    }

    #[test]
    fn unbalanced_pop_is_tolerated() {
        // Spurious Success without a matching Invoke — happens under
        // log truncation. detect_reentry no-ops on empty-stack pop.
        let a = pk(1);
        let events = vec![
            CpiEvent::Success { pid: a },
            CpiEvent::Invoke { pid: a, depth: 1 },
            CpiEvent::Success { pid: a },
        ];
        assert_eq!(detect_reentry(&events, &[]), None);
    }
}
