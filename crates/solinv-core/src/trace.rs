//! # trace — invariant-aware CPI call-tree visualization
//!
//! Turns a transaction's runtime logs (`TxOutcome.logs()`, or mainnet
//! `getTransaction` `logMessages`) into a nested CPI call tree, then
//! renders it as a [Mermaid](https://mermaid.js.org) `flowchart` that
//! renders inline on GitHub, in docs, and in disclosure reports.
//!
//! What makes this more than a generic trace viewer: it reuses the
//! same log parser the `cpi-reentrancy` invariant runs on, so the tree
//! can be **annotated with where an invariant fired** — the CPI frame a
//! program re-entered, the depth a check was skipped — turning "custom
//! program error: 0x…" into "here, at this frame, is what broke".
//!
//! ```
//! use solinv_core::trace;
//! let logs = vec![
//!     "Program 675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8 invoke [1]".to_string(),
//!     "Program log: Instruction: SwapBaseIn".to_string(),
//!     "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [2]".to_string(),
//!     "Program log: Instruction: Transfer".to_string(),
//!     "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA consumed 4645 of 200000 compute units".to_string(),
//!     "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success".to_string(),
//!     "Program 675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8 consumed 30000 of 200000 compute units".to_string(),
//!     "Program 675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8 success".to_string(),
//! ];
//! let tree = trace::build_tree(&logs);
//! let diagram = trace::to_mermaid(&tree);
//! assert!(diagram.starts_with("flowchart TD"));
//! ```

use solana_pubkey::Pubkey;

use crate::invariants::cpi_reentrancy::{detect_reentry, parse_cpi_events};

/// One CPI frame: a program invocation and everything nested inside it
/// before it returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpiNode {
    pub program: Pubkey,
    /// Runtime invoke depth (outermost user ix = 1).
    pub depth: u32,
    /// Instruction name from `Program log: Instruction: <name>`, if emitted.
    pub instruction: Option<String>,
    /// Compute units consumed by this frame, from the `consumed N of M` line.
    pub compute_units: Option<u64>,
    /// The frame ended in `failed`.
    pub failed: bool,
    /// Invariant annotation — why this frame is flagged (e.g. re-entry).
    pub note: Option<String>,
    pub children: Vec<CpiNode>,
}

/// A parsed transaction: the top-level ix frames and their CPI subtrees.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CpiTree {
    pub roots: Vec<CpiNode>,
}

impl CpiTree {
    /// Mark the first frame matching `program` at `depth` with `note`.
    /// Returns whether a frame was found.
    pub fn annotate(&mut self, program: &Pubkey, depth: u32, note: impl Into<String>) -> bool {
        fn walk(node: &mut CpiNode, program: &Pubkey, depth: u32, note: &str) -> bool {
            if node.program == *program && node.depth == depth && node.note.is_none() {
                node.note = Some(note.to_string());
                return true;
            }
            node.children
                .iter_mut()
                .any(|c| walk(c, program, depth, note))
        }
        let note = note.into();
        self.roots.iter_mut().any(|r| walk(r, program, depth, &note))
    }

    /// Total CPI frames in the tree.
    pub fn frame_count(&self) -> usize {
        fn count(n: &CpiNode) -> usize {
            1 + n.children.iter().map(count).sum::<usize>()
        }
        self.roots.iter().map(count).sum()
    }
}

// Frame under construction, arena-indexed so we can build the tree with a
// simple index stack instead of fighting the borrow checker.
struct Raw {
    program: Pubkey,
    depth: u32,
    instruction: Option<String>,
    compute_units: Option<u64>,
    failed: bool,
    children: Vec<usize>,
}

/// Parse runtime log lines into a CPI call tree. Fail-soft: unrecognized
/// or truncated lines are skipped, never panic.
pub fn build_tree(logs: &[String]) -> CpiTree {
    let mut arena: Vec<Raw> = Vec::new();
    let mut roots: Vec<usize> = Vec::new();
    let mut stack: Vec<usize> = Vec::new();

    for line in logs {
        let Some(rest) = line.trim().strip_prefix("Program ") else {
            continue;
        };

        // "Program log: Instruction: <name>" — attach the ix name to the
        // current (innermost open) frame.
        if let Some(msg) = rest.strip_prefix("log: ") {
            if let Some(name) = msg.strip_prefix("Instruction: ") {
                if let Some(&top) = stack.last() {
                    if arena[top].instruction.is_none() {
                        arena[top].instruction = Some(name.trim().to_string());
                    }
                }
            }
            continue;
        }

        let Some((pid_str, tail)) = rest.split_once(' ') else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<Pubkey>() else {
            continue;
        };

        if let Some(depth) = tail
            .strip_prefix("invoke [")
            .and_then(|s| s.strip_suffix(']'))
            .and_then(|s| s.parse::<u32>().ok())
        {
            let idx = arena.len();
            arena.push(Raw {
                program: pid,
                depth,
                instruction: None,
                compute_units: None,
                failed: false,
                children: Vec::new(),
            });
            match stack.last() {
                Some(&parent) => arena[parent].children.push(idx),
                None => roots.push(idx),
            }
            stack.push(idx);
        } else if tail == "success" {
            stack.pop();
        } else if tail.starts_with("failed") {
            if let Some(&top) = stack.last() {
                arena[top].failed = true;
            }
            stack.pop();
        } else if let Some(cu) = tail
            .strip_prefix("consumed ")
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse::<u64>().ok())
        {
            // "consumed N of M compute units" arrives while the frame is
            // still the stack top (just before its success/failed line).
            if let Some(&top) = stack.last() {
                if arena[top].program == pid {
                    arena[top].compute_units = Some(cu);
                }
            }
        }
    }

    fn to_node(arena: &[Raw], idx: usize) -> CpiNode {
        let r = &arena[idx];
        CpiNode {
            program: r.program,
            depth: r.depth,
            instruction: r.instruction.clone(),
            compute_units: r.compute_units,
            failed: r.failed,
            note: None,
            children: r.children.iter().map(|&c| to_node(arena, c)).collect(),
        }
    }

    CpiTree {
        roots: roots.iter().map(|&i| to_node(&arena, i)).collect(),
    }
}

/// Build a tree and annotate the frame where `cpi-reentrancy` fires, if
/// any. The annotated frame is the inner (re-entered) invocation.
pub fn build_annotated_tree(logs: &[String]) -> CpiTree {
    let mut tree = build_tree(logs);
    if let Some(r) = detect_reentry(&parse_cpi_events(logs), &[]) {
        tree.annotate(
            &r.pid,
            r.inner_depth,
            format!("cpi-reentrancy: re-entered (already open at depth {})", r.outer_depth),
        );
    }
    tree
}

/// Friendly label for well-known program ids; otherwise a shortened
/// base58 (`AbCd…WxYz`).
pub fn program_name(pid: &Pubkey) -> String {
    let s = pid.to_string();
    let known = match s.as_str() {
        "11111111111111111111111111111111" => Some("System"),
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" => Some("SPL Token"),
        "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb" => Some("Token-2022"),
        "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL" => Some("ATA"),
        "ComputeBudget111111111111111111111111111111" => Some("ComputeBudget"),
        "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8" => Some("Raydium AMM v4"),
        "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc" => Some("Orca Whirlpool"),
        _ => None,
    };
    match known {
        Some(name) => name.to_string(),
        None if s.len() > 12 => format!("{}…{}", &s[..4], &s[s.len() - 4..]),
        None => s,
    }
}

/// Render the tree as a Mermaid `flowchart TD`. Failed frames are styled
/// red; annotated (invariant-flagged) frames are highlighted.
pub fn to_mermaid(tree: &CpiTree) -> String {
    let mut s = String::from("flowchart TD\n");
    let mut counter = 0usize;
    let mut failed = Vec::new();
    let mut alert = Vec::new();

    #[allow(clippy::too_many_arguments)]
    fn walk(
        node: &CpiNode,
        parent: Option<usize>,
        s: &mut String,
        counter: &mut usize,
        failed: &mut Vec<usize>,
        alert: &mut Vec<usize>,
    ) {
        let id = *counter;
        *counter += 1;

        let mut label = program_name(&node.program);
        if let Some(ix) = &node.instruction {
            label.push_str(&format!("<br/>{}", sanitize(ix)));
        }
        if let Some(cu) = node.compute_units {
            label.push_str(&format!("<br/>{} CU", cu));
        }
        if let Some(note) = &node.note {
            label.push_str(&format!("<br/>⚠ {}", sanitize(note)));
        }
        s.push_str(&format!("  n{id}[\"{label}\"]\n"));
        if let Some(p) = parent {
            s.push_str(&format!("  n{p} --> n{id}\n"));
        }
        if node.failed {
            failed.push(id);
        }
        if node.note.is_some() {
            alert.push(id);
        }
        for c in &node.children {
            walk(c, Some(id), s, counter, failed, alert);
        }
    }

    for r in &tree.roots {
        walk(r, None, &mut s, &mut counter, &mut failed, &mut alert);
    }

    s.push_str("  classDef failed fill:#fde8e8,stroke:#c0392b,color:#7b241c;\n");
    s.push_str("  classDef alert fill:#fff3cd,stroke:#c9910d,stroke-width:3px;\n");
    let join = |ids: &[usize]| ids.iter().map(|i| format!("n{i}")).collect::<Vec<_>>().join(",");
    if !failed.is_empty() {
        s.push_str(&format!("  class {} failed;\n", join(&failed)));
    }
    if !alert.is_empty() {
        s.push_str(&format!("  class {} alert;\n", join(&alert)));
    }
    s
}

/// Render the tree as a self-contained HTML fragment: nested
/// `<div class="cpi-frame">` boxes (indent = CPI depth), each carrying
/// the program name, instruction, a `CU` badge, and `failed` / `alert`
/// classes. No inline styles and no scripts — the caller supplies CSS —
/// so it drops straight into a disclosure report or a static page.
pub fn to_html(tree: &CpiTree) -> String {
    fn walk(node: &CpiNode, s: &mut String) {
        let mut classes = String::from("cpi-frame");
        if node.failed {
            classes.push_str(" failed");
        }
        if node.note.is_some() {
            classes.push_str(" alert");
        }
        s.push_str(&format!("<div class=\"{classes}\">"));
        s.push_str(&format!(
            "<span class=\"prog\">{}</span>",
            html_escape(&program_name(&node.program))
        ));
        if let Some(ix) = &node.instruction {
            s.push_str(&format!("<span class=\"ix\">{}</span>", html_escape(ix)));
        }
        if let Some(cu) = node.compute_units {
            s.push_str(&format!("<span class=\"cu\">{cu} CU</span>"));
        }
        if let Some(note) = &node.note {
            s.push_str(&format!("<span class=\"note\">⚠ {}</span>", html_escape(note)));
        }
        for c in &node.children {
            walk(c, s);
        }
        s.push_str("</div>");
    }
    let mut s = String::from("<div class=\"cpi-tree\">");
    for r in &tree.roots {
        walk(r, &mut s);
    }
    s.push_str("</div>");
    s
}

fn html_escape(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '&' => "&amp;".chars().collect::<Vec<_>>(),
            '<' => "&lt;".chars().collect(),
            '>' => "&gt;".chars().collect(),
            '"' => "&quot;".chars().collect(),
            other => vec![other],
        })
        .collect()
}

// Mermaid node labels are wrapped in `["..."]`; keep the label from
// breaking the quoting or the diagram grammar.
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '"' => '\'',
            '[' | ']' | '{' | '}' | '|' => ' ',
            _ => c,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    const RAYDIUM: &str = "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8";
    const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

    fn swap_logs() -> Vec<String> {
        [
            &format!("Program {RAYDIUM} invoke [1]"),
            "Program log: Instruction: SwapBaseIn",
            &format!("Program {TOKEN} invoke [2]"),
            "Program log: Instruction: Transfer",
            &format!("Program {TOKEN} consumed 4645 of 200000 compute units"),
            &format!("Program {TOKEN} success"),
            &format!("Program {TOKEN} invoke [2]"),
            "Program log: Instruction: Transfer",
            &format!("Program {TOKEN} consumed 4645 of 195000 compute units"),
            &format!("Program {TOKEN} success"),
            &format!("Program {RAYDIUM} consumed 30000 of 200000 compute units"),
            &format!("Program {RAYDIUM} success"),
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    #[test]
    fn builds_nested_tree_with_ix_names_and_cu() {
        let tree = build_tree(&swap_logs());
        assert_eq!(tree.roots.len(), 1);
        let root = &tree.roots[0];
        assert_eq!(root.program, Pubkey::from_str(RAYDIUM).unwrap());
        assert_eq!(root.depth, 1);
        assert_eq!(root.instruction.as_deref(), Some("SwapBaseIn"));
        assert_eq!(root.compute_units, Some(30000));
        assert!(!root.failed);
        // Two token transfers nested under the swap.
        assert_eq!(root.children.len(), 2);
        for child in &root.children {
            assert_eq!(child.program, Pubkey::from_str(TOKEN).unwrap());
            assert_eq!(child.depth, 2);
            assert_eq!(child.instruction.as_deref(), Some("Transfer"));
            assert_eq!(child.compute_units, Some(4645));
        }
        assert_eq!(tree.frame_count(), 3);
    }

    #[test]
    fn mermaid_has_nodes_edges_and_friendly_names() {
        let m = to_mermaid(&build_tree(&swap_logs()));
        assert!(m.starts_with("flowchart TD"));
        assert!(m.contains("Raydium AMM v4"));
        assert!(m.contains("SPL Token"));
        assert!(m.contains("SwapBaseIn"));
        assert!(m.contains("30000 CU"));
        assert!(m.contains("n0 --> n1"), "parent→child edge present:\n{m}");
    }

    #[test]
    fn failed_frame_is_marked() {
        let logs: Vec<String> = [
            &format!("Program {RAYDIUM} invoke [1]"),
            "Program log: Instruction: SwapBaseIn",
            &format!("Program {RAYDIUM} failed: custom program error: 0x1"),
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let tree = build_tree(&logs);
        assert!(tree.roots[0].failed);
        let m = to_mermaid(&tree);
        assert!(m.contains("class n0 failed;"), "failed class emitted:\n{m}");
    }

    #[test]
    fn annotates_cpi_reentrancy_frame() {
        // Raydium invokes itself at depth 2 before returning — a re-entry.
        let logs: Vec<String> = [
            &format!("Program {RAYDIUM} invoke [1]"),
            "Program log: Instruction: SwapBaseIn",
            &format!("Program {RAYDIUM} invoke [2]"),
            &format!("Program {RAYDIUM} success"),
            &format!("Program {RAYDIUM} success"),
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let tree = build_annotated_tree(&logs);
        // The inner (depth-2) Raydium frame carries the re-entry note.
        let inner = &tree.roots[0].children[0];
        assert_eq!(inner.depth, 2);
        assert!(inner.note.as_deref().unwrap().contains("re-entered"));
        let m = to_mermaid(&tree);
        assert!(m.contains("⚠"), "alert glyph present:\n{m}");
        assert!(m.contains("alert;"), "alert class emitted");
    }

    #[test]
    fn html_nests_frames_and_flags_alerts() {
        let logs: Vec<String> = [
            &format!("Program {RAYDIUM} invoke [1]"),
            "Program log: Instruction: SwapBaseIn",
            &format!("Program {RAYDIUM} invoke [2]"),
            &format!("Program {RAYDIUM} success"),
            &format!("Program {RAYDIUM} success"),
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let html = to_html(&build_annotated_tree(&logs));
        assert!(html.contains("class=\"cpi-tree\""));
        assert!(html.contains("Raydium AMM v4"));
        assert!(html.contains("cpi-frame alert"), "re-entered frame flagged:\n{html}");
        assert!(html.contains("SwapBaseIn"));
    }

    #[test]
    fn build_is_fail_soft_on_garbage() {
        let logs = vec![
            "not a program line".to_string(),
            "Program log: hello".to_string(),
            "Program badpubkey invoke [1]".to_string(), // unparseable pid → skipped
            "".to_string(),
        ];
        // No panic; nothing parses into a frame.
        assert_eq!(build_tree(&logs).frame_count(), 0);
    }
}
