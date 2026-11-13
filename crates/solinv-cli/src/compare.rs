//! What `solinv diff` and `solinv check` read, shared by the CLI and the
//! MCP server.

use anyhow::{bail, Result};
use solinv_static::diff::{self, Change, Check, Severity};
use solinv_static::native::{self, NativeChecks};
use solinv_static::{lint, source::SourceKinds};
use std::path::Path;

pub struct Diffed {
    pub changes: Vec<Change>,
    /// `anchor` or `native`.
    pub mode: &'static str,
    /// The base has account structs and the head none: every check gone.
    pub all_gone: Option<String>,
}

pub fn diff_src(base_src: &Path, head_src: &Path) -> Result<Diffed> {
    // Program-wide findings the head adds (a hook `execute` that stops
    // being reachable, a signature without a bump).
    let lint_changes = lint::diff(&lint::read(base_src)?, &lint::read(head_src)?);
    let base = SourceKinds::read(base_src)?;
    let head = SourceKinds::read(head_src)?;
    let (mut changes, mode, all_gone) = if base.is_empty() {
        // A native or Pinocchio program: the checks in its code.
        let nb = NativeChecks::read(base_src)?;
        // A program with an entrypoint whose checks are not read here (in
        // another crate, say) compares as empty.
        if nb.is_empty() && !nb.has_entrypoint() {
            bail!(
                "no #[derive(Accounts)] field under {} could be matched to an instruction, and no \
                 account check (`if !a.is_signer()`, `if a.owner() != ..`, `if a.key() != ..` \
                 returning Err) was found in its code",
                base_src.display()
            );
        }
        let nh = NativeChecks::read(head_src)?;
        (native::diff(&nb, &nh), "native", None)
    } else {
        // Every account struct gone: every check with it, which the
        // per-instruction comparison would only warn about.
        let all_gone = head.is_empty().then(|| {
            format!(
                "{} has account structs, {} has none: every account check is gone",
                base_src.display(),
                head_src.display()
            )
        });
        (diff::diff(&base, &head), "anchor", all_gone)
    };
    changes.extend(lint_changes);
    Ok(Diffed { changes, mode, all_gone })
}

/// A whole program's checks gone, as one removal.
pub fn program_gone(message: String, file: String) -> Change {
    Change {
        severity: Severity::Regression,
        ix: String::new(),
        path: String::new(),
        message,
        file,
        line: 0,
        check: Check::Program,
        widened: false,
        before: None,
    }
}

/// One version's program-wide findings, as `solinv diff` reports them
/// when the head adds them.
pub fn check_src(src: &Path) -> Result<(Vec<Change>, &'static str)> {
    let findings = lint::read(src)?;
    let mode = if !SourceKinds::read(src)?.is_empty() {
        "anchor"
    } else if NativeChecks::read(src)?.has_entrypoint() {
        "native"
    } else {
        bail!(
            "no #[derive(Accounts)] field under {} could be matched to an instruction, and no native \
             entrypoint was found",
            src.display()
        );
    };
    Ok((lint::diff(&[], &findings), mode))
}

pub fn render_check_text(changes: &[Change]) -> String {
    let mut out = format!("solinv check: {} finding(s)\n", changes.len());
    for c in changes {
        out += &format!("  {}:{} in `{}`: {}\n", c.file, c.line, c.ix, c.message);
    }
    out
}
