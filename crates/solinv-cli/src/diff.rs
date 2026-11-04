//! `solinv diff`: the account checks a change removes.
//!
//! An audited program is mostly clean; what breaks it later is a pull
//! request that drops a check — an `Account<'info, Vault>` loosened to
//! `UncheckedAccount` to make a test pass, a `Signer` turned into a plain
//! account, a `has_one` or `seeds` constraint deleted with a refactor.
//! Anchor enforces the declaration, so when the declaration goes, so does
//! the check, silently. This compares two versions of the source slot by
//! slot and names every check that is gone.
//!
//! Source only: no build, no IDL, no toolchain, so it runs on any CI
//! runner. It reads what the source declares; a check moved into the
//! handler body (`require_keys_eq!`) reads as removed, which is the
//! right default for a reviewer to look at.

use crate::source::{Slot, SourceKinds};
use solinv_fuzz::SlotKind;
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// A check the base version declared is gone.
    Regression,
    /// New code with the shape of a missing check.
    Warning,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    pub severity: Severity,
    pub ix: String,
    pub path: String,
    pub message: String,
    /// Where to point a reviewer: the slot in the head version.
    pub file: String,
    pub line: usize,
}

pub fn diff(base: &SourceKinds, head: &SourceKinds) -> Vec<Change> {
    let mut out = Vec::new();
    for ((ix, path), b) in base.slots() {
        let Some(h) = head.slot(ix, path) else { continue };
        let mut push = |message: String| {
            out.push(Change {
                severity: Severity::Regression,
                ix: ix.clone(),
                path: path.clone(),
                message,
                file: h.file.clone(),
                line: h.line,
            })
        };
        // A Signer loosened is reported as the signature it loses, below.
        if b.kind == Some(SlotKind::Typed) && h.kind == Some(SlotKind::Unchecked) && b.ty != "Signer" {
            push(format!(
                "was {}, now {}: Anchor no longer checks its owner and type",
                b.ty, h.ty
            ));
        }
        if signs(b) && !signs(h) {
            push(format!("was {}, now {}: no longer required to sign", label(b), label(h)));
        }
        let (ba, ha) = (&b.attrs, &h.attrs);
        if ba.seeds && !ha.seeds {
            push("`seeds` constraint removed: any address is accepted".into());
        }
        if ba.address && !ha.address {
            push("`address` constraint removed".into());
        }
        if ba.owner && !ha.owner {
            push("`owner` constraint removed".into());
        }
        for target in &ba.has_one {
            if !ha.has_one.contains(target) {
                push(format!("`has_one = {target}` removed: it no longer has to match `{target}`"));
            }
        }
        if ha.constraints < ba.constraints {
            push(format!(
                "{} of its `constraint = …` checks removed",
                ba.constraints - ha.constraints
            ));
        }
    }

    // New instructions with the shape of a missing authority check.
    let base_ixs: BTreeSet<&str> = base.slots().iter().map(|((ix, _), _)| ix.as_str()).collect();
    let head_slots = head.slots();
    let head_ixs: BTreeSet<&str> = head_slots.iter().map(|((ix, _), _)| ix.as_str()).collect();
    for ix in head_ixs.difference(&base_ixs) {
        let slots: Vec<&(&(String, String), &Slot)> =
            head_slots.iter().filter(|((i, _), _)| i == ix).collect();
        let signed = slots.iter().any(|(_, s)| signs(s));
        let written = slots.iter().find(|(_, s)| s.attrs.mutable);
        if let (false, Some(((_, path), s))) = (signed, written) {
            out.push(Change {
                severity: Severity::Warning,
                ix: ix.to_string(),
                path: path.clone(),
                message: "new instruction with no signer writes this account: \
                          permissionless by design, or a missing authority check?"
                    .into(),
                file: s.file.clone(),
                line: s.line,
            });
        }
    }
    out.sort_by(|a, b| (a.severity, &a.ix, &a.path).cmp(&(b.severity, &b.ix, &b.path)));
    out
}

fn signs(s: &Slot) -> bool {
    s.ty == "Signer" || s.attrs.signer
}

fn label(s: &Slot) -> String {
    if s.ty == "Signer" || !s.attrs.signer {
        s.ty.clone()
    } else {
        format!("{} with #[account(signer)]", s.ty)
    }
}

pub fn render_text(changes: &[Change]) -> String {
    let regressions = changes.iter().filter(|c| c.severity == Severity::Regression).count();
    let warnings = changes.len() - regressions;
    let mut out = format!(
        "solinv diff: {regressions} removed check(s), {warnings} warning(s)\n"
    );
    for c in changes {
        let tag = match c.severity {
            Severity::Regression => "REMOVED",
            Severity::Warning => "WARNING",
        };
        out += &format!("{tag} {}.{} ({}:{}): {}\n", c.ix, c.path, c.file, c.line, c.message);
    }
    out
}

/// GitHub Actions workflow commands: each change becomes an annotation on
/// the line that declares the slot.
pub fn render_github(changes: &[Change]) -> String {
    let mut out = String::new();
    for c in changes {
        let level = match c.severity {
            Severity::Regression => "error",
            Severity::Warning => "warning",
        };
        out += &format!(
            "::{level} file={},line={},title=solinv: {}.{}::{}\n",
            c.file,
            c.line,
            c.ix,
            c.path,
            escape(&c.message)
        );
    }
    out
}

fn escape(s: &str) -> String {
    s.replace('%', "%25").replace('\r', "%0D").replace('\n', "%0A")
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {}
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(
        mut,
        seeds = [b"vault", depositor.key().as_ref()],
        bump,
        has_one = depositor,
        constraint = vault.amount > 0 @ E::Empty,
    )]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub depositor: Signer<'info>,
}
"#;

    fn kinds(src: &str) -> SourceKinds {
        SourceKinds::parse_files(&[("programs/x/src/lib.rs".into(), src.into())])
    }

    #[test]
    fn identical_sources_report_nothing() {
        assert!(diff(&kinds(BASE), &kinds(BASE)).is_empty());
    }

    #[test]
    fn each_removed_check_is_named_at_its_line() {
        let head = BASE
            .replace("pub vault: Account<'info, Vault>", "pub vault: UncheckedAccount<'info>")
            .replace("pub depositor: Signer<'info>", "pub depositor: AccountInfo<'info>")
            .replace("        has_one = depositor,\n", "")
            .replace("        constraint = vault.amount > 0 @ E::Empty,\n", "");
        let changes = diff(&kinds(BASE), &kinds(&head));
        let msgs: Vec<_> = changes.iter().map(|c| (c.path.as_str(), c.message.as_str())).collect();
        assert_eq!(
            msgs,
            vec![
                ("depositor", "was Signer, now AccountInfo: no longer required to sign"),
                ("vault", "was Account, now UncheckedAccount: Anchor no longer checks its owner and type"),
                ("vault", "`has_one = depositor` removed: it no longer has to match `depositor`"),
                ("vault", "1 of its `constraint = …` checks removed"),
            ]
        );
        let vault = changes.iter().find(|c| c.path == "vault").unwrap();
        // Lines in the head version: the two removed attribute lines
        // move `vault` up to 10 and `depositor` to 12.
        assert_eq!((vault.file.as_str(), vault.line), ("programs/x/src/lib.rs", 10));
        assert_eq!(head.lines().nth(9).unwrap().trim(), "pub vault: UncheckedAccount<'info>,");
        assert!(render_github(&changes)
            .starts_with("::error file=programs/x/src/lib.rs,line=12,title=solinv: withdraw.depositor::"));
    }

    #[test]
    fn removed_seeds_and_new_unsigned_writer() {
        let head = BASE.replace(
            "        seeds = [b\"vault\", depositor.key().as_ref()],\n        bump,\n",
            "",
        ) + r#"
pub fn sweep(ctx: Context<Sweep>) -> Result<()> {}
#[derive(Accounts)]
pub struct Sweep<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
}
"#;
        let changes = diff(&kinds(BASE), &kinds(&head));
        assert_eq!(changes[0].message, "`seeds` constraint removed: any address is accepted");
        assert_eq!(changes[1].severity, Severity::Warning);
        assert_eq!((changes[1].ix.as_str(), changes[1].path.as_str()), ("sweep", "vault"));
    }
}
