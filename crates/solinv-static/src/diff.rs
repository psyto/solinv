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
use crate::idl::SlotKind;
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
    let head_slots = head.slots();
    let in_ix = |ix: &str| -> Vec<(&String, &Slot)> {
        head_slots.iter().filter(|((i, _), _)| i == ix).map(|((_, p), s)| (p, *s)).collect()
    };

    for ((ix, path), b) in base.slots() {
        let siblings = in_ix(ix);
        let Some(h) = head.slot(ix, path) else {
            // The instruction is still there but this slot is not: renamed
            // or removed. Its checks cannot be compared, so say which.
            let checks = checks_of(b);
            if let (Some((_, any)), false) = (siblings.first(), checks.is_empty()) {
                out.push(Change {
                    severity: Severity::Warning,
                    ix: ix.clone(),
                    path: path.clone(),
                    message: format!(
                        "slot removed or renamed; its checks ({}) are not compared — \
                         confirm the replacement keeps them",
                        checks.join(", ")
                    ),
                    file: any.file.clone(),
                    line: any.line,
                });
            }
            continue;
        };
        let mut push = |severity: Severity, message: String| {
            out.push(Change {
                severity,
                ix: ix.clone(),
                path: path.clone(),
                message,
                file: h.file.clone(),
                line: h.line,
            })
        };
        // A Signer loosened is reported as the signature it loses, below.
        if b.kind == Some(SlotKind::Typed) && h.kind == Some(SlotKind::Unchecked) && b.ty != "Signer" {
            push(
                Severity::Regression,
                format!("was {}, now {}: Anchor no longer checks its owner and type", b.ty, h.ty),
            );
        } else if b.kind == Some(SlotKind::Typed)
            && h.kind == Some(SlotKind::Typed)
            && b.full_ty != h.full_ty
        {
            push(
                Severity::Warning,
                format!(
                    "type changed from {} to {}: confirm it still validates what the old one did",
                    b.full_ty, h.full_ty
                ),
            );
        }
        if !b.optional && h.optional {
            push(Severity::Warning, "now optional: the instruction runs without it".into());
        }
        if signs(b) && !signs(h) {
            push(
                Severity::Regression,
                format!("was {}, now {}: no longer required to sign", label(b), label(h)),
            );
        }
        let (ba, ha) = (&b.attrs, &h.attrs);
        if ba.seeds && !ha.seeds {
            push(Severity::Regression, "`seeds` constraint removed: any address is accepted".into());
        }
        if ba.address && !ha.address {
            push(Severity::Regression, "`address` constraint removed".into());
        }
        if ba.owner && !ha.owner {
            push(Severity::Regression, "`owner` constraint removed".into());
        }
        for target in ba.has_one.iter().filter(|t| !ha.has_one.contains(t)) {
            match siblings.iter().find(|(_, s)| s.attrs.has_one.contains(target)) {
                Some((other, _)) => push(
                    Severity::Warning,
                    format!("`has_one = {target}` moved to `{other}`: confirm it checks the same account"),
                ),
                None => push(
                    Severity::Regression,
                    format!("`has_one = {target}` removed: it no longer has to match `{target}`"),
                ),
            }
        }
        for expr in ba.constraints.iter().filter(|e| !ha.constraints.contains(e)) {
            match siblings.iter().find(|(_, s)| s.attrs.constraints.contains(expr)) {
                Some((other, _)) => push(
                    Severity::Warning,
                    format!("`constraint = {expr}` moved to `{other}`"),
                ),
                None => push(Severity::Regression, format!("`constraint = {expr}` removed")),
            }
        }
        for check in ba.validate.iter().filter(|e| !ha.validate.contains(e)) {
            match siblings.iter().find(|(_, s)| s.attrs.validate.contains(check)) {
                Some((other, _)) => push(
                    Severity::Warning,
                    format!("`{check}` in validate() moved to `{other}`"),
                ),
                None => push(Severity::Regression, format!("`{check}` removed from validate()")),
            }
        }
    }

    // New instructions with the shape of a missing authority check.
    let base_ixs: BTreeSet<&str> = base.slots().iter().map(|((ix, _), _)| ix.as_str()).collect();
    let head_ixs: BTreeSet<&str> = head_slots.iter().map(|((ix, _), _)| ix.as_str()).collect();
    for ix in head_ixs.difference(&base_ixs) {
        let slots = in_ix(ix);
        let signed = slots.iter().any(|(_, s)| signs(s));
        let written = slots.iter().find(|(_, s)| s.attrs.mutable);
        if let (false, Some((path, s))) = (signed, written) {
            out.push(Change {
                severity: Severity::Warning,
                ix: ix.to_string(),
                path: path.to_string(),
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

/// What a slot checks, for naming what a removed slot took with it.
fn checks_of(s: &Slot) -> Vec<String> {
    let mut c = Vec::new();
    if s.kind == Some(SlotKind::Typed) && s.ty != "Signer" {
        c.push(format!("type {}", s.full_ty));
    }
    if signs(s) {
        c.push("signer".into());
    }
    let a = &s.attrs;
    for (on, name) in [(a.seeds, "seeds"), (a.address, "address"), (a.owner, "owner")] {
        if on {
            c.push(name.into());
        }
    }
    c.extend(a.has_one.iter().map(|t| format!("has_one = {t}")));
    c.extend(a.constraints.iter().map(|e| format!("constraint = {e}")));
    c.extend(a.validate.iter().cloned());
    c
}

/// Required to sign: an `Option<Signer>` may be left out, so it does not.
fn signs(s: &Slot) -> bool {
    (s.ty == "Signer" || s.attrs.signer) && !s.optional
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
        let at = if c.file.is_empty() { String::new() } else { format!(" ({}:{})", c.file, c.line) };
        out += &format!("{tag} {}{at}: {}\n", c.slot(), c.message);
    }
    out
}

impl Change {
    /// `ix.path`, or `ix` for a change to the instruction as a whole.
    pub fn slot(&self) -> String {
        if self.path.is_empty() {
            self.ix.clone()
        } else {
            format!("{}.{}", self.ix, self.path)
        }
    }

    /// `{severity, ix, path, message, file, line}`; `file` is `""` and
    /// `line` 0 for a change read from an IDL.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "severity": match self.severity {
                Severity::Regression => "regression",
                Severity::Warning => "warning",
            },
            "ix": self.ix,
            "path": self.path,
            "message": self.message,
            "file": self.file,
            "line": self.line,
        })
    }
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
        // A change read from an IDL has no line to point at.
        let at = if c.file.is_empty() {
            String::new()
        } else {
            format!("file={},line={},", escape_property(&c.file), c.line)
        };
        out += &format!(
            "::{level} {at}title={}::{}\n",
            escape_property(&format!("solinv: {}", c.slot())),
            escape(&c.message)
        );
    }
    out
}

fn escape(s: &str) -> String {
    s.replace('%', "%25").replace('\r', "%0D").replace('\n', "%0A")
}

/// Workflow-command properties also reserve `:` and `,`.
fn escape_property(s: &str) -> String {
    escape(s).replace(':', "%3A").replace(',', "%2C")
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
                ("vault", "`constraint = vault.amount > 0` removed"),
            ]
        );
        let vault = changes.iter().find(|c| c.path == "vault").unwrap();
        // Lines in the head version: the two removed attribute lines
        // move `vault` up to 10 and `depositor` to 12.
        assert_eq!((vault.file.as_str(), vault.line), ("programs/x/src/lib.rs", 10));
        assert_eq!(head.lines().nth(9).unwrap().trim(), "pub vault: UncheckedAccount<'info>,");
        assert!(render_github(&changes)
            .starts_with("::error file=programs/x/src/lib.rs,line=12,title=solinv%3A withdraw.depositor::"));
    }

    /// Codex r10: each of these used to pass silently or misfire.
    #[test]
    fn renamed_slots_type_swaps_swapped_constraints_and_moved_checks() {
        let base = r#"
pub fn act(ctx: Context<Act>) -> Result<()> {}
#[derive(Accounts)]
pub struct Act<'info> {
    #[account(
        constraint = vault.authority == authority.key(),
        constraint = vault.amount >= 1,
        has_one = config,
    )]
    pub vault: Account<'info, Vault>,
    #[account(signer)]
    pub authority: Account<'info, Config>,
    #[account(has_one = admin)]
    pub config: Account<'info, Config>,
    pub old: Account<'info, Pool>,
}
"#;
        let head = r#"
pub fn act(ctx: Context<Act>) -> Result<()> {}
#[derive(Accounts)]
pub struct Act<'info> {
    #[account(
        constraint = vault.amount >= 1,
        constraint = vault.amount <= 9,
    )]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
    #[account(has_one = admin, has_one = config)]
    pub config: Account<'info, Config>,
    pub renamed: UncheckedAccount<'info>,
}
"#;
        let changes = diff(&kinds(base), &kinds(head));
        let got: Vec<(Severity, &str, &str)> =
            changes.iter().map(|c| (c.severity, c.path.as_str(), c.message.as_str())).collect();
        assert!(got.contains(&(
            Severity::Regression,
            "vault",
            "`constraint = vault.authority == authority.key()` removed"
        )));
        assert!(got.iter().any(|(s, p, m)| *s == Severity::Warning
            && *p == "authority"
            && m.starts_with("type changed from Account<'info,Config> to Signer<'info>")));
        assert!(got.contains(&(
            Severity::Warning,
            "vault",
            "`has_one = config` moved to `config`: confirm it checks the same account"
        )));
        assert!(got.iter().any(|(s, p, m)| *s == Severity::Warning
            && *p == "old"
            && m.contains("type Account<'info,Pool>")));
        // Signer type still signs: no signer regression.
        assert!(!got.iter().any(|(_, p, m)| *p == "authority" && m.contains("sign")));
    }

    #[test]
    fn reformatting_and_error_codes_are_not_changes() {
        let head = BASE.replace(
            "constraint = vault.amount > 0 @ E::Empty,",
            "constraint = vault.amount\n            > 0 @ E::NewName,",
        );
        assert!(diff(&kinds(BASE), &kinds(&head)).is_empty());
    }

    #[test]
    fn changed_literal_in_a_constraint_and_an_optional_signer() {
        let base = BASE.replace("vault.amount > 0", "vault.role == \"admin\"");
        let head = BASE.replace("vault.amount > 0", "vault.role == \"attacker\"");
        let changes = diff(&kinds(&base), &kinds(&head));
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].message, "`constraint = vault.role == \"admin\"` removed");

        let new_ix = BASE.to_string()
            + r#"
pub fn sweep(ctx: Context<Sweep>) -> Result<()> {}
#[derive(Accounts)]
pub struct Sweep<'info> {
    pub admin: Option<Signer<'info>>,
    #[account(mut)]
    pub vault: Account<'info, Vault>,
}
"#;
        let changes = diff(&kinds(BASE), &kinds(&new_ix));
        assert!(changes.iter().any(|c| c.ix == "sweep" && c.severity == Severity::Warning));
    }

    #[test]
    fn annotation_properties_are_escaped() {
        let c = Change {
            severity: Severity::Regression,
            ix: "a".into(),
            path: "b".into(),
            message: "m".into(),
            file: "dir,x/f%:.rs".into(),
            line: 1,
        };
        assert_eq!(render_github(&[c]), "::error file=dir%2Cx/f%25%3A.rs,line=1,title=solinv%3A a.b::m\n");
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

    #[test]
    fn a_line_removed_from_validate_is_a_removed_check() {
        let base = crate::source::tests::VALIDATED;
        let head = base.replace("        assert_keys_eq!(self.bank.crate_mint, self.crate_mint, \"mint\");\n", "");
        let changes = diff(&kinds(base), &kinds(&head));
        let msgs: Vec<_> = changes.iter().map(|c| (c.severity, c.ix.as_str(), c.path.as_str(), c.message.as_str())).collect();
        assert_eq!(
            msgs,
            vec![(
                Severity::Regression,
                "print",
                "common.bank",
                "`assert_keys_eq!(common.bank.crate_mint, common.crate_mint)` removed from validate()"
            )]
        );
        // Swapping the arguments is not a change; dropping the
        // `#[access_control]` removes every check it ran.
        let swapped = base.replace("assert_keys_eq![&self.depositor, self.source.owner.key()]", "assert_keys_eq!(self.source.owner, self.depositor)");
        assert!(diff(&kinds(base), &kinds(&swapped)).is_empty());
        // The program's wrapper and the action it calls share a name and
        // a context; the order the files are read in changes nothing.
        let action = "pub fn print(ctx: Context<Print>, amount: u64) -> Result<()> {}\n";
        let wrapper = "pub mod p {\n#[access_control(ctx.accounts.validate())]\npub fn print(ctx: Context<Print>, amount: u64) -> Result<()> {}\n}\n";
        let rest = base.replace("#[access_control(ctx.accounts.validate())]\npub fn print(ctx: Context<Print>, amount: u64) -> Result<()> {}\n", "");
        let files = |a: &str, b: &str| {
            SourceKinds::parse_files(&[(a.into(), wrapper.to_string()), (b.into(), format!("{action}{rest}"))])
        };
        for (w, a) in [("lib.rs", "actions.rs"), ("lib.rs", "a.rs"), ("a.rs", "lib.rs")] {
            let k = files(w, a);
            assert!(!k.unbound("print", "common.bank"), "{w} {a}");
            assert!(diff(&kinds(base), &k).is_empty(), "{w} {a}");
        }
        let unrun = base.replace("#[access_control(ctx.accounts.validate())]\n", "");
        let removed = diff(&kinds(base), &kinds(&unrun));
        assert_eq!(removed.iter().filter(|c| c.severity == Severity::Regression).count(), 5);
    }
}
