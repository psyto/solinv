//! `--format json`: `solinv diff` and `solinv check` for a program to read
//! (an AI agent after an edit, a CI script).
//!
//! The shape is fixed by `schema_version`. A field or a `check` value may
//! be added within a version; renaming or removing one, or changing what
//! one means, is a new version.

use crate::diff::{Change, Check, Severity};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;

pub const SCHEMA_VERSION: u32 = 1;

/// One pair of sources compared (`check`: one source read, `base` null).
pub struct Compared {
    pub base: Option<String>,
    pub head: String,
    /// `anchor`, `native` or `idl`.
    pub mode: &'static str,
    /// Why it was not compared (a program new since the base), or `None`.
    pub note: Option<&'static str>,
}

/// The report. `relabel` turns a path as read (a temporary checkout, say)
/// into the one to show.
pub fn report(command: &str, compared: &[Compared], changes: &[Change], relabel: &dyn Fn(&str) -> String) -> Value {
    let mut files = Files::default();
    let status = |c: &Change| match (c.severity, c.widened) {
        (Severity::Warning, _) => "warning",
        (Severity::Regression, true) => "widened",
        (Severity::Regression, false) => "removed",
    };
    let count = |s: &str| changes.iter().filter(|c| status(c) == s).count();
    let findings: Vec<Value> = changes
        .iter()
        .map(|c| {
            let at = |file: &str, line: usize, text: Option<String>| {
                json!({ "file": relabel(file), "line": line, "text": text })
            };
            let before = c.before.as_ref().filter(|(f, _)| !f.is_empty()).map(|(f, l)| {
                let text = match c.check {
                    // The check as written, not the handler's or fn's first line.
                    Check::Handler => files.find(f, *l, &quoted(&c.message)),
                    // Written on `self`; named in the message by the slot's
                    // path in a composite (`common.bank`).
                    Check::Validate => {
                        let outer = c.path.rfind('.').map_or("", |i| &c.path[..=i]);
                        files.find(f, *l, &quoted(&c.message).replace(outer, ""))
                    }
                    _ if native(c.check) => files.find(f, *l, &condition(&quoted(&c.message))),
                    Check::Instruction => files.line(f, *l),
                    _ => files.declaration(f, *l),
                };
                match text {
                    Some((line, text)) => at(f, line, Some(text)),
                    None => at(f, *l, None),
                }
            });
            // The slot as it now reads; a handler's or a program's finding
            // is pointed at by `file`/`line` alone.
            let after = (!c.file.is_empty()
                && !c.path.is_empty()
                && !matches!(c.check, Check::Slot | Check::Handler | Check::Validate)
                && !native(c.check))
                .then(|| files.declaration(&c.file, c.line).map(|(l, t)| at(&c.file, l, Some(t))))
                .flatten();
            json!({
                "status": status(c),
                "check": c.check.as_str(),
                "instruction": (!c.ix.is_empty()).then_some(&c.ix),
                "account": (!c.path.is_empty()).then_some(&c.path),
                "file": (!c.file.is_empty()).then(|| relabel(&c.file)),
                "line": (!c.file.is_empty()).then_some(c.line),
                "message": c.message,
                "before": before,
                "after": after,
            })
        })
        .collect();
    json!({
        "schema_version": SCHEMA_VERSION,
        "solinv_version": env!("CARGO_PKG_VERSION"),
        "command": command,
        "compared": compared.iter().map(|c| json!({ "base": c.base, "head": c.head, "mode": c.mode, "note": c.note })).collect::<Vec<_>>(),
        "summary": { "removed": count("removed"), "widened": count("widened"), "warning": count("warning") },
        "findings": findings,
    })
}

/// What could not be compared, in the same envelope.
pub fn error(command: &str, message: &str) -> Value {
    json!({
        "schema_version": SCHEMA_VERSION,
        "solinv_version": env!("CARGO_PKG_VERSION"),
        "command": command,
        "error": { "message": message },
    })
}

/// Lines with the indent they share removed.
fn dedent(lines: &[String]) -> String {
    let indent = lines
        .iter()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.len() - l.trim_start().len())
        .min()
        .unwrap_or(0);
    lines.iter().map(|l| l.get(indent..).unwrap_or(l.trim_start()).trim_end()).collect::<Vec<_>>().join("\n")
}

fn native(c: Check) -> bool {
    matches!(
        c,
        Check::NativeSigner | Check::NativeOwner | Check::NativeKey | Check::NativeWritable | Check::NativeExecutable
    )
}

/// What to look for of a native check: `if !a.is_signer()` of
/// `if !a.is_signer() { return Err(..) }`, `check(a)` of `check(a)?`.
fn condition(quoted: &str) -> String {
    quoted.split(" {").next().unwrap_or(quoted).trim_end_matches('?').to_string()
}

/// The first `` `..` `` in a message: the check a handler finding names.
fn quoted(message: &str) -> String {
    message.split('`').nth(1).unwrap_or_default().to_string()
}

#[derive(Default)]
struct Files(HashMap<String, Option<Vec<String>>>);

impl Files {
    fn lines(&mut self, file: &str) -> Option<&Vec<String>> {
        self.0
            .entry(file.to_string())
            .or_insert_with(|| fs::read_to_string(file).ok().map(|s| s.lines().map(str::to_string).collect()))
            .as_ref()
    }

    fn line(&mut self, file: &str, line: usize) -> Option<(usize, String)> {
        let l = self.lines(file)?.get(line.checked_sub(1)?)?;
        Some((line, l.trim().to_string()))
    }

    /// A field with the attributes and doc comments above it: from the
    /// first of them down to `line`.
    fn declaration(&mut self, file: &str, line: usize) -> Option<(usize, String)> {
        let lines = self.lines(file)?;
        let end = line.checked_sub(1)?;
        lines.get(end)?;
        let mut start = end;
        // Brackets closed below and not yet opened, reading upwards: inside
        // a multi-line `#[account(..)]`.
        let mut depth = 0i32;
        while start > 0 && end - start < 40 {
            let t = lines[start - 1].trim();
            let net = t.matches([')', ']']).count() as i32 - t.matches(['(', '[']).count() as i32;
            if depth == 0 && net <= 0 && !t.starts_with("#[") && !t.starts_with("//") {
                break;
            }
            depth += net;
            start -= 1;
        }
        Some((start + 1, dedent(&lines[start..=end])))
    }

    /// Where `check` is written, from line `from` on and then anywhere in
    /// the file, as solinv reads it: spaces, `ctx.accounts.` and `self.` ignored, a
    /// call matched up to its last argument. The statement's lines, up to
    /// its `;` (30 at most); line `from` when not found.
    fn find(&mut self, file: &str, from: usize, check: &str) -> Option<(usize, String)> {
        let squash = |s: &str| {
            s.chars().filter(|c| !c.is_whitespace()).collect::<String>().replace("ctx.accounts.", "").replace("self.", "")
        };
        let mut want = squash(check);
        // `require!(a.ok)` is `require!(a.ok, E::No);` in the source.
        if want.ends_with(')') && want.contains('(') {
            want.pop();
        }
        let want: String = want.chars().take(60).collect();
        let head: String = want.chars().take_while(|c| *c != '(').chain(['(']).collect();
        if want.is_empty() {
            return self.line(file, from);
        }
        let lines = self.lines(file)?;
        // A statement over up to 30 lines, blank ones not counted.
        let window = |i: usize| lines[i..lines.len().min(i + 30)].join("");
        let starts = (from.saturating_sub(1)..lines.len()).chain(0..from.saturating_sub(1));
        let at = starts.into_iter().find(|&i| {
            let first = squash(&lines[i]);
            (first.contains(&want) || first.contains(&head) && want.contains('('))
                && squash(&window(i)).contains(&want)
        });
        let Some(i) = at else { return self.line(file, from) };
        let end = (i..lines.len().min(i + 30)).find(|&j| lines[j].trim_end().ends_with(';')).unwrap_or(i);
        Some((i + 1, dedent(&lines[i..=end])))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str, src: &str) -> String {
        let p = std::env::temp_dir().join(format!("solinv-json-{}-{name}", std::process::id()));
        fs::write(&p, src).unwrap();
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn declaration_takes_a_multiline_attribute_and_stops_at_the_field_above() {
        let f = tmp(
            "decl.rs",
            "pub struct W<'info> {\n    #[account(mut)]\n    pub depositor: Signer<'info>,\n    /// the vault\n    #[account(\n        mut,\n        has_one = depositor,\n    )]\n    pub vault: Account<'info, Vault>,\n}\n",
        );
        let (line, text) = Files::default().declaration(&f, 9).unwrap();
        assert_eq!(line, 4);
        assert_eq!(text, "/// the vault\n#[account(\n    mut,\n    has_one = depositor,\n)]\npub vault: Account<'info, Vault>,");
        let (line, text) = Files::default().declaration(&f, 3).unwrap();
        assert_eq!((line, text.as_str()), (2, "#[account(mut)]\npub depositor: Signer<'info>,"));
    }

    #[test]
    fn handler_check_is_found_by_its_text() {
        let f = tmp("h.rs", "pub fn go(ctx: Context<Go>) -> Result<()> {\n    require!(ctx.accounts.a.ok,   E::No);\n    Ok(())\n}\n");
        let got = Files::default().find(&f, 1, "require!(a.ok)");
        assert_eq!(got, Some((2, "require!(ctx.accounts.a.ok,   E::No);".to_string())));
        let f = tmp(
            "h2.rs",
            "fn helper() {}\npub fn go(ctx: Context<Go>) -> Result<()> {\n    require_keys_eq!(\n        ctx.accounts.admin.key(),\n        ctx.accounts.config.admin,\n        E::No\n    );\n    Ok(())\n}\n",
        );
        let got = Files::default().find(&f, 2, "require_keys_eq!(admin.key(),config.admin)").unwrap();
        assert_eq!(got.0, 3);
        assert!(got.1.starts_with("require_keys_eq!(\n    ctx.accounts.admin.key(),") && got.1.ends_with(");"), "{got:?}");
    }

    #[test]
    fn a_validate_finding_quotes_the_assertion() {
        let base = crate::source::tests::VALIDATED;
        let line = "        assert_keys_eq!(self.bank.crate_mint, self.crate_mint, \"mint\");\n";
        let (b, h) = (tmp("v-base.rs", base), tmp("v-head.rs", &base.replace(line, "")));
        let read = |f: &str| crate::source::SourceKinds::parse_files(&[(f.to_string(), fs::read_to_string(f).unwrap())]);
        let changes = crate::diff::diff(&read(&b), &read(&h));
        let v = report("diff", &[], &changes, &|f| f.to_string());
        assert_eq!(v["findings"][0]["check"], "validate");
        assert_eq!(v["findings"][0]["before"]["text"], line.trim());
        assert_eq!(v["findings"][0]["after"], Value::Null);
    }

    #[test]
    fn status_splits_widened_from_removed() {
        let c = |severity, widened| Change {
            severity,
            ix: "a".into(),
            path: String::new(),
            message: "m".into(),
            file: String::new(),
            line: 0,
            check: Check::Constraint,
            widened,
            before: None,
        };
        let v = report(
            "diff",
            &[],
            &[c(Severity::Regression, true), c(Severity::Regression, false), c(Severity::Warning, false)],
            &|f| f.to_string(),
        );
        assert_eq!(v["summary"], json!({ "removed": 1, "widened": 1, "warning": 1 }));
        assert_eq!(v["findings"][0]["status"], "widened");
        assert_eq!(v["findings"][0]["account"], Value::Null);
        assert_eq!(v["findings"][0]["file"], Value::Null);
    }
}
