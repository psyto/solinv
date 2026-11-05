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
//! runner. It reads what the source declares, and the checks at the top
//! level of each handler body; a declared check moved into the handler
//! reads as removed, which is the right default for a reviewer to look at.

use crate::source::{clauses, Slot, SourceKinds};
use crate::idl::SlotKind;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

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
    let base_ixs: BTreeSet<String> = base.slots().iter().map(|((ix, _), _)| ix.clone()).collect();
    let head_ixs: BTreeSet<String> = head_slots.iter().map(|((ix, _), _)| ix.clone()).collect();

    // Each base instruction's name in the head version: its own, or — for
    // one that is gone — the new instruction whose slots it shares most,
    // so a rename that also drops a check is still compared (#9). Slots
    // every instruction has (programs, sysvars, `authority`, `payer`) do
    // not count towards the match. Pairs are taken best first; a score
    // two pairs share for one instruction is ambiguous and pairs neither.
    let mut renamed: BTreeMap<String, String> = BTreeMap::new();
    let gone: Vec<&String> = base_ixs.difference(&head_ixs).collect();
    let new: Vec<&String> = head_ixs.difference(&base_ixs).collect();
    let telling = |k: &SourceKinds, ix: &str| -> BTreeSet<String> {
        k.slots()
            .into_iter()
            .filter(|((i, p), s)| {
                i == ix
                    && !matches!(s.ty.as_str(), "Program" | "Interface" | "Sysvar")
                    && !matches!(p.rsplit('.').next(), Some("authority" | "payer"))
            })
            .map(|((_, p), _)| p.clone())
            .collect()
    };
    let mut scored: Vec<(f64, &String, &String)> = Vec::new();
    for old in &gone {
        let a = telling(base, old);
        for n in &new {
            let b = telling(head, n);
            let shared = a.intersection(&b).count();
            let score = shared as f64 / a.union(&b).count().max(1) as f64;
            if shared > 0 && score >= 0.5 {
                scored.push((score, *old, *n));
            }
        }
    }
    scored.sort_by(|x, y| y.0.total_cmp(&x.0).then(x.1.cmp(y.1)).then(x.2.cmp(y.2)));
    // Settled on either side: paired, or left out by a tie at its best.
    let (mut settled, mut taken): (BTreeSet<&String>, BTreeSet<&String>) = Default::default();
    for &(score, old, n) in &scored {
        if settled.contains(old) || taken.contains(n) {
            continue;
        }
        let rival = scored.iter().any(|&(s, o, m)| s == score && (o, m) != (old, n) && (o == old || m == n));
        if !rival {
            renamed.insert(old.to_string(), n.to_string());
        }
        settled.insert(old);
        taken.insert(n);
    }
    for old in &gone {
        let checks: Vec<String> = base
            .slots()
            .into_iter()
            .filter(|((i, _), _)| i == *old)
            .flat_map(|(_, s)| checks_of(s))
            .chain(base.ix_checks(old).iter().cloned())
            .collect();
        let message = match renamed.get(*old) {
            Some(n) => format!("instruction renamed to `{n}` (its slots match): compared with it"),
            None if checks.is_empty() => continue,
            None => format!(
                "instruction removed, or renamed past recognition: its {} check(s) are not \
                 compared — confirm no remaining instruction relied on them",
                checks.len()
            ),
        };
        let at = renamed.get(*old).and_then(|n| in_ix(n).first().map(|(_, s)| (s.file.clone(), s.line)));
        let (file, line) = at.unwrap_or_default();
        out.push(Change { severity: Severity::Warning, ix: old.to_string(), path: String::new(), message, file, line });
    }

    for ((base_ix, path), b) in base.slots() {
        let Some(ix) = renamed.get(base_ix).or(head_ixs.get(base_ix)) else { continue };
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
        // This slot's changes start here; a placeholder's are merged below.
        let start = out.len();
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
        let leaf = path.rsplit('.').next().unwrap_or(path);
        // A Signer loosened is reported as the signature it loses, below.
        // A check moved out of the declaration into a fn the handler hands
        // the account to (orca's sparse swap: the tick arrays go to a
        // builder that compares owner, discriminator and whirlpool) is
        // still a removal, naming that fn as where to look. Which account a
        // fn checks cannot be told from text: an intermediate `let`, a
        // shadowed name, a `program_id` passed in, an import each hide it
        // (three review rounds, diff_adversarial*.rs), so it never lowers
        // the severity.
        let handed = |want: &dyn Fn(&crate::source::Handed) -> bool| h.attrs.handed.iter().find(|d| want(d));
        let handed_at = |d: &crate::source::Handed| format!("`{}` ({}:{})", d.call, d.file, d.line);
        // The call compares `target`'s key with a value it computed, or
        // with this slot's data: not a third account's.
        let keys = |d: &crate::source::Handed, target: &str| {
            d.keyed.iter().any(|(t, o)| t == target && o.as_ref().is_none_or(|o| o == path))
        };
        if b.kind == Some(SlotKind::Typed) && h.kind == Some(SlotKind::Unchecked) && b.ty != "Signer" {
            match handed(&|d| d.owner && d.discriminator && d.owner_on.as_ref().is_none_or(|v| v.contains(path))) {
                Some(d) => push(
                    Severity::Regression,
                    format!(
                        "was {}, now {}: Anchor no longer checks its owner and type. The handler passes it \
                         to {}, which compares an owner and a discriminator: if they are this account's, \
                         the check moved there",
                        b.ty, h.ty, handed_at(d)
                    ),
                ),
                None => push(
                    Severity::Regression,
                    format!("was {}, now {}: Anchor no longer checks its owner and type", b.ty, h.ty),
                ),
            }
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
        // A key equality still declared in other words — `has_one` on the
        // holder, `address` on the target, a `constraint` — is not gone:
        // `Some(None)`. `Some(Some(r))` when it holds only once a renamed
        // slot `r` (`old → new`) is read as the old one.
        let restated = |eqs: Vec<KeyEq>| -> Option<Option<String>> {
            let held = declared_eqs(head, ix);
            if eqs.iter().all(|e| held.contains(e)) {
                return Some(None);
            }
            let renames = renamed_slots(base, head, base_ix, ix);
            let used: Vec<String> = renames
                .iter()
                .filter(|&(o, n)| rename_eqs(&eqs, &BTreeMap::from([(o.clone(), n.clone())])) != eqs)
                .map(|(o, n)| format!("`{o}` → `{n}`"))
                .collect();
            rename_eqs(&eqs, &renames).iter().all(|e| held.contains(e)).then(|| Some(used.join(", ")))
        };
        // `seeds` and `address` each fix the account, when built from other
        // accounts or constants rather than an instruction argument: one
        // replacing the other is a change to look at, not a check gone.
        // `owner` is implied by such a fixed address.
        let slot_or_const = |names: &[String]| {
            names.iter().any(|n| n == "::" || head.slot(ix, &sibling(path, n)).is_some_and(|_| sibling(path, n) != *path))
        };
        let fixed_address = ha.address && !ba.address && slot_or_const(&ha.address_names);
        let fixed_seeds = ha.seeds
            && !ba.seeds
            && (ha.seed_names.iter().all(|n| n == "::") || slot_or_const(&ha.seed_names));
        if ba.seeds && !ha.seeds {
            match fixed_address {
                true => push(Severity::Warning, "`seeds` replaced by `address`: confirm it names the same account".into()),
                false => push(Severity::Regression, "`seeds` constraint removed: any address is accepted".into()),
            }
        }
        if ba.address && !ha.address {
            match fixed_seeds {
                true => push(Severity::Warning, "`address` replaced by `seeds`: confirm it names the same account".into()),
                false => match ba.address_expr.as_ref().and_then(|e| restated(vec![key_eq(base, base_ix, path, &format!("{leaf}.key()"), e)])) {
                    Some(None) => {}
                    Some(Some(r)) => push(Severity::Warning, format!("`address` is still declared in other words once {r} is read as a rename: confirm it is the same account")),
                    None => push(Severity::Regression, "`address` constraint removed".into()),
                },
            }
        }
        if let (Some(x), Some(y)) = (&ba.address_expr, &ha.address_expr) {
            if x != y && restated(vec![key_eq(base, base_ix, path, &format!("{leaf}.key()"), x)]).is_none() {
                push(Severity::Warning, format!("`address` changed from `{x}` to `{y}`: confirm it names the account it should"));
            }
        }
        // `token::mint` / `token::authority`: which mint, which owner.
        for (key, field, was, now) in [
            ("token::mint", "mint", &ba.token_mint, &ha.token_mint),
            ("token::authority", "owner", &ba.token_owner, &ha.token_owner),
        ] {
            let Some(x) = was else { continue };
            if now.as_ref() == Some(x) {
                continue;
            }
            match (now, restated(vec![key_eq(base, base_ix, path, &format!("{leaf}.{field}"), &token_value(x))])) {
                (_, Some(None)) => {}
                (_, Some(Some(r))) => push(Severity::Warning, format!("`{key} = {x}` is still declared in other words once {r} is read as a rename: confirm it is the same account")),
                (Some(y), None) => push(Severity::Warning, format!("`{key}` changed from `{x}` to `{y}`: confirm it names the account it should")),
                (None, None) => push(Severity::Regression, format!("`{key} = {x}` removed: any {field} is accepted")),
            }
        }
        if ba.owner && !ha.owner {
            match fixed_address {
                true => push(
                    Severity::Warning,
                    "`owner` constraint replaced by a fixed address: confirm that account has the owner expected".into(),
                ),
                false => push(Severity::Regression, "`owner` constraint removed".into()),
            }
        }
        for target in ba.has_one.iter().filter(|t| !ha.has_one.contains(t)) {
            match siblings.iter().find(|(_, s)| s.attrs.has_one.contains(target)) {
                Some((other, _)) => push(
                    Severity::Warning,
                    format!("`has_one = {target}` moved to `{other}`: confirm it checks the same account"),
                ),
                None => match restated(vec![key_eq(base, base_ix, path, &format!("{leaf}.{target}"), &format!("{target}.key()"))]) {
                    Some(None) => {}
                    Some(Some(r)) => push(
                        Severity::Warning,
                        format!("`has_one = {target}` is still declared in other words once {r} is read as a rename: confirm it is the same account"),
                    ),
                    None => match handed(&|d| keys(d, &sibling(path, target))) {
                        Some(d) => push(
                            Severity::Regression,
                            format!(
                                "`has_one = {target}` removed: it no longer has to match `{target}`. The handler \
                                 passes it and `{target}` to {}, which compares `{target}`'s key: if with this \
                                 account's, the check moved there",
                                handed_at(d)
                            ),
                        ),
                        None => push(
                            Severity::Regression,
                            format!("`has_one = {target}` removed: it no longer has to match `{target}`"),
                        ),
                    },
                },
            }
        }
        let mut used_gates: BTreeSet<String> = BTreeSet::new();
        for expr in ba.constraints.iter().filter(|e| !ha.constraints.contains(e)) {
            match siblings.iter().find(|(_, s)| s.attrs.constraints.contains(expr)) {
                Some((other, _)) => push(
                    Severity::Warning,
                    format!("`constraint = {expr}` moved to `{other}`"),
                ),
                None => match constraint_eqs(base, base_ix, path, expr).and_then(&restated) {
                    Some(None) => {}
                    Some(Some(r)) => push(
                        Severity::Warning,
                        format!("`constraint = {expr}` is still declared in other words once {r} is read as a rename: confirm it is the same account"),
                    ),
                    // A gate on this account's own state swapped for another
                    // (`is_operational()` → `is_ix_enabled(IxGate::…)`): the
                    // account still has to pass one. The new one must be a
                    // yes/no the state answers, not a comparison: a changed
                    // literal (`role == "admin"` → `"attacker"`) is a removal.
                    // With `||` it may let a second way through.
                    None => match ha.constraints.iter().find(|e| {
                        !ba.constraints.contains(e)
                            && !used_gates.contains(*e)
                            && yes_no(e)
                            && !negated(expr, e)
                            && gate_on(head, ix, path, e)
                            && gate_on(base, base_ix, path, expr)
                    }) {
                        Some(e) => {
                            // One new gate stands in for one removed.
                            used_gates.insert(e.clone());
                            push(
                                Severity::Warning,
                                format!("`constraint = {expr}` replaced by `constraint = {e}` on the same account: confirm the new gate is as strict"),
                            )
                        }
                        // A key comparison with other accounts, all of them
                        // handed to one call with this one that compares keys.
                        None => match (expr.contains(".key"), others_named(base, base_ix, path, expr)) {
                            (true, others) if !others.is_empty() => match handed(&|d| others.iter().all(|o| keys(d, o))) {
                                Some(d) => push(
                                    Severity::Regression,
                                    format!(
                                        "`constraint = {expr}` removed. The handler passes the accounts it names to {}, \
                                         which compares their keys: if with this account's, the check moved there",
                                        handed_at(d)
                                    ),
                                ),
                                None => push(Severity::Regression, format!("`constraint = {expr}` removed")),
                            },
                            _ => push(Severity::Regression, format!("`constraint = {expr}` removed")),
                        },
                    },
                },
            }
        }
        match (&ba.close, &ha.close) {
            (Some(t), None) => push(
                Severity::Regression,
                format!(
                    "`close = {t}` removed: the account is no longer emptied and handed back \
                     to the system program when the instruction ends"
                ),
            ),
            (Some(t), Some(u)) if t != u => push(
                Severity::Warning,
                format!("`close` target changed from `{t}` to `{u}`: that is where its lamports go"),
            ),
            _ => {}
        }
        // Counted, not de-duplicated: the same check written in two fns
        // the instruction runs (a wrapper and its `handler`) is two, and
        // removing one is a removal. Copies this slot lost are removed
        // only when the instruction as a whole has fewer: an alias can
        // move one to another account or to the instruction.
        let mut seen = BTreeSet::new();
        for check in ba.body.iter().filter(|c| seen.insert(*c)) {
            let lost = count(&ba.body, check) > count(&ha.body, check);
            if !lost || body_total(head, ix, check) >= body_total(base, base_ix, check) {
                continue;
            }
            match declared_instead(base, head, base_ix, ix, check, Some(path)) {
                Some(slot) => push(Severity::Warning, moved_message(check, &slot)),
                None => push(Severity::Regression, format!("`{check}` removed from the handler")),
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
        // Made a placeholder (`/// CHECK: Deprecated …`): its removals are
        // one that says so. Still a removal — a retired account's checks may
        // have pinned one still in use (a `has_one`, an allowlist PDA seeded
        // by another account), which the source cannot tell from
        // bookkeeping. A lost signature stays on its own; warnings stay.
        let placeholder = |s: &Slot| s.deprecated && s.kind == Some(SlotKind::Unchecked);
        if placeholder(h) && !placeholder(b) {
            let (lost, kept): (Vec<Change>, Vec<Change>) = out.drain(start..).partition(|c| {
                c.severity == Severity::Regression && !c.message.contains("no longer required to sign")
            });
            out.extend(kept);
            if !lost.is_empty() {
                let what: Vec<&str> = lost.iter().map(|c| c.message.as_str()).collect();
                out.push(Change {
                    severity: Severity::Regression,
                    ix: ix.clone(),
                    path: path.clone(),
                    message: format!(
                        "now a placeholder its `/// CHECK:` calls deprecated, and with it: {}. If nothing \
                         reads `{leaf}` these guard nothing of its own — confirm none of them pinned \
                         another account still in use",
                        what.join("; ")
                    ),
                    file: h.file.clone(),
                    line: h.line,
                });
            }
        }
    }

    // Handler checks that name no slot (they read a local), per
    // instruction: compared as a whole.
    for base_ix in &base_ixs {
        let Some(ix) = renamed.get(base_ix).or(head_ixs.get(base_ix)) else { continue };
        let (file, line) = head.handler_at(ix).map_or((String::new(), 0), |(f, l)| (f.to_string(), l));
        let mut seen = BTreeSet::new();
        let lost = |c: &String| {
            count(base.ix_checks(base_ix), c) > count(head.ix_checks(ix), c)
                && body_total(head, ix, c) < body_total(base, base_ix, c)
        };
        for check in base.ix_checks(base_ix).iter().filter(|c| seen.insert(*c) && lost(c)) {
            let (severity, message) = match declared_instead(base, head, base_ix, ix, check, None) {
                Some(slot) => (Severity::Warning, moved_message(check, &slot)),
                None => (Severity::Regression, format!("`{check}` removed from the handler")),
            };
            out.push(Change { severity, ix: ix.clone(), path: String::new(), message, file: file.clone(), line });
        }
    }

    // New instructions with the shape of a missing authority check.
    for ix in new.iter().filter(|n| !renamed.values().any(|v| v == **n)) {
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

/// A handler check that is gone may have become a declaration — the
/// safer form. The account it names that now declares a check of the
/// same kind, if one does: a signer check needs a signer, a key check a
/// `has_one`, `constraint`, `seeds`, `address` or a `Program` / `Sysvar`
/// type, an owner or discriminator check a typed account, a bump check
/// `seeds` on some account of the instruction. Any other check
/// (an amount, a slot number) has no declared form and stays removed.
fn declared_instead(
    base: &SourceKinds,
    head: &SourceKinds,
    base_ix: &str,
    ix: &str,
    check: &str,
    slot: Option<&str>,
) -> Option<String> {
    let kind = if check.contains("is_signer") {
        Kind::Signer
    } else if check.contains(".key") {
        Kind::Key
    } else if check.contains(".owner") || check.contains("discrimin") {
        Kind::Type
    } else if check.contains("bump") {
        // A bump compared by hand names no account; `seeds` + `bump` on
        // any account of the instruction is its declared form.
        Kind::Bump
    } else {
        return None;
    };
    let words: BTreeSet<&str> =
        check.split(|c: char| !(c.is_alphanumeric() || c == '_')).filter(|w| !w.is_empty()).collect();
    let slots = head.slots();
    let leaves: BTreeSet<&str> = slots
        .iter()
        .filter(|((i, _), _)| i == ix)
        .map(|((_, p), _)| p.rsplit('.').next().unwrap_or(p))
        .collect();
    slots.iter().find_map(|((i, p), h)| {
        let leaf = p.rsplit('.').next().unwrap_or(p);
        let named = slot == Some(p.as_str()) || words.contains(leaf) || matches!(kind, Kind::Bump);
        let b = base.slot(base_ix, p);
        // The other accounts the check names: words that are slot names of
        // the instruction, not `key`, `owner` or the macro's.
        let others: BTreeSet<&str> = words
            .iter()
            .copied()
            .filter(|w| *w != leaf && leaves.contains(w))
            .collect();
        (i == ix && named && b.is_some_and(|b| gained(kind, b, h, &others))).then(|| p.clone())
    })
}

#[derive(Clone, Copy)]
enum Kind {
    Signer,
    Key,
    Type,
    Bump,
}

/// `h` declares a check of `kind` that `b` did not. For a key check the
/// declaration must tie `h` to something else the check names (`others`:
/// the check's other account names): a `has_one` on one of them, a
/// `constraint` comparing a key with one of them, or `seeds` / `address`
/// built from one of them; a check against a constant only is covered by
/// `seeds` / `address` / a program type fixing `h` itself.
fn gained(kind: Kind, b: &Slot, h: &Slot, others: &BTreeSet<&str>) -> bool {
    let (ba, ha) = (&b.attrs, &h.attrs);
    let typed = b.kind == Some(SlotKind::Unchecked) && h.kind == Some(SlotKind::Typed);
    match kind {
        Kind::Signer => signs(h) && !signs(b),
        // Against a constant only, a declaration fixing `h` itself does it;
        // against another account, the declaration must name that account.
        Kind::Key if others.is_empty() => {
            (typed && matches!(h.ty.as_str(), "Program" | "Sysvar"))
                || (ha.seeds && !ba.seeds)
                || (ha.address && !ba.address)
        }
        Kind::Key => {
            (ha.seeds && !ba.seeds && ha.seed_names.iter().any(|n| others.contains(n.as_str())))
                || (ha.address && !ba.address && ha.address_names.iter().any(|n| others.contains(n.as_str())))
                || ha.has_one.iter().any(|t| !ba.has_one.contains(t) && others.contains(t.as_str()))
                || ha.constraints.iter().any(|e| {
                    !ba.constraints.contains(e)
                        && e.contains(".key")
                        && e.split(|c: char| !(c.is_alphanumeric() || c == '_')).any(|w| others.contains(w))
                })
        }
        Kind::Type => (typed && h.ty != "Signer") || (ha.owner && !ba.owner),
        Kind::Bump => ha.seeds && !ba.seeds,
    }
}

fn moved_message(check: &str, slot: &str) -> String {
    format!(
        "`{check}` removed from the handler, and `{slot}` now declares a check: \
         confirm the declaration covers it"
    )
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
    c.extend(a.token_mint.iter().map(|t| format!("token::mint = {t}")));
    c.extend(a.token_owner.iter().map(|t| format!("token::authority = {t}")));
    c.extend(a.constraints.iter().map(|e| format!("constraint = {e}")));
    c.extend(a.close.iter().map(|t| format!("close = {t}")));
    // Each check once in the list, however many copies the handler writes.
    for b in &a.body {
        if !c.contains(b) {
            c.push(b.clone());
        }
    }
    c.extend(a.validate.iter().cloned());
    c
}

/// One key said to equal another, in order. Each side is as written with
/// spaces, `ctx.accounts.`, `.load()?` / `.load_mut()?` and a leading
/// `&` / `*` dropped, and each name that is a slot beside `path` written
/// `@` and its full path, so `state` in `left` is not `state` in `right`
/// and an instruction argument is not the account of that name.
/// `has_one = f` on `x`, `address = x.f` on `f` and
/// `constraint = x.load()?.f == f.key()` are each `(@f.key(), @x.f)`.
type KeyEq = (String, String);

fn key_eq(k: &SourceKinds, ix: &str, path: &str, a: &str, b: &str) -> KeyEq {
    // A name at the head of a path: not after `.` (a field) or `::`.
    let name = regex::Regex::new(r"(^|[^.:\w@])([A-Za-z_]\w*)").unwrap();
    let side = |e: &str| {
        let mut t: String = e.chars().filter(|c| !c.is_whitespace()).collect();
        for p in ["ctx.accounts.", ".load()?", ".load_mut()?"] {
            t = t.replace(p, "");
        }
        let t = t.trim_start_matches(['&', '*']);
        name.replace_all(t, |c: &regex::Captures| {
            let full = sibling(path, &c[2]);
            match k.slot(ix, &full) {
                Some(_) => format!("{}@{full}", &c[1]),
                None => c[0].to_string(),
            }
        })
        .into_owned()
    };
    ordered(side(a), side(b))
}

fn ordered(a: String, b: String) -> KeyEq {
    if a <= b { (a, b) } else { (b, a) }
}

/// What a `constraint` on the slot at `path` says, when it is nothing but
/// `==` joined by `&&`.
fn constraint_eqs(k: &SourceKinds, ix: &str, path: &str, c: &str) -> Option<Vec<KeyEq>> {
    if c.contains("||") || c.contains("!=") {
        return None;
    }
    let parts = clauses(c);
    let eqs: Vec<KeyEq> = parts
        .iter()
        .filter_map(|p| match p.split("==").collect::<Vec<_>>()[..] {
            [l, r] if !l.trim().is_empty() && !r.trim().is_empty() => Some(key_eq(k, ix, path, l, r)),
            _ => None,
        })
        .collect();
    (!eqs.is_empty() && eqs.len() == parts.len()).then_some(eqs)
}

/// A gate that answers yes or no from the account's state, comparing
/// nothing: no `==`-like operator or method, no `matches!`, no `|`, no
/// literal. A changed literal (`role == "admin"` → `"attacker"`,
/// `.ge(&3)` → `.ge(&0)`) is a removal.
fn yes_no(e: &str) -> bool {
    static CMP: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r#"==|!=|<|>|\||\^|\.\s*(?:eq|ne|ge|gt|le|lt|cmp|partial_cmp)\s*\(|\bmatches\s*!|"|'|\b\d|\btrue\b|\bfalse\b"#).unwrap()
    });
    !CMP.is_match(e)
}

/// One gate the other with a `!` added or taken away: inverted. Read
/// alike: `load_mut()?` / `load_init()?` and `load()?`; `x == false`,
/// `x != true` and `x.not()` and `!x`.
fn negated(a: &str, b: &str) -> bool {
    let core = |e: &str| -> (usize, String) {
        let mut t: String = e.chars().filter(|c| !c.is_whitespace()).collect();
        t = t.replace(".load_mut()?", ".load()?").replace(".load_init()?", ".load()?");
        let mut bangs = 0;
        for (suffix, flips) in [("==false", 1), ("!=true", 1), ("==true", 0), ("!=false", 0), (".not()", 1)] {
            if let Some(r) = t.strip_suffix(suffix) {
                t = r.to_string();
                bangs += flips;
                break;
            }
        }
        loop {
            if let Some(r) = t.strip_prefix('!') {
                t = r.to_string();
                bangs += 1;
            } else if t.starts_with('(') && t.ends_with(')') && closing_paren_at(&t) == Some(t.len() - 1) {
                t = t[1..t.len() - 1].to_string();
            } else {
                return (bangs, t);
            }
        }
    };
    let ((x, s), (y, t)) = (core(a), core(b));
    s == t && x % 2 != y % 2
}

/// The index of the `)` closing the `(` at 0.
fn closing_paren_at(t: &str) -> Option<usize> {
    let mut d = 0i32;
    for (i, c) in t.char_indices() {
        match c {
            '(' => d += 1,
            ')' => {
                d -= 1;
                if d == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// A name at the head of a path: not after `.` (a field) or `::`.
static HEAD_NAME: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"(^|[^.:\w])([A-Za-z_]\w*)").unwrap());

/// A `constraint` on the slot at `path` that reads only that account's
/// state (`group.load()?.is_operational()`, `g.testing == 1`): no other
/// account of the instruction, and no key compared.
fn gate_on(k: &SourceKinds, ix: &str, path: &str, c: &str) -> bool {
    if c.contains(".key") {
        return false;
    }
    let leaf = path.rsplit('.').next().unwrap_or(path);
    let named: BTreeSet<&str> = HEAD_NAME
        .captures_iter(c)
        .map(|m| m.get(2).unwrap().as_str())
        .filter(|n| k.slot(ix, &sibling(path, n)).is_some())
        .collect();
    named.len() == 1 && named.contains(leaf)
}

/// The slots beside `path` other than it that a `constraint` names, as
/// full paths.
fn others_named(k: &SourceKinds, ix: &str, path: &str, c: &str) -> BTreeSet<String> {
    HEAD_NAME
        .captures_iter(c)
        .map(|m| sibling(path, m.get(2).unwrap().as_str()))
        .filter(|p| p != path && k.slot(ix, p).is_some())
        .collect()
}

/// A `token::mint` / `token::authority` value as a key: Anchor takes
/// `m.key()`, so a plain name is an account.
fn token_value(e: &str) -> String {
    match e.chars().all(|c| c.is_alphanumeric() || c == '_') {
        true => format!("{e}.key()"),
        false => e.to_string(),
    }
}

/// Every key equality the slots of `ix` declare. An `Option` slot's
/// declarations are not checked when it is left out: not counted.
fn declared_eqs(k: &SourceKinds, ix: &str) -> BTreeSet<KeyEq> {
    let mut out = BTreeSet::new();
    for ((i, path), s) in k.slots() {
        if i != ix || s.optional {
            continue;
        }
        let leaf = path.rsplit('.').next().unwrap_or(path);
        let a = &s.attrs;
        let eq = |x: &str, y: &str| key_eq(k, ix, path, x, y);
        out.extend(a.has_one.iter().map(|t| eq(&format!("{leaf}.{t}"), &format!("{t}.key()"))));
        out.extend(a.address_expr.iter().map(|e| eq(&format!("{leaf}.key()"), e)));
        out.extend(a.token_mint.iter().map(|e| eq(&format!("{leaf}.mint"), &token_value(e))));
        out.extend(a.token_owner.iter().map(|e| eq(&format!("{leaf}.owner"), &token_value(e))));
        out.extend(a.constraints.iter().filter_map(|c| constraint_eqs(k, ix, path, c)).flatten());
    }
    out
}

/// Typed slots of `base_ix` gone from `ix`, each paired with the one new
/// slot of `ix` of the same type when that pairing is the only one:
/// `marginfi_group` renamed `group`. Full paths.
fn renamed_slots(base: &SourceKinds, head: &SourceKinds, base_ix: &str, ix: &str) -> BTreeMap<String, String> {
    let typed = |k: &SourceKinds, i: &str| -> BTreeMap<String, String> {
        k.slots()
            .into_iter()
            .filter(|((x, _), s)| x == i && s.kind == Some(SlotKind::Typed))
            .map(|((_, p), s)| (p.clone(), s.full_ty.clone()))
            .collect()
    };
    let (b, h) = (typed(base, base_ix), typed(head, ix));
    let gone: Vec<_> = b.iter().filter(|(n, _)| !h.contains_key(*n)).collect();
    let new: Vec<_> = h.iter().filter(|(n, _)| !b.contains_key(*n)).collect();
    let mut out = BTreeMap::new();
    for (n, ty) in &gone {
        let olds = gone.iter().filter(|(_, t)| t == ty).count();
        let mut news = new.iter().filter(|(_, t)| t == ty);
        if let (1, Some((m, _)), None) = (olds, news.next(), news.next()) {
            out.insert(n.to_string(), m.to_string());
        }
    }
    out
}

/// `eqs` with each renamed slot read as its new path.
fn rename_eqs(eqs: &[KeyEq], renames: &BTreeMap<String, String>) -> Vec<KeyEq> {
    let swap = |e: &str| {
        let mut t = e.to_string();
        for (old, new) in renames {
            let re = regex::Regex::new(&format!(r"@{}\b", regex::escape(old))).unwrap();
            t = re.replace_all(&t, format!("@{new}").as_str()).into_owned();
        }
        t
    };
    eqs.iter().map(|(a, b)| ordered(swap(a), swap(b))).collect()
}

fn count(v: &[String], c: &str) -> usize {
    v.iter().filter(|x| *x == c).count()
}

/// How many times the handler of `ix` writes `c`, on any account or none.
fn body_total(k: &SourceKinds, ix: &str, c: &str) -> usize {
    count(k.ix_checks(ix), c)
        + k.slots().iter().filter(|((i, _), _)| i == ix).map(|(_, s)| count(&s.attrs.body, c)).sum::<usize>()
}

/// `n` as named in an attribute of the slot at `path`: a sibling.
fn sibling(path: &str, n: &str) -> String {
    format!("{}{n}", path.rfind('.').map_or("", |i| &path[..=i]))
}

/// Required to sign: an `Option<Signer>` may be left out, so it does not.
/// A non-PDA `init` / `init_if_needed` account signs too: Anchor adds the signer constraint,
/// since it is created at a fresh keypair's address.
fn signs(s: &Slot) -> bool {
    let a = &s.attrs;
    (s.ty == "Signer" || a.signer || ((a.init || a.init_if_needed) && !a.seeds && !a.token_authority))
        && !s.optional
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
#[path = "diff_adversarial.rs"]
mod adversarial;

#[cfg(test)]
#[path = "diff_adversarial_round2.rs"]
mod adversarial_round2;

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

    #[test]
    fn a_renamed_instruction_is_compared_and_a_removed_one_named() {
        let base = r#"
pub fn init(ctx: Context<Init>) -> Result<()> {}
pub fn close(ctx: Context<Close>) -> Result<()> {}
#[derive(Accounts)]
pub struct Init<'info> {
    #[account(init, payer = authority, space = 8)]
    pub user: Account<'info, User>,
    #[account(mut)]
    pub authority: Signer<'info>,
}
#[derive(Accounts)]
pub struct Close<'info> {
    #[account(mut, close = destination, has_one = owner)]
    pub vault: Account<'info, Vault>,
    pub owner: Signer<'info>,
    pub destination: SystemAccount<'info>,
}
"#;
        // `init` → `initialize` with its check dropped; `close` loses
        // `close =`.
        let head = base
            .replace("fn init(ctx: Context<Init>)", "fn initialize(ctx: Context<Initialize>)")
            .replace("struct Init<'info>", "struct Initialize<'info>")
            .replace("pub user: Account<'info, User>", "pub user: AccountInfo<'info>")
            .replace("close = destination, ", "");
        let changes = diff(&kinds(base), &kinds(&head));
        let got: Vec<_> = changes.iter().map(|c| (c.severity, c.slot(), c.message.as_str())).collect();
        assert!(got.iter().any(|(s, slot, m)| *s == Severity::Regression
            && slot == "initialize.user"
            && m.starts_with("was Account, now AccountInfo")));
        assert!(got.iter().any(|(s, slot, m)| *s == Severity::Warning
            && slot == "init"
            && m.starts_with("instruction renamed to `initialize`")));
        assert!(got.iter().any(|(s, slot, m)| *s == Severity::Regression
            && slot == "close.vault"
            && m.starts_with("`close = destination` removed")));
        // A renamed instruction is not also reported as a new one.
        assert!(!got.iter().any(|(_, _, m)| m.starts_with("new instruction")));

        // The `@ Error` is not part of the target.
        let err = base.replace("close = destination", "close = destination @ E::A");
        let err2 = base.replace("close = destination", "close = destination @ E::B");
        assert!(diff(&kinds(&err), &kinds(&err2)).is_empty());
        assert!(diff(&kinds(base), &kinds(&err)).is_empty());

        // Two gone instructions match one new one: the better match wins,
        // whatever the names' order.
        let pair = r#"
pub fn a_old(ctx: Context<A>) -> Result<()> {}
pub fn b_old(ctx: Context<B>) -> Result<()> {}
#[derive(Accounts)]
pub struct A<'info> {
    pub pool: Account<'info, P>,
    pub vault: Account<'info, V>,
    pub junk: Account<'info, J>,
    pub authority: Signer<'info>,
}
#[derive(Accounts)]
pub struct B<'info> {
    #[account(has_one = authority)]
    pub pool: Account<'info, P>,
    pub vault: Account<'info, V>,
    pub authority: Signer<'info>,
}
"#;
        let one = r#"
pub fn n(ctx: Context<N>) -> Result<()> {}
#[derive(Accounts)]
pub struct N<'info> {
    pub pool: Account<'info, P>,
    pub vault: Account<'info, V>,
    pub authority: Signer<'info>,
}
"#;
        let c = diff(&kinds(pair), &kinds(one));
        assert!(c.iter().any(|c| c.severity == Severity::Regression && c.slot() == "n.pool"), "{c:?}");

        // Tied between two new instructions: no pair, not even a worse one.
        let tie = r#"
pub fn x(ctx: Context<X>) -> Result<()> {}
#[derive(Accounts)]
pub struct X<'info> {
    #[account(has_one = q)]
    pub p: Account<'info, D>,
    pub q: Account<'info, D>,
    pub r: Account<'info, D>,
    pub s: Account<'info, D>,
}
"#;
        let three = r#"
pub fn n1(ctx: Context<N1>) -> Result<()> {}
pub fn n2(ctx: Context<N2>) -> Result<()> {}
pub fn n3(ctx: Context<N3>) -> Result<()> {}
#[derive(Accounts)]
pub struct N1<'info> {
    pub p: Account<'info, D>,
    pub q: Account<'info, D>,
    pub r: Account<'info, D>,
    pub t1: Account<'info, D>,
}
#[derive(Accounts)]
pub struct N2<'info> {
    pub p: Account<'info, D>,
    pub q: Account<'info, D>,
    pub r: Account<'info, D>,
    pub t2: Account<'info, D>,
}
#[derive(Accounts)]
pub struct N3<'info> {
    pub p: Account<'info, D>,
    pub q: Account<'info, D>,
    pub r: Account<'info, D>,
    pub t4: Account<'info, D>,
    pub t5: Account<'info, D>,
}
"#;
        let c = diff(&kinds(tie), &kinds(three));
        assert!(!c.iter().any(|c| c.severity == Severity::Regression), "{c:?}");
        assert!(c.iter().any(|c| c.slot() == "x" && c.message.contains("not compared")), "{c:?}");

        // Shared generic slots alone are not a rename.
        let crank = base
            .replace("pub fn init(ctx: Context<Init>)", "pub fn crank(ctx: Context<Crank>)")
            .replace("struct Init<'info>", "struct Crank<'info>")
            .replace("pub user: Account<'info, User>", "pub config: Account<'info, Config>");
        let c = diff(&kinds(base), &kinds(&crank));
        assert!(!c.iter().any(|c| c.message.starts_with("instruction renamed")), "{c:?}");

        // A target change is a warning.
        let moved = base.replace("close = destination", "close = owner");
        let c = diff(&kinds(base), &kinds(&moved));
        assert!(c.len() == 1 && c[0].severity == Severity::Warning && c[0].message.contains("from `destination` to `owner`"));

        // Gone with nothing that matches: named, not silent.
        let gone = base.replace("pub fn close(ctx: Context<Close>) -> Result<()> {}\n", "");
        let c = diff(&kinds(base), &kinds(&gone));
        assert_eq!(c.len(), 1);
        assert!(c[0].slot() == "close" && c[0].message.contains("not compared") && c[0].file.is_empty());

        // Two equally good candidates: no guess.
        let two = base
            .replace("fn init(ctx: Context<Init>) -> Result<()> {}", "fn a(ctx: Context<Init>) -> Result<()> {}\npub fn b(ctx: Context<Init>) -> Result<()> {}");
        let c = diff(&kinds(base), &kinds(&two));
        assert!(c.iter().any(|c| c.slot() == "init" && c.message.contains("not compared")));
    }

    #[test]
    fn a_handler_check_removed_or_moved_to_a_declaration() {
        let base = r#"
pub fn log(ctx: Context<Log>) -> Result<()> {
    if !ctx.accounts.authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let user = User::try_from_slice(&ctx.accounts.user.data.borrow())?;
    if user.discriminant != Kind::User {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(())
}
#[derive(Accounts)]
pub struct Log<'info> {
    pub authority: AccountInfo<'info>,
    pub user: AccountInfo<'info>,
}
"#;
        // Deleted: removed.
        let gone = base.replace(
            "    if !ctx.accounts.authority.is_signer {\n        return Err(ProgramError::MissingRequiredSignature);\n    }\n",
            "",
        );
        let c = diff(&kinds(base), &kinds(&gone));
        assert!(c.len() == 1 && c[0].severity == Severity::Regression && c[0].slot() == "log.authority", "{c:?}");
        assert_eq!(c[0].message, "`if !authority.is_signer` removed from the handler");

        // Moved into the declaration (`Signer`, `Account<User>`): warnings.
        let declared = base
            .replace(
                "    if !ctx.accounts.authority.is_signer {\n        return Err(ProgramError::MissingRequiredSignature);\n    }\n",
                "",
            )
            .replace(
                "    if user.discriminant != Kind::User {\n        return Err(ProgramError::InvalidAccountData);\n    }\n",
                "",
            )
            .replace("pub authority: AccountInfo<'info>", "pub authority: Signer<'info>")
            .replace("pub user: AccountInfo<'info>", "pub user: Account<'info, User>");
        let c = diff(&kinds(base), &kinds(&declared));
        assert_eq!(c.len(), 2, "{c:?}");
        assert!(c.iter().all(|c| c.severity == Severity::Warning && c.message.contains("now declares a check")));
    }

    #[test]
    fn handler_refactors_are_not_removals_and_unrelated_declarations_hide_nothing() {
        let base = r#"
pub fn act(ctx: Context<Act>, amount: u64) -> Result<()> {
    require_keys_eq!(ctx.accounts.vault.authority, ctx.accounts.authority.key(), E::Owner);
    require!(ctx.accounts.pool.open, E::Closed);
    require!(amount <= MAX, E::TooMuch);
    Ok(())
}
#[derive(Accounts)]
pub struct Act<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub authority: AccountInfo<'info>,
    pub pool: Account<'info, Pool>,
    pub config: Account<'info, Config>,
}
"#;
        let same = |head: &str| diff(&kinds(base), &kinds(head));
        // An alias, swapped arguments: the same checks.
        let alias = base
            .replace("    require!(ctx.accounts.pool.open, E::Closed);", "    let pool = &ctx.accounts.pool;\n    require!(pool.open, E::Closed);")
            .replace(
                "require_keys_eq!(ctx.accounts.vault.authority, ctx.accounts.authority.key(), E::Owner)",
                "require_keys_eq!(ctx.accounts.authority.key(), ctx.accounts.vault.authority, E::Owner)",
            );
        assert!(same(&alias).is_empty(), "{:?}", same(&alias));

        // A signer is not a key tie: the deleted require_keys_eq! stays removed.
        let signer = base
            .replace("    require_keys_eq!(ctx.accounts.vault.authority, ctx.accounts.authority.key(), E::Owner);\n", "")
            .replace("pub authority: AccountInfo<'info>", "pub authority: Signer<'info>");
        assert!(same(&signer).iter().any(|c| c.severity == Severity::Regression), "{:?}", same(&signer));

        // A fixed address on the vault does not tie it to `authority`.
        let addressed = base
            .replace("    require_keys_eq!(ctx.accounts.vault.authority, ctx.accounts.authority.key(), E::Owner);\n", "")
            .replace("#[account(mut)]\n    pub vault", "#[account(mut, address = VAULT)]\n    pub vault");
        assert!(same(&addressed).iter().any(|c| c.severity == Severity::Regression), "{:?}", same(&addressed));
        // Operands of `==` read the same both ways round.
        let req = base.replace("require!(ctx.accounts.pool.open, E::Closed)", "require!(ctx.accounts.pool.key() == ctx.accounts.vault.pool, E::P)");
        let swapped = req.replace("require!(ctx.accounts.pool.key() == ctx.accounts.vault.pool, E::P)", "require!(ctx.accounts.vault.pool == ctx.accounts.pool.key(), E::P)");
        assert!(diff(&kinds(&req), &kinds(&swapped)).is_empty(), "{:?}", diff(&kinds(&req), &kinds(&swapped)));

        // A declaration that ties nothing the check named does not excuse it.
        let check = "    require_keys_eq!(ctx.accounts.vault.authority, ctx.accounts.authority.key(), E::Owner);\n";
        for decl in [
            "#[account(mut, has_one = mint)]",
            "#[account(mut, constraint = vault.amount > 0)]",
            "#[account(mut, constraint = vault.key() != Pubkey::default())]",
        ] {
            let h = base.replace(check, "").replace("#[account(mut)]\n    pub vault", &format!("{decl}\n    pub vault"));
            assert!(same(&h).iter().any(|c| c.severity == Severity::Regression), "{decl}: {:?}", same(&h));
        }
        let tied = base.replace(check, "").replace("#[account(mut)]\n    pub vault", "#[account(mut, has_one = authority)]\n    pub vault");
        assert!(same(&tied).iter().all(|c| c.severity == Severity::Warning), "{:?}", same(&tied));

        // An unrelated new constraint does not excuse a deleted amount check.
        let unrelated = base
            .replace("    require!(amount <= MAX, E::TooMuch);\n", "")
            .replace("    pub config: Account<'info, Config>,", "    #[account(constraint = config.paused == false)]\n    pub config: Account<'info, Config>,");
        let c = same(&unrelated);
        assert!(c.len() == 1 && c[0].severity == Severity::Regression && c[0].slot() == "act", "{c:?}");
    }

    /// Marinade's anchor-0.27 upgrade: `#[account(signer)] AccountInfo`
    /// became an `init` account, which Anchor makes sign anyway.
    #[test]
    fn a_non_pda_init_account_still_signs() {
        let base = r#"
pub fn split(ctx: Context<Split>) -> Result<()> {}
#[derive(Accounts)]
pub struct Split<'info> {
    #[account(signer, mut)]
    pub split_stake: AccountInfo<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
}
"#;
        let init = base.replace(
            "#[account(signer, mut)]\n    pub split_stake: AccountInfo<'info>",
            "#[account(init, payer = payer, space = 200)]\n    pub split_stake: Account<'info, StakeAccount>",
        );
        assert!(!diff(&kinds(base), &kinds(&init)).iter().any(|c| c.message.contains("sign")));
        let gone = init.replace("#[account(init, payer = payer, space = 200)]\n    pub split_stake: Account<'info, StakeAccount>", "pub split_stake: AccountInfo<'info>");
        let if_needed = init.replace("init, payer", "init_if_needed, payer");
        assert!(diff(&kinds(&if_needed), &kinds(&gone)).iter().any(|c| c.message.contains("no longer required to sign")));
        let pda = init.replace("init, payer", "init, seeds = [b\"s\"], bump, payer");
        assert!(diff(&kinds(base), &kinds(&pda)).iter().any(|c| c.message.contains("no longer required to sign")));
    }

    /// Seen in real histories: equivalent or stronger rewrites of a
    /// declared check are warnings, not removals.
    #[test]
    fn replaced_declared_checks_and_id_spellings() {
        let base = r#"
pub fn act(ctx: Context<Act>) -> Result<()> {}
#[derive(Accounts)]
pub struct Act<'info> {
    #[account(owner = spl_stake_pool::id())]
    pub list: AccountInfo<'info>,
    #[account(seeds = [b"v"], bump)]
    pub vault: Account<'info, Vault>,
    #[account(constraint = owner.key() == crate::admin::id())]
    pub owner: Signer<'info>,
    pub config: Account<'info, Config>,
}
"#;
        let head = base
            .replace("owner = spl_stake_pool::id()", "address = get_validator_list(&config)?")
            .replace("seeds = [b\"v\"], bump", "address = VAULT")
            .replace("crate::admin::id()", "crate::admin::ID");
        let c = diff(&kinds(base), &kinds(&head));
        let warn = |c: &[Change], slot: &str| c.iter().any(|c| c.slot() == slot && c.severity == Severity::Warning);
        assert!(warn(&c, "act.list") && warn(&c, "act.vault"), "{c:?}");
        // Rust does not make `id()` and `ID` the same: still a change.
        assert!(c.iter().any(|c| c.slot() == "act.owner" && c.severity == Severity::Regression), "{c:?}");

        // An address the caller passes, or a typed account in place of
        // `owner`, fixes nothing: removals.
        let arg = base.replace("seeds = [b\"v\"], bump", "address = target");
        assert!(diff(&kinds(base), &kinds(&arg)).iter().any(|c| c.slot() == "act.vault" && c.severity == Severity::Regression));
        let typed = base
            .replace("#[account(owner = spl_stake_pool::id())]\n    pub list: AccountInfo<'info>", "pub list: Account<'info, Local>");
        assert!(diff(&kinds(base), &kinds(&typed)).iter().any(|c| c.slot() == "act.list" && c.severity == Severity::Regression));
    }

    #[test]
    fn one_key_equality_written_another_way_is_not_removed() {
        let base = r#"
pub fn act(ctx: Context<Act>) -> Result<()> {}
#[derive(Accounts)]
pub struct Act<'info> {
    pub marginfi_group: AccountLoader<'info, Group>,
    #[account(constraint = bank.load()?.group == marginfi_group.key())]
    pub bank: AccountLoader<'info, Bank>,
    #[account(has_one = authority)]
    pub account: AccountLoader<'info, Account>,
    #[account(address = account.load()?.admin)]
    pub admin: Signer<'info>,
    pub authority: Signer<'info>,
    #[account(constraint = user_token.mint == vault.mint)]
    pub user_token: Account<'info, TokenAccount>,
    pub vault: Account<'info, TokenAccount>,
    #[account(constraint = pool.config == config.key())]
    pub pool: Account<'info, Pool>,
    pub config: Account<'info, Config>,
}
"#;
        let head = base
            .replace("#[account(has_one = authority)]", "#[account(has_one = admin)]")
            .replace("#[account(address = account.load()?.admin)]\n", "")
            .replace("pub authority: Signer", "#[account(address = account.load()?.authority)]\n    pub authority: Signer")
            .replace("constraint = user_token.mint == vault.mint", "token::mint = vault.mint")
            .replace("constraint = pool.config == config.key())]\n    pub pool: Account<'info, Pool>",
                "constraint = pool.load()?.config == config.key())]\n    pub pool: AccountLoader<'info, Pool>");
        let c = diff(&kinds(base), &kinds(&head));
        let gone = |c: &[Change]| c.iter().filter(|c| c.severity == Severity::Regression).map(|c| c.slot()).collect::<Vec<_>>();
        assert_eq!(gone(&c), Vec::<String>::new(), "{c:?}");

        // Held only by a renamed slot of the same type: a warning to look at.
        let renamed = base
            .replace("pub marginfi_group:", "pub group:")
            .replace("constraint = bank.load()?.group == marginfi_group.key()", "has_one = group");
        let c = diff(&kinds(base), &kinds(&renamed));
        assert!(gone(&c).is_empty(), "{c:?}");
        assert!(c.iter().any(|c| c.slot() == "act.bank" && c.message.contains("`marginfi_group` → `group`")), "{c:?}");

        let changed = base.replace("address = account.load()?.admin", "address = admin_key");
        assert!(diff(&kinds(base), &kinds(&changed)).iter().any(|c| c.slot() == "act.admin" && c.severity == Severity::Warning));

        // Another key, or one branch of `||`: removed.
        for loose in [
            base.replace("#[account(has_one = authority)]", "").replace("pub authority: Signer", "#[account(address = account.load()?.owner)]\n    pub authority: Signer"),
            base.replace("#[account(has_one = authority)]", "#[account(constraint = account.load()?.authority == authority.key() || open)]"),
            base.replace("pub marginfi_group:", "pub group:").replace("constraint = bank.load()?.group == marginfi_group.key()", "has_one = other"),
        ] {
            assert!(!gone(&diff(&kinds(base), &kinds(&loose))).is_empty(), "{loose}");
        }
    }

    #[test]
    fn a_key_equality_counts_only_for_the_same_accounts() {
        let gone = |b: &str, h: &str| diff(&kinds(b), &kinds(h)).into_iter().filter(|c| c.severity == Severity::Regression).count();
        // `state` in `left` is not `state` in `right`.
        let base = r#"
pub fn act(ctx: Context<Act>) -> Result<()> {}
#[derive(Accounts)]
pub struct Left<'info> {
    #[account(has_one = authority)]
    pub state: Account<'info, State>,
    pub authority: Signer<'info>,
}
#[derive(Accounts)]
pub struct Right<'info> {
    pub state: Account<'info, State>,
    pub authority: Signer<'info>,
}
#[derive(Accounts)]
pub struct Act<'info> {
    pub left: Left<'info>,
    pub right: Right<'info>,
}
"#;
        let head = base
            .replace("    #[account(has_one = authority)]\n", "")
            .replace("pub struct Right<'info> {\n", "pub struct Right<'info> {\n    #[account(constraint = state.authority == authority.key())]\n");
        assert_eq!(gone(base, &head), 1);

        // An instruction argument is not the account of that name.
        let base = r#"
pub fn act(ctx: Context<Act>, expected: Pubkey) -> Result<()> {}
#[derive(Accounts)]
#[instruction(expected: Pubkey)]
pub struct Act<'info> {
    #[account(address = expected.key())]
    pub target: UncheckedAccount<'info>,
}
"#;
        let head = r#"
pub fn act(ctx: Context<Act>) -> Result<()> {}
#[derive(Accounts)]
pub struct Act<'info> {
    pub expected: UncheckedAccount<'info>,
    #[account(constraint = target.key() == expected.key())]
    pub target: UncheckedAccount<'info>,
}
"#;
        assert_eq!(gone(base, head), 1);

        // A new account of the same type standing in for a gone one is
        // only read as a rename: a warning, never silence.
        let base = r#"
pub fn act(ctx: Context<Act>) -> Result<()> {}
#[derive(Accounts)]
pub struct Act<'info> {
    pub old: Account<'info, Config>,
    #[account(constraint = state.config == old.key())]
    pub state: Account<'info, State>,
}
"#;
        let head = base.replace("pub old:", "pub new:").replace("old.key()", "new.key()").replace("state.config ==", "state.other ==");
        assert_eq!(gone(base, &head), 1);
        let head = base.replace("pub old:", "pub new:").replace("old.key()", "new.key()");
        let c = diff(&kinds(base), &kinds(&head));
        assert!(c.iter().any(|c| c.slot() == "act.state" && c.severity == Severity::Warning), "{c:?}");

        // An `Option` composite runs none of its checks when left out.
        let base = r#"
pub fn act(ctx: Context<Act>) -> Result<()> {}
#[derive(Accounts)]
pub struct Group<'info> {
    #[account(has_one = authority)]
    pub state: Account<'info, State>,
    pub guard: UncheckedAccount<'info>,
    pub authority: Signer<'info>,
}
#[derive(Accounts)]
pub struct Act<'info> {
    pub group: Group<'info>,
}
"#;
        let head = base
            .replace("    #[account(has_one = authority)]\n", "")
            .replace("    pub guard:", "    #[account(constraint = state.authority == authority.key())]\n    pub guard:")
            .replace("pub group: Group<'info>", "pub group: Option<Group<'info>>");
        let c = diff(&kinds(base), &kinds(&head));
        assert!(c.iter().any(|c| c.slot() == "act.group.state" && c.severity == Severity::Regression), "{c:?}");
    }

    #[test]
    fn token_mint_and_authority_removed_or_changed() {
        let base = r#"
pub fn act(ctx: Context<Act>) -> Result<()> {}
#[derive(Accounts)]
pub struct Act<'info> {
    pub mint: Account<'info, Mint>,
    pub owner: Signer<'info>,
    #[account(mut, token::mint = mint, token::authority = owner)]
    pub vault: Account<'info, TokenAccount>,
}
"#;
        let sev = |h: &str| diff(&kinds(base), &kinds(h)).iter().filter(|c| c.slot() == "act.vault").map(|c| c.severity).collect::<Vec<_>>();
        assert_eq!(sev(&base.replace("token::mint = mint, ", "")), [Severity::Regression]);
        assert_eq!(sev(&base.replace(", token::authority = owner", "")), [Severity::Regression]);
        assert_eq!(sev(&base.replace("token::mint = mint", "token::mint = other")), [Severity::Warning]);
        // Said as a constraint instead: the same check.
        assert_eq!(sev(&base.replace("token::mint = mint, ", "constraint = vault.mint == mint.key(), ")), []);
    }

    #[test]
    fn a_deprecated_placeholder_is_one_removal() {
        let base = r#"
pub fn act(ctx: Context<Act>) -> Result<()> {}
#[derive(Accounts)]
pub struct Act<'info> {
    pub pool: Account<'info, Pool>,
    #[account(seeds = [b"p", pool.key().as_ref()], bump, constraint = old.pool == pool.key())]
    pub old: Account<'info, Old>,
}
"#;
        let head = base.replace(
            "#[account(seeds = [b\"p\", pool.key().as_ref()], bump, constraint = old.pool == pool.key())]\n    pub old: Account<'info, Old>,",
            "/// CHECK: Deprecated: kept for compatibility.\n    pub old: UncheckedAccount<'info>,",
        );
        let c = diff(&kinds(base), &kinds(&head));
        let old: Vec<_> = c.iter().filter(|c| c.slot() == "act.old").collect();
        assert_eq!(old.len(), 1, "{c:?}");
        assert!(old[0].severity == Severity::Regression && old[0].message.contains("placeholder"), "{c:?}");
        // What the normal comparison calls a warning stays one.
        let raw = "pub fn act(ctx: Context<Act>) -> Result<()> {}\n#[derive(Accounts)]\npub struct Act<'info> {\n    /// CHECK: pda\n    #[account(seeds = [b\"old\"], bump)]\n    pub old: UncheckedAccount<'info>,\n}\n";
        let moved = raw.replace("/// CHECK: pda\n    #[account(seeds = [b\"old\"], bump)]", "/// CHECK: Deprecated compatibility slot.\n    #[account(address = OLD)]");
        let c = diff(&kinds(raw), &kinds(&moved));
        assert!(!c.is_empty() && c.iter().all(|c| c.severity == Severity::Warning), "{c:?}");
        // Inside a block comment it is not a doc comment.
        let block = head.replace("/// CHECK: Deprecated: kept for compatibility.", "/*\n    /// CHECK: Deprecated\n    */");
        assert!(diff(&kinds(base), &kinds(&block)).iter().filter(|c| c.slot() == "act.old").count() > 1);
        // Kept as it is in a later version: nothing to report.
        assert!(diff(&kinds(&head), &kinds(&head)).is_empty());
        let keeps = base.replace("pub old: Account<'info, Old>,", "/// CHECK: Deprecated\n    pub old: UncheckedAccount<'info>,");
        let c = diff(&kinds(base), &kinds(&keeps));
        assert!(c.iter().all(|c| !c.message.contains("seeds")), "{c:?}");
        assert!(diff(&kinds(&keeps), &kinds(&keeps)).is_empty());
        // Made optional: still said.
        let opt = head.replace("pub old: UncheckedAccount<'info>", "pub old: Option<UncheckedAccount<'info>>");
        assert!(diff(&kinds(&head), &kinds(&opt)).iter().any(|c| c.slot() == "act.old" && c.message.contains("optional")));
        // Without the comment: each check on its own.
        let bare = head.replace("Deprecated: kept for compatibility.", "checked in the handler");
        assert!(diff(&kinds(base), &kinds(&bare)).iter().filter(|c| c.slot() == "act.old").count() > 1);
    }

    #[test]
    fn a_gate_swapped_for_another_on_the_same_account() {
        let base = r#"
pub fn act(ctx: Context<Act>) -> Result<()> {}
#[derive(Accounts)]
pub struct Act<'info> {
    #[account(constraint = group.load()?.is_operational() @ Err::Halted)]
    pub group: AccountLoader<'info, Group>,
    #[account(has_one = group)]
    pub account: AccountLoader<'info, Account>,
    pub owner: Signer<'info>,
}
"#;
        let at = |h: &str| {
            diff(&kinds(base), &kinds(h))
                .into_iter()
                .filter(|c| c.slot() == "act.group")
                .map(|c| c.severity)
                .collect::<Vec<_>>()
        };
        // A per-instruction gate in its place: a warning to look at.
        let gate = base.replace("is_operational() @ Err::Halted", "is_ix_enabled(IxGate::Act) @ Err::Disabled");
        assert_eq!(at(&gate), [Severity::Warning]);
        let flag = base.replace("is_operational()", "testing == 1");
        assert_eq!(diff(&kinds(&flag), &kinds(&base.replace("is_operational()", "is_testing()"))).into_iter().filter(|c| c.slot() == "act.group").map(|c| c.severity).collect::<Vec<_>>(), [Severity::Warning]);
        // A comparison in its place is not a yes/no gate: removed.
        assert_eq!(at(&flag), [Severity::Regression]);
        // Gone, or made a way around it: still removed.
        assert_eq!(at(&base.replace("constraint = group.load()?.is_operational() @ Err::Halted", "mut")), [Severity::Regression]);
        let or = base.replace("is_operational()", "is_operational() || account.load()?.flag");
        assert_eq!(at(&or), [Severity::Regression]);
        let or_same = base.replace("is_operational()", "is_operational() || group.load()?.testing == 1");
        assert_eq!(at(&or_same), [Severity::Regression]);
        // A new constraint naming another account is not a gate on this one.
        let other = base.replace("is_operational()", "admin == owner.key()");
        assert_eq!(at(&other), [Severity::Regression]);
        let other = base.replace("is_operational()", "is_owner(account.load()?.owner)");
        assert_eq!(at(&other), [Severity::Regression]);
    }

    #[test]
    fn checks_moved_into_a_fn_the_handler_hands_the_account_to() {
        // orca's sparse swap: the tick array made unchecked, its owner,
        // discriminator and whirlpool compared by a builder two calls deep.
        let base = r#"
pub fn swap(ctx: Context<Swap>) -> Result<()> {
    let whirlpool = &mut ctx.accounts.whirlpool;
    Ok(())
}
#[derive(Accounts)]
pub struct Swap<'info> {
    pub whirlpool: Account<'info, Whirlpool>,
    #[account(mut, has_one = whirlpool)]
    pub tick_array: AccountLoader<'info, TickArray>,
}
impl<'a> Builder<'a> {
    pub fn try_from(whirlpool: &Account<Whirlpool>, arrays: Vec<AccountInfo>) -> Result<Self> {
        for a in arrays {
            let t = peek(a)?;
            if t.whirlpool != whirlpool.key() {
                return Err(ErrorCode::DifferentWhirlpool.into());
            }
        }
        Ok(Self {})
    }
}
fn peek(a: AccountInfo) -> Result<TickArray> {
    if a.owner != &TickArray::owner() {
        return Err(ErrorCode::AccountOwnedByWrongProgram.into());
    }
    if a.data.borrow()[..8] != TickArray::discriminator() {
        return Err(ErrorCode::AccountDiscriminatorMismatch.into());
    }
    Ok(load(a))
}
"#;
        let moved = base
            .replace("    #[account(mut, has_one = whirlpool)]\n    pub tick_array: AccountLoader<'info, TickArray>,", "    /// CHECK: checked in the handler\n    #[account(mut)]\n    pub tick_array: UncheckedAccount<'info>,")
            .replace("    Ok(())\n}\n#[derive", "    let b = Builder::try_from(whirlpool, vec![ctx.accounts.tick_array.to_account_info()])?;\n    Ok(())\n}\n#[derive");
        // Still removals: the hint says where they may have gone.
        let at = |b: &str, h: &str| {
            diff(&kinds(b), &kinds(h))
                .into_iter()
                .filter(|c| c.slot() == "swap.tick_array")
                .map(|c| (c.severity, c.message.contains("moved there")))
                .collect::<Vec<_>>()
        };
        let (r, hint, bare) = (Severity::Regression, true, false);
        assert_eq!(at(base, &moved), [(r, hint), (r, hint)]);
        let k = kinds(&moved);
        let d = &k.slot("swap", "tick_array").unwrap().attrs.handed[0];
        assert_eq!((d.call.as_str(), d.owner, d.discriminator), ("Builder::try_from", true, true));
        assert_eq!(d.keyed, [("whirlpool".to_string(), None)]);
        assert_eq!(d.with, ["tick_array", "whirlpool"]);

        // Not handed to it: both removed.
        let unhanded = moved.replace("vec![ctx.accounts.tick_array.to_account_info()]", "vec![]");
        assert_eq!(at(base, &unhanded), [(r, bare), (r, bare)]);
        // The fn checks no discriminator: the type check is removed.
        let no_disc = moved.replace("TickArray::discriminator()", "[0u8; 8]");
        assert_eq!(at(base, &no_disc), [(r, bare), (r, hint)]);
        // The whirlpool not handed with it: its `has_one` is removed.
        let alone = moved.replace("Builder::try_from(whirlpool,", "Builder::try_from(other,");
        assert_eq!(at(base, &alone), [(r, hint), (r, bare)]);
        // A check that does not reject (a value read, `Ok` either way) is none.
        let soft = moved.replace("return Err(ErrorCode::AccountOwnedByWrongProgram.into());", "return Ok(default());");
        assert_eq!(at(base, &soft), [(r, bare), (r, hint)]);
        // Two fns of the name, the call not saying which: not followed.
        let two = moved.replace("fn peek(a: AccountInfo)", "fn other() {}\nimpl X { fn try_from() {} }\nfn peek(a: AccountInfo)").replace("Builder::try_from(", "try_from(");
        assert_eq!(at(base, &two), [(r, bare), (r, bare)]);
    }

    #[test]
    fn one_line_fields_and_per_module_handlers() {
        let base = r#"
pub mod p {
    pub fn deposit(ctx: Context<Deposit>) -> Result<()> { deposit::handler(ctx) }
    pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> { withdraw::handler(ctx) }
}
mod deposit {
    #[derive(Accounts)]
    pub struct Deposit<'info> {
        #[account(mut, has_one = owner)] pub vault: Account<'info, Vault>,
        pub owner: Signer<'info>,
    }
    pub fn handler(ctx: Context<Deposit>) -> Result<()> { Ok(()) }
}
mod withdraw {
    #[derive(Accounts)]
    pub struct Withdraw<'info> {
        #[account(mut)] pub vault: Account<'info, Vault>,
        pub boss: Signer<'info>,
    }
    pub fn handler(ctx: Context<Withdraw>) -> Result<()> {
        require_keys_eq!(ctx.accounts.vault.boss, ctx.accounts.boss.key());
        Ok(())
    }
}
"#;
        let k = kinds(base);
        assert!(k.slot("handler", "vault").is_none());
        assert!(k.slot("withdraw", "vault").is_some_and(|s| s.attrs.mutable));
        assert!(!k.slot("withdraw", "boss").unwrap().attrs.mutable);
        // A check on a one-line field, or in a module's `handler`, removed:
        // named on the instruction it belongs to.
        let gone = |h: &str| diff(&kinds(base), &kinds(h)).into_iter().filter(|c| c.severity == Severity::Regression).map(|c| c.slot()).collect::<Vec<_>>();
        assert_eq!(gone(&base.replace("mut, has_one = owner", "mut")), ["deposit.vault"]);
        let removed = base.replace("        require_keys_eq!(ctx.accounts.vault.boss, ctx.accounts.boss.key());\n", "");
        assert_eq!(gone(&removed), ["withdraw.vault"]);
        // Annotated where the check was written: the module's `handler`.
        let at = base.lines().position(|l| l.contains("fn handler(ctx: Context<Withdraw>)")).unwrap() + 1;
        assert_eq!(kinds(base).handler_at("withdraw").map(|(_, l)| l), Some(at));

        // No one other fn takes its struct (two share it, or none does):
        // still compared, as `handler(Shared)`, never dropped.
        let shared = r#"
pub mod p {
    pub fn open(ctx: Context<Shared>) -> Result<()> { s::handler(ctx) }
    pub fn close(ctx: Context<Shared>) -> Result<()> { s::handler(ctx) }
}
mod s {
    #[derive(Accounts)]
    pub struct Shared<'info> {
        #[account(mut)]
        pub vault: Account<'info, Vault>,
        pub boss: Signer<'info>,
    }
    pub fn handler(ctx: Context<Shared>) -> Result<()> {
        require_keys_eq!(ctx.accounts.vault.boss, ctx.accounts.boss.key());
        Ok(())
    }
}
mod t {
    #[derive(Accounts)]
    pub struct Other<'info> { pub x: Signer<'info> }
    pub fn handler(ctx: Context<Other>) -> Result<()> { Ok(()) }
}
"#;
        let removed = shared.replace("        require_keys_eq!(ctx.accounts.vault.boss, ctx.accounts.boss.key());\n", "");
        let regressions = |b: &str, h: &str| diff(&kinds(b), &kinds(h)).into_iter().filter(|c| c.severity == Severity::Regression).count();
        assert_eq!(regressions(shared, &removed), 1);
        // A real instruction named `handler` beside module ones: still compared.
        let real = shared.replace("pub fn close(ctx: Context<Shared>)", "pub fn handler(ctx: Context<Shared>)");
        let removed = real.replace("        require_keys_eq!(ctx.accounts.vault.boss, ctx.accounts.boss.key());\n", "");
        assert!(regressions(&real, &removed) > 0);
        // The real one with the same check as the module's: removing only
        // the real one's is still a removal.
        let both = real.replace(
            "pub fn handler(ctx: Context<Shared>) -> Result<()> { s::handler(ctx) }",
            "pub fn handler(ctx: Context<Shared>) -> Result<()> {\n        require_keys_eq!(ctx.accounts.vault.boss, ctx.accounts.boss.key());\n        s::handler(ctx)\n    }",
        );
        let removed = both.replacen("        require_keys_eq!(ctx.accounts.vault.boss, ctx.accounts.boss.key());\n", "", 1);
        assert!(regressions(&both, &removed) > 0, "{:?}", diff(&kinds(&both), &kinds(&removed)));
        // Two `open` wrappers and the module's `handler` with the same check:
        // removing only the handler's is still a removal; moving one to
        // another account is not.
        let wrappers = shared
            .replace("pub fn close(ctx: Context<Shared>) -> Result<()> { s::handler(ctx) }\n}",
                "}\npub mod q {\n    pub fn open(ctx: Context<Shared>) -> Result<()> {\n        require_keys_eq!(ctx.accounts.vault.boss, ctx.accounts.boss.key());\n        s::handler(ctx)\n    }\n}");
        let in_handler = "    pub fn handler(ctx: Context<Shared>) -> Result<()> {\n        require_keys_eq!(ctx.accounts.vault.boss, ctx.accounts.boss.key());\n";
        let removed = wrappers.replace(in_handler, "    pub fn handler(ctx: Context<Shared>) -> Result<()> {\n");
        assert_eq!(regressions(&wrappers, &removed), 1, "{:?}", diff(&kinds(&wrappers), &kinds(&removed)));
        assert_eq!(regressions(&wrappers, &wrappers), 0);
    }
}
