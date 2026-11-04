//! `solinv diff --base-idl --head-idl`: the account checks an IDL update removes.
//!
//! The source diff reads what a pull request changes; this reads what a
//! deployed program changed, from two versions of its IDL — the one an
//! audit saw and the one on chain now, or each upgrade against the one
//! before it. The IDL says less than the source (no `owner`, no
//! `constraint`, no account types), so this sees fewer removals: a slot
//! that stops being a `Signer`, loses its `seeds` or `address`, or loses
//! a `has_one` (the IDL's `relations`). What it sees, it sees without
//! the source, which is the point for a program whose source is not
//! published or not pinned to the deployed build.
//!
//! Renames are paired by shape, so a renamed slot or instruction is still
//! compared: slots one to one, only when signer and writable agree;
//! instructions when the argument names match and three quarters of the
//! slot names do. Relations and account seeds are read through the
//! pairing. What a pairing finds is a warning, not a removed check,
//! because the pairing is a guess, and a pairing that is not plainly a
//! rename is reported itself. An instruction that goes away loosens
//! nothing, unless a new one replaces it: one that had checks while new
//! instructions appeared is reported with the closest of them.
//!
//! Anchor writes seeds, addresses and relations only for an IDL built with
//! account resolution, so for a version built without it those three are
//! not compared (one warning says so); signer and optional still are. A
//! lost `has_one` is a removed check only while the slot that declared it
//! is still there under its name.

use crate::diff::{Change, Severity};
use crate::idl::{Idl, IdlAccount, IdlInstruction, IdlPda, IdlSeed};
use std::collections::{BTreeMap, BTreeSet};

fn change(severity: Severity, ix: &str, path: &str, message: String) -> Change {
    Change { severity, ix: ix.to_string(), path: path.to_string(), message, file: String::new(), line: 0 }
}

/// A slot's checks as labels, for "slot removed" messages.
fn checks(a: &IdlAccount) -> Vec<String> {
    let mut out = Vec::new();
    if a.signer {
        out.push("signer".to_string());
    }
    if a.pda.is_some() {
        out.push("seeds".to_string());
    }
    if a.address.is_some() {
        out.push("address".to_string());
    }
    // `relations` sit on the slot a `has_one` names: `authority` listing
    // `vault` means `vault` declares `has_one = authority`.
    out.extend(a.relations.iter().map(|r| format!("{r} has_one = {}", a.name)));
    out
}

/// Base slot names as head calls them: renamed slots map to their new
/// name, the rest to themselves. Keyed by leaf name within one composite,
/// which is how relations and account seeds name a sibling.
struct Renames {
    paths: BTreeMap<String, String>,
    /// Pairings a reader should be told about: base path -> head path.
    guessed: Vec<(String, String)>,
}

fn prefix_of(path: &str) -> &str {
    path.rsplit_once('.').map_or("", |(p, _)| p)
}

fn leaf_of(path: &str) -> &str {
    path.rsplit_once('.').map_or(path, |(_, l)| l)
}

impl Renames {
    /// The head path of a base slot, if it is still there (same path or renamed).
    fn head_path<'a>(&'a self, base_path: &'a str) -> &'a str {
        self.paths.get(base_path).map_or(base_path, String::as_str)
    }

    /// A sibling name (relation target, seed path's first segment) seen from
    /// the composite `prefix`, in head's names.
    fn sibling(&self, prefix: &str, name: &str) -> String {
        let (first, rest) = name.split_once('.').map_or((name, None), |(f, r)| (f, Some(r)));
        let full = if prefix.is_empty() { first.to_string() } else { format!("{prefix}.{first}") };
        let renamed = self.paths.get(&full).map_or(first, |p| leaf_of(p));
        match rest {
            Some(r) => format!("{renamed}.{r}"),
            None => renamed.to_string(),
        }
    }

    /// `legacy`: the seed's IDL was converted from the legacy format, the only place an
    /// unconverted-seed mark can come from.
    fn seed_key(&self, prefix: &str, s: &IdlSeed, legacy: bool) -> String {
        match s {
            IdlSeed::Const { value } if legacy && value.starts_with(crate::legacy::UNCONVERTED) => {
                format!("unconverted:{value:?}")
            }
            IdlSeed::Const { value } => format!("const:{value:?}"),
            // `account` names the account's type, which does not change the
            // derivation (and the legacy format writes it where the current
            // one leaves it out).
            IdlSeed::Account { path, .. } => format!("account:{}", self.sibling(prefix, path)),
            IdlSeed::Arg { path } => format!("arg:{path}"),
        }
    }
}

fn same_seeds(r: &Renames, prefix: &str, base: &IdlPda, head: &IdlPda, legacy: (bool, bool)) -> bool {
    let none = Renames { paths: BTreeMap::new(), guessed: Vec::new() };
    let b = (
        base.seeds.iter().map(|s| r.seed_key(prefix, s, legacy.0)).collect::<Vec<_>>(),
        base.program.as_ref().map(|s| r.seed_key(prefix, s, legacy.0)),
    );
    let h = (
        head.seeds.iter().map(|s| none.seed_key("", s, legacy.1)).collect::<Vec<_>>(),
        head.program.as_ref().map(|s| none.seed_key("", s, legacy.1)),
    );
    b == h
}

/// Pair slots only base has with slots only head has, one to one, in
/// order. A pair must agree on signer and writable: a "rename" that drops
/// the signer is reported as a removed slot instead, which keeps it loud.
/// Among those, the same composite and the same seed and address presence
/// come first.
fn renames(b: &[(String, &IdlAccount)], h: &[(String, &IdlAccount)]) -> Renames {
    let bset: BTreeSet<&str> = b.iter().map(|(p, _)| p.as_str()).collect();
    let hset: BTreeSet<&str> = h.iter().map(|(p, _)| p.as_str()).collect();
    let free: Vec<&(String, &IdlAccount)> = h.iter().filter(|(p, _)| !bset.contains(p.as_str())).collect();
    // Relations tie a slot to its siblings by name, so they are the best
    // evidence of a rename: `b` -> `c` when the slots that listed `b` now
    // list `c`, or when the slot lists the same siblings it did.
    let listed_by = |slots: &[(String, &IdlAccount)], name: &str, prefix: &str| -> BTreeSet<String> {
        slots
            .iter()
            .filter(|(p, a)| prefix_of(p) == prefix && a.relations.iter().any(|r| r == name))
            .map(|(p, _)| leaf_of(p).to_string())
            .collect()
    };
    // Best pair first across all candidates, so slot order does not decide.
    let gone: Vec<&(String, &IdlAccount)> = b.iter().filter(|(p, _)| !hset.contains(p.as_str())).collect();
    let mut pairs = Vec::new();
    let mut shared_of = BTreeMap::new();
    for (bi, (bp, ba)) in gone.iter().map(|x| (&x.0, x.1)).enumerate() {
        let b_listers = listed_by(b, leaf_of(bp), prefix_of(bp));
        for (hi, (hp, ha)) in free.iter().map(|x| (&x.0, x.1)).enumerate() {
            if ha.signer != ba.signer || ha.writable != ba.writable {
                continue;
            }
            let h_listers = listed_by(h, leaf_of(hp), prefix_of(hp));
            let shared = b_listers.intersection(&h_listers).count()
                + ba.relations.iter().filter(|r| ha.relations.contains(r)).count();
            let score = (shared, prefix_of(hp) == prefix_of(bp), ha.pda.is_some() == ba.pda.is_some(), ha.address == ba.address);
            pairs.push((score, std::cmp::Reverse(bi), std::cmp::Reverse(hi), bi, hi));
            shared_of.insert((bi, hi), shared);
        }
    }
    pairs.sort_by(|x, y| y.cmp(x));
    let (mut used_b, mut used_h) = (BTreeSet::new(), BTreeSet::new());
    let mut paths = BTreeMap::new();
    let mut guessed = Vec::new();
    for (_, _, _, bi, hi) in pairs {
        if used_b.contains(&bi) || used_h.contains(&hi) {
            continue;
        }
        used_b.insert(bi);
        used_h.insert(hi);
        paths.insert(gone[bi].0.clone(), free[hi].0.clone());
        // Sure only when it is the one slot gone and the one slot new in its
        // composite, and either relations agree or the slot checked nothing
        // itself. Anything else (two new slots for one gone, a signer
        // replaced by a differently named signer) is a guess a reader must
        // see, or it could silently excuse a lost check.
        let (bp, ba) = (&gone[bi].0, gone[bi].1);
        let hp = &free[hi].0;
        // A dropped fixed-address slot (a sysvar) is not a rename candidate.
        let candidate = |a: &IdlAccount| !(a.address.is_some() && !a.signer && a.pda.is_none() && a.relations.is_empty());
        let one_to_one = gone.iter().filter(|(p, a)| prefix_of(p) == prefix_of(bp) && candidate(a)).count() == 1
            && free.iter().filter(|(p, _)| prefix_of(p) == prefix_of(hp)).count() == 1;
        // A slot another slot's seeds read is checked through them.
        let named_by_seeds = b.iter().any(|(p, a)| {
            prefix_of(p) == prefix_of(bp)
                && a.pda.as_ref().is_some_and(|pda| {
                    pda.seeds.iter().any(|s| matches!(s, IdlSeed::Account { path, .. } if path.split('.').next() == Some(leaf_of(bp))))
                })
        });
        let checks_itself =
            ba.signer || ba.pda.is_some() || ba.address.is_some() || !ba.relations.is_empty() || named_by_seeds;
        if !(one_to_one && (shared_of[&(bi, hi)] > 0 || !checks_itself)) {
            guessed.push((bp.clone(), hp.clone()));
        }
    }
    Renames { paths, guessed }
}

fn flat(ix: &IdlInstruction) -> Vec<(String, &IdlAccount)> {
    ix.flat_accounts().into_iter().map(|f| (f.path(), f.account)).collect()
}

fn signers(ix: &IdlInstruction) -> usize {
    ix.flat_accounts().iter().filter(|f| f.account.signer).count()
}

/// `guessed`: `h` was paired with `b` by shape, not by name, so every
/// finding is a warning — a wrong guess must not fail a build.
/// `resolved`: head was built with account resolution, so its seeds,
/// addresses and relations can be compared at all.
/// `legacy`: (base, head) converted from the legacy format.
fn diff_ix(b: &IdlInstruction, h: &IdlInstruction, guessed: bool, resolved: bool, legacy: (bool, bool), out: &mut Vec<Change>) {
    let addresses = !legacy.0 && !legacy.1;
    let (bs, hs) = (flat(b), flat(h));
    let head: BTreeMap<&str, &IdlAccount> = hs.iter().map(|(p, a)| (p.as_str(), *a)).collect();
    let r = renames(&bs, &hs);
    let mut signer_reported = false;
    for (bp, hp) in &r.guessed {
        out.push(change(
            Severity::Warning,
            &h.name,
            bp,
            format!(
                "taken to be renamed to `{hp}`, a guess from its shape: its checks and the has_one \
                 that name it are compared through that guess — confirm it"
            ),
        ));
    }
    // In the IDL's slot order, so the report reads like the struct.
    for (path, ba) in &bs {
        let hp = r.head_path(path);
        let prefix = prefix_of(path);
        let Some(ha) = head.get(hp) else {
            let gone = checks(ba);
            // A slot with only a fixed address (a sysvar, a program) that the
            // instruction stops taking loosens nothing.
            let address_only = gone.len() == 1 && ba.address.is_some();
            if !gone.is_empty() && !address_only {
                signer_reported |= ba.signer;
                out.push(change(
                    Severity::Warning,
                    &h.name,
                    path,
                    format!(
                        "slot removed or renamed; its checks ({}) are not compared — \
                         confirm the replacement keeps them",
                        gone.join(", ")
                    ),
                ));
            }
            continue;
        };
        let at = if hp == path { path.clone() } else { format!("{path} (now {hp})") };
        let mut removed = Vec::new();
        if ba.signer && !ha.signer {
            signer_reported = true;
            removed.push("no longer a signer".to_string());
        }
        let mut loosened = Vec::new(); // removed, but not surely: reported as warnings
        match (&ba.pda, &ha.pda) {
            _ if !resolved => {}
            (Some(_), None) => removed.push("seeds removed".to_string()),
            (Some(x), Some(y)) if !same_seeds(&r, prefix, x, y, legacy) => out.push(change(
                Severity::Warning,
                &h.name,
                &at,
                "seeds changed: the slot now resolves to a different address".to_string(),
            )),
            _ => {}
        }
        match (&ba.address, &ha.address) {
            _ if !resolved || !addresses => {}
            (Some(_), None) => removed.push("fixed address removed".to_string()),
            (Some(x), Some(y)) if x != y => out.push(change(
                Severity::Warning,
                &h.name,
                &at,
                format!("fixed address changed from {x} to {y}"),
            )),
            _ => {}
        }
        for rel in ba.relations.iter().filter(|_| resolved) {
            let now = r.sibling(prefix, rel);
            if ha.relations.contains(&now) {
                continue;
            }
            let msg = format!("`{now}` no longer declares `has_one = {}`", leaf_of(hp));
            // Sure only when the declaring slot is still there under its name:
            // a declarer that was removed or renamed takes its has_one with it.
            let declarer = if prefix.is_empty() { rel.clone() } else { format!("{prefix}.{rel}") };
            if r.head_path(&declarer) == declarer && head.contains_key(declarer.as_str()) {
                removed.push(msg);
            } else {
                loosened.push(format!("{msg} (that slot was removed or renamed)"));
            }
        }
        // On a slot paired by shape the loss may be the pairing's.
        let sure = !guessed && hp == path;
        if !removed.is_empty() {
            let severity = if sure { Severity::Regression } else { Severity::Warning };
            out.push(change(severity, &h.name, &at, removed.join("; ")));
        }
        if !loosened.is_empty() {
            out.push(change(Severity::Warning, &h.name, &at, loosened.join("; ")));
        }
        if !ba.optional && ha.optional {
            out.push(change(Severity::Warning, &h.name, &at, "now optional: a caller may leave it out".to_string()));
        }
    }
    let (sb, sh) = (signers(b), signers(h));
    if sh < sb && !signer_reported {
        out.push(change(
            Severity::Warning,
            &h.name,
            "",
            format!("takes {sh} signer(s), down from {sb}: confirm no required signature was dropped"),
        ));
    }
    if !b.is_unsigned_writer() && h.is_unsigned_writer() {
        out.push(change(
            Severity::Warning,
            &h.name,
            "",
            "now has no signer and writes an account the IDL leaves unchecked".to_string(),
        ));
    }
}

/// An instruction renamed between versions: the unmatched head instruction
/// with the same argument names and at least three quarters of the slot
/// names (of the larger of the two) in common, nine tenths when neither
/// takes arguments. Common names (`group`,
/// `authority`, `token_program`) make a looser rule pair unrelated
/// instructions.
fn renamed_ix<'a>(b: &IdlInstruction, candidates: &[&'a IdlInstruction]) -> Option<&'a IdlInstruction> {
    let names: BTreeSet<String> = b.flat_accounts().iter().map(|f| f.path()).collect();
    let args: Vec<&str> = b.args.iter().map(|a| a.name.as_str()).collect();
    if names.is_empty() {
        return None;
    }
    candidates
        .iter()
        .filter(|h| h.args.iter().map(|a| a.name.as_str()).collect::<Vec<_>>() == args)
        .map(|h| {
            let theirs = h.flat_accounts();
            let common = theirs.iter().filter(|f| names.contains(&f.path())).count();
            (common, names.len().max(theirs.len()), *h)
        })
        // With no arguments to agree on, ask for nearly every slot.
        .filter(|(common, size, _)| if args.is_empty() { common * 10 >= size * 9 } else { common * 4 >= size * 3 })
        .max_by_key(|(common, _, _)| *common)
        .map(|(_, _, h)| h)
}

/// Anchor writes seeds, addresses and relations only when the IDL is built with account
/// resolution, and then every fixed-address slot (`system_program`, a sysvar) carries its
/// `address`. So a base with a fixed address anywhere (or, legacy, with seeds or relations) was
/// built with it, and a head with none of the three anywhere was built without it: it changed
/// its build, not (necessarily) those checks. They are not compared, and one warning says so.
/// Judged on the whole IDL, so renaming or dropping one slot cannot dodge it; a base with no
/// fixed address at all proves nothing, so a small IDL that loses its only has_one is still
/// compared slot by slot.
fn built_without_resolution(base: &Idl, head: &Idl) -> bool {
    let any = |idl: &Idl, f: &dyn Fn(&crate::idl::IdlAccount) -> bool| {
        idl.instructions.iter().any(|ix| ix.flat_accounts().iter().any(|s| f(s.account)))
    };
    let base_resolved = any(base, &|a| a.address.is_some())
        || (base.legacy && any(base, &|a| a.pda.is_some() || !a.relations.is_empty()));
    let head_resolved = any(head, &|a| a.address.is_some() || a.pda.is_some() || !a.relations.is_empty());
    base_resolved && !head_resolved
}

pub fn diff_idl(base: &Idl, head: &Idl) -> Vec<Change> {
    let resolved = !built_without_resolution(base, head);
    let legacy = (base.legacy, head.legacy);
    let mut out = Vec::new();
    if !resolved {
        out.push(change(
            Severity::Warning,
            "",
            "",
            "the new IDL gives no fixed address, seeds or has_one anywhere, even for slots that \
             had one: built without account resolution? Only signer, optional and writable are \
             compared"
                .to_string(),
        ));
    }
    let base_names: BTreeSet<&str> = base.instructions.iter().map(|b| b.name.as_str()).collect();
    let head_names: BTreeSet<&str> = head.instructions.iter().map(|h| h.name.as_str()).collect();
    let mut unmatched: Vec<&IdlInstruction> = head.instructions.iter().filter(|h| !base_names.contains(h.name.as_str())).collect();
    let mut renamed_to: BTreeMap<&str, &IdlInstruction> = BTreeMap::new();
    for b in base.instructions.iter().filter(|b| !head_names.contains(b.name.as_str())) {
        if let Some(h) = renamed_ix(b, &unmatched) {
            unmatched.retain(|u| u.name != h.name);
            renamed_to.insert(h.name.as_str(), b);
        }
    }
    // A base instruction with checks that went away while new ones came:
    // one of them may replace it under a new name and signature. Say so,
    // naming the closest, so a loosening there is never silent.
    let overlap = |b: &IdlInstruction, h: &IdlInstruction| {
        let names: BTreeSet<String> = b.flat_accounts().iter().map(|f| f.path()).collect();
        h.flat_accounts().iter().filter(|f| names.contains(&f.path())).count()
    };
    for b in base.instructions.iter().filter(|b| !head_names.contains(b.name.as_str())) {
        if renamed_to.values().any(|r| r.name == b.name) {
            continue;
        }
        // Fixed addresses are left out: nearly every instruction takes
        // `system_program`, and a replacement that drops one shows up as an
        // unsigned writer or in its own slots more often than not.
        let checked = b.flat_accounts().iter().any(|f| f.account.signer || f.account.pda.is_some() || !f.account.relations.is_empty());
        // Named even with no slot name in common: a replacement may rename
        // every slot, and "shares 0" says how weak the guess is.
        let closest = unmatched.iter().max_by_key(|h| overlap(b, h));
        if let (true, Some(h)) = (checked, closest) {
            out.push(change(
                Severity::Warning,
                &b.name,
                "",
                format!(
                    "removed; if `{}` (shares {} slot name(s)) replaces it, its checks are not compared",
                    h.name,
                    overlap(b, h)
                ),
            ));
        }
    }
    for h in &head.instructions {
        if let Some(b) = base.instructions.iter().find(|b| b.name == h.name) {
            diff_ix(b, h, false, resolved, legacy, &mut out);
        } else if let Some(b) = renamed_to.get(h.name.as_str()) {
            let before = out.len();
            diff_ix(b, h, true, resolved, legacy, &mut out);
            for c in &mut out[before..] {
                c.message = format!("{} (compared with `{}`, which this may replace)", c.message, b.name);
            }
        } else if h.is_unsigned_writer() {
            out.push(change(
                Severity::Warning,
                &h.name,
                "",
                "new instruction with no signer that writes an account the IDL leaves unchecked: \
                 confirm it is meant to be callable by anyone"
                    .to_string(),
            ));
        }
    }
    collapse_guesses(out)
}

/// The same rename guessed in several instructions is one line, listing them.
fn collapse_guesses(changes: Vec<Change>) -> Vec<Change> {
    let mut out: Vec<Change> = Vec::new();
    for c in changes {
        if c.message.contains("a guess from its shape") {
            if let Some(prev) = out.iter_mut().find(|p| p.path == c.path && p.message == c.message) {
                prev.ix = format!("{}, {}", prev.ix, c.ix);
                continue;
            }
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn idl(accounts: &str) -> Idl {
        Idl::from_json(&format!(
            r#"{{"instructions":[{{"name":"withdraw","discriminator":[1,2,3,4,5,6,7,8],"accounts":[{accounts}]}}]}}"#
        ))
        .unwrap()
    }

    const BASE: &str = r#"
        {"name":"vault","writable":true,"pda":{"seeds":[{"kind":"const","value":[118]},{"kind":"account","path":"owner"}]}},
        {"name":"owner","signer":true,"relations":["vault"]},
        {"name":"rent","address":"SysvarRent111111111111111111111111111111111"}"#;

    fn messages(c: &[Change]) -> Vec<String> {
        c.iter().map(|c| format!("{:?} {} {}", c.severity, c.slot(), c.message)).collect()
    }

    #[test]
    fn same_idl_is_quiet() {
        assert!(diff_idl(&idl(BASE), &idl(BASE)).is_empty());
    }

    #[test]
    fn dropped_signer_seeds_and_has_one_are_regressions() {
        let head = idl(r#"
            {"name":"vault","writable":true},
            {"name":"owner"},
            {"name":"rent","address":"SysvarRent111111111111111111111111111111111"}"#);
        let m = messages(&diff_idl(&idl(BASE), &head));
        assert_eq!(m, vec![
            "Regression withdraw.vault seeds removed".to_string(),
            "Regression withdraw.owner no longer a signer; `vault` no longer declares `has_one = owner`".to_string(),
            "Warning withdraw now has no signer and writes an account the IDL leaves unchecked".to_string(),
        ]);
    }

    #[test]
    fn dropped_sysvar_slot_and_clean_rename_are_quiet() {
        // `owner` -> `authority`: Anchor rewrites the seed path and the
        // relation with it. `rent` goes.
        let head = idl(r#"
            {"name":"vault","writable":true,"pda":{"seeds":[{"kind":"const","value":[118]},{"kind":"account","path":"authority"}]}},
            {"name":"authority","signer":true,"relations":["vault"]}"#);
        assert!(diff_idl(&idl(BASE), &head).is_empty(), "{:?}", messages(&diff_idl(&idl(BASE), &head)));
    }

    #[test]
    fn renaming_the_declaring_slot_keeps_its_has_one() {
        let base = idl(r#"{"name":"vault"},{"name":"authority","signer":true,"relations":["vault"]}"#);
        let head = idl(r#"{"name":"user_vault"},{"name":"authority","signer":true,"relations":["user_vault"]}"#);
        assert!(diff_idl(&base, &head).is_empty(), "{:?}", messages(&diff_idl(&base, &head)));
    }

    #[test]
    fn a_new_slot_stands_in_for_one_removed_slot_at_most() {
        // Two signers become one: the second is reported, not absorbed.
        let base = idl(r#"{"name":"owner","signer":true},{"name":"cosigner","signer":true},{"name":"state","writable":true}"#);
        let head = idl(r#"{"name":"authority","signer":true},{"name":"state","writable":true}"#);
        let m = messages(&diff_idl(&base, &head));
        assert_eq!(m.len(), 2, "{m:?}");
        assert!(m[0].starts_with("Warning withdraw.owner taken to be renamed to `authority`"), "{m:?}");
        assert!(m[1].starts_with("Warning withdraw.cosigner slot removed or renamed"), "{m:?}");
        // A dropped signer is not "renamed" to an unrelated writable payer.
        let base = idl(r#"{"name":"state","writable":true},{"name":"admin","signer":true}"#);
        let head = idl(r#"{"name":"state","writable":true},{"name":"payer","signer":true,"writable":true}"#);
        let m = messages(&diff_idl(&base, &head));
        assert!(m.iter().any(|m| m.starts_with("Warning withdraw.admin slot removed")), "{m:?}");
    }

    #[test]
    fn renamed_slot_losses_are_warnings_naming_the_new_slot() {
        let head = idl(r#"
            {"name":"user_vault","writable":true},
            {"name":"owner","signer":true,"relations":["user_vault"]},
            {"name":"rent","address":"SysvarRent111111111111111111111111111111111"}"#);
        let m = messages(&diff_idl(&idl(BASE), &head));
        assert_eq!(m, vec!["Warning withdraw.vault (now user_vault) seeds removed".to_string()]);
    }

    #[test]
    fn a_renamed_instruction_is_compared_as_warnings() {
        let base = idl(r#"{"name":"vault","writable":true},{"name":"owner","signer":true,"relations":["vault"]},{"name":"payer","signer":true}"#);
        let mut head = idl(r#"{"name":"vault","writable":true},{"name":"owner"},{"name":"payer","signer":true}"#);
        head.instructions[0].name = "withdraw_v2".into();
        let m = messages(&diff_idl(&base, &head));
        assert_eq!(m.len(), 1, "{m:?}");
        assert!(m[0].starts_with("Warning withdraw_v2.owner no longer a signer"), "{m:?}");
        assert!(m[0].ends_with("(compared with `withdraw`, which this may replace)"), "{m:?}");
    }

    #[test]
    fn an_idl_built_without_resolution_is_not_compared_slot_by_slot() {
        let head = idl(r#"{"name":"vault","writable":true},{"name":"owner","signer":true},{"name":"rent"}"#);
        let m = messages(&diff_idl(&idl(BASE), &head));
        assert_eq!(m.len(), 1, "{m:?}");
        assert!(m[0].contains("without account resolution"), "{m:?}");
    }

    #[test]
    fn without_resolution_signers_are_still_compared() {
        let base = idl(r#"{"name":"state","writable":true},{"name":"owner","signer":true},{"name":"system_program","address":"11111111111111111111111111111111"}"#);
        let head = idl(r#"{"name":"state","writable":true},{"name":"owner"},{"name":"system_program"}"#);
        let m = messages(&diff_idl(&base, &head));
        assert!(m[0].starts_with("Warning withdraw the new IDL gives no fixed address") || m[0].starts_with("Warning  the new IDL"), "{m:?}");
        assert!(m.contains(&"Regression withdraw.owner no longer a signer".to_string()), "{m:?}");
    }

    #[test]
    fn a_head_with_any_seeds_is_resolved() {
        // `system_program` turned Unchecked while seeds remain: a real loss.
        let base = idl(r#"{"name":"vault","writable":true,"pda":{"seeds":[{"kind":"const","value":[1]}]}},{"name":"owner","signer":true,"relations":["vault"]},{"name":"system_program","address":"11111111111111111111111111111111"}"#);
        let head = idl(r#"{"name":"vault","writable":true,"pda":{"seeds":[{"kind":"const","value":[1]}]}},{"name":"owner","signer":true},{"name":"system_program"}"#);
        let m = messages(&diff_idl(&base, &head));
        assert_eq!(m, vec![
            "Regression withdraw.owner `vault` no longer declares `has_one = owner`".to_string(),
            "Regression withdraw.system_program fixed address removed".to_string(),
        ]);
    }

    #[test]
    fn pairing_follows_relations_and_says_when_it_guessed() {
        // `a` dropped, `b` renamed to `c`: the has_one survives through the
        // pairing, which is named because two slots left for one.
        let base = idl(r#"{"name":"a"},{"name":"b"},{"name":"authority","signer":true,"relations":["b"]}"#);
        let head = idl(r#"{"name":"c"},{"name":"authority","signer":true,"relations":["c"]}"#);
        let m = messages(&diff_idl(&base, &head));
        assert_eq!(m.len(), 1, "{m:?}");
        assert!(m[0].starts_with("Warning withdraw.b taken to be renamed to `c`"), "{m:?}");
        // Two renamed targets in swapped order pair by what lists them.
        let base = idl(r#"{"name":"vault"},{"name":"mint"},{"name":"owner","relations":["vault"]},{"name":"mint_auth","relations":["mint"]}"#);
        let head = idl(r#"{"name":"vault"},{"name":"mint"},{"name":"mint_authority","relations":["mint"]},{"name":"user","relations":["vault"]}"#);
        let m = messages(&diff_idl(&base, &head));
        assert!(m.iter().all(|m| m.contains("taken to be renamed")), "{m:?}");
        assert!(m.iter().any(|m| m.starts_with("Warning withdraw.owner taken to be renamed to `user`")), "{m:?}");
        assert!(m.iter().any(|m| m.starts_with("Warning withdraw.mint_auth taken to be renamed to `mint_authority`")), "{m:?}");
    }

    #[test]
    fn a_guessed_pairing_never_silently_excuses_a_lost_check() {
        // `vault` stops declaring has_one = authority; a new `decoy` does.
        let base = idl(r#"{"name":"vault"},{"name":"authority","signer":true,"relations":["vault"]}"#);
        let head = idl(r#"{"name":"user_vault"},{"name":"decoy"},{"name":"authority","signer":true,"relations":["decoy"]}"#);
        let m = messages(&diff_idl(&base, &head));
        assert!(!m.is_empty(), "silent");
        assert!(m[0].starts_with("Warning withdraw.vault taken to be renamed to `decoy`"), "{m:?}");
        // A signer replaced by a differently named signer.
        let base = idl(r#"{"name":"config","writable":true},{"name":"admin","signer":true}"#);
        let head = idl(r#"{"name":"config","writable":true},{"name":"anyone","signer":true}"#);
        let m = messages(&diff_idl(&base, &head));
        assert_eq!(m.len(), 1, "{m:?}");
        assert!(m[0].starts_with("Warning withdraw.admin taken to be renamed to `anyone`"), "{m:?}");
    }

    #[test]
    fn a_replaced_instruction_with_new_args_is_named() {
        let base = idl(r#"{"name":"vault","writable":true},{"name":"owner","signer":true,"relations":["vault"]},{"name":"payer","signer":true,"writable":true}"#);
        let mut head = idl(r#"{"name":"vault","writable":true},{"name":"owner"},{"name":"payer","signer":true,"writable":true}"#);
        head.instructions[0].name = "withdraw_v2".into();
        head.instructions[0].args = idl(r#""#).instructions[0].args.clone();
        head.instructions[0].args.push(crate::idl::IdlArg { name: "memo".into(), ty: serde_json::json!("string") });
        let m = messages(&diff_idl(&base, &head));
        assert_eq!(m, vec!["Warning withdraw removed; if `withdraw_v2` (shares 3 slot name(s)) replaces it, its checks are not compared".to_string()]);
    }

    #[test]
    fn a_slot_named_by_seeds_is_not_silently_renamed() {
        let base = idl(r#"{"name":"pos","writable":true,"pda":{"seeds":[{"kind":"account","path":"market"}]}},{"name":"market"},{"name":"user","signer":true}"#);
        let head = idl(r#"{"name":"pos","writable":true,"pda":{"seeds":[{"kind":"account","path":"other"}]}},{"name":"other"},{"name":"user","signer":true}"#);
        let m = messages(&diff_idl(&base, &head));
        assert_eq!(m.len(), 1, "{m:?}");
        assert!(m[0].starts_with("Warning withdraw.market taken to be renamed to `other`"), "{m:?}");
    }

    #[test]
    fn one_guess_across_instructions_is_one_line() {
        let ix = |name: &str, acc: &str| format!(r#"{{"name":"{name}","discriminator":[1,2,3,4,5,6,7,8],"accounts":[{acc}]}}"#);
        let base = Idl::from_json(&format!(r#"{{"instructions":[{},{}]}}"#, ix("a", r#"{"name":"admin","signer":true}"#), ix("b", r#"{"name":"admin","signer":true}"#))).unwrap();
        let head = Idl::from_json(&format!(r#"{{"instructions":[{},{}]}}"#, ix("a", r#"{"name":"boss","signer":true}"#), ix("b", r#"{"name":"boss","signer":true}"#))).unwrap();
        let m = messages(&diff_idl(&base, &head));
        assert_eq!(m.len(), 1, "{m:?}");
        assert!(m[0].starts_with("Warning a, b.admin taken to be renamed to `boss`"), "{m:?}");
    }

    #[test]
    fn a_has_one_whose_declarer_left_is_a_warning() {
        // Declarer renamed and made writable: not paired, so not sure.
        let base = idl(r#"{"name":"vault"},{"name":"authority","signer":true,"relations":["vault"]}"#);
        let head = idl(r#"{"name":"user_vault","writable":true},{"name":"authority","signer":true,"relations":["user_vault"]}"#);
        let m = messages(&diff_idl(&base, &head));
        assert!(m.iter().all(|m| m.starts_with("Warning")), "{m:?}");
        // Declarer removed outright.
        let base = idl(r#"{"name":"vault","writable":true},{"name":"authority","signer":true,"relations":["vault"]}"#);
        let head = idl(r#"{"name":"authority","signer":true}"#);
        let m = messages(&diff_idl(&base, &head));
        assert_eq!(m, vec!["Warning withdraw.authority `vault` no longer declares `has_one = authority` (that slot was removed or renamed)".to_string()]);
    }

    #[test]
    fn renaming_the_address_slot_does_not_dodge_the_resolution_check() {
        let base = idl(r#"{"name":"vault","writable":true,"pda":{"seeds":[{"kind":"const","value":[118]}]}},{"name":"authority","signer":true,"relations":["vault"]},{"name":"system_program","address":"11111111111111111111111111111111"}"#);
        let head = idl(r#"{"name":"vault","writable":true},{"name":"authority","signer":true},{"name":"program"}"#);
        let m = messages(&diff_idl(&base, &head));
        assert!(m.iter().all(|m| !m.starts_with("Regression")), "{m:?}");
        assert!(m[0].contains("without account resolution"), "{m:?}");
    }

    #[test]
    fn a_legacy_head_has_no_addresses_to_lose() {
        let base = idl(r#"{"name":"vault","writable":true,"pda":{"seeds":[{"kind":"const","value":[118]}]}},{"name":"authority","signer":true,"relations":["vault"]},{"name":"system_program","address":"11111111111111111111111111111111"}"#);
        let legacy = r#"{"version":"0.1.0","name":"d","instructions":[{"name":"withdraw","accounts":[
            {"name":"vault","isMut":true,"isSigner":false,"pda":{"seeds":[{"kind":"const","type":"string","value":"v"}]},"relations":["authority"]},
            {"name":"authority","isMut":false,"isSigner":true},{"name":"systemProgram","isMut":false,"isSigner":false}],"args":[]}]}"#;
        let (head, _) = Idl::from_json_any(legacy).unwrap();
        let m = messages(&diff_idl(&base, &head));
        assert!(m.iter().all(|m| !m.contains("fixed address removed")), "{m:?}");
    }

    #[test]
    fn a_lost_byte_array_seed_in_a_legacy_base_is_reported() {
        let legacy = r#"{"version":"0.1.0","name":"d","instructions":[{"name":"withdraw","accounts":[
            {"name":"vault","isMut":true,"isSigner":false,"pda":{"seeds":[{"kind":"const","type":{"array":["u8",2]},"value":[118,49]}]}},
            {"name":"authority","isMut":false,"isSigner":true},{"name":"cfg","isMut":false,"isSigner":false,"pda":{"seeds":[{"kind":"const","type":"string","value":"c"}]}}],"args":[]}]}"#;
        let (base, _) = Idl::from_json_any(legacy).unwrap();
        let head = idl(r#"{"name":"vault","writable":true},{"name":"authority","signer":true},{"name":"cfg","pda":{"seeds":[{"kind":"const","value":[99]}]}}"#);
        let m = messages(&diff_idl(&base, &head));
        assert_eq!(m, vec!["Regression withdraw.vault seeds removed".to_string()]);
    }

    #[test]
    fn legacy_has_one_compares_cleanly_against_the_current_format() {
        let legacy = r#"{"version":"0.1.0","name":"d","instructions":[{"name":"withdraw","accounts":[
            {"name":"vault","isMut":true,"isSigner":false,"relations":["authority"]},
            {"name":"authority","isMut":false,"isSigner":true}],"args":[]}]}"#;
        let (base, _) = Idl::from_json_any(legacy).unwrap();
        let same = idl(r#"{"name":"vault","writable":true},{"name":"authority","signer":true,"relations":["vault"]}"#);
        assert!(diff_idl(&base, &same).is_empty(), "{:?}", messages(&diff_idl(&base, &same)));
        // With its only has_one gone the head declares nothing resolution writes, so a drop
        // and a build without resolution look the same: one visible warning, not silence.
        let dropped = idl(r#"{"name":"vault","writable":true},{"name":"authority","signer":true}"#);
        let m = messages(&diff_idl(&base, &dropped));
        assert_eq!(m.len(), 1, "{m:?}");
        assert!(m[0].contains("without account resolution"), "{m:?}");
        // With seeds left elsewhere it is plainly a drop.
        let base2 = Idl::from_json_any(&legacy.replace(r#""isSigner":true}"#, r#""isSigner":true},{"name":"cfg","isMut":false,"isSigner":false,"pda":{"seeds":[{"kind":"const","type":"string","value":"c"}]}}"#)).unwrap().0;
        let dropped2 = idl(r#"{"name":"vault","writable":true},{"name":"authority","signer":true},{"name":"cfg","pda":{"seeds":[{"kind":"const","value":[99]}]}}"#);
        assert_eq!(
            messages(&diff_idl(&base2, &dropped2)),
            vec!["Regression withdraw.authority `vault` no longer declares `has_one = authority`".to_string()]
        );
    }

    #[test]
    fn rename_that_loses_a_check_warns() {
        let head = idl(r#"
            {"name":"vault","writable":true,"pda":{"seeds":[{"kind":"const","value":[118]},{"kind":"account","path":"authority"}]}},
            {"name":"authority","signer":true}"#);
        let m = messages(&diff_idl(&idl(BASE), &head));
        assert_eq!(m.len(), 2, "{m:?}");
        assert!(m[0].starts_with("Warning withdraw.owner taken to be renamed to `authority`"), "{m:?}");
        assert_eq!(m[1], "Warning withdraw.owner (now authority) `vault` no longer declares `has_one = authority`");
    }

    #[test]
    fn changed_seeds_warn_and_seed_type_names_do_not_count() {
        let typed = idl(r#"
            {"name":"vault","writable":true,"pda":{"seeds":[{"kind":"const","value":[118]},{"kind":"account","path":"owner","account":"Owner"}]}},
            {"name":"owner","signer":true,"relations":["vault"]},
            {"name":"rent","address":"SysvarRent111111111111111111111111111111111"}"#);
        assert!(diff_idl(&idl(BASE), &typed).is_empty());
        let moved = idl(r#"
            {"name":"vault","writable":true,"pda":{"seeds":[{"kind":"const","value":[119]},{"kind":"account","path":"owner"}]}},
            {"name":"owner","signer":true,"relations":["vault"]},
            {"name":"rent","address":"SysvarRent111111111111111111111111111111111"}"#);
        let m = messages(&diff_idl(&idl(BASE), &moved));
        assert_eq!(m, vec!["Warning withdraw.vault seeds changed: the slot now resolves to a different address".to_string()]);
    }

    #[test]
    fn new_unsigned_writer_instruction_warns() {
        let base = idl(BASE);
        let mut head = idl(BASE);
        let mut crank = head.instructions[0].clone();
        crank.name = "crank".into();
        crank.accounts = idl(r#"{"name":"state","writable":true}"#).instructions[0].accounts.clone();
        head.instructions.push(crank);
        let m = messages(&diff_idl(&base, &head));
        assert_eq!(m.len(), 1);
        assert!(m[0].starts_with("Warning crank new instruction with no signer"), "{m:?}");
    }
}
