//! `solinv diff` for a native or Pinocchio program: the account checks a
//! change removes from the code itself.
//!
//! Such a program has no `#[derive(Accounts)]` to compare. Its checks are
//! statements: `if !payer.is_signer() { return Err(..) }`,
//! `if vault.owner() != program_id { .. }`, `if &expected != pda.key() { .. }`,
//! or a call to a helper that holds them (`require_signer(payer)?`). This
//! reads each fn's checks as atoms (what is checked about which account),
//! follows the helpers a fn propagates the result of, and names an atom a fn
//! had and no longer has, directly or through the fns it calls.
//!
//! Text only, like the rest of the source diff. An account is named by the
//! variable that holds it, or by its place in the accounts slice when the
//! fn binds it from one (`let vault = &accounts[1];`, `let [payer, vault, ..]
//! = accounts`). A check through a name it cannot resolve (another crate, a
//! fn two modules share) is not read at all, and outside instruction `match`
//! arms a fn's checks are one set: a check one branch drops and another
//! still makes on the same account is not seen. Every finding is a warning:
//! a reviewer looks, CI does not fail on it.

use crate::diff::{Change, Severity};
use crate::source::{
    braced, calls_in, closing_paren, collect, failing_conditions_at, past_logs, FAILS_RE, IF_RE, split_at_top, strip_comments, strip_comments_and_strings,
    file_mods, top_level, unparen, Callee, Demand, FnIndex,
};
use anyhow::{Context, Result};
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::sync::LazyLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    Signer,
    Writable,
    Executable,
    Owner,
    Key,
}

/// One thing checked about one account: `payer` signs, `vault`'s owner is
/// `program_id`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Atom {
    pub kind: Kind,
    /// The account: `payer`, `accounts[0]`.
    pub var: String,
    /// What its owner or key is compared with.
    pub against: Option<String>,
    /// Parameters that must be `true` for the check to run:
    /// `if expect_signer && !a.is_signer()`.
    when: Vec<String>,
    /// `var` is a value, not an account (`if admin != signer`): a check on
    /// an account once a caller passes one's key or owner for it
    /// (`require_admin(header.admin, a.key)`).
    pending: bool,
}

/// How an atom came into a fn.
#[derive(Clone, Debug)]
enum Origin {
    /// The fn's own condition, as written.
    Direct(String),
    /// Through a call: its index in the fn's calls, and whether the callee
    /// holds the atom unconditionally itself (so a change inside it is
    /// reported there).
    Call(usize, bool),
}

#[derive(Clone)]
struct Call {
    target: Option<usize>,
    /// `name(args)`, whitespace dropped.
    text: String,
    args: Vec<String>,
    at: usize,
}

struct NativeFn {
    key: String,
    display: String,
    file: String,
    line: usize,
    /// Each atom, the condition it is from, where.
    direct: Vec<(Atom, String, usize)>,
    calls: Vec<Call>,
    /// `let name = &slice[n]` and `let [a, b, ..] = slice`: (where, name,
    /// `slice[n]`).
    lets: Vec<(usize, String, String)>,
    /// Its body (an arm's, inside the braces), literals blanked.
    text: String,
    /// An arm: the fn it is in, whose checks before the `match` it runs too.
    parent: Option<usize>,
    /// Where `text` is in the fn's body.
    span: std::ops::Range<usize>,
}

/// The fns of a native or Pinocchio program and their checks.
pub struct NativeChecks {
    fns: Vec<NativeFn>,
    params: Vec<Vec<String>>,
    entrypoint: bool,
}

/// A fn whose body is one expression: inlined where a condition calls it.
type Preds = HashMap<String, Option<(Vec<String>, String)>>;

/// How many calls deep a check is followed.
const DEPTH: usize = 4;

static CHAIN: &str = r"[A-Za-z_]\w*(?:\[[^\]]*\])?(?:\.[A-Za-z_]\w*(?:\(\))?(?:\[[^\]]*\])?)*?";
static FLAG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r"^({CHAIN})\.(is_signer|is_writable|executable)(?:\(\))?$")).unwrap());
static OWNED_BY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r"^({CHAIN})\.(?:is_owned_by|owned_by)\((.*)\)$")).unwrap());
static SIDE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r"^({CHAIN})\.(key|address|owner)(?:\(\))?$")).unwrap());
static EQ_FN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:[A-Za-z_]\w*::)*(?:[a-z_]*eq|cmp_pubkeys|[a-z_]*_equal)\((.*)\)$").unwrap()
});
/// `sol_memcmp(a, b, 32) == 0`: `a` equals `b`.
static MEMCMP_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:[A-Za-z_]\w*::)*sol_memcmp\((.*)\)$").unwrap());
/// This program's id, however it is named.
static THIS_PROGRAM_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:(?:crate::)?(?:ID|id\(\))|program_id)$").unwrap());
static METHOD_EQ_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(.*)\.(eq|ne)\((.*)\)$").unwrap());
static CALL_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(?:[A-Za-z_]\w*::)*([a-z_]\w*)\((.*)\)$").unwrap());
static WRAP_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:[A-Za-z_]\w*::)*(?:Pubkey|Address)::(?:new_from_array|from|new)\((.*)\)$").unwrap()
});
static MATCH_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bmatch\b").unwrap());
static VARIANT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^((?:[A-Za-z_]\w*\s*::\s*)+[A-Z]\w*)\s*(?:[({][\s\S]*)?$").unwrap());
static RETURN_ERR_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\breturn\s+Err\s*\(").unwrap());
static HINT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:[A-Za-z_]\w*::)*(?:likely|unlikely)\((.*)\)$").unwrap());
static ENTRYPOINT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\b(?:lazy_program_entrypoint|program_entrypoint|lazy_entrypoint|entrypoint|entrypoint_no_alloc)\s*!\s*\(|\bextern\s+"[^"]*"\s+fn\s+entrypoint\b"#).unwrap()
});
static HEAD_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(^|[^.\w:])([A-Za-z_]\w*)").unwrap());
/// An argument that needs no parentheses: `&a.b[0].c()`.
static PLAIN_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[&*]*[A-Za-z_][\w.\[\]()]*$").unwrap());
static PLACE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z_]\w*\[\d+\]").unwrap());
static IDENT_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z_]\w*$").unwrap());
static WORD_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b[A-Za-z_]\w*\b").unwrap());
static INDEXED_LET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\blet\s+(?:mut\s+)?([a-z_]\w*)\s*(?::[^=;]*)?=\s*&?\s*(?:mut\s+)?([a-z_]\w*)\s*\[\s*(\d+)\s*\]\s*;").unwrap()
});
static SLICE_LET_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\blet\s*\[([^\]]*)\]\s*=\s*(?:match\s+)?&?\s*([a-z_]\w*)\b").unwrap());

/// A text with whitespace dropped; `&mut x` kept apart from `&mutx`.
fn squeeze(s: &str) -> String {
    let s = Regex::new(r"&\s*mut\s+").unwrap().replace_all(s, "&");
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

/// `&*x.as_ref()` → `x`: the value, not how it is borrowed.
fn bare(s: &str) -> String {
    let mut t = s.trim().to_string();
    loop {
        let before = t.clone();
        t = t.trim_start_matches(['&', '*']).to_string();
        if let Some(inner) = t.strip_prefix("unsafe{").and_then(|r| r.strip_suffix('}')) {
            t = inner.to_string();
        }
        t = unparen(&t);
        // Branch hints: `unlikely(c)` is `c`.
        if let Some(m) = HINT_RE.captures(&t) {
            if closing_paren(&t[m.get(1).unwrap().start()..]) == Some(m[1].len()) {
                t = m[1].to_string();
            }
        }
        if let Some(m) = WRAP_RE.captures(&t) {
            if closing_paren(&t[m.get(1).unwrap().start()..]) == Some(m[1].len()) {
                t = m[1].to_string();
            }
        }
        for suffix in [".as_ref()", ".as_array()", ".to_bytes()", ".to_account_info()", ".clone()", ".deref()"] {
            if let Some(r) = t.strip_suffix(suffix) {
                t = r.to_string();
            }
        }
        if t == before {
            return t;
        }
    }
}

/// The atoms of a rejecting condition (`if cond { return Err }`). Each
/// `||` part rejects alone; a part joined by `&&` checks only when every
/// other conjunct is a bare name (a flag), and needs those names `true`.
fn atoms_of(cond: &str, preds: &Preds) -> Vec<Atom> {
    atoms_in(&squeeze(cond), preds, 0)
}

fn atoms_in(t: &str, preds: &Preds, depth: usize) -> Vec<Atom> {
    let mut out = Vec::new();
    for part in split_at_top(&unparen(t), "||") {
        let part = unparen(part);
        let conj = split_at_top(&part, "&&");
        let mut when = Vec::new();
        let mut checks = Vec::new();
        for c in &conj {
            let c = unparen(c);
            if conj.len() > 1 && IDENT_RE.is_match(&c) {
                when.push(c);
            } else {
                checks.push(c);
            }
        }
        let [c] = &checks[..] else { continue };
        for mut a in rejects(c, preds, depth) {
            a.when.extend(when.iter().cloned());
            out.push(a);
        }
    }
    out
}

/// A call of a one-expression fn, with its parameters replaced by the
/// arguments: `owner_ok(o, a.key)` → `(o)==(a.key)`.
fn inline(c: &str, preds: &Preds) -> Option<String> {
    let m = CALL_RE.captures(c)?;
    let args_at = m.get(2).unwrap().start();
    if closing_paren(&c[args_at..]) != Some(m[2].len()) {
        return None;
    }
    let (params, body) = preds.get(&m[1])?.as_ref()?;
    let args = top_level(&m[2]);
    if args.len() != params.len() {
        return None;
    }
    Some(heads(body, |w| {
        let a = args[params.iter().position(|p| p == w)?];
        Some(if PLAIN_RE.is_match(a) { a.to_string() } else { format!("({a})") })
    }))
}

/// `t` with each name at the head of a path (not a field after `.`, not
/// after `::`) replaced where `f` gives a replacement.
fn heads(t: &str, f: impl Fn(&str) -> Option<String>) -> String {
    HEAD_RE
        .replace_all(t, |m: &regex::Captures| match f(&m[2]) {
            Some(r) => format!("{}{r}", &m[1]),
            None => m[0].to_string(),
        })
        .into_owned()
}

/// What a condition that rejects when true checks.
fn rejects(c: &str, preds: &Preds, depth: usize) -> Vec<Atom> {
    let c = &bare(c);
    if let Some(inner) = c.strip_prefix('!').filter(|r| !r.starts_with('=')) {
        let inner = bare(inner);
        if depth < DEPTH {
            if let Some(e) = inline(&inner, preds) {
                return rejects(&format!("!({e})"), preds, depth + 1);
            }
        }
        // `!(a && b)`: rejects without either.
        let conj = split_at_top(&inner, "&&");
        if conj.len() > 1 {
            return conj.iter().flat_map(|c| rejects(&format!("!({c})"), preds, depth)).collect();
        }
        if let Some(m) = FLAG_RE.captures(&inner) {
            let kind = match &m[2] {
                "is_signer" => Kind::Signer,
                "is_writable" => Kind::Writable,
                _ => Kind::Executable,
            };
            return vec![atom(kind, &m[1], None)];
        }
        if let Some(m) = OWNED_BY_RE.captures(&inner) {
            let id = bare(&m[2]);
            let id = if THIS_PROGRAM_RE.is_match(&id) { "program_id".to_string() } else { id };
            return vec![atom(Kind::Owner, &m[1], Some(id))];
        }
        if let Some(m) = EQ_FN_RE.captures(&inner) {
            if let [a, b] = top_level(&m[1])[..] {
                return compared(a, b);
            }
        }
        if let Some(m) = METHOD_EQ_RE.captures(&inner).filter(|m| &m[2] == "eq") {
            return compared(&m[1], &m[3]);
        }
        if let [a, b] = split_at_top(&inner, "==")[..] {
            return compared(a, b);
        }
        return Vec::new();
    }
    if depth < DEPTH {
        if let Some(e) = inline(&bare(c), preds) {
            return atoms_in(&e, preds, depth + 1);
        }
    }
    if let [a, b] = split_at_top(c, "!=")[..] {
        return compared(a, b);
    }
    if let Some(m) = METHOD_EQ_RE.captures(c).filter(|m| &m[2] == "ne") {
        return compared(&m[1], &m[3]);
    }
    Vec::new()
}

/// A rejected inequality: an account's key or owner on either side, or a
/// bare name a caller may pass one for.
fn compared(a: &str, b: &str) -> Vec<Atom> {
    let bad = |x: &str| ["==", "!=", "||", "&&", "<", ">"].iter().any(|o| split_at_top(x, o).len() > 1);
    if bad(a) || bad(b) {
        return Vec::new();
    }
    // `sol_memcmp(x, y, 32)` against `0`: `x` against `y`.
    for (m, z) in [(a, b), (b, a)] {
        if let Some(m) = MEMCMP_RE.captures(&bare(m)).filter(|_| bare(z) == "0") {
            if let [x, y, _] = top_level(&m[1])[..] {
                return compared(x, y);
            }
        }
    }
    let this = |x: String| if THIS_PROGRAM_RE.is_match(&x) { "program_id".to_string() } else { x };
    let (a, b) = (this(bare(a)), this(bare(b)));
    let side = |x: &str| {
        SIDE_RE.captures(x).map(|m| {
            let kind = if &m[2] == "owner" { Kind::Owner } else { Kind::Key };
            (kind, m[1].to_string())
        })
    };
    match (side(&a), side(&b)) {
        (Some((k, v)), None) => vec![atom(k, &v, Some(b))],
        (None, Some((k, v))) => vec![atom(k, &v, Some(a))],
        // `a.key() != b.key()`: one atom, the lesser name as the account.
        (Some((k, v)), Some(_)) if a <= b => vec![atom(k, &v, Some(b))],
        (Some(_), Some((k, v))) => vec![atom(k, &v, Some(a))],
        (None, None) => [(&a, &b), (&b, &a)]
            .into_iter()
            .filter(|(x, _)| IDENT_RE.is_match(x))
            .map(|(x, y)| Atom { pending: true, ..atom(Kind::Key, x, Some(y.clone())) })
            .collect(),
    }
}

fn atom(kind: Kind, var: &str, against: Option<String>) -> Atom {
    // `a.to_account_info().key`: the account `a`.
    let var = var.replace(".to_account_info()", "").replace(".as_ref()", "");
    Atom { kind, var, against, when: Vec::new(), pending: false }
}

/// The name a path starts with: `accounts` of `accounts[0].x`.
fn root(v: &str) -> &str {
    WORD_RE.find(v).filter(|m| m.start() == 0).map_or("", |m| m.as_str())
}

/// `if cond { .. } else { Err(..) }`: rejects on `!(cond)`.
fn else_fails(blanked: &str, expr: &str) -> Vec<(Demand, String, usize)> {
    let mut out = Vec::new();
    for m in IF_RE.find_iter(blanked) {
        // An `else if`: its condition is read by its own `if`.
        let (mut d, mut u) = (0i32, 0i32);
        let open = blanked[m.end()..].char_indices().find_map(|(j, c)| {
            match c {
                '(' | '[' => d += 1,
                ')' | ']' => d -= 1,
                '{' if d == 0 && blanked[..m.end() + j].trim_end().ends_with("unsafe") => u += 1,
                '{' if d == 0 && u > 0 => u += 1,
                '}' if d == 0 && u > 0 => u -= 1,
                '{' if d == 0 && u == 0 => return Some(Some(m.end() + j)),
                ';' if d == 0 && u == 0 => return Some(None),
                _ => {}
            }
            None
        });
        let Some(Some(open)) = open else { continue };
        let Some(block) = braced(&blanked[open + 1..]) else { continue };
        let after = open + 1 + block.len() + 1;
        let rest = &blanked[after..];
        let Some(r) = rest.trim_start().strip_prefix("else") else { continue };
        let r = r.trim_start();
        let Some(else_body) = r.strip_prefix('{') else { continue };
        let at = blanked.len() - else_body.len();
        let at = at + past_logs(&blanked[at..]);
        if FAILS_RE.is_match(expr[at..].trim_start()) {
            out.push((Demand::RejectsIf, format!("!({})", expr[m.end()..open].trim()), m.start()));
        }
    }
    out
}

/// The arms of the outermost `match` in a body whose arms are enum
/// variants (`Instruction::Deposit { amount } => { .. }`, at least one with
/// a block): where the `match` starts, and each arm's byte range and
/// variant path.
fn arms(body: &str) -> (usize, Vec<(std::ops::Range<usize>, String)>) {
    for m in MATCH_RE.find_iter(body) {
        // The `{` after the scrutinee.
        let mut d = 0i32;
        let Some(open) = body[m.end()..].char_indices().find_map(|(j, c)| {
            match c {
                '(' | '[' => d += 1,
                ')' | ']' => d -= 1,
                '{' if d == 0 => return Some(m.end() + j + 1),
                _ => {}
            }
            None
        }) else {
            continue;
        };
        let Some(block) = braced(&body[open..]) else { continue };
        let mut out = Vec::new();
        let (mut at, end) = (open, open + block.len());
        while at < end {
            let Some(arrow) = arrow_at(&body[at..end]).map(|a| at + a) else { break };
            let pattern = body[at..arrow].trim().trim_start_matches(',').trim();
            let rest = &body[arrow + 2..end];
            let lead = rest.len() - rest.trim_start().len();
            let start = arrow + 2 + lead;
            let stop = if body[start..].starts_with('{') {
                start + 1 + braced(&body[start + 1..end]).map_or(end - start - 1, str::len) + 1
            } else {
                start + top_level_comma(&body[start..end]).unwrap_or(end - start)
            };
            if let Some(p) = VARIANT_RE.captures(pattern) {
                out.push((start..stop, p[1].chars().filter(|c| !c.is_whitespace()).collect()));
            }
            at = stop.max(arrow + 2);
        }
        if out.len() > 1 && out.iter().any(|(r, _)| body[r.start..].starts_with('{')) {
            return (m.start(), out);
        }
    }
    (0, Vec::new())
}

/// The first `=>` at the top level of `s`.
fn arrow_at(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    let mut d = 0i32;
    for i in 0..b.len() {
        match b[i] {
            b'(' | b'[' | b'{' => d += 1,
            b')' | b']' | b'}' => d -= 1,
            b'=' if d == 0 && b.get(i + 1) == Some(&b'>') => return Some(i),
            _ => {}
        }
    }
    None
}

/// The first `,` at the top level of `s`.
fn top_level_comma(s: &str) -> Option<usize> {
    let mut d = 0i32;
    for (i, c) in s.char_indices() {
        match c {
            '(' | '[' | '{' => d += 1,
            ')' | ']' | '}' => d -= 1,
            ',' if d == 0 => return Some(i),
            _ => {}
        }
    }
    None
}

impl NativeChecks {
    pub fn read(dir: &Path) -> Result<Self> {
        let mut files = Vec::new();
        collect(dir, &mut files).with_context(|| format!("failed to read sources under {}", dir.display()))?;
        let root = dir.display().to_string();
        Ok(Self::parse_in(&files, Some(&root)))
    }

    #[cfg(test)]
    pub fn parse(src: &str) -> Self {
        Self::parse_files(&[("<src>".to_string(), src.to_string())])
    }

    pub fn parse_files(files: &[(String, String)]) -> Self {
        Self::parse_in(files, None)
    }

    /// `root`: the directory the files were read under. A fn is matched
    /// across versions by its module path below it, so two checkouts in
    /// different places compare.
    fn parse_in(files: &[(String, String)], root: Option<&str>) -> Self {
        let stripped: Vec<(String, String)> =
            files.iter().map(|(f, t)| (f.clone(), strip_comments_and_strings(t))).collect();
        let exprs: HashMap<&str, String> = files.iter().map(|(f, t)| (f.as_str(), strip_comments(t))).collect();
        let index = FnIndex::new(&stripped, &exprs);
        let blanked: HashMap<&str, &str> = stripped.iter().map(|(f, t)| (f.as_str(), t.as_str())).collect();
        // One-expression fns, by name; a name two fns share is not inlined.
        let mut preds: Preds = HashMap::new();
        for f in &index.fns {
            let body = exprs[f.file.as_str()][f.body.clone()].trim();
            let body = body.strip_prefix("return ").unwrap_or(body).trim_end_matches(';').trim();
            // No statement: a `;` or block only inside brackets (`[0u8; 32]`).
            let mut d = 0i32;
            let top = body.chars().any(|c| {
                match c {
                    '(' | '[' => d += 1,
                    ')' | ']' => d -= 1,
                    _ => {}
                }
                (c == ';' && d == 0) || c == '{'
            });
            let one = !body.is_empty() && !top && !body.starts_with("let ");
            let entry = preds.entry(f.name.clone());
            match entry {
                std::collections::hash_map::Entry::Occupied(mut o) => {
                    o.insert(None);
                }
                std::collections::hash_map::Entry::Vacant(v) => {
                    v.insert(one.then(|| (f.params.clone(), squeeze(body))));
                }
            }
        }
        let (mut fns, mut arm_fns) = (Vec::new(), Vec::new());
        for f in &index.fns {
            let body = &blanked[f.file.as_str()][f.body.clone()];
            let expr = &exprs[f.file.as_str()][f.body.clone()];
            let mut direct = Vec::new();
            for (d, cond, at) in failing_conditions_at(body, expr, true).into_iter().chain(else_fails(body, expr)) {
                if d != Demand::RejectsIf {
                    continue;
                }
                let written = cond.split_whitespace().collect::<Vec<_>>().join(" ");
                direct.extend(atoms_of(&cond, &preds).into_iter().map(|a| (a, written.clone(), at)));
            }
            let mut calls: Vec<Call> = calls_in(body)
                .into_iter()
                .filter(|c| c.propagated)
                .map(|c| {
                    let args: Vec<String> = top_level(c.args).iter().map(|a| squeeze(a)).collect();
                    let target = index.resolve(&c.callee, &c.name, f.ty.as_deref(), None);
                    let name = match &c.callee {
                        Callee::Typed(_, t) => format!("{t}::{}", c.name),
                        Callee::SelfTy => format!("Self::{}", c.name),
                        _ => c.name.clone(),
                    };
                    Call { target, text: format!("{name}({})", args.join(",")), args, at: c.at }
                })
                .collect();
            let mut lets = Vec::new();
            for m in INDEXED_LET_RE.captures_iter(body) {
                lets.push((m.get(0).unwrap().start(), m[1].to_string(), format!("{}[{}]", &m[2], &m[3])));
            }
            for m in SLICE_LET_RE.captures_iter(body) {
                for (n, name) in m[1].split(',').map(str::trim).enumerate() {
                    if name == ".." || name.starts_with("..") {
                        break;
                    }
                    let name = name.trim_start_matches("ref ").trim_start_matches("mut ").trim();
                    if IDENT_RE.is_match(name) && name != "_" {
                        lets.push((m.get(0).unwrap().start(), name.to_string(), format!("{}[{n}]", &m[2])));
                    }
                }
            }
            lets.sort();
            let display = match &f.ty {
                Some(t) => format!("{t}::{}", f.name),
                None => f.name.clone(),
            };
            let inline = &f.mods[file_mods(&f.file).len().min(f.mods.len())..];
            let rel = match root.and_then(|r| f.file.strip_prefix(r)) {
                Some(rel) => file_mods(&format!("src/{}", rel.trim_start_matches('/'))),
                None => file_mods(&f.file),
            };
            let key = format!("{}::{}::{display}", rel.join("::"), inline.join("::"));
            // A `match` on the instruction: each arm is compared apart, as its
            // own instruction. The rest stays with the fn.
            let line_at = |at: usize| f.line + body[..at].matches('\n').count();
            // Each arm also runs what the fn checks before the `match`.
            let (from, arm_list) = arms(body);
            let in_arm = |at: usize| arm_list.iter().any(|(r, _)| r.contains(&at));
            let before = |at: usize| at < from && !in_arm(at);
            let parent = fns.len();
            for (range, pattern) in &arm_list {
                let keep = |at: usize| range.contains(&at) || before(at);
                let span = if body[range.start..].starts_with('{') { range.start + 1..range.end - 1 } else { range.clone() };
                arm_fns.push(NativeFn {
                    key: format!("{key}[{pattern}]"),
                    display: format!("{display}[{pattern}]"),
                    file: f.file.clone(),
                    line: line_at(range.start),
                    direct: direct.iter().filter(|(_, _, at)| keep(*at)).cloned().collect(),
                    calls: calls.iter().filter(|c| keep(c.at)).cloned().collect(),
                    lets: lets.clone(),
                    text: body[span.clone()].to_string(),
                    parent: Some(parent),
                    span,
                });
            }
            direct.retain(|(_, _, at)| !in_arm(*at));
            calls.retain(|c| !in_arm(c.at));
            fns.push(NativeFn { key, display, file: f.file.clone(), line: f.line, direct, calls, lets, text: body.to_string(), parent: None, span: 0..body.len() });
        }
        fns.extend(arm_fns);
        let params = index.fns.iter().map(|f| f.params.clone()).collect();
        let entrypoint = exprs.values().any(|t| ENTRYPOINT_RE.is_match(t));
        NativeChecks { fns, params, entrypoint }
    }

    /// Has a native or Pinocchio entrypoint (`entrypoint!(..)`).
    pub fn has_entrypoint(&self) -> bool {
        self.entrypoint
    }

    pub fn is_empty(&self) -> bool {
        self.fns.iter().all(|f| f.direct.iter().all(|(a, _, _)| a.pending))
    }

    /// `name` at byte `at` of fn `i`: its place in a slice when the last
    /// `let` before binds it from one.
    fn canon(&self, i: usize, name: &str, at: usize) -> String {
        let f = &self.fns[i];
        f.lets
            .iter()
            .rev()
            .find(|(p, n, _)| *p < at && n == name)
            .map_or_else(|| name.to_string(), |(_, _, c)| c.clone())
    }

    /// An atom of fn `i` read at byte `at`: every name its place.
    fn placed(&self, i: usize, a: &Atom, at: usize) -> Atom {
        let r = root(&a.var);
        let var = format!("{}{}", self.canon(i, r, at), &a.var[r.len()..]);
        let against = a.against.as_ref().map(|t| heads(t, |w| Some(self.canon(i, w, at))));
        Atom { var, against, ..a.clone() }
    }

    /// Callee `j`'s atom as fn `i`'s call `k` makes it: a parameter becomes
    /// the argument passed. None when a flag it needs is passed other than
    /// `true`.
    fn through(&self, i: usize, k: usize, a: &Atom) -> Option<(Atom, String)> {
        let call = &self.fns[i].calls[k];
        let params = self.params.get(call.target?)?;
        if params.len() != call.args.len() {
            return None;
        }
        let arg = |p: &str| params.iter().position(|q| q == p).map(|n| bare(&call.args[n]));
        let mut when = Vec::new();
        for w in &a.when {
            match arg(w).as_deref() {
                Some("true") => {}
                Some(_) => return None,
                None => when.push(w.clone()),
            }
        }
        let r = root(&a.var);
        let var = match arg(r) {
            Some(v) => format!("{v}{}", &a.var[r.len()..]),
            None => a.var.clone(),
        };
        let against = a.against.as_ref().map(|t| heads(t, |w| arg(w)));
        let mut out = Atom { var, against, when, ..a.clone() };
        // A value parameter given an account's key or owner.
        if out.pending {
            if let Some(m) = SIDE_RE.captures(&bare(&out.var)) {
                out.kind = if &m[2] == "owner" { Kind::Owner } else { Kind::Key };
                out.var = m[1].to_string();
                out.pending = false;
            }
        }
        let shown = out.var.clone();
        Some((self.placed(i, &out, call.at), shown))
    }

    /// Every atom fn `i` checks, to `depth` calls down, each with where it
    /// came from and the name it was written with.
    fn atoms(&self, i: usize, depth: usize) -> Vec<(Atom, Origin, String)> {
        let f = &self.fns[i];
        let mut out: Vec<(Atom, Origin, String)> = f
            .direct
            .iter()
            .map(|(a, w, at)| (self.placed(i, a, *at), Origin::Direct(w.clone()), a.var.clone()))
            .collect();
        if depth == 0 {
            return out;
        }
        for (k, call) in f.calls.iter().enumerate() {
            let Some(j) = call.target.filter(|&j| j != i) else { continue };
            if self.params[j].len() != call.args.len() {
                continue;
            }
            for (a, _, _) in self.atoms(j, depth - 1) {
                let own = a.when.is_empty() && !a.pending;
                let Some((b, shown)) = self.through(i, k, &a) else { continue };
                out.push((b, Origin::Call(k, own), shown));
            }
        }
        out
    }

    /// Atoms that hold unconditionally in fn `i`.
    fn holds(&self, i: usize) -> BTreeMap<Atom, (Origin, String)> {
        let mut m = BTreeMap::new();
        for (a, o, shown) in self.atoms(i, DEPTH) {
            if a.when.is_empty() && !a.pending {
                m.entry(a).or_insert((o, shown));
            }
        }
        m
    }
}

pub fn diff(base: &NativeChecks, head: &NativeChecks) -> Vec<Change> {
    let by_key = |k: &NativeChecks| -> HashMap<String, usize> {
        let mut seen: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, f) in k.fns.iter().enumerate() {
            seen.entry(f.key.clone()).or_default().push(i);
        }
        // A name two fns share is not compared: which is which is unknown.
        seen.into_iter().filter(|(_, v)| v.len() == 1).map(|(k, v)| (k, v[0])).collect()
    };
    let (bk, hk) = (by_key(base), by_key(head));
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for (key, &bi) in &bk {
        let Some(&hi) = hk.get(key) else { continue };
        let (bf, hf) = (&base.fns[bi], &head.fns[hi]);
        // Now rejects every call: the instruction is turned off.
        if turned_off(&hf.text) {
            continue;
        }
        let had = base.holds(bi);
        let has = head.holds(hi);
        for (a, (origin, shown)) in &had {
            // An account the fn no longer takes: nothing left to check.
            if has.contains_key(a) || gone(base, bi, head, hi, a, shown) {
                continue;
            }
            // Checked before the `match`: reported once, on the fn.
            if bf.parent.is_some_and(|p| base.holds(p).contains_key(a)) {
                continue;
            }
            // Still compared, with one new thing.
            let instead: Vec<&str> = has
                .keys()
                .filter(|h| h.kind == a.kind && h.var == a.var && a.against.is_some())
                .filter(|h| !had.keys().any(|b| b.kind == h.kind && b.var == h.var && b.against == h.against))
                .filter_map(|h| h.against.as_deref())
                .collect();
            let lost = match instead[..] {
                [new] => format!(
                    "`{shown}`'s {} is now compared with `{new}` instead of `{}`",
                    if a.kind == Kind::Owner { "owner" } else { "key" },
                    a.against.as_deref().unwrap_or_default()
                ),
                _ => consequence(a, shown),
            };
            let message = match origin {
                Origin::Direct(cond) => {
                    // Moved into the fns that call it: still there.
                    if moved_up(base, head, &bk, &hk, bi, a) {
                        continue;
                    }
                    format!("`if {cond} {{ return Err(..) }}` is gone: {lost}")
                }
                Origin::Call(k, own) => {
                    let call = &bf.calls[*k];
                    let still = hf.calls.iter().any(|c| c.text == call.text);
                    // The same call is still made and the callee is compared
                    // on its own: what changed is inside it, reported there.
                    let callee = call.target.map(|j| &base.fns[j].key);
                    let compared = callee.is_some_and(|c| bk.contains_key(c) && hk.contains_key(c));
                    if still && *own && compared {
                        continue;
                    }
                    if still {
                        format!("`{}?` still runs, but no longer checks this: {lost}", call.text)
                    } else {
                        format!("`{}?` is gone or its result is not propagated: {lost}", call.text)
                    }
                }
            };
            if seen.insert((bf.key.clone(), message.clone())) {
                out.push(Change {
                    severity: Severity::Warning,
                    ix: hf.display.clone(),
                    path: shown.clone(),
                    message,
                    file: hf.file.clone(),
                    line: hf.line,
                });
            }
        }
    }
    out.sort_by(|a, b| (&a.file, a.line, &a.path, &a.message).cmp(&(&b.file, b.line, &b.path, &b.message)));
    out
}

/// A body whose first statement rejects: `return Err(..)`, or `Err(..)`
/// alone.
fn turned_off(text: &str) -> bool {
    let t = text.trim_start();
    RETURN_ERR_RE.find(t).is_some_and(|m| m.start() == 0) || (t.starts_with("Err(") && !t.contains(';'))
}

/// The account of atom `a` is not in head fn `hi` at all: not a parameter,
/// its place in the slice bound to no name but `_x` and not indexed, or
/// (an account named only by a variable) the name not there.
fn gone(base: &NativeChecks, bi: usize, head: &NativeChecks, hi: usize, a: &Atom, shown: &str) -> bool {
    let f = &head.fns[hi];
    let r = root(shown);
    // A parameter, by its place: renamed (`_a`) it is still passed.
    let param = base.params.get(bi).and_then(|ps| ps.iter().position(|p| p == r));
    if r.is_empty() || param.is_some_and(|n| head.params.get(hi).is_some_and(|ps| ps.len() > n)) {
        return false;
    }
    let word = |n: &str| Regex::new(&format!(r"\b{}\b", regex::escape(n))).unwrap().is_match(&f.text);
    match PLACE_RE.find(&a.var) {
        Some(place) => {
            let place = place.as_str();
            // The whole slice handed on (`f(accounts)`): any place may be read.
            let slice = root(place);
            if Regex::new(&format!(r"\b{}\b(?:[^\[\w]|$)", regex::escape(slice))).unwrap().is_match(&f.text) {
                return false;
            }
            // An arm runs the fn's bindings before it too (`let [a, ..] =
            // accounts;` above the `match`).
            let reach = if f.parent.is_some() { 0..f.span.end } else { f.span.clone() };
            let here = || f.lets.iter().filter(|(at, _, c)| c == place && reach.contains(at));
            let bound = here().any(|(_, n, _)| !n.starts_with('_'));
            // Indexed other than in a `let` that binds it.
            let lets = here().count();
            let indexed = squeeze(&f.text).matches(place).count() > lets;
            !bound && !indexed && !word(r)
        }
        None => !word(r),
    }
}

/// A check fn `bi` made itself on a parameter, now made by every caller
/// instead: each base call site's fn, in the head, still holds it on the
/// argument it passed.
fn moved_up(
    base: &NativeChecks,
    head: &NativeChecks,
    bk: &HashMap<String, usize>,
    hk: &HashMap<String, usize>,
    bi: usize,
    a: &Atom,
) -> bool {
    if !base.params.get(bi).is_some_and(|ps| ps.iter().any(|p| p == root(&a.var))) {
        return false;
    }
    let mut callers = 0;
    for (ci, cf) in base.fns.iter().enumerate() {
        for (k, call) in cf.calls.iter().enumerate() {
            if call.target != Some(bi) {
                continue;
            }
            callers += 1;
            let Some((want, _)) = base.through(ci, k, a) else { continue };
            let Some(&hi) = bk.get(&cf.key).filter(|&&i| i == ci).and_then(|_| hk.get(&cf.key)) else { return false };
            if !head.holds(hi).contains_key(&want) {
                return false;
            }
        }
    }
    callers > 0
}

fn consequence(a: &Atom, v: &str) -> String {
    let against = a.against.as_deref().unwrap_or("?");
    match a.kind {
        Kind::Signer => format!("`{v}` no longer has to sign"),
        Kind::Writable => format!("`{v}` no longer has to be writable"),
        Kind::Executable => format!("`{v}` no longer has to be a program"),
        Kind::Owner => format!("`{v}`'s owner is no longer compared with `{against}`"),
        Kind::Key => format!("`{v}`'s key is no longer compared with `{against}`"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(base: &str, head: &str) -> Vec<String> {
        diff(&NativeChecks::parse(base), &NativeChecks::parse(head))
            .into_iter()
            .map(|c| format!("{} {}: {}", c.ix, c.path, c.message))
            .collect()
    }

    const BASE: &str = r#"
fn require_signer(ai: &AccountInfo) -> ProgramResult {
    if !ai.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    Ok(())
}

fn deposit(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [payer, vault, token_program] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    require_signer(payer)?;
    if data.len() < 8 {
        return Err(ProgramError::InvalidInstructionData);
    }
    if vault.owner() != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }
    if token_program.key() != &TOKEN_PROGRAM_ID || !vault.is_writable() {
        return Err(ProgramError::IncorrectProgramId);
    }
    Ok(())
}
"#;

    #[test]
    fn unchanged_reports_nothing() {
        assert!(run(BASE, BASE).is_empty());
        assert!(!NativeChecks::parse(BASE).is_empty());
    }

    #[test]
    fn a_removed_condition_and_a_removed_helper_call() {
        let head = BASE
            .replace("    require_signer(payer)?;\n", "")
            .replace("    if vault.owner() != program_id {\n        return Err(ProgramError::IncorrectProgramId);\n    }\n", "");
        assert_eq!(
            run(BASE, &head),
            [
                "deposit payer: `require_signer(payer)?` is gone or its result is not propagated: `payer` no longer has to sign",
                "deposit vault: `if vault.owner() != program_id { return Err(..) }` is gone: `vault`'s owner is no longer compared with `program_id`",
            ]
        );
    }

    #[test]
    fn a_flipped_or_loosened_check_is_gone() {
        let head = BASE.replace("!vault.is_writable()", "vault.is_writable()").replace("&TOKEN_PROGRAM_ID", "&OTHER_ID");
        assert_eq!(
            run(BASE, &head),
            [
                "deposit token_program: `if token_program.key() != &TOKEN_PROGRAM_ID || !vault.is_writable() { return Err(..) }` is gone: `token_program`'s key is now compared with `OTHER_ID` instead of `TOKEN_PROGRAM_ID`",
                "deposit vault: `if token_program.key() != &TOKEN_PROGRAM_ID || !vault.is_writable() { return Err(..) }` is gone: `vault` no longer has to be writable",
            ]
        );
    }

    #[test]
    fn a_check_moved_into_a_helper_or_out_of_one_is_still_there() {
        // Inlined into the caller.
        let inlined = BASE.replace(
            "    require_signer(payer)?;\n",
            "    if !payer.is_signer() {\n        return Err(ProgramError::MissingRequiredSignature);\n    }\n",
        );
        assert!(run(BASE, &inlined).is_empty(), "{:?}", run(BASE, &inlined));
        // And back into a helper.
        assert!(run(&inlined, BASE).is_empty());
        // A helper of the caller's that checks the owner.
        let helper = BASE.replace(
            "    if vault.owner() != program_id {\n        return Err(ProgramError::IncorrectProgramId);\n    }\n",
            "    check_owner(vault, program_id)?;\n",
        ) + "\nfn check_owner(a: &AccountInfo, id: &Pubkey) -> ProgramResult {\n    if a.owner() != id {\n        return Err(ProgramError::IncorrectProgramId);\n    }\n    Ok(())\n}\n";
        assert!(run(BASE, &helper).is_empty(), "{:?}", run(BASE, &helper));
    }

    #[test]
    fn a_helper_that_stops_checking_is_named_once() {
        let head = BASE.replace("if !ai.is_signer() {", "if ai.data_len() == 0 {");
        assert_eq!(
            run(BASE, &head),
            ["require_signer ai: `if !ai.is_signer() { return Err(..) }` is gone: `ai` no longer has to sign"]
        );
    }

    #[test]
    fn a_result_dropped_is_a_check_gone() {
        let head = BASE.replace("    require_signer(payer)?;", "    let _ = require_signer(payer);");
        assert_eq!(run(BASE, &head).len(), 1);
    }

    #[test]
    fn spellings_of_the_same_check() {
        for (cond, want) in [
            ("!a.is_signer", "Signer a None"),
            ("!a.is_owned_by(&crate::ID)", "Owner a Some(\"program_id\")"),
            ("!Self::cmp_pubkeys(a.key, &b.mint)", "Key a Some(\"b.mint\")"),
            ("sol_memcmp(a.key.as_ref(), b.as_ref(), 32) != 0", "Key a Some(\"b\")"),
            ("!a.owned_by(token_program_id)", "Owner a Some(\"token_program_id\")"),
            ("*a.owner != spl_token::ID", "Owner a Some(\"spl_token::ID\")"),
            ("&expected != a.key()", "Key a Some(\"expected\")"),
            ("a.address().as_array() != &output.recipient", "Key a Some(\"output.recipient\")"),
            ("!pubkey_eq(a.key(), &b)", "Key a Some(\"b\")"),
            ("registry.super_admin != *a.key()", "Key a Some(\"registry.super_admin\")"),
            ("unsafe { a.owner() } != &ID", "Owner a Some(\"program_id\")"),
            ("accounts[0].key() != &ID", "Key accounts[0] Some(\"program_id\")"),
            ("a.to_account_info().key != b.key", "Key a Some(\"b.key\")"),
            ("expect && !a.is_writable()", "Writable a None [\"expect\"]"),
            ("!(a.is_signer() && x > 0)", "Signer a None"),
            ("unlikely(!pubkey_eq(e, a.key()))", "Key a Some(\"e\")"),
        ] {
            let got: Vec<String> = atoms_of(cond, &Preds::new())
                .iter()
                .map(|a| {
                    let w = if a.when.is_empty() { String::new() } else { format!(" {:?}", a.when) };
                    format!("{:?} {} {:?}{w}", a.kind, a.var, a.against)
                })
                .collect();
            assert_eq!(got, [want], "{cond}");
        }
        // Not checks: a check that passes when it should fail, an init guard,
        // two accounts' flags together, data.
        for cond in ["a.is_signer()", "a.key() == &b", "!a.is_signer() && !b.is_signer()", "!(a.is_signer() || b.is_signer())", "data.len() < 8", "a.lamports() == 0"] {
            assert!(atoms_of(cond, &Preds::new()).is_empty(), "{cond}");
        }
    }

    #[test]
    fn a_flag_passed_true_makes_the_check() {
        let src = |flag: &str| {
            format!(
                "fn verify_signer(a: &AccountInfo, expect: bool) -> ProgramResult {{\n    if expect && !a.is_signer() {{\n        return Err(E);\n    }}\n    Ok(())\n}}\nfn go(accounts: &[AccountInfo]) -> ProgramResult {{\n    verify_signer(&accounts[0], {flag})?;\n    Ok(())\n}}\n"
            )
        };
        assert_eq!(run(&src("true"), &src("false")), ["go accounts[0]: `verify_signer(&accounts[0],true)?` is gone or its result is not propagated: `accounts[0]` no longer has to sign"]);
        assert!(run(&src("false"), &src("true")).is_empty());
    }

    #[test]
    fn a_one_line_predicate_is_read_through() {
        let src = |cond: &str| {
            format!(
                "fn owner_ok(stored: [u8; 32], signer: [u8; 32]) -> bool {{\n    stored == signer\n}}\nfn signer_ok(s: bool) -> bool {{ s }}\nfn go(accounts: &[AccountInfo]) -> ProgramResult {{\n    let a_user = &accounts[0];\n    if {cond} {{\n        return Err(E);\n    }}\n    Ok(())\n}}\n"
            )
        };
        let base = src("Pubkey::new_from_array(owner) != *a_user.key");
        // The same check through a predicate, and the signer flag through one.
        assert!(run(&base, &src("!crate::verify::owner_ok(owner, a_user.key.to_bytes())")).is_empty());
        let signer = src("!signer_ok(a_user.is_signer)");
        assert!(run(&signer, &src("!a_user.is_signer")).is_empty());
        assert_eq!(run(&signer, &src("signer_ok(a_user.is_signer)")).len(), 1);
    }

    #[test]
    fn a_key_handed_to_a_helper_is_the_account_checked() {
        let base = "fn go(accounts: &[AccountInfo]) -> ProgramResult {\n    let a_admin = &accounts[0];\n    if header.admin != a_admin.key.to_bytes() {\n        return Err(E);\n    }\n    Ok(())\n}\n";
        let head = "fn require_admin(header_admin: [u8; 32], signer: &Pubkey) -> Result<(), ProgramError> {\n    if header_admin != signer.to_bytes() {\n        return Err(E);\n    }\n    Ok(())\n}\nfn go(accounts: &[AccountInfo]) -> ProgramResult {\n    let a_admin = &accounts[0];\n    require_admin(header.admin, a_admin.key)?;\n    Ok(())\n}\n";
        assert!(run(base, head).is_empty(), "{:?}", run(base, head));
        // A value compared with a value checks no account.
        assert!(NativeChecks::parse("fn f(a: u64, b: u64) -> ProgramResult {\n    if a != b {\n        return Err(E);\n    }\n    Ok(())\n}\n").is_empty());
    }

    #[test]
    fn an_account_is_its_place_in_the_slice() {
        let base = "fn go(accounts: &[AccountInfo]) -> ProgramResult {\n    read_price(&accounts[4])?;\n    Ok(())\n}\nfn read_price(p: &AccountInfo) -> ProgramResult {\n    if *p.owner != PYTH {\n        return Err(E);\n    }\n    Ok(())\n}\n";
        let named = base.replace("    read_price(&accounts[4])?;", "    let a_oracle = &accounts[4];\n    read_price(a_oracle)?;");
        assert!(run(base, &named).is_empty(), "{:?}", run(base, &named));
        let destructured = base.replace("    read_price(&accounts[4])?;", "    let [_a, _b, _c, _d, oracle, ..] = accounts else { return Err(E) };\n    read_price(oracle)?;");
        assert!(run(base, &destructured).is_empty(), "{:?}", run(base, &destructured));
        // Another place is another account.
        let other = base.replace("&accounts[4]", "&accounts[5]");
        assert_eq!(run(base, &other).len(), 1);
    }

    #[test]
    fn a_condition_with_an_unsafe_block() {
        let src = "fn go(a: &AccountInfo) -> ProgramResult {\n    if unsafe { a.owner() } != &crate::ID {\n        return Err(E);\n    }\n    use_it(a);\n    Ok(())\n}\n";
        assert_eq!(run(src, &src.replace("    if unsafe { a.owner() } != &crate::ID {\n        return Err(E);\n    }\n", "")).len(), 1);
    }

    #[test]
    fn each_instruction_arm_is_compared_apart() {
        let base = "fn process(accounts: &[AccountInfo], ix: Instruction) -> ProgramResult {\n    match ix {\n        Instruction::Trade { size } => {\n            let a_user = &accounts[0];\n            if !a_user.is_signer { return Err(E); }\n            trade(a_user, size);\n        }\n        Instruction::Withdraw { amount } => {\n            let a_user = &accounts[0];\n            if !a_user.is_signer { return Err(E); }\n        }\n    }\n    Ok(())\n}\n";
        let head = base.replacen("            if !a_user.is_signer { return Err(E); }\n", "            // if !a_user.is_signer { return Err(E); }\n", 1);
        assert_eq!(run(base, &head), ["process[Instruction::Trade] a_user: `if !a_user.is_signer { return Err(..) }` is gone: `a_user` no longer has to sign"]);
    }

    #[test]
    fn an_instruction_turned_off_or_an_account_no_longer_read() {
        let base = "fn set(accounts: &[AccountInfo]) -> ProgramResult {\n    let a_admin = &accounts[0];\n    if !a_admin.is_signer() {\n        return Err(E);\n    }\n    write(a_admin);\n    Ok(())\n}\n";
        let off = "fn set(accounts: &[AccountInfo]) -> ProgramResult {\n    return Err(E);\n}\n";
        assert!(run(base, off).is_empty());
        let unused = "fn set(accounts: &[AccountInfo]) -> ProgramResult {\n    let _a_admin = &accounts[0];\n    Ok(())\n}\n";
        assert!(run(base, unused).is_empty());
        let unchecked = base.replace("    if !a_admin.is_signer() {\n        return Err(E);\n    }\n", "");
        assert_eq!(run(base, &unchecked).len(), 1);
    }

    #[test]
    fn an_if_that_errs_in_its_else() {
        let src = |cond: &str| {
            format!("fn check(a: &AccountInfo) -> ProgramResult {{\n    if {cond} {{\n        Ok(())\n    }} else {{\n        Err(E)\n    }}\n}}\n")
        };
        let a = NativeChecks::parse(&src("a.is_owned_by(&TOKEN_PROGRAM_ID)"));
        assert!(!a.is_empty());
        assert!(diff(&a, &NativeChecks::parse(&src("likely(a.is_owned_by(&TOKEN_PROGRAM_ID))"))).is_empty());
        let base = "fn check(a: &AccountInfo) -> ProgramResult {\n    if &TOKEN_PROGRAM_ID != a.owner() {\n        return Err(E);\n    }\n    Ok(())\n}\n";
        assert!(diff(&NativeChecks::parse(base), &a).is_empty());
    }
}
