//! Declared account types from an Anchor program's source.
//!
//! The IDL cannot tell `Account<'info, T>` from `UncheckedAccount<'info>`
//! (Anchor strips the `/// CHECK:` line from `docs`), and that is the
//! distinction that matters: a typed slot's owner and discriminator are
//! checked by Anchor, an unchecked one's by hand. The source says which.
//!
//! Text, not a parser: one field per line, as rustfmt writes them. A
//! field this misses is reported as "not found in source", never guessed.
//! Each slot also keeps the constraints written in its `#[account(...)]`
//! and where it is declared, which is what `solinv diff` compares.

use anyhow::{Context, Result};
use regex::Regex;
use crate::idl::{Idl, IdlAccount, IdlAccountItem, IdlInstruction, IdlPda, SlotKind};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

enum Field {
    Kind(SlotKind),
    /// A type the reader does not recognise: left unplaced.
    Unknown,
    /// A nested `#[derive(Accounts)]` struct, by name.
    Composite(String),
}

/// The constraints written in a field's `#[account(...)]` attribute.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Attrs {
    pub mutable: bool,
    pub signer: bool,
    pub seeds: bool,
    pub address: bool,
    pub owner: bool,
    pub has_one: Vec<String>,
    /// Each `constraint = <expr>`, whitespace collapsed, error dropped.
    pub constraints: Vec<String>,
    /// `close = <target>`: when the instruction ends Anchor sends the
    /// lamports to the target, clears the data and hands the account back
    /// to the system program.
    pub close: Option<String>,
    /// `init` (not `init_if_needed`, which also accepts an existing
    /// account): the account is created here.
    pub init: bool,
    /// `associated_token::authority`: the account is the one associated
    /// token account of that authority and mint. `token::authority` and
    /// `token::mint` are not: one authority can own many token accounts.
    pub token_authority: bool,
    /// The names in the `seeds` and `address` values, `"::"` marking a
    /// constant as in `keyed_constraints`.
    pub seed_names: Vec<String>,
    pub address_names: Vec<String>,
    /// The names in `associated_token::authority`.
    pub authority_names: Vec<String>,
    /// The names in each `constraint` that compares a `.key()`, with
    /// `"::"` standing for an upper-case constant (`VAULT_ID`, `crate::ID`): it fixes
    /// this slot's identity when it names this slot and something else.
    /// What the comparison says is not checked.
    pub keyed_constraints: Vec<Vec<String>>,
    /// The names (not field selectors: `a` in `a.b`, never `b`) in each
    /// `seeds`, `address`, `token::authority` and `associated_token::*`
    /// value. Each names a slot this one is tied to.
    pub refs: Vec<String>,
    /// Each vipers `assert_keys_eq!` / `assert_keys_neq!` in an
    /// `impl Validate` that the handler's `#[access_control]` runs, with
    /// this slot as its first argument naming a slot: arguments sorted,
    /// paths from the instruction's root, e.g.
    /// `assert_keys_eq!(common.bank.crate_mint, common.crate_mint)`.
    pub validate: Vec<String>,
    /// For each `assert_keys_eq!` above, the slots its arguments name
    /// (full paths) and `"::"` for a constant: like `keyed_constraints`.
    pub validate_keys: Vec<Vec<String>>,
}

/// One account slot as the source declares it.
#[derive(Clone, Debug)]
pub struct Slot {
    /// `None` when the type is not one the reader recognises.
    pub kind: Option<SlotKind>,
    /// The type's name under `Box<` / `Option<`: `Account`, `Signer`, …
    pub ty: String,
    /// The whole type, whitespace and `Box<…>` removed: tells
    /// `Account<'info, Config>` from `Account<'info, Vault>`.
    pub full_ty: String,
    /// Wrapped in `Option<…>`: the account may be left out.
    pub optional: bool,
    pub attrs: Attrs,
    /// Where the field is declared, for annotations.
    pub file: String,
    pub line: usize,
    /// Position in the instruction's account list, composites flattened
    /// in place, as Anchor lays the accounts out.
    pub order: usize,
}

/// Declared slots per (instruction, dotted slot path).
pub struct SourceKinds {
    map: HashMap<(String, String), Slot>,
}

/// `assert_keys_eq!` / `assert_keys_neq!` calls and `self.<field>.validate()`
/// calls in one `impl Validate for <struct>`.
#[derive(Default)]
struct ValidateImpl {
    checks: Vec<(bool, [String; 2])>,
    calls: Vec<String>,
}

struct RawField {
    name: String,
    field: Field,
    ty: String,
    full_ty: String,
    optional: bool,
    attrs: Attrs,
    file: String,
    line: usize,
}

impl SourceKinds {
    pub fn is_empty(&self) -> bool {
        !self.map.values().any(|s| s.kind.is_some())
    }

    pub fn get(&self, ix: &str, path: &str) -> Option<SlotKind> {
        self.slot(ix, path).and_then(|s| s.kind)
    }

    pub fn slot(&self, ix: &str, path: &str) -> Option<&Slot> {
        self.map.get(&(ix.to_string(), path.to_string()))
    }

    /// A data account (`Account`, `AccountLoader`, `InterfaceAccount`)
    /// whose identity no attribute fixes: no `seeds`, `address`,
    /// `associated_token::authority` or `has_one` on it naming another
    /// slot or a constant (`seeds` of literals alone count; an
    /// instruction argument does not), no `&&` clause of a `constraint`
    /// on it naming it and another slot or constant beside a `.key()`,
    /// no other slot's `has_one` or identity-fixing value naming it
    /// (`vault.key() == pool.load()?.vault` ties `pool` too: the pool
    /// the caller picks is what the vault is checked against), and not
    /// created by `init`. Anchor checks its owner and type, so
    /// unless the handler body compares its key (not read), a caller can
    /// pass any account of the type. Names in another slot's attribute
    /// are resolved among that slot's siblings.
    pub fn unbound(&self, ix: &str, path: &str) -> bool {
        let Some(s) = self.slot(ix, path) else { return false };
        if s.kind != Some(SlotKind::Typed)
            || !matches!(s.ty.as_str(), "Account" | "AccountLoader" | "InterfaceAccount")
        {
            return false;
        }
        let a = &s.attrs;
        if a.init {
            return false;
        }
        // An `assert_keys_eq!` naming it and another slot or a constant.
        if self.map.iter().any(|((i, _), t)| {
            i == ix
                && t.attrs.validate_keys.iter().any(|c| c.iter().any(|n| n == path) && c.iter().any(|n| n != path))
        }) {
            return false;
        }
        // A name in slot `p`'s attribute, resolved among `p`'s siblings.
        let resolve = |p: &str, n: &str| format!("{}{n}", p.rfind('.').map_or("", |i| &p[..=i]));
        // A keyed constraint on `p` ties `path` when it names `path` and
        // another slot of the instruction or a constant — not only
        // `path`, and not an instruction argument.
        // `x.key` (no `()`) compares an address only when `x` is an
        // `AccountInfo`-like slot; on `Account<T>` it reads a data field.
        let address_field = |p: &str, recv: &str| {
            self.slot(ix, &resolve(p, recv)).is_some_and(|s| {
                matches!(s.ty.as_str(), "AccountInfo" | "UncheckedAccount" | "Signer" | "SystemAccount" | "Program" | "Sysvar")
            })
        };
        let ties = |p: &str, c: &[String]| {
            c.iter().filter_map(|n| n.strip_prefix("@key:")).all(|recv| address_field(p, recv))
                && c.iter().any(|n| resolve(p, n) == path)
                && c.iter().any(|n| {
                    n == "::" || {
                        let q = resolve(p, n);
                        q != path && self.map.contains_key(&(ix.to_string(), q))
                    }
                })
        };
        // Another slot of the instruction, or a constant — not an
        // instruction argument, which the caller picks.
        let fixed = |n: &String| {
            n == "::" || {
                let q = resolve(path, n);
                q != path && self.map.contains_key(&(ix.to_string(), q))
            }
        };
        // Seeds of literals alone name one address; seeds or an address
        // built only from arguments name whichever the caller picks.
        let seeds_fix = a.seeds
            && (a.seed_names.iter().all(|n| n == "::") || a.seed_names.iter().any(fixed));
        // `has_one = x` compares against `x.key()`, and `x` may be an
        // instruction argument as well as a slot.
        if seeds_fix
            || a.has_one.iter().any(|n| n != "::" && fixed(n))
            || (a.address && a.address_names.iter().any(fixed))
            || (a.token_authority && a.authority_names.iter().any(fixed))
        {
            return false;
        }
        !self.map.iter().any(|((i, p), t)| {
            i == ix && {
                let named = |n: &String| p != path && resolve(p, n) == path;
                t.attrs.has_one.iter().any(named)
                    || t.attrs.refs.iter().any(named)
                    || t.attrs.keyed_constraints.iter().any(|c| ties(p, c))
            }
        })
    }

    /// The account lists as an IDL would give them, read from source
    /// alone, for programs with no IDL to hand (#11): signer from `Signer`
    /// or `#[account(signer)]`, writable from `mut` / `init`, a PDA from
    /// `seeds` or `associated_token::authority` (seed values not read), a
    /// fixed address from an `address` constraint — constant or not, where
    /// an IDL lists only constant ones — or a `Program<'info, T>` / `Sysvar`
    /// type,
    /// relations from `has_one`. Unplaced slots (an alias, a multi-line
    /// type) are listed too, as nothing declared. No discriminators, args
    /// or program id: enough for the map, not for building a spec.
    pub fn to_idl(&self) -> Idl {
        let mut by_ix: std::collections::BTreeMap<&str, Vec<(&String, &Slot)>> = Default::default();
        for ((ix, path), s) in &self.map {
            by_ix.entry(ix.as_str()).or_default().push((path, s));
        }
        let instructions = by_ix
            .into_iter()
            .map(|(ix, mut slots)| {
                slots.sort_by_key(|(_, s)| s.order);
                IdlInstruction {
                    name: ix.to_string(),
                    discriminator: Vec::new(),
                    args: Vec::new(),
                    accounts: slots
                        .into_iter()
                        .map(|(path, s)| {
                            IdlAccountItem::Single(IdlAccount {
                                name: path.clone(),
                                writable: s.attrs.mutable,
                                // Anchor makes a non-PDA `init` account sign: it is
                                // created at a fresh keypair's address.
                                signer: s.ty == "Signer"
                                    || s.attrs.signer
                                    || (s.attrs.init && !s.attrs.seeds && !s.attrs.token_authority),
                                optional: s.optional,
                                // `Program<'info, T>` and `Sysvar` name one address by type.
                                address: (s.attrs.address || matches!(s.ty.as_str(), "Program" | "Sysvar"))
                                    .then(|| "(from source)".into()),
                                // An associated token account is a PDA of the ATA program.
                                pda: (s.attrs.seeds || s.attrs.token_authority)
                                    .then(|| IdlPda { seeds: Vec::new(), program: None }),
                                relations: s.attrs.has_one.clone(),
                            })
                        })
                        .collect(),
                }
            })
            .collect();
        Idl { address: String::new(), instructions, accounts: Vec::new() }
    }

    /// Every placed slot, as ((instruction, path), slot), sorted.
    pub fn slots(&self) -> Vec<(&(String, String), &Slot)> {
        let mut v: Vec<_> = self.map.iter().collect();
        v.sort_by(|a, b| a.0.cmp(b.0));
        v
    }

    /// Read every `.rs` file under `dir` (or `dir` itself, if a file).
    pub fn read(dir: &Path) -> Result<Self> {
        let mut files = Vec::new();
        collect(dir, &mut files)
            .with_context(|| format!("failed to read sources under {}", dir.display()))?;
        Ok(Self::parse_files(&files))
    }

    #[cfg(test)]
    pub fn parse(src: &str) -> Self {
        Self::parse_files(&[("<src>".to_string(), src.to_string())])
    }

    pub fn parse_files(files: &[(String, String)]) -> Self {
        // Type aliases are not resolved: what an alias names depends on
        // module scope and imports (`use x::Account as Raw`), which a
        // line reader cannot follow. A slot typed by an alias is
        // unplaced, never guessed.
        let derive = Regex::new(
            // `[^{]`, not `[^{;]`: an `#[instruction(.., proof: Vec<[u8; 32]>)]`
            // between the derive and the struct carries a `;`.
            r"#\[derive\([^)]*\bAccounts\b[^)]*\)\][^{]*?\bstruct\s+([A-Za-z_]\w*)[^{;]*\{",
        )
        .unwrap();
        // A field's type starts upper-case, which also keeps attribute
        // lines like `token::mint = x,` from reading as fields.
        let field = Regex::new(
            r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?([a-z_]\w*)\s*:\s*([A-Z].*?),?\s*$",
        )
        .unwrap();
        let handler = Regex::new(
            r"fn\s+([A-Za-z_]\w*)\s*(?:<[^>(]*>)?\s*\(\s*[A-Za-z_]\w*\s*:\s*Context\s*<([^()]*?)>\s*[,)]",
        )
        .unwrap();
        let ident = Regex::new(r"\b([A-Z]\w*)\b").unwrap();
        // vipers' `impl<'info> Validate<'info> for X<'info>`, run by
        // `#[access_control(ctx.accounts.validate())]` on the handler.
        let validate_impl = Regex::new(
            r"\bimpl\b[^{;]*?\bValidate\s*(?:<[^{;>]*>)?\s+for\s+(?:[A-Za-z_]\w*::)*([A-Za-z_]\w*)[^{;]*\{",
        )
        .unwrap();
        let key_assert = Regex::new(r"\bassert_keys_(eq|neq)\s*!\s*[(\[]").unwrap();
        // `self.x.validate()` or `Validate::validate(&self.x)`.
        let validate_call = Regex::new(
            r"\bself\s*\.\s*([a-z_]\w*)\s*\.\s*validate\s*\(\s*\)|\bValidate\s*::\s*validate\s*\(\s*&\s*self\s*\.\s*([a-z_]\w*)\s*\)",
        )
        .unwrap();
        let access_control =
            Regex::new(r"access_control\s*\([^]]*\bctx\s*\.\s*accounts\s*\.\s*validate\s*\(\s*\)")
                .unwrap();

        let stripped: Vec<(String, String)> = files
            .iter()
            .map(|(f, t)| (f.clone(), strip_comments_and_strings(t)))
            .collect();
        let exprs: HashMap<&str, String> =
            files.iter().map(|(f, t)| (f.as_str(), strip_comments(t))).collect();

        // (struct name, file, file text, body offset in it, body)
        let mut bodies: Vec<(String, &str, &str, usize, &str)> = Vec::new();
        for (file, src) in &stripped {
            for c in derive.captures_iter(src) {
                let open = c.get(0).unwrap().end();
                if let Some(body) = braced(&src[open..]) {
                    bodies.push((c[1].to_string(), file, src, open, body));
                }
            }
        }
        let names: Vec<String> = bodies.iter().map(|b| b.0.clone()).collect();
        // A name defined twice (two modules, cfg alternatives) cannot be
        // told apart by `Context<Name>`: map neither.
        let dup = |n: &str| names.iter().filter(|m| *m == n).count() > 1;

        let mut structs: HashMap<String, Vec<RawField>> = HashMap::new();
        for (name, file, src, open, body) in &bodies {
            if dup(name) {
                continue;
            }
            let expr_body = &exprs[*file][*open..*open + body.len()];
            let mut prev = 0;
            let mut fields = Vec::new();
            for c in field.captures_iter(body) {
                let m = c.get(0).unwrap();
                let attrs = read_attrs(&body[prev..m.start()], &expr_body[prev..m.start()]);
                prev = m.end();
                let at = open + c.get(1).unwrap().start();
                fields.push(RawField {
                    name: c[1].to_string(),
                    field: classify(&c[2], &names),
                    ty: base_ident(&c[2]),
                    full_ty: full_type(&c[2]),
                    optional: c[2].trim().trim_start_matches("Box<").trim().starts_with("Option<"),
                    attrs,
                    file: file.to_string(),
                    line: src[..at].matches('\n').count() + 1,
                });
            }
            structs.insert(name.clone(), fields);
        }

        let mut validates: HashMap<String, ValidateImpl> = HashMap::new();
        let mut seen: HashMap<String, usize> = HashMap::new();
        for (file, src) in &stripped {
            for c in validate_impl.captures_iter(src) {
                let open = c.get(0).unwrap().end();
                let Some(body) = braced(&src[open..]) else { continue };
                let expr_body = &exprs[file.as_str()][open..open + body.len()];
                *seen.entry(c[1].to_string()).or_default() += 1;
                let v = validates.entry(c[1].to_string()).or_default();
                for m in key_assert.captures_iter(body) {
                    let at = m.get(0).unwrap().end();
                    let Some(close) = closing_paren(&body[at..]) else { continue };
                    let args = split_top(&body[at..at + close], &expr_body[at..at + close]);
                    if let [a, b, ..] = args.as_slice() {
                        v.checks.push((&m[1] == "eq", [a.clone(), b.clone()]));
                    }
                }
                v.calls.extend(
                    validate_call
                        .captures_iter(body)
                        .filter_map(|c| c.get(1).or(c.get(2)).map(|m| m.as_str().to_string())),
                );
            }
        }
        // Two impls for one name cannot be told apart: use neither.
        validates.retain(|n, _| seen[n] == 1);

        let mut map = HashMap::new();
        let mut validated = Vec::new();
        for (_, src) in &stripped {
            for c in handler.captures_iter(src) {
                let Some(ctx) = ident.captures_iter(&c[2]).last() else { continue };
                walk(&structs, &ctx[1], &c[1], "", &mut map, 0);
                // The handler's attributes: back to the item before it.
                let start = c.get(0).unwrap().start();
                let from = src[..start].rfind(['}', ';', '{']).map_or(0, |i| i + 1);
                if access_control.is_match(&src[from..start]) {
                    validated.push((ctx[1].to_string(), c[1].to_string()));
                }
            }
        }
        // After every walk: a second fn of the same name (the program's
        // wrapper and the action it calls) walks the same slots again.
        for (ctx, ix) in validated {
            apply_validate(&structs, &validates, &ctx, &ix, "", &mut map, 0);
        }
        SourceKinds { map }
    }
}

/// The constraints in the `#[account(...)]` attribute(s) preceding a
/// field, read item by item at the top level — a `signer` or `seeds`
/// inside a constraint's expression is part of that expression. `text`
/// has comments and literals blanked and decides the structure;
/// `expr`, the same bytes with only comments blanked, supplies the
/// constraint expressions.
fn read_attrs(text: &str, expr: &str) -> Attrs {
    // An upper-case constant: `VAULT_ID`, `crate::ID`. A qualified call
    // (`helpers::f(arg)`) is not one.
    let constant = Regex::new(r"\b[A-Z][A-Z0-9_]*\b").unwrap();
    // `x.key()`, or `x.key` — the `AccountInfo` field older Anchor code
    // compares (`authority.key == &token.owner`).
    let keyed = Regex::new(r"\.\s*key\b(?:\s*\(\s*\))?").unwrap();
    let keyed_call = Regex::new(r"\.\s*key\s*\(\s*\)").unwrap();
    let field_key = Regex::new(r"\b([a-z_][A-Za-z0-9_]*)\s*\.\s*key\b").unwrap();
    // A name at the head of a path: not after `.` (a field) or `::` (a
    // module item). `text` has literals blanked, so `b"vault"` names
    // nothing.
    let name = Regex::new(r"(?:^|[^.:\w\s])\s*([a-z_][A-Za-z0-9_]*)|^\s*([a-z_][A-Za-z0-9_]*)").unwrap();
    // The names in `s` (a slice of `text`), `"::"` added for a constant.
    // `expr` has the same bytes with literals kept, so a `b` or `br`
    // before a quote there is a byte-string prefix, not a name.
    let names_in = |s: &str| -> Vec<String> {
        let at = s.as_ptr() as usize - text.as_ptr() as usize;
        let mut names: Vec<String> = name
            .captures_iter(s)
            .filter_map(|c| c.get(1).or(c.get(2)))
            .filter(|m| !matches!(expr.as_bytes().get(at + m.end()), Some(b'"' | b'\'' | b'#')))
            .map(|m| m.as_str().to_string())
            .collect();
        if constant.is_match(s) {
            names.push("::".into());
        }
        names
    };
    let mut a = Attrs::default();
    for r in account_items(text) {
        let item = &text[r.clone()];
        let eq = assignment(item);
        let key = eq.map_or(item, |e| &item[..e]).trim();
        let value = eq.map(|e| item[e + 1..].trim());
        let bare = key.split_whitespace().next().unwrap_or("");
        if let Some(v) = value {
            // The `@ Error` names no account.
            let v = &v[..error_cut(v)];
            if bare == "constraint" {
                // Each `&&` / `||` clause on its own: in
                // `admin.key() == ADMIN && vault.amount > 0` the key
                // comparison says nothing about `vault`.
                for clause in clauses(v).into_iter().filter(|c| keyed.is_match(c)) {
                    let mut names = names_in(clause);
                    // `x.key` without `()` is the address only on an
                    // `AccountInfo`-like slot; on `Account<T>` it is a data
                    // field. Mark the receivers so `unbound` can check.
                    if !keyed_call.is_match(clause) {
                        names.extend(field_key.captures_iter(clause).map(|c| format!("@key:{}", &c[1])));
                    }
                    a.keyed_constraints.push(names);
                }
            }
            let fixes = match bare {
                "seeds" | "address" | "token::authority" => true,
                b => b.starts_with("associated_token::"),
            };
            if fixes {
                let marked = names_in(v);
                a.refs.extend(marked.iter().filter(|n| *n != "::").cloned());
                match bare {
                    "seeds" => a.seed_names = marked,
                    "address" => a.address_names = marked,
                    "associated_token::authority" => a.authority_names = marked,
                    _ => {}
                }
            }
        }
        a.token_authority |= bare == "associated_token::authority";
        match (bare, value) {
            ("init", _) => {
                a.mutable = true;
                a.init = true;
            }
            ("mut" | "init_if_needed", _) => a.mutable = true,
            ("signer", _) => a.signer = true,
            ("seeds", Some(_)) => a.seeds = true,
            ("address", Some(_)) => a.address = true,
            ("owner", Some(_)) => a.owner = true,
            ("close", Some(v)) => a.close = Some(v[..error_cut(v)].split_whitespace().collect()),
            ("has_one", Some(v)) => {
                let target: String =
                    v.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
                a.has_one.push(target);
            }
            ("constraint", Some(_)) => {
                let at = r.start + eq.unwrap() + 1..r.end;
                a.constraints.push(normalise_expr(&text[at.clone()], &expr[at]));
            }
            _ => {}
        }
    }
    a
}

/// Offset of an item's `key = value` sign: the first `=` that is not
/// part of `==`, `!=`, `<=` or `>=`.
fn assignment(item: &str) -> Option<usize> {
    let b = item.as_bytes();
    (0..b.len()).find(|&i| {
        b[i] == b'='
            && b.get(i + 1) != Some(&b'=')
            && !matches!(i.checked_sub(1).map(|p| b[p]), Some(b'=' | b'!' | b'<' | b'>'))
    })
}

/// Byte ranges of the top-level comma-separated items of every
/// `#[account(...)]` in `text`. `::<…>` nests, and so does a `<`
/// directly inside it (not inside its `{…}` or `(…)`, where `<` compares),
/// so a turbofish's commas do not split an expression.
fn account_items(text: &str) -> Vec<std::ops::Range<usize>> {
    let mut items = Vec::new();
    let mut from = 0;
    while let Some(i) = text[from..].find("#[account(") {
        let base = from + i + "#[account(".len();
        let body = &text[base..];
        let b = body.as_bytes();
        let (mut depth, mut start, mut end) = (0i32, 0usize, body.len());
        // The bracket depth at which each open `<` of a turbofish sits.
        let mut angles: Vec<i32> = Vec::new();
        for (j, ch) in body.char_indices() {
            match ch {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' if depth == 0 => {
                    end = j;
                    break;
                }
                ')' | ']' | '}' => depth -= 1,
                '<' if angles.last() == Some(&depth) || (j >= 2 && &b[j - 2..j] == b"::") => {
                    angles.push(depth)
                }
                '>' if angles.last() == Some(&depth) && (j == 0 || b[j - 1] != b'-') => {
                    angles.pop();
                }
                ',' if depth == 0 && angles.is_empty() => {
                    items.push(base + start..base + j);
                    start = j + 1;
                }
                _ => {}
            }
        }
        if !body[start..end].trim().is_empty() {
            items.push(base + start..base + end);
        }
        from = base + end;
    }
    items
}

/// A constraint's expression with its `@ Error` dropped and whitespace
/// collapsed, so reformatting does not read as a change. `blanked` is
/// the same bytes with literals blanked and finds the `@`, so an `@` or
/// bracket inside a string is part of the expression.
fn normalise_expr(blanked: &str, v: &str) -> String {
    v[..error_cut(blanked)].split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The clauses every passing evaluation of `v` must satisfy: `v` split
/// at its top-level `&&`, wrapping parentheses removed, recursively. A
/// part with a top-level `||` contributes nothing, since one branch
/// alone can pass.
fn clauses(v: &str) -> Vec<&str> {
    let v = v.trim();
    let b = v.as_bytes();
    // `( … )` around the whole value, matched at its own depth.
    if b.first() == Some(&b'(') {
        let mut depth = 0i32;
        let close = b.iter().position(|&c| {
            depth += match c {
                b'(' | b'[' | b'{' => 1,
                b')' | b']' | b'}' => -1,
                _ => 0,
            };
            depth == 0
        });
        if close == Some(b.len() - 1) {
            return clauses(&v[1..v.len() - 1]);
        }
    }
    let (mut depth, mut start, mut parts, mut or) = (0i32, 0usize, Vec::new(), false);
    let mut j = 0;
    while j < b.len() {
        match b[j] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b'|' if depth == 0 && b.get(j + 1) == Some(&b'|') => {
                or = true;
                j += 1;
            }
            b'&' if depth == 0 && b.get(j + 1) == Some(&b'&') => {
                parts.push(&v[start..j]);
                start = j + 2;
                j += 1;
            }
            _ => {}
        }
        j += 1;
    }
    if or {
        return Vec::new();
    }
    if parts.is_empty() {
        return vec![v];
    }
    parts.push(&v[start..]);
    parts.into_iter().flat_map(clauses).collect()
}

/// Where a value's top-level `@ Error` starts (its end if none), found
/// in literal-blanked text so an `@` inside a string is not one.
fn error_cut(blanked: &str) -> usize {
    let mut depth = 0i32;
    for (j, ch) in blanked.char_indices() {
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            '@' if depth == 0 => return j,
            _ => {}
        }
    }
    blanked.len()
}

fn full_type(ty: &str) -> String {
    let compact: String = ty.chars().filter(|c| !c.is_whitespace()).collect();
    let mut t = compact.as_str();
    while let Some(inner) = t.strip_prefix("Box<").and_then(|r| r.strip_suffix('>')) {
        t = inner;
    }
    t.to_string()
}

fn walk(
    structs: &HashMap<String, Vec<RawField>>,
    name: &str,
    ix: &str,
    prefix: &str,
    out: &mut HashMap<(String, String), Slot>,
    depth: usize,
) {
    let Some(fields) = structs.get(name) else { return };
    if depth > 8 {
        return;
    }
    for f in fields {
        let path = if prefix.is_empty() { f.name.clone() } else { format!("{prefix}.{}", f.name) };
        let kind = match &f.field {
            Field::Composite(inner) => {
                walk(structs, inner, ix, &path, out, depth + 1);
                continue;
            }
            Field::Kind(k) => Some(*k),
            Field::Unknown => None,
        };
        let key = (ix.to_string(), path);
        // A second handler of the same name walks the same slots again.
        let order = out
            .get(&key)
            .map_or_else(|| out.keys().filter(|(i, _)| i == ix).count(), |s| s.order);
        out.insert(
            key,
            Slot {
                kind,
                ty: f.ty.clone(),
                full_ty: f.full_ty.clone(),
                optional: f.optional,
                attrs: f.attrs.clone(),
                file: f.file.clone(),
                line: f.line,
                order,
            },
        );
    }
}

/// Attach the key checks `name`'s `validate()` runs (and the composites'
/// `validate()` it calls) to the slots they name, for instruction `ix`.
fn apply_validate(
    structs: &HashMap<String, Vec<RawField>>,
    validates: &HashMap<String, ValidateImpl>,
    name: &str,
    ix: &str,
    prefix: &str,
    out: &mut HashMap<(String, String), Slot>,
    depth: usize,
) {
    let Some(v) = validates.get(name) else { return };
    if depth > 8 {
        return;
    }
    let join = |p: &str, f: &str| if p.is_empty() { f.to_string() } else { format!("{p}.{f}") };
    let constant = Regex::new(r"^(?:[A-Za-z_]\w*::)*[A-Z][A-Z0-9_]*$").unwrap();
    for (eq, args) in &v.checks {
        // Each argument: its text from the instruction's root, and the
        // slot it names (`self.bank.crate_mint` names `bank`), or "::"
        // for a constant.
        let mut resolved: Vec<(String, Option<String>)> = args
            .iter()
            .map(|a| a.trim_start_matches(['&', '*']))
            .map(|a| a.strip_suffix(".key()").unwrap_or(a))
            .map(|a| match a.strip_prefix("self.") {
                Some(rest) => {
                    let segs: Vec<&str> = rest
                        .split('.')
                        .take_while(|s| !s.is_empty() && s.chars().all(|c| c.is_alphanumeric() || c == '_'))
                        .collect();
                    let text = join(prefix, rest);
                    let head = (1..=segs.len()).rev().map(|k| join(prefix, &segs[..k].join("."))).find(|p| {
                        out.contains_key(&(ix.to_string(), p.clone()))
                    });
                    (text, head)
                }
                None if constant.is_match(a) => (a.to_string(), Some("::".to_string())),
                None => (a.to_string(), None),
            })
            .collect();
        // Sorted, so swapping the arguments is not a change.
        resolved.sort();
        let Some(slot) = resolved.iter().find_map(|(_, h)| h.clone().filter(|h| h != "::")) else {
            continue;
        };
        let texts: Vec<&str> = resolved.iter().map(|(t, _)| t.as_str()).collect();
        let check = format!("assert_keys_{}!({})", if *eq { "eq" } else { "neq" }, texts.join(", "));
        let names: Vec<String> = resolved.iter().filter_map(|(_, h)| h.clone()).collect();
        if let Some(s) = out.get_mut(&(ix.to_string(), slot)) {
            if !s.attrs.validate.contains(&check) {
                s.attrs.validate.push(check);
                if *eq {
                    s.attrs.validate_keys.push(names);
                }
            }
        }
    }
    let Some(fields) = structs.get(name) else { return };
    for call in &v.calls {
        if let Some(Field::Composite(inner)) = fields.iter().find(|f| &f.name == call).map(|f| &f.field) {
            apply_validate(structs, validates, inner, ix, &join(prefix, call), out, depth + 1);
        }
    }
}

/// Offset of the `)` that closes a parenthesis already opened.
fn closing_paren(s: &str) -> Option<usize> {
    let mut depth = 0i32;
    for (i, ch) in s.char_indices() {
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' if depth == 0 => return Some(i),
            ')' | ']' | '}' => depth -= 1,
            _ => {}
        }
    }
    None
}

/// `expr` split at the top-level commas `blanked` (the same bytes, with
/// literals blanked) shows, each part with whitespace removed.
fn split_top(blanked: &str, expr: &str) -> Vec<String> {
    let (mut depth, mut start, mut parts) = (0i32, 0usize, Vec::new());
    for (i, ch) in blanked.char_indices() {
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(&expr[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&expr[start..]);
    parts
        .into_iter()
        .map(|p| p.chars().filter(|c| !c.is_whitespace()).collect::<String>())
        .filter(|p| !p.is_empty())
        .collect()
}

const TYPED: &[&str] = &[
    "Account",
    "AccountLoader",
    "InterfaceAccount",
    "Signer",
    "Program",
    "Interface",
    "Sysvar",
    "SystemAccount",
];

fn is_unchecked(ty: &str) -> bool {
    let base = base_ident(ty);
    base == "UncheckedAccount" || base == "AccountInfo"
}

/// First identifier under any `Box<` / `Option<` wrappers.
fn base_ident(ty: &str) -> String {
    let mut t = ty.trim();
    loop {
        let next = t.strip_prefix("Box<").or_else(|| t.strip_prefix("Option<"));
        match next {
            Some(rest) => t = rest.trim(),
            None => break,
        }
    }
    t.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect()
}

fn classify(ty: &str, accounts_structs: &[String]) -> Field {
    if is_unchecked(ty) {
        return Field::Kind(SlotKind::Unchecked);
    }
    let base = base_ident(ty);
    if TYPED.contains(&base.as_str()) {
        return Field::Kind(SlotKind::Typed);
    }
    if accounts_structs.iter().any(|n| *n == base) {
        return Field::Composite(base);
    }
    Field::Unknown
}

/// Blank out comments and string literals, keeping line structure, so
/// text inside them is never read as a struct or a field.
fn strip_comments_and_strings(src: &str) -> String {
    strip(src, false)
}

/// Blank out comments only: the text constraint expressions are read
/// from, so a changed string literal in one is still a change.
fn strip_comments(src: &str) -> String {
    strip(src, true)
}

/// Both strippers blank byte for byte, so offsets in their outputs and
/// in `src` agree.
fn strip(src: &str, keep_strings: bool) -> String {
    let b = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    let blank = |out: &mut String, s: &str| {
        for ch in s.chars() {
            let fill = if ch == '\n' { '\n' } else { ' ' };
            for _ in 0..ch.len_utf8() {
                out.push(fill);
            }
        }
    };
    while i < b.len() {
        let rest = &src[i..];
        let skip = if rest.starts_with("//") {
            rest.find('\n').unwrap_or(rest.len())
        } else if rest.starts_with("/*") {
            block_comment_len(rest)
        } else if let Some(n) = raw_string_len(rest) {
            n
        } else if rest.starts_with('"') {
            let mut j = 1;
            while j < rest.len() {
                match rest.as_bytes()[j] {
                    b'\\' => j += 2,
                    b'"' => break,
                    _ => j += 1,
                }
            }
            (j + 1).min(rest.len())
        } else if let Some(n) = char_literal_len(rest) {
            n
        } else {
            0
        };
        let is_comment = rest.starts_with("//") || rest.starts_with("/*");
        if skip > 0 && keep_strings && !is_comment {
            out.push_str(&src[i..i + skip]);
            i += skip;
        } else if skip > 0 {
            blank(&mut out, &src[i..i + skip]);
            i += skip;
        } else {
            let ch = rest.chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

/// Length of a block comment at the start of `s`, nesting as Rust's do;
/// unterminated runs to the end.
fn block_comment_len(s: &str) -> usize {
    let b = s.as_bytes();
    let (mut depth, mut i) = (0usize, 0usize);
    while i + 1 < b.len() {
        if b[i] == b'/' && b[i + 1] == b'*' {
            depth += 1;
            i += 2;
        } else if b[i] == b'*' && b[i + 1] == b'/' {
            depth -= 1;
            i += 2;
            if depth == 0 {
                return i;
            }
        } else {
            i += 1;
        }
    }
    s.len()
}

/// Length of a char literal (`'{'`, `'\n'`, `'\u{7b}'`) at the start of
/// `s`. A lifetime (`'info`) has no closing quote within reach.
fn char_literal_len(s: &str) -> Option<usize> {
    let rest = s.strip_prefix('\'')?;
    if let Some(esc) = rest.strip_prefix('\\') {
        let close = esc.find('\'')?;
        return (close <= 8).then_some(close + 3);
    }
    let ch = rest.chars().next()?;
    rest[ch.len_utf8()..].starts_with('\'').then_some(ch.len_utf8() + 2)
}

/// Length of a raw string literal (`r"…"`, `r#"…"#`, …) at the start of
/// `s`, if there is one.
fn raw_string_len(s: &str) -> Option<usize> {
    let rest = s.strip_prefix('r').or_else(|| s.strip_prefix("br"))?;
    let hashes = rest.chars().take_while(|c| *c == '#').count();
    let body = rest[hashes..].strip_prefix('"')?;
    let close = format!("\"{}", "#".repeat(hashes));
    // Unterminated: blank to the end rather than reading the rest as code.
    Some(body.find(&close).map_or(s.len(), |end| s.len() - body.len() + end + close.len()))
}

/// The text up to the brace that closes one already opened.
fn braced(s: &str) -> Option<&str> {
    let mut depth = 1;
    for (i, ch) in s.char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&s[..i]);
                }
            }
            _ => {}
        }
    }
    None
}

fn collect(dir: &Path, out: &mut Vec<(String, String)>) -> Result<()> {
    if dir.is_file() {
        out.push((dir.display().to_string(), fs::read_to_string(dir)?));
        return Ok(());
    }
    let mut entries: Vec<_> = fs::read_dir(dir)?.collect::<std::io::Result<_>>()?;
    entries.sort_by_key(|e| e.path());
    for e in entries {
        let p = e.path();
        if p.is_dir() {
            collect(&p, out)?;
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push((p.display().to_string(), fs::read_to_string(&p)?));
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn escrow_slots_are_classified_by_declared_type() {
        let k = SourceKinds::parse(include_str!(
            "../../../examples/escrow-demo/programs/escrow/src/lib.rs"
        ));
        assert_eq!(k.get("unsafe_withdraw", "vault"), Some(SlotKind::Unchecked));
        assert_eq!(k.get("unsafe_withdraw", "depositor"), Some(SlotKind::Unchecked));
        assert_eq!(k.get("deposit", "vault"), Some(SlotKind::Typed));
        assert_eq!(k.get("claim", "depositor"), Some(SlotKind::Unchecked));
        assert_eq!(k.get("unsafe_set_amount_from_source", "target"), Some(SlotKind::Typed));
    }

    #[test]
    fn aliases_unknown_types_duplicates_and_text_in_strings() {
        let src = r##"
type Raw<'info> = AccountInfo<'info>;
pub fn a(ctx: Context<A>) -> Result<()> {}
pub fn b(ctx: Context<Dup>) -> Result<()> {}
#[derive(Accounts)]
pub struct A<'info> {
    pub vault: Raw<'info>,
    pub(crate) state: Box<Account<'info, State>>,
    hidden: UncheckedAccount<'info>,
    pub custom: Wrapper<'info>,
    pub maybe: Option<UncheckedAccount<'info>>,
}
mod one {
    #[derive(Accounts)]
    pub struct Dup<'info> { pub x: AccountInfo<'info>, }
}
mod two {
    #[derive(Accounts)]
    pub struct Dup<'info> { pub x: Account<'info, X>, }
}
/* #[derive(Accounts)]
pub struct A<'info> { pub state: AccountInfo<'info>, } */
const DOC: &str = r#"
#[derive(Accounts)]
pub struct A<'info> {
    pub custom: AccountInfo<'info>,
}
"#;
"##;
        let k = SourceKinds::parse(src);
        assert_eq!(k.get("a", "vault"), None); // alias: unplaced
        assert_eq!(k.get("a", "state"), Some(SlotKind::Typed));
        assert_eq!(k.get("a", "hidden"), Some(SlotKind::Unchecked));
        assert_eq!(k.get("a", "custom"), None);
        assert_eq!(k.get("a", "maybe"), Some(SlotKind::Unchecked));
        assert_eq!(k.get("b", "x"), None);
    }

    #[test]
    fn nested_comments_and_unterminated_raw_strings_hide_their_contents() {
        // Either leak would define a second X, and a duplicate name is
        // left unmapped — so Some(Unchecked) proves neither leaked.
        let src = r####"
pub fn a(ctx: Context<X>) -> Result<()> {}
#[derive(Accounts)]
pub struct X<'info> {
    pub vault: AccountInfo<'info>,
}
/* outer /* inner */
#[derive(Accounts)]
pub struct X<'info> { pub vault: Account<'info, V>, }
*/
const S: &str = r##"never closed "# and then
#[derive(Accounts)]
pub struct X<'info> { pub vault: Account<'info, V>, }
"####;
        assert_eq!(SourceKinds::parse(src).get("a", "vault"), Some(SlotKind::Unchecked));
    }

    #[test]
    fn aliases_are_never_resolved() {
        let src = r#"
mod a { type Base<'info> = AccountInfo<'info>; }
mod b {
    type Base<'info> = Account<'info, State>;
    type Local<'info> = Base<'info>;
}
pub fn f(ctx: Context<F>) -> Result<()> {}
#[derive(Accounts)]
pub struct F<'info> {
    pub state: Local<'info>,
}
"#;
        assert_eq!(SourceKinds::parse(src).get("f", "state"), None);
    }

    #[test]
    fn attribute_items_not_words_in_expressions() {
        let src = r#"
pub fn f(ctx: Context<F>) -> Result<()> {}
#[derive(Accounts)]
pub struct F<'info> {
    #[account(
        mut,
        has_one = authority @ E::Auth,
        constraint = {
            let signer = is_ok(seeds, owner);
            signer
        } @ E::Bad,
        constraint = vault.amount
            >= min,
    )]
    pub vault: Box<Account<'info, Vault>>,
    pub maybe: Option<Account<'info, Config>>,
}
"#;
        let k = SourceKinds::parse(src);
        let v = k.slot("f", "vault").unwrap();
        assert!(v.attrs.mutable && !v.attrs.signer && !v.attrs.seeds && !v.attrs.owner);
        assert_eq!(v.attrs.has_one, vec!["authority"]);
        assert_eq!(
            v.attrs.constraints,
            vec!["{ let signer = is_ok(seeds, owner); signer }", "vault.amount >= min"]
        );
        assert_eq!(v.full_ty, "Account<'info,Vault>");
        assert!(!v.optional && k.slot("f", "maybe").unwrap().optional);
    }

    #[test]
    fn constraint_literals_and_turbofish_commas_are_kept() {
        let src = r#"
pub fn f(ctx: Context<F>) -> Result<()> {}
#[derive(Accounts)]
pub struct F<'info> {
    #[account(
        constraint = role == "admin" // a comment, with a comma
            @ E::Role,
        constraint = check::<Policy, Admin>(x),
        constraint = name == "team@alpha(" @ E::Name,
        constraint = check::<Result<Admin, User>, Policy>(y),
        constraint = check::<{ N < 3 }, Policy>(z),
        signer,
    )]
    pub vault: Account<'info, Vault>,
}
"#;
        let k = SourceKinds::parse(src);
        assert_eq!(
            k.slot("f", "vault").unwrap().attrs.constraints,
            vec![
                r#"role == "admin""#,
                "check::<Policy, Admin>(x)",
                r#"name == "team@alpha(""#,
                "check::<Result<Admin, User>, Policy>(y)",
                "check::<{ N < 3 }, Policy>(z)",
            ]
        );
        assert!(k.slot("f", "vault").unwrap().attrs.signer);
    }

    #[test]
    fn typed_accounts_not_tied_to_another_slot_are_unbound() {
        let src = r#"
pub fn buy(ctx: Context<Buy>) -> Result<()> {}
pub fn bound(ctx: Context<Bound>) -> Result<()> {}
#[derive(Accounts)]
pub struct Buy<'info> {
    #[account(mut)]
    pub sale: Account<'info, Sale>,
    #[account(mut)]
    pub vault: Account<'info, TokenAccount>,
    #[account(mut, constraint = own.amount > 0 && config.vault == sale.payout)]
    pub config: Account<'info, Config>,
    #[account(mut, constraint = own.key() == config.sale)]
    pub own: Account<'info, TokenAccount>,
    #[account(mut, token::mint = sale.mint)]
    pub mint_only: Account<'info, TokenAccount>,
    #[account(mut, constraint = buyer.key() == consts::reused() @ E::X)]
    pub elsewhere: Account<'info, TokenAccount>,
    #[account(seeds = [b"vault", b"sale"], bump)]
    pub registry: Account<'info, Registry>,
    #[account(mut, constraint = same.key() == same.key())]
    pub same: Account<'info, TokenAccount>,
    #[account(mut, constraint = fixed.key() == FIXED_ID)]
    pub fixed: Account<'info, TokenAccount>,
    #[account(constraint = buyer.key == &field_key.owner)]
    pub field_key: Account<'info, TokenAccount>,
    #[account(mut, constraint = keyring.keys_len > 0 && buyer.key() == ADMIN)]
    pub keyring: Account<'info, TokenAccount>,
    #[account(mut, constraint = order.key == config.key)]
    pub order: Account<'info, Order>,
    #[account(mut, constraint = arg.key() == expected)]
    pub arg: Account<'info, TokenAccount>,
    #[account(mut, constraint = sale.key() == sale.key())]
    pub other: Account<'info, TokenAccount>,
    #[account(mut, constraint = err.key() == err.key() @ ErrorCode::Unauthorized)]
    pub err: Account<'info, TokenAccount>,
    #[account(mut, constraint = call.key() == helpers::identity(expected))]
    pub call: Account<'info, TokenAccount>,
    #[account(mut, address = expected)]
    pub by_arg: Account<'info, TokenAccount>,
    #[account(mut, token::authority = expected)]
    pub owned_by_arg: Account<'info, TokenAccount>,
    #[account(mut, has_one = authority)]
    pub arg_has_one: Account<'info, Vault>,
    #[account(mut, constraint = buyer.key() == ADMIN && clause.amount > 0)]
    pub clause: Account<'info, TokenAccount>,
    #[account(mut, constraint = (buyer.key() == ADMIN && grouped.amount > 0))]
    pub grouped: Account<'info, TokenAccount>,
    #[account(mut, constraint = either.key() == EITHER || buyer.key() == ADMIN)]
    pub either: Account<'info, TokenAccount>,
    #[account(mut, constraint = (both.key() == BOTH) && (both.amount > 0 || buyer.key() == ADMIN))]
    pub both: Account<'info, TokenAccount>,
    #[account(seeds = [b"pos", expected.as_ref()], bump)]
    pub seeded_by_arg: Account<'info, Position>,
    #[account(init_if_needed, payer = buyer, space = 8)]
    pub reused: Account<'info, Receipt>,
    #[account(mut)]
    pub buyer: Signer<'info>,
    pub token_program: Program<'info, Token>,
}
#[derive(Accounts)]
pub struct Bound<'info> {
    #[account(mut, has_one = vault)]
    pub sale: Account<'info, Sale>,
    #[account(mut)]
    pub vault: Account<'info, TokenAccount>,
    #[account(mut, associated_token::mint = mint, associated_token::authority = sale)]
    pub escrow: Account<'info, TokenAccount>,
    #[account(mut, token::authority = sale)]
    pub owned_by_sale: Account<'info, TokenAccount>,
    pub mint: Account<'info, Mint>,
    #[account(mut, constraint = payout.key() == sale.payout @ E::Payout)]
    pub payout: Account<'info, TokenAccount>,
    #[account(address = crate::TREASURY)]
    pub treasury: Account<'info, TokenAccount>,
    #[account(seeds = [b"config"], bump)]
    pub singleton: Account<'info, Config>,
    #[account(init, payer = buyer, space = 8)]
    pub receipt: Account<'info, Receipt>,
    #[account(mut, constraint = fee.key() == FEE_VAULT)]
    pub fee: Account<'info, TokenAccount>,
    #[account(seeds = [b"pos", owner.key().as_ref()], bump)]
    pub position: Account<'info, Position>,
    pub owner: Account<'info, Owner>,
    #[account(mut)]
    pub buyer: Signer<'info>,
}
"#;
        let k = SourceKinds::parse(src);
        // `config.vault` and `config.sale` select fields: they do not tie
        // `vault` or `sale`. `own.key() == config.sale` ties both `own` and
        // `config`; `consts::reused()` names no slot, and `b"vault"` is a literal.
        for slot in [
            "sale", "vault", "mint_only", "reused", "elsewhere", "same", "arg", "other", "err",
            "call", "by_arg", "seeded_by_arg", "owned_by_arg", "arg_has_one", "clause",
            "grouped", "either", "keyring", "order",
        ] {
            assert!(k.unbound("buy", slot), "{slot}");
        }
        for slot in ["own", "config", "registry", "fixed", "both", "field_key", "buyer", "token_program"] {
            assert!(!k.unbound("buy", slot), "{slot}");
        }
        for slot in [
            "sale", "vault", "escrow", "payout", "receipt", "fee", "position", "owner", "treasury",
            "singleton", "mint",
        ] {
            assert!(!k.unbound("bound", slot), "{slot}");
        }
        // One authority can own many token accounts.
        assert!(k.unbound("bound", "owned_by_sale"));
    }

    /// vipers' `impl Validate` blocks, run through `#[access_control]`,
    /// the way the Saber family (Cashio among them) writes its checks.
    pub(crate) const VALIDATED: &str = r#"
#[access_control(ctx.accounts.validate())]
pub fn print(ctx: Context<Print>, amount: u64) -> Result<()> {}
pub fn unvalidated(ctx: Context<Print>) -> Result<()> {}
#[derive(Accounts)]
pub struct Common<'info> {
    pub bank: Box<Account<'info, Bank>>,
    pub crate_mint: Account<'info, Mint>,
    pub crate_token: Account<'info, CrateToken>,
}
#[derive(Accounts)]
pub struct Print<'info> {
    pub common: Common<'info>,
    #[account(mut)]
    pub source: Account<'info, TokenAccount>,
    #[account(mut)]
    pub destination: Account<'info, TokenAccount>,
    #[account(mut)]
    pub fee: Account<'info, TokenAccount>,
    pub issue_authority: Account<'info, Authority>,
    pub depositor: Signer<'info>,
}
impl<'info> Validate<'info> for Common<'info> {
    fn validate(&self) -> Result<()> {
        assert_keys_eq!(self.bank.crate_mint, self.crate_mint, "mint");
        assert_keys_eq!(self.crate_mint, self.crate_token.mint);
        Ok(())
    }
}
impl<'info> ::vipers::Validate<'info> for crate::Print<'info> {
    fn validate(&self) -> Result<()> {
        Validate::validate(&self.common)?;
        assert_keys_eq![&self.depositor, self.source.owner.key()];
        assert_keys_neq!(self.destination, self.source);
        assert_keys_eq!(self.issue_authority, crate::ISSUE_AUTHORITY);
        Ok(())
    }
}
"#;

    #[test]
    fn vipers_validate_checks_tie_slots_when_access_control_runs_them() {
        let k = SourceKinds::parse(VALIDATED);
        for slot in ["common.bank", "common.crate_mint", "common.crate_token", "source", "issue_authority"] {
            assert!(!k.unbound("print", slot), "{slot}");
        }
        // `assert_keys_neq!` ties nothing; `fee` is checked nowhere.
        assert!(k.unbound("print", "destination") && k.unbound("print", "fee"));
        // Without `#[access_control]` the impl never runs.
        assert!(k.unbound("unvalidated", "source") && k.unbound("unvalidated", "common.bank"));
        assert_eq!(
            k.slot("print", "common.bank").unwrap().attrs.validate,
            vec!["assert_keys_eq!(common.bank.crate_mint, common.crate_mint)"]
        );
        assert_eq!(
            k.slot("print", "destination").unwrap().attrs.validate,
            vec!["assert_keys_neq!(destination, source)"]
        );
    }

    /// Without an IDL the map's columns come from the attributes (#11),
    /// accounts in declaration order with composites flattened in place.
    #[test]
    fn to_idl_reads_the_columns_from_the_attributes() {
        let src = r#"
pub fn swap(ctx: Context<Swap>) -> Result<()> {}
#[derive(Accounts)]
pub struct Pool<'info> {
    #[account(mut, seeds = [b"pool"], bump)]
    pub state: Account<'info, State>,
}
#[derive(Accounts)]
pub struct Swap<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    pub pool: Pool<'info>,
    #[account(mut, address = pool.state.vault)]
    pub vault: Account<'info, TokenAccount>,
    #[account(mut, associated_token::mint = mint, associated_token::authority = user)]
    pub user_ata: Account<'info, TokenAccount>,
    pub mint: Account<'info, Mint>,
    pub token_program: Program<'info, Token>,
}
"#;
        let idl = SourceKinds::parse(src).to_idl();
        let ix = &idl.instructions[0];
        let rows: Vec<(String, bool, bool, bool, bool)> = ix
            .flat_accounts()
            .iter()
            .map(|f| {
                let a = f.account;
                (f.path(), a.signer, a.writable, a.pda.is_some(), a.address.is_some())
            })
            .collect();
        let fresh = SourceKinds::parse(&src.replace("    pub mint: Account<'info, Mint>,", "    #[account(init, payer = user, space = 8)]\n    pub mint: Account<'info, Mint>,"))
            .to_idl();
        let mint = fresh.instructions[0].flat_accounts().into_iter().find(|f| f.path() == "mint").unwrap();
        // A non-PDA `init` account signs, as Anchor's IDL says.
        assert!(mint.account.signer && mint.account.writable);
        let want = [
            ("user", true, true, false, false),
            ("pool.state", false, true, true, false),
            ("vault", false, true, false, true),
            ("user_ata", false, true, true, false),
            ("mint", false, false, false, false),
            ("token_program", false, false, false, true),
        ];
        assert_eq!(
            rows,
            want.iter().map(|&(p, s, w, pda, a)| (p.to_string(), s, w, pda, a)).collect::<Vec<_>>()
        );
    }

    /// strip() blanks byte for byte: non-ASCII text in a comment or a
    /// string before the attribute must not shift the expression read
    /// from the comments-only copy.
    #[test]
    fn non_ascii_before_an_expression_keeps_offsets_aligned() {
        let src = "pub fn f(ctx: Context<F>) -> Result<()> {}\n\
            // 日本語のコメント — with an em dash\n\
            const NOTE: &str = \"ünïcödé ✓\";\n\
            #[derive(Accounts)]\n\
            pub struct F<'info> {\n\
                /// ドキュメント\n\
                #[account(constraint = vault.owner_name == \"所有者\" @ E::X)]\n\
                pub vault: Account<'info, Vault>,\n\
            }\n";
        assert_eq!(strip(src, false).len(), src.len());
        assert_eq!(strip(src, true).len(), src.len());
        let k = SourceKinds::parse(src);
        let v = k.slot("f", "vault").unwrap();
        assert_eq!(v.attrs.constraints, vec!["vault.owner_name == \"所有者\""]);
        assert_eq!(v.line, 8);
    }

    #[test]
    fn brace_char_literals_do_not_end_a_struct() {
        let src = r#"
pub fn a(ctx: Context<A>) -> Result<()> { let _ = '}'; let _ = '\''; }
#[derive(Accounts)]
pub struct A<'info> {
    pub vault: AccountInfo<'info>,
}
"#;
        assert_eq!(SourceKinds::parse(src).get("a", "vault"), Some(SlotKind::Unchecked));
    }

    #[test]
    fn instruction_attribute_with_an_array_type_is_skipped_over() {
        let src = r#"
pub fn claim(ctx: Context<Claim>, bump: u8, proof: Vec<[u8; 32]>) -> Result<()> {}
#[derive(Accounts)]
#[instruction(_bump: u8, _proof: Vec<[u8; 32]>)]
pub struct Claim<'info> {
    pub claimant: AccountInfo<'info>,
}
"#;
        assert_eq!(SourceKinds::parse(src).get("claim", "claimant"), Some(SlotKind::Unchecked));
    }

    #[test]
    fn lifetimed_context_boxed_types_and_composites() {
        let src = r#"
pub fn swap<'info>(ctx: Context<'_, '_, '_, 'info, Swap<'info>>, amount: u64) -> Result<()> {}
#[derive(Accounts)]
pub struct Swap<'info> {
    pub pool: Box<Account<'info, Pool>>,
    /// CHECK: anything
    pub recipient: UncheckedAccount<'info>,
    pub inner: Inner<'info>,
}
#[derive(Accounts)]
pub struct Inner<'info> {
    pub authority: AccountInfo<'info>, // comment, with a comma
    pub mint: Box<InterfaceAccount<'info, Mint>>,
}
"#;
        let k = SourceKinds::parse(src);
        assert_eq!(k.get("swap", "pool"), Some(SlotKind::Typed));
        assert_eq!(k.get("swap", "recipient"), Some(SlotKind::Unchecked));
        assert_eq!(k.get("swap", "inner.authority"), Some(SlotKind::Unchecked));
        assert_eq!(k.get("swap", "inner.mint"), Some(SlotKind::Typed));
        assert_eq!(k.get("swap", "missing"), None);
    }
}
