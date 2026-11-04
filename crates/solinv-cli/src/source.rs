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
use solinv_fuzz::SlotKind;
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
}

/// Declared slots per (instruction, dotted slot path).
pub struct SourceKinds {
    map: HashMap<(String, String), Slot>,
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

        let mut map = HashMap::new();
        for (_, src) in &stripped {
            for c in handler.captures_iter(src) {
                let Some(ctx) = ident.captures_iter(&c[2]).last() else { continue };
                walk(&structs, &ctx[1], &c[1], "", &mut map, 0);
            }
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
    let mut a = Attrs::default();
    for r in account_items(text) {
        let item = &text[r.clone()];
        let eq = assignment(item);
        let key = eq.map_or(item, |e| &item[..e]).trim();
        let value = eq.map(|e| item[e + 1..].trim());
        let bare = key.split_whitespace().next().unwrap_or("");
        match (bare, value) {
            ("mut" | "init" | "init_if_needed", _) => a.mutable = true,
            ("signer", _) => a.signer = true,
            ("seeds", Some(_)) => a.seeds = true,
            ("address", Some(_)) => a.address = true,
            ("owner", Some(_)) => a.owner = true,
            ("has_one", Some(v)) => {
                let target: String =
                    v.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
                a.has_one.push(target);
            }
            ("constraint", Some(_)) => {
                let raw = &expr[r.start + eq.unwrap() + 1..r.end];
                a.constraints.push(normalise_expr(raw));
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
/// `#[account(...)]` in `text`. `::<…>` nests, so a turbofish's commas
/// do not split an expression.
fn account_items(text: &str) -> Vec<std::ops::Range<usize>> {
    let mut items = Vec::new();
    let mut from = 0;
    while let Some(i) = text[from..].find("#[account(") {
        let base = from + i + "#[account(".len();
        let body = &text[base..];
        let b = body.as_bytes();
        let (mut depth, mut angle, mut start, mut end) = (0i32, 0i32, 0usize, body.len());
        for (j, ch) in body.char_indices() {
            match ch {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' if depth == 0 => {
                    end = j;
                    break;
                }
                ')' | ']' | '}' => depth -= 1,
                '<' if j >= 2 && &b[j - 2..j] == b"::" => angle += 1,
                '>' if angle > 0 => angle -= 1,
                ',' if depth == 0 && angle == 0 => {
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
/// collapsed, so reformatting does not read as a change.
fn normalise_expr(v: &str) -> String {
    let (mut depth, mut cut) = (0i32, v.len());
    for (j, ch) in v.char_indices() {
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            '@' if depth == 0 => {
                cut = j;
                break;
            }
            _ => {}
        }
    }
    v[..cut].split_whitespace().collect::<Vec<_>>().join(" ")
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
        out.insert(
            (ix.to_string(), path),
            Slot {
                kind,
                ty: f.ty.clone(),
                full_ty: f.full_ty.clone(),
                optional: f.optional,
                attrs: f.attrs.clone(),
                file: f.file.clone(),
                line: f.line,
            },
        );
    }
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
mod tests {
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
    )]
    pub vault: Account<'info, Vault>,
}
"#;
        let k = SourceKinds::parse(src);
        assert_eq!(
            k.slot("f", "vault").unwrap().attrs.constraints,
            vec![r#"role == "admin""#, "check::<Policy, Admin>(x)"]
        );
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
