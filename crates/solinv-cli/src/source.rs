//! Declared account types from an Anchor program's source.
//!
//! The IDL cannot tell `Account<'info, T>` from `UncheckedAccount<'info>`
//! (Anchor strips the `/// CHECK:` line from `docs`), and that is the
//! distinction that matters: a typed slot's owner and discriminator are
//! checked by Anchor, an unchecked one's by hand. The source says which.
//!
//! Text, not a parser: one field per line, as rustfmt writes them. A
//! field this misses is reported as "not found in source", never guessed.

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

/// Declared kind per (instruction, dotted slot path).
pub struct SourceKinds {
    map: HashMap<(String, String), SlotKind>,
}

impl SourceKinds {
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn get(&self, ix: &str, path: &str) -> Option<SlotKind> {
        self.map.get(&(ix.to_string(), path.to_string())).copied()
    }

    /// Read every `.rs` file under `dir`.
    pub fn read(dir: &Path) -> Result<Self> {
        let mut text = String::new();
        collect(dir, &mut text)
            .with_context(|| format!("failed to read sources under {}", dir.display()))?;
        Ok(Self::parse(&text))
    }

    pub fn parse(src: &str) -> Self {
        let src = strip_comments_and_strings(src);

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
        let mut bodies: Vec<(String, String)> = Vec::new();
        for c in derive.captures_iter(&src) {
            let open = c.get(0).unwrap().end();
            if let Some(body) = braced(&src[open..]) {
                bodies.push((c[1].to_string(), body.to_string()));
            }
        }
        let names: Vec<String> = bodies.iter().map(|(n, _)| n.clone()).collect();
        // A name defined twice (two modules, cfg alternatives) cannot be
        // told apart by `Context<Name>`: map neither.
        let dup = |n: &str| names.iter().filter(|m| *m == n).count() > 1;

        // A field's type starts upper-case, which also keeps attribute
        // lines like `token::mint = x,` from reading as fields.
        let field = Regex::new(
            r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?([a-z_]\w*)\s*:\s*([A-Z].*?),?\s*$",
        )
        .unwrap();
        let mut structs: HashMap<String, Vec<(String, Field)>> = HashMap::new();
        for (name, body) in &bodies {
            if dup(name) {
                continue;
            }
            let fields = field
                .captures_iter(body)
                .map(|c| (c[1].to_string(), classify(&c[2], &names)))
                .collect();
            structs.insert(name.clone(), fields);
        }

        let handler = Regex::new(
            r"fn\s+([A-Za-z_]\w*)\s*(?:<[^>(]*>)?\s*\(\s*[A-Za-z_]\w*\s*:\s*Context\s*<([^()]*?)>\s*[,)]",
        )
        .unwrap();
        let ident = Regex::new(r"\b([A-Z]\w*)\b").unwrap();
        let mut map = HashMap::new();
        for c in handler.captures_iter(&src) {
            let Some(ctx) = ident.captures_iter(&c[2]).last() else { continue };
            walk(&structs, &ctx[1], &c[1], "", &mut map, 0);
        }
        SourceKinds { map }
    }
}

fn walk(
    structs: &HashMap<String, Vec<(String, Field)>>,
    name: &str,
    ix: &str,
    prefix: &str,
    out: &mut HashMap<(String, String), SlotKind>,
    depth: usize,
) {
    let Some(fields) = structs.get(name) else { return };
    if depth > 8 {
        return;
    }
    for (field, f) in fields {
        let path = if prefix.is_empty() { field.clone() } else { format!("{prefix}.{field}") };
        match f {
            Field::Kind(k) => {
                out.insert((ix.to_string(), path), *k);
            }
            Field::Composite(inner) => walk(structs, inner, ix, &path, out, depth + 1),
            Field::Unknown => {}
        }
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
    let b = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    let blank = |out: &mut String, s: &str| {
        for ch in s.chars() {
            out.push(if ch == '\n' { '\n' } else { ' ' });
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
        if skip > 0 {
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

fn collect(dir: &Path, out: &mut String) -> Result<()> {
    if dir.is_file() {
        out.push_str(&fs::read_to_string(dir)?);
        out.push('\n');
        return Ok(());
    }
    let mut entries: Vec<_> = fs::read_dir(dir)?.collect::<std::io::Result<_>>()?;
    entries.sort_by_key(|e| e.path());
    for e in entries {
        let p = e.path();
        if p.is_dir() {
            collect(&p, out)?;
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push_str(&fs::read_to_string(&p)?);
            out.push('\n');
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
