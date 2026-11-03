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
    /// A nested `#[derive(Accounts)]` struct, by name.
    Composite(String),
}

/// Declared kind per (instruction, dotted slot path).
pub struct SourceKinds {
    map: HashMap<(String, String), SlotKind>,
}

impl SourceKinds {
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
        let line_comment = Regex::new(r"(?m)//.*$").unwrap();
        let src = line_comment.replace_all(src, "");

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

        let field = Regex::new(r"(?m)^\s*pub\s+([A-Za-z_]\w*)\s*:\s*(.+?),?\s*$").unwrap();
        let mut structs: HashMap<String, Vec<(String, Field)>> = HashMap::new();
        for (name, body) in &bodies {
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
        }
    }
}

fn classify(ty: &str, accounts_structs: &[String]) -> Field {
    if ty.contains("UncheckedAccount") || ty.contains("AccountInfo") {
        return Field::Kind(SlotKind::Unchecked);
    }
    let head = ty.trim_start_matches("Box<").trim();
    let base: String = head.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
    if accounts_structs.iter().any(|n| *n == base) {
        return Field::Composite(base);
    }
    Field::Kind(SlotKind::Typed)
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
