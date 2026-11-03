//! # Mutant generation
//!
//! Locates every site in a program's source where an operator applies
//! and emits one [`Mutant`] per site. One mutant carries exactly one
//! mutation: a mutant with two planted bugs cannot attribute a kill to
//! either of them.
//!
//! ## Source digests, and why a plan can go stale
//!
//! A mutant is a byte span. Byte spans are meaningless against a file
//! that has since changed, and applying a stale span silently produces
//! a mutant that is not the one the plan describes — the same class of
//! silent-wrong-bytes failure the field schema exists to prevent on the
//! invariant side. Every mutant therefore records a digest of the file
//! it was cut from, and [`apply`] refuses to patch a file whose digest
//! no longer matches.
//!
//! The digest is FNV-1a: the requirement is determinism across runs and
//! machines, not collision resistance against an adversary, and it keeps
//! this crate free of a hashing dependency.

use crate::operator::{catalog, MutationOperator, Tier};
use anyhow::{bail, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};

/// One planted bug: a single operator applied at a single site.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Mutant {
    /// Stable id — `{operator}@{file}:{line}#{occurrence}`. Stable
    /// across runs on unchanged source, which is what lets a result
    /// file be joined back to the plan that produced it.
    pub id: String,
    /// Operator that produced this mutant.
    pub operator: String,
    /// Invariant expected to kill it.
    pub expected_killer: String,
    /// Tier of that invariant.
    pub tier: Tier,
    /// Source file, as supplied to [`generate`].
    pub file: String,
    /// 1-indexed line of the match start.
    pub line: usize,
    /// Byte span of the match within the file.
    pub byte_start: usize,
    pub byte_end: usize,
    /// The matched source text, for the report.
    pub original: String,
    /// The text it is replaced with.
    pub mutated: String,
    /// FNV-1a digest of the file this span was cut from.
    pub source_digest: String,
    /// Name of the function the mutation sits inside, when one can be
    /// found above it.
    ///
    /// This is what lets a campaign runner join a mutant to solinv's
    /// reachability ledger, which records instruction names. The join
    /// is a proxy and is sound in exactly one direction: if the
    /// enclosing function's instruction never executed, this mutation
    /// certainly did not run. The converse does not hold — the
    /// instruction may have executed without taking the branch the
    /// mutation sits in — so a consumer may use it to demote a mutant
    /// to `not_reached` and never to promote one to `survived`.
    pub enclosing_fn: Option<String>,
}

/// FNV-1a, 64-bit. Deterministic across runs and platforms.
pub fn digest(bytes: &[u8]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{h:016x}")
}

/// Generate every mutant the catalog can produce from the given
/// sources.
///
/// `sources` is `(path, contents)`. Paths are recorded verbatim so a
/// plan stays readable; the caller decides whether they are absolute or
/// repo-relative.
pub fn generate(sources: &[(String, String)]) -> Result<Vec<Mutant>> {
    generate_with(sources, &catalog())
}

/// Generate mutants using a specific operator set. Exposed so a
/// campaign can restrict itself to, say, the Critical tier.
/// Name of the handler a byte offset belongs to, if any.
///
/// Not simply "the last `fn` above the offset". On an Anchor program the
/// most productive operator — weakening a `Signer<'info>` — matches
/// inside a `#[derive(Accounts)]` struct, and every one of those structs
/// sits *below* the last handler in the file. Taking the nearest `fn`
/// attributed all four signer mutants in escrow-clean to `claim`,
/// including the one in `Initialize`, and the campaign then counted it
/// as reached because `claim` had run. The join is only as sound as this
/// function.
///
/// So: find the innermost declaration above the offset, `fn` or
/// `struct`, whichever comes later. A `fn` is its own answer. A struct
/// resolves through the handler that takes it as its `Context<..>`,
/// which is the relationship that actually determines what executes that
/// code. A struct no handler names resolves to `None` — better to
/// exclude the mutant from the denominator than to credit it to a
/// function that never touches it.
pub fn enclosing_fn(contents: &str, offset: usize) -> Option<String> {
    let head = &contents[..offset.min(contents.len())];

    let fn_re = Regex::new(
        r"(?m)^\s*(?:pub\s*(?:\([^)]*\)\s*)?)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+\x22[^\x22]*\x22\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)",
    )
    .ok()?;
    let struct_re =
        Regex::new(r"(?m)^\s*(?:pub\s*(?:\([^)]*\)\s*)?)?struct\s+([A-Za-z_][A-Za-z0-9_]*)").ok()?;

    let last_fn = fn_re.captures_iter(head).last();
    let last_struct = struct_re.captures_iter(head).last();

    match (last_fn, last_struct) {
        (Some(f), Some(s)) => {
            if s.get(0)?.start() > f.get(0)?.start() {
                handler_taking_context(contents, &s[1])
            } else {
                Some(f[1].to_string())
            }
        }
        (Some(f), None) => Some(f[1].to_string()),
        (None, Some(s)) => handler_taking_context(contents, &s[1]),
        (None, None) => None,
    }
}

/// The handler whose signature names `struct_name` as its Anchor
/// context: `pub fn deposit(ctx: Context<Deposit>, ..)` -> `deposit`.
fn handler_taking_context(contents: &str, struct_name: &str) -> Option<String> {
    let pattern = format!(
        r"fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*Context\s*<\s*{}\s*>",
        regex::escape(struct_name)
    );
    Regex::new(&pattern)
        .ok()?
        .captures(contents)
        .map(|c| c[1].to_string())
}

pub fn generate_with(
    sources: &[(String, String)],
    operators: &[MutationOperator],
) -> Result<Vec<Mutant>> {
    let mut out = Vec::new();
    for (path, contents) in sources {
        let file_digest = digest(contents.as_bytes());
        for op in operators {
            let re = Regex::new(op.pattern)?;
            for (occurrence, m) in re.find_iter(contents).enumerate() {
                let mutated = re.replace(m.as_str(), op.replacement).into_owned();
                // A rewrite that changes nothing is not a mutant — it
                // would be scored as an un-killable survivor and drag
                // the denominator down for no reason.
                if mutated == m.as_str() {
                    continue;
                }
                let line = contents[..m.start()].lines().count().max(1);
                out.push(Mutant {
                    id: format!("{}@{}:{}#{}", op.id, path, line, occurrence),
                    operator: op.id.to_string(),
                    expected_killer: op.expected_killer.to_string(),
                    tier: op.tier,
                    file: path.clone(),
                    line,
                    byte_start: m.start(),
                    byte_end: m.end(),
                    original: m.as_str().to_string(),
                    mutated,
                    source_digest: file_digest.clone(),
                    enclosing_fn: enclosing_fn(contents, m.start()),
                });
            }
        }
    }
    Ok(out)
}

/// Produce the mutated contents of a file for one mutant.
///
/// Fails if `contents` is not the source the mutant was cut from — see
/// the module note on stale plans.
pub fn apply(contents: &str, mutant: &Mutant) -> Result<String> {
    let actual = digest(contents.as_bytes());
    if actual != mutant.source_digest {
        bail!(
            "mutant {} was cut from {} at digest {}, but the file now digests to {}. \
             The plan is stale — regenerate it rather than applying a byte span to \
             source that has moved.",
            mutant.id,
            mutant.file,
            mutant.source_digest,
            actual
        );
    }
    if mutant.byte_end > contents.len() || mutant.byte_start > mutant.byte_end {
        bail!(
            "mutant {} has span {}..{} outside a {}-byte file",
            mutant.id,
            mutant.byte_start,
            mutant.byte_end,
            contents.len()
        );
    }
    let mut out = String::with_capacity(contents.len());
    out.push_str(&contents[..mutant.byte_start]);
    out.push_str(&mutant.mutated);
    out.push_str(&contents[mutant.byte_end..]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: &str = r#"
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    if !ctx.accounts.authority.is_signer {
        return Err(ErrorCode::Unauthorized.into());
    }
    require!(amount > 0, ErrorCode::ZeroAmount);
    let vault = &mut ctx.accounts.vault;
    vault.total = vault.total.checked_sub(amount).ok_or(ErrorCode::Math)?;
    vault.paid = vault.paid.saturating_add(amount);
    Ok(())
}
"#;

    fn sources() -> Vec<(String, String)> {
        vec![("programs/vault/src/lib.rs".into(), SRC.to_string())]
    }

    #[test]
    fn generates_one_mutant_per_site() {
        let mutants = generate(&sources()).unwrap();
        let ops: Vec<_> = mutants.iter().map(|m| m.operator.as_str()).collect();
        assert!(ops.contains(&"signer-check-drop"), "{ops:?}");
        assert!(ops.contains(&"guard-drop"), "{ops:?}");
        assert!(ops.contains(&"checked-to-wrapping"), "{ops:?}");
        assert!(ops.contains(&"saturating-to-wrapping"), "{ops:?}");
    }

    #[test]
    fn mutant_ids_are_unique_and_stable() {
        let a = generate(&sources()).unwrap();
        let b = generate(&sources()).unwrap();
        assert_eq!(a, b, "generation must be deterministic");

        let mut ids: Vec<_> = a.iter().map(|m| m.id.clone()).collect();
        let total = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), total, "duplicate mutant id");
    }

    #[test]
    fn each_mutant_names_its_expected_killer() {
        for m in generate(&sources()).unwrap() {
            assert!(!m.expected_killer.is_empty(), "{} has no killer", m.id);
        }
    }

    #[test]
    fn line_numbers_point_at_the_mutated_site() {
        let mutants = generate(&sources()).unwrap();
        let signer = mutants
            .iter()
            .find(|m| m.operator == "signer-check-drop")
            .unwrap();
        let line = SRC.lines().nth(signer.line - 1).unwrap();
        assert!(line.contains("is_signer"), "line {} was {line:?}", signer.line);
    }

    #[test]
    fn apply_produces_source_containing_the_planted_bug() {
        let mutants = generate(&sources()).unwrap();
        let signer = mutants
            .iter()
            .find(|m| m.operator == "signer-check-drop")
            .unwrap();
        let out = apply(SRC, signer).unwrap();
        assert!(out.contains("if false {"), "{out}");
        assert!(!out.contains("!ctx.accounts.authority.is_signer"));
        // Everything else is untouched — one mutant, one bug.
        assert!(out.contains("require!(amount > 0"));
        assert!(out.contains("checked_sub"));
    }

    #[test]
    fn apply_rejects_a_stale_plan() {
        let mutants = generate(&sources()).unwrap();
        let m = &mutants[0];
        let edited = format!("// a new comment\n{SRC}");
        let err = apply(&edited, m).unwrap_err().to_string();
        assert!(err.contains("stale"), "{err}");
    }

    #[test]
    fn digest_is_deterministic_and_content_sensitive() {
        assert_eq!(digest(b"abc"), digest(b"abc"));
        assert_ne!(digest(b"abc"), digest(b"abd"));
    }

    #[test]
    fn no_op_rewrites_are_not_emitted() {
        // A file where an operator matches but the replacement equals
        // the original would yield an unkillable mutant. Guard it by
        // construction: every emitted mutant changes the text.
        for m in generate(&sources()).unwrap() {
            assert_ne!(m.original, m.mutated, "{} is a no-op mutant", m.id);
        }
    }

    #[test]
    fn empty_sources_produce_no_mutants() {
        assert!(generate(&[]).unwrap().is_empty());
    }

    #[test]
    fn mutants_record_the_function_they_sit_in() {
        for m in generate(&sources()).unwrap() {
            assert_eq!(
                m.enclosing_fn.as_deref(),
                Some("withdraw"),
                "{} lost its enclosing fn",
                m.id
            );
        }
    }

    #[test]
    fn enclosing_fn_picks_the_nearest_declaration_above() {
        let src = "pub fn alpha() {\n    let a = 1;\n}\npub fn beta() {\n    let b = 2;\n}\n";
        let at_a = src.find("let a").unwrap();
        let at_b = src.find("let b").unwrap();
        assert_eq!(enclosing_fn(src, at_a).as_deref(), Some("alpha"));
        assert_eq!(enclosing_fn(src, at_b).as_deref(), Some("beta"));
    }

    #[test]
    fn enclosing_fn_handles_visibility_and_qualifiers() {
        for decl in [
            "fn plain() {",
            "pub fn public() {",
            "pub(crate) fn scoped() {",
            "    pub async fn nested() {",
            "pub unsafe fn risky() {",
        ] {
            let src = format!("{decl}\n    let x = 1;\n}}\n");
            let at = src.find("let x").unwrap();
            assert!(
                enclosing_fn(&src, at).is_some(),
                "failed to parse: {decl}"
            );
        }
    }

    #[test]
    fn enclosing_fn_is_none_before_any_function() {
        let src = "use std::fmt;\nconst X: u64 = 1;\nfn later() {}\n";
        assert_eq!(enclosing_fn(src, 5), None);
    }

    // The shape of every Anchor program: handlers first, then the
    // `#[derive(Accounts)]` structs they take. A site inside one of
    // those structs is below *every* handler, so the nearest-fn rule
    // attributes all of them to the last one.
    const ANCHOR_SHAPE: &str = "\
pub mod prog {
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> { Ok(()) }
    pub fn claim(ctx: Context<Claim>) -> Result<()> { Ok(()) }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    pub depositor: Signer<'info>,
}

#[derive(Accounts)]
pub struct Claim<'info> {
    pub beneficiary: Signer<'info>,
}
";

    #[test]
    fn a_site_in_an_accounts_struct_resolves_through_its_handler() {
        let at_init = ANCHOR_SHAPE.find("pub depositor").unwrap();
        let at_claim = ANCHOR_SHAPE.find("pub beneficiary").unwrap();
        assert_eq!(
            enclosing_fn(ANCHOR_SHAPE, at_init).as_deref(),
            Some("initialize"),
            "a field of Initialize belongs to the handler taking Context<Initialize>"
        );
        assert_eq!(
            enclosing_fn(ANCHOR_SHAPE, at_claim).as_deref(),
            Some("claim")
        );
    }

    #[test]
    fn a_struct_no_handler_takes_resolves_to_nothing() {
        // Excluding it from the denominator is the conservative answer.
        // Naming some unrelated function would let the campaign call the
        // mutant reached because that function happened to run.
        let src = "fn helper() {}\n\npub struct Orphan {\n    pub field: u64,\n}\n";
        let at = src.find("pub field").unwrap();
        assert_eq!(enclosing_fn(src, at), None);
    }

    #[test]
    fn a_site_inside_a_function_still_wins_over_a_struct_above_it() {
        let src = "pub struct S { pub a: u64 }\npub fn after() {\n    let x = 1;\n}\n";
        let at = src.find("let x").unwrap();
        assert_eq!(enclosing_fn(src, at).as_deref(), Some("after"));
    }
}
