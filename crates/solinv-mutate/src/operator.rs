//! # Mutation operators — the Solana bug-class catalog, executable
//!
//! A mutation operator is a rewrite that turns correct program source
//! into source containing one specific, realistic bug. The catalog
//! below is not a generic set of arithmetic perturbations: each
//! operator models a bug class solinv already has a detector and a
//! spec doc for, and each one names the invariant that is *supposed*
//! to kill it.
//!
//! That naming is what makes the campaign a measurement rather than a
//! smoke test. A mutant killed by the expected invariant confirms that
//! detector on that target. A mutant killed by some *other* invariant
//! is still dead but tells you the coverage came from somewhere you
//! did not predict. A mutant that survives is the interesting case:
//! either the detector has a blind spot on real code, or the harness
//! never drives that path.
//!
//! ## Why the patterns neutralize conditions instead of deleting blocks
//!
//! Most operators rewrite a *condition* to `false` rather than delete
//! the guard it protects. Deleting a block requires brace matching,
//! which text patterns do badly; neutralizing the condition leaves the
//! code compiling and the guard dead, which is the same bug with far
//! fewer ways to produce a mutant that simply fails to build. Build
//! failures are not free — every one of them is compute spent to learn
//! nothing, and they are excluded from the score rather than counted
//! as survivors (see [`crate::score`]).
//!
//! ## Coverage is partial, and says so
//!
//! v1 operators reach 6 of the 10 catalog invariants. `cu-dos`,
//! `cpi-reentrancy`, `realloc-race` and the account-swap
//! context-binding class are **not** covered: each needs a mutation
//! that is structural rather than textual (inflate a loop bound past a
//! CU budget, introduce a call cycle, drop a lamport top-up adjacent to
//! a `realloc`, rebind an account to a foreign context). Those want an
//! AST-level engine, which is v2. A campaign report states the
//! uncovered invariants explicitly — a mutation score that quietly
//! omits four detectors reads as a verdict on all ten.

use serde::{Deserialize, Serialize};

/// Catalog tier of the invariant an operator targets, mirroring the
/// tiers in `docs/invariants/`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Critical,
    High,
}

/// One source-level rewrite that plants a known bug class.
#[derive(Clone, Debug)]
pub struct MutationOperator {
    /// Stable identifier, used in mutant ids and score breakdowns.
    pub id: &'static str,
    /// What the rewrite does, in one line.
    pub description: &'static str,
    /// The catalog invariant expected to kill mutants of this operator.
    pub expected_killer: &'static str,
    /// Tier of that invariant.
    pub tier: Tier,
    /// Regex matched against program source.
    pub pattern: &'static str,
    /// Replacement, with `$1`-style capture references.
    pub replacement: &'static str,
    /// Why this rewrite models a bug that has actually shipped.
    pub rationale: &'static str,
}

/// Catalog invariants that no v1 operator can produce a mutant for.
///
/// Reported in every campaign summary so a score is never mistaken for
/// a verdict on the whole catalog.
pub const UNCOVERED_INVARIANTS: [&str; 4] = [
    "cu-dos",
    "cpi-reentrancy",
    "realloc-race",
    "account-swap",
];

/// The v1 operator catalog.
pub fn catalog() -> Vec<MutationOperator> {
    vec![
        MutationOperator {
            id: "signer-check-drop",
            description: "neutralize a manual `!x.is_signer` guard",
            expected_killer: "signer-skip",
            tier: Tier::Critical,
            pattern: r"!\s*([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\.is_signer\b",
            replacement: "false",
            rationale: "Authorization on a raw AccountInfo is entirely the program's \
                        responsibility — the runtime never checks it. Dropping the guard \
                        is the canonical Solana privilege-escalation bug.",
        },
        MutationOperator {
            id: "signer-type-weaken",
            description: "weaken an Anchor `Signer<'info>` to `AccountInfo<'info>`",
            expected_killer: "signer-skip",
            tier: Tier::Critical,
            pattern: r"\bSigner<'([a-z]+)>",
            replacement: "AccountInfo<'$1>",
            rationale: "Anchor's type-level signer check is the reason most programs pass \
                        signer-skip. Weakening the type removes the check without touching \
                        any handler logic — the shape of a refactor that silently drops it.",
        },
        MutationOperator {
            id: "owner-check-drop",
            description: "neutralize an `x.owner != ...` guard",
            expected_killer: "owner-skip",
            tier: Tier::Critical,
            // The right-hand side stops at the last non-space character
            // before the block: `[^{\n]+` would swallow the separating
            // space and emit `if false{`. The regex crate has no
            // lookahead, so the bound is expressed as "ends on a
            // non-space" instead.
            pattern: r"\*?\s*([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\.owner\s*!=\s*[^{\n]*[^{\n\s]",
            replacement: "false",
            rationale: "An UncheckedAccount whose owner is never verified lets an attacker \
                        substitute a look-alike account they control.",
        },
        MutationOperator {
            id: "discriminator-check-drop",
            description: "neutralize an 8-byte account discriminator comparison",
            expected_killer: "discriminator-skip",
            tier: Tier::Critical,
            pattern: r"&?\s*[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\[\.\.8\]\s*!=\s*[^{\n]*[^{\n\s]",
            replacement: "false",
            rationale: "Without the discriminator check, one account type is deserializable \
                        as another — type confusion across the program's own accounts.",
        },
        MutationOperator {
            id: "pda-key-check-drop",
            description: "neutralize a derived-vs-passed PDA key comparison",
            expected_killer: "pda-forge",
            tier: Tier::Critical,
            pattern: r"([A-Za-z_][A-Za-z0-9_]*)\s*!=\s*\*?\s*([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\.key\b",
            replacement: "false",
            rationale: "The runtime verifies seeds only for `invoke_signed`. At read time a \
                        program that derives the expected PDA and then fails to compare it \
                        accepts any account the caller passes.",
        },
        MutationOperator {
            id: "native-guard-neutralize",
            description: "neutralize the condition of an `if .. { return Err(..) }` guard",
            expected_killer: "precondition-skip",
            tier: Tier::High,
            pattern: r"if ([^\n{]+?)\s*\{\s*\n(\s*)return Err\(",
            replacement: "if false {\n${2}return Err(",
            rationale: "`guard-drop` finds Anchor's `require!` and nothing else, which \
                        meant the catalog could not mutate a native program at all — 0 \
                        matches across raydium-amm, whose 212 error returns are all \
                        `if cond { return Err(..) }`. Much of Solana's highest-value code \
                        is native, so an Anchor-only operator set measures detector power \
                        only where Anchor is used. Neutralizing the condition rather than \
                        deleting the block keeps the code compiling, and requiring the \
                        very next statement to be `return Err(` is what distinguishes a \
                        guard from ordinary control flow.",
        },
        MutationOperator {
            id: "guard-drop",
            description: "delete an Anchor `require!`-family guard",
            expected_killer: "precondition-skip",
            tier: Tier::High,
            pattern: r"require(?:_eq|_neq|_gt|_gte|_lt|_lte|_keys_eq|_keys_neq)?!\s*\([^;]*\)\s*;",
            replacement: "",
            rationale: "The most common real shape: a validation guard removed during a \
                        refactor. It was labelled `unchecked-math` until a campaign on \
                        escrow-clean showed why that was wrong: five guard-drops survived, \
                        none of them arithmetic bugs, and no invariant modelled the shape \
                        at all. `precondition-skip` was built from those survivors. A kill \
                        by another detector is still informative — which invariant catches \
                        a dropped guard depends on what the guard protected.",
        },
        MutationOperator {
            id: "checked-to-wrapping",
            description: "rewrite `checked_*(x).ok_or(..)?` / `.unwrap()` to `wrapping_*(x)`",
            expected_killer: "unchecked-math",
            tier: Tier::High,
            pattern: r"\.checked_(add|sub|mul|div)\(([^()]*)\)\s*\.\s*(?:ok_or(?:_else)?\([^()]*\)\?|unwrap\(\)|expect\(\s*\x22[^\x22]*\x22\s*\)|unwrap_or\([^()]*\))",
            replacement: ".wrapping_$1($2)",
            rationale: "Overflow reaching protocol state. The rewrite preserves arity and \
                        the value type, so the mutant compiles wherever the original did.",
        },
        MutationOperator {
            id: "saturating-to-wrapping",
            description: "rewrite `saturating_sub`/`saturating_add` to the wrapping form",
            expected_killer: "unchecked-math",
            tier: Tier::High,
            pattern: r"\.saturating_(add|sub|mul)\(",
            replacement: ".wrapping_$1(",
            rationale: "`saturating_sub` is the idiomatic underflow guard on balances. \
                        Wrapping instead produces the near-u64::MAX signature that the \
                        Bounded and Monotonic state invariants are shaped to catch.",
        },
        MutationOperator {
            id: "canonical-bump-assert-drop",
            description: "delete an assertion pinning a bump to the canonical value",
            expected_killer: "bump-seed-canonicalization",
            tier: Tier::High,
            pattern: r"assert_eq!\s*\([^;()]*bump[^;]*\)\s*;",
            replacement: "",
            rationale: "Accepting a caller-supplied non-canonical bump admits the alt-PDA \
                        substitution attack: a second valid address for the same logical \
                        account.",
        },
    ]
}

/// Look up one operator by id.
pub fn by_id(id: &str) -> Option<MutationOperator> {
    catalog().into_iter().find(|op| op.id == id)
}

/// Distinct invariants the catalog can produce mutants for.
pub fn covered_invariants() -> Vec<&'static str> {
    let mut v: Vec<_> = catalog().into_iter().map(|op| op.expected_killer).collect();
    v.sort_unstable();
    v.dedup();
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;

    #[test]
    fn every_pattern_compiles() {
        for op in catalog() {
            Regex::new(op.pattern)
                .unwrap_or_else(|e| panic!("operator {} has an invalid pattern: {e}", op.id));
        }
    }

    #[test]
    fn operator_ids_are_unique() {
        let mut ids: Vec<_> = catalog().into_iter().map(|op| op.id).collect();
        let total = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), total, "duplicate operator id");
    }

    fn apply(op_id: &str, src: &str) -> String {
        let op = by_id(op_id).unwrap();
        Regex::new(op.pattern)
            .unwrap()
            .replace_all(src, op.replacement)
            .into_owned()
    }

    #[test]
    fn signer_check_drop_neutralizes_the_condition() {
        let out = apply(
            "signer-check-drop",
            "if !authority.is_signer { return Err(ProgramError::MissingRequiredSignature); }",
        );
        assert!(out.starts_with("if false {"), "{out}");
    }

    #[test]
    fn signer_check_drop_handles_a_field_path() {
        let out = apply("signer-check-drop", "if !ctx.accounts.admin.is_signer {");
        assert_eq!(out, "if false {");
    }

    #[test]
    fn signer_type_weaken_rewrites_the_anchor_type() {
        let out = apply("signer-type-weaken", "pub authority: Signer<'info>,");
        assert_eq!(out, "pub authority: AccountInfo<'info>,");
    }

    #[test]
    fn native_guard_neutralize_kills_the_condition_and_keeps_the_body() {
        let src = "        if amm.status == 0 {\n            return Err(AmmError::Bad.into());\n        }";
        let out = apply("native-guard-neutralize", src);
        assert!(out.contains("if false {"), "condition not neutralized: {out}");
        assert!(
            out.contains("return Err(AmmError::Bad.into());"),
            "the guard body must survive so the code still compiles: {out}"
        );
    }

    #[test]
    fn native_guard_neutralize_ignores_control_flow_that_is_not_a_guard() {
        // An `if` whose body does anything other than return an error is
        // ordinary logic. Neutralizing it produces a mutant that tests
        // nothing and still costs a full SBF rebuild.
        let src = "        if a > b {\n            total += 1;\n        }";
        assert_eq!(apply("native-guard-neutralize", src), src);
    }

    #[test]
    fn owner_check_drop_neutralizes_the_condition() {
        let out = apply("owner-check-drop", "if *vault.owner != crate::ID {\n    panic!()\n}");
        assert!(out.starts_with("if false {"), "{out}");
    }

    #[test]
    fn discriminator_check_drop_neutralizes_the_condition() {
        let out = apply("discriminator-check-drop", "if &data[..8] != Pool::DISCRIMINATOR {");
        assert!(out.starts_with("if false {"), "{out}");
    }

    #[test]
    fn pda_key_check_drop_neutralizes_the_comparison() {
        let out = apply("pda-key-check-drop", "if expected != *vault.key {");
        assert!(out.starts_with("if false {"), "{out}");
    }

    #[test]
    fn checked_to_wrapping_covers_the_common_postfixes() {
        assert_eq!(
            apply("checked-to-wrapping", "a.checked_add(b).ok_or(Err::Math)?"),
            "a.wrapping_add(b)"
        );
        assert_eq!(
            apply("checked-to-wrapping", "a.checked_sub(1).unwrap()"),
            "a.wrapping_sub(1)"
        );
        assert_eq!(
            apply("checked-to-wrapping", r#"a.checked_mul(x).expect("overflow")"#),
            "a.wrapping_mul(x)"
        );
    }

    #[test]
    fn saturating_to_wrapping_preserves_arity() {
        assert_eq!(
            apply("saturating-to-wrapping", "balance.saturating_sub(amount)"),
            "balance.wrapping_sub(amount)"
        );
    }

    #[test]
    fn guard_drop_deletes_the_whole_statement() {
        let out = apply("guard-drop", "require!(amount > 0, Err::Zero);\nlet x = 1;");
        assert_eq!(out.trim_start(), "let x = 1;");
    }

    #[test]
    fn canonical_bump_assert_drop_deletes_the_assertion() {
        let out = apply(
            "canonical-bump-assert-drop",
            "assert_eq!(bump, canonical_bump);\nnext();",
        );
        assert_eq!(out.trim_start(), "next();");
    }

    #[test]
    fn operators_do_not_fire_on_unrelated_source() {
        let benign = "let total = a.checked_add(b)?; // already propagates\nlet k = x * y;\n";
        for op in catalog() {
            let re = Regex::new(op.pattern).unwrap();
            assert!(
                !re.is_match(benign),
                "operator {} fired on benign source",
                op.id
            );
        }
    }

    #[test]
    fn coverage_and_gaps_do_not_overlap() {
        for gap in UNCOVERED_INVARIANTS {
            assert!(
                !covered_invariants().contains(&gap),
                "{gap} is listed as uncovered but an operator targets it"
            );
        }
    }
}
