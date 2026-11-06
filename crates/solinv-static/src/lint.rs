//! Program-wide findings that belong to no account slot: a PDA signature
//! whose seeds carry no bump, and a Token-2022 transfer hook whose
//! `execute` the token program can never reach.
//!
//! Text, like the rest of this crate. A seed list is only judged once
//! every name in it is resolved to a `let` in the same file; one built by
//! a call (`vault.signer_seeds()`) or passed in is left alone, never
//! guessed.

use crate::source::{collect, strip_comments};
use anyhow::{Context, Result};
use regex::Regex;
use std::path::Path;
use std::sync::LazyLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// `invoke_signed` / `with_signer` / `new_with_signer` seeds with no
    /// bump: `find_program_address` addresses are off the curve only with
    /// their bump, so the signature fails.
    SignerSeedsWithoutBump,
    /// A transfer hook `execute` with no SPL Execute discriminator and no
    /// `fallback` that calls it: Token-2022's Execute never runs it.
    HookExecuteUnreachable,
    /// A `fallback` that accepts the SPL Execute discriminator and returns
    /// without running `execute`'s checks.
    HookFallbackSkipsExecute,
    /// An entry PDA created or written under a gate (a registry checked
    /// against a signer) that its seeds do not name (#18).
    EntryNotScopedToGate,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub kind: Kind,
    /// The enclosing function.
    pub function: String,
    pub message: String,
    pub file: String,
    pub line: usize,
}

pub fn read(dir: &Path) -> Result<Vec<Finding>> {
    let mut files = Vec::new();
    collect(dir, &mut files).with_context(|| format!("failed to read sources under {}", dir.display()))?;
    Ok(parse_files(&files))
}

pub fn parse_files(files: &[(String, String)]) -> Vec<Finding> {
    let mut out = Vec::new();
    for (ix, entry, gate, file, line) in crate::source::SourceKinds::parse_files(files).unscoped_entries() {
        out.push(Finding {
            kind: Kind::EntryNotScopedToGate,
            function: ix.clone(),
            message: format!(
                "`{ix}` writes `{entry}` under `{gate}`'s authority, but `{entry}`'s seeds do not name \
                 `{gate}`: every `{gate}` writes the same addresses, so an entry made under one is found \
                 under another (put `{gate}` in the seeds, or tie `{entry}` to it)"
            ),
            file,
            line,
        });
    }
    for (file, src) in files {
        let text = strip_comments(src);
        signer_seeds(file, &text, &mut out);
        transfer_hook(file, &text, &mut out);
    }
    out
}

/// The findings as a section for `solinv idl --src`, or "" if none.
pub fn render(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return String::new();
    }
    let mut out = format!("\nprogram-wide findings ({}):\n", findings.len());
    for f in findings {
        out += &format!("  {}:{} in `{}`: {}\n", f.file, f.line, f.function, f.message);
    }
    out
}

/// Findings in `head` that `base` does not have, as diff changes. A hook
/// whose `execute` stops being reachable loses every check in it, so that
/// is a regression; a new signature without a bump fails closed, a warning.
pub fn diff(base: &[Finding], head: &[Finding]) -> Vec<crate::diff::Change> {
    let key = |f: &Finding| (f.kind, f.function.clone(), f.message.clone());
    let seen: std::collections::HashSet<_> = base.iter().map(key).collect();
    head.iter()
        .filter(|f| !seen.contains(&key(f)))
        .map(|f| crate::diff::Change {
            severity: match f.kind {
                Kind::SignerSeedsWithoutBump | Kind::EntryNotScopedToGate => crate::diff::Severity::Warning,
                Kind::HookExecuteUnreachable | Kind::HookFallbackSkipsExecute => crate::diff::Severity::Regression,
            },
            ix: f.function.clone(),
            path: String::new(),
            message: f.message.clone(),
            file: f.file.clone(),
            line: f.line,
        })
        .collect()
}

static SIGNED_CALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(invoke_signed|new_with_signer|with_signer)\s*\(").unwrap());
static FN_DEF: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bfn\s+([A-Za-z_]\w*)").unwrap());

fn signer_seeds(file: &str, text: &str, out: &mut Vec<Finding>) {
    for m in SIGNED_CALL.captures_iter(text) {
        let call = m.get(0).unwrap();
        let open = call.end() - 1;
        let Some(close) = matching(text, open) else { continue };
        let args = split_top(&text[open + 1..close]);
        // The signer seeds: the last argument of all three.
        let Some(arg) = args.last() else { continue };
        let before = &text[..call.start()];
        // Names resolve to `let`s in the enclosing function only.
        let fn_start = FN_DEF.find_iter(before).last().map_or(0, |m| m.start());
        let scope = &before[fn_start..];
        let Some(sets) = seed_sets(arg, scope, 0) else { continue };
        if sets.iter().any(|set| !set.iter().any(|e| is_bump(e, scope))) {
            let function = enclosing_fn(before);
            out.push(Finding {
                kind: Kind::SignerSeedsWithoutBump,
                message: format!(
                    "`{}` signs with seeds that carry no bump ({}): a PDA from find_program_address \
                     only signs with its bump, so this call fails",
                    &m[1],
                    sets.iter().map(|s| format!("[{}]", s.join(", "))).collect::<Vec<_>>().join(", ")
                ),
                function,
                file: file.to_string(),
                line: line_of(text, call.start()),
            });
        }
    }
}

/// The seed sets an expression stands for (`&[&[a, b]]`, `&[seeds]`,
/// `signer`), each as its elements, or None if any part is not a literal
/// list reachable through `let`s.
fn seed_sets(expr: &str, before: &str, depth: usize) -> Option<Vec<Vec<String>>> {
    if depth > 4 {
        return None;
    }
    let e = expr.trim();
    if let Some(inner) = list(e) {
        let items = split_top(inner);
        // A list of seed lists, or one seed list (`invoke_signed(.., &[seeds])`
        // where `seeds` is itself the list).
        let mut sets = Vec::new();
        for item in &items {
            sets.push(seed_list(item, before, depth + 1)?);
        }
        return Some(sets);
    }
    let name = ident(e)?;
    let (init, earlier) = let_init(before, name)?;
    seed_sets(init, earlier, depth + 1)
}

/// One seed list's elements: `&[b"x", k.as_ref(), &[bump]]`, `&seeds[..]`,
/// `seeds`.
fn seed_list(expr: &str, before: &str, depth: usize) -> Option<Vec<String>> {
    if depth > 4 {
        return None;
    }
    let e = expr.trim();
    if let Some(inner) = list(e) {
        return Some(split_top(inner).into_iter().map(|s| s.trim().to_string()).collect());
    }
    let e = e.trim_start_matches('&').trim();
    let e = e.strip_suffix("[..]").unwrap_or(e).trim();
    let name = ident(e)?;
    let (init, earlier) = let_init(before, name)?;
    seed_list(init, earlier, depth + 1)
}

/// A bump element: `&[bump]`, `[x.bump]`, `&bump.to_le_bytes()`, any
/// element naming a bump or nonce outside a string literal, or a name
/// (`&b`) bound by a `let` to one of those.
fn is_bump(e: &str, before: &str) -> bool {
    let code: String = split_strings(e);
    let low = code.to_ascii_lowercase();
    if low.contains("bump") || low.contains("nonce") || low.contains("from_ref(") {
        return true;
    }
    if list(e.trim()).is_some_and(|inner| split_top(inner).len() == 1) {
        return true;
    }
    let bare = e.trim().trim_start_matches('&').trim();
    match ident(bare).and_then(|n| let_init(before, n)) {
        Some((init, earlier)) => is_bump(init, earlier),
        None => false,
    }
}

/// `e` with the contents of its string literals removed.
fn split_strings(e: &str) -> String {
    let mut out = String::new();
    let mut in_str = false;
    let mut chars = e.chars();
    while let Some(c) = chars.next() {
        if in_str {
            if c == '\\' {
                chars.next();
            } else if c == '"' {
                in_str = false;
            }
        } else if c == '"' {
            in_str = true;
        } else {
            out.push(c);
        }
    }
    out
}

/// The inside of `[..]` or `&[..]` (also `&[..][..]`), if `e` is one.
fn list(e: &str) -> Option<&str> {
    let e = e.trim().trim_start_matches('&').trim();
    let e = e.strip_suffix("[..]").unwrap_or(e).trim();
    if !e.starts_with('[') {
        return None;
    }
    let close = matching(e, 0)?;
    (close == e.len() - 1).then(|| &e[1..close])
}

fn ident(e: &str) -> Option<&str> {
    let e = e.trim();
    (!e.is_empty() && e.chars().all(|c| c.is_alphanumeric() || c == '_') && !e.starts_with(|c: char| c.is_ascii_digit()))
        .then_some(e)
}

/// The initializer of the closest `let name` before the call, up to its
/// `;`, and the text before that `let` (where names in the initializer
/// resolve, so `let seeds = &[&seeds[..]];` reads the earlier `seeds`).
fn let_init<'a>(before: &'a str, name: &str) -> Option<(&'a str, &'a str)> {
    let re = Regex::new(&format!(r"\blet\s+(?:mut\s+)?{}\b\s*(?::[^=]*)?=", regex::escape(name))).ok()?;
    let m = re.find_iter(before).last()?;
    let rest = &before[m.end()..];
    let end = top_level_semicolon(rest)?;
    Some((&rest[..end], &before[..m.start()]))
}

fn top_level_semicolon(s: &str) -> Option<usize> {
    let mut depth = 0i32;
    for (i, c) in s.char_indices() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ';' if depth == 0 => return Some(i),
            _ => {}
        }
    }
    None
}

static AMOUNT_ARG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bamount\s*:\s*u64\b").unwrap());
static PUB_FN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bpub\s+fn\s+([A-Za-z_]\w*)\b").unwrap());

fn transfer_hook(file: &str, text: &str, out: &mut Vec<Finding>) {
    // An Anchor program that implements the transfer hook interface: it
    // builds the ExtraAccountMetaList and names the Execute instruction,
    // not one that only imports a CPI helper.
    let Some(prog) = text.find("#[program]") else { return };
    if !text.contains("ExtraAccountMetaList")
        || !(text.contains("ExecuteInstruction") || text.contains("TransferHookInstruction"))
    {
        return;
    }
    // The `#[program]` module's body.
    let Some(open) = text[prog..].find('{').map(|i| prog + i) else { return };
    let Some(close) = matching(text, open) else { return };
    let mut handler = None;
    let mut fallback = None;
    for c in PUB_FN.captures_iter(&text[open..close]) {
        let m = c.get(0).unwrap();
        let at = open + m.start();
        let name = c[1].to_string();
        // `#[instruction(discriminator = ..)]` (Anchor 0.31+) or
        // `#[interface(spl_transfer_hook_interface::execute)]` (0.30) on
        // any handler: Token-2022's Execute is routed to it.
        let attrs = attrs_before(text, at);
        if attrs.contains("discriminator") || attrs.contains("#[interface(") {
            return;
        }
        if name == "fallback" {
            fallback = Some(at);
            continue;
        }
        // The handler Execute should reach: one taking the amount.
        let params = text[open + m.end()..close]
            .find('(')
            .map(|i| open + m.end() + i)
            .and_then(|p| matching(text, p).map(|q| &text[p..q]));
        if handler.is_none() && params.is_some_and(|p| AMOUNT_ARG.is_match(p)) {
            handler = Some((name, at));
        }
    }
    let Some((name, at)) = handler else { return };
    let Some(fb) = fallback else {
        out.push(Finding {
            kind: Kind::HookExecuteUnreachable,
            function: name.clone(),
            message: format!(
                "transfer hook `{name}` has no `#[instruction(discriminator = \
                 ExecuteInstruction::SPL_DISCRIMINATOR_SLICE)]` and no `fallback` dispatches to it: \
                 Token-2022's Execute call never reaches its checks"
            ),
            file: file.to_string(),
            line: line_of(text, at),
        });
        return;
    };
    let Some(b_open) = text[fb..close].find('{').map(|i| fb + i) else { return };
    let Some(b_close) = matching(text, b_open) else { return };
    let body = &text[b_open..=b_close];
    let dispatches = body.contains("__global::")
        || body.contains("process_instruction")
        || Regex::new(&format!(r"\b{}\s*\(", regex::escape(&name))).unwrap().is_match(body);
    if !dispatches {
        out.push(Finding {
            kind: Kind::HookFallbackSkipsExecute,
            function: "fallback".into(),
            message: format!(
                "`fallback` receives Token-2022's Execute but never runs `{name}` \
                 (no `__private::__global::{name}` call): transfers pass without the hook's checks"
            ),
            file: file.to_string(),
            line: line_of(text, fb),
        });
    }
}

/// The `#[...]` attributes directly above the item starting at `at`.
fn attrs_before(text: &str, at: usize) -> &str {
    let b = text.as_bytes();
    let mut start = at;
    loop {
        let mut i = start;
        while i > 0 && b[i - 1].is_ascii_whitespace() {
            i -= 1;
        }
        if i == 0 || b[i - 1] != b']' {
            return &text[start..at];
        }
        // Back to the `[` that opens this attribute.
        let mut depth = 0;
        let mut j = i;
        while j > 0 {
            j -= 1;
            match b[j] {
                b']' => depth += 1,
                b'[' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
        }
        if depth != 0 || j == 0 || b[j - 1] != b'#' {
            return &text[start..at];
        }
        start = j - 1;
    }
}

fn enclosing_fn(before: &str) -> String {
    FN_DEF.captures_iter(before).last().map(|c| c[1].to_string()).unwrap_or_default()
}

fn line_of(text: &str, at: usize) -> usize {
    text[..at].matches('\n').count() + 1
}

/// The index of the bracket closing the one at `open`.
fn matching(s: &str, open: usize) -> Option<usize> {
    let b = s.as_bytes();
    let (o, c) = match b.get(open)? {
        b'(' => (b'(', b')'),
        b'[' => (b'[', b']'),
        b'{' => (b'{', b'}'),
        _ => return None,
    };
    let mut depth = 0;
    let mut i = open;
    let mut in_str = false;
    while i < b.len() {
        let ch = b[i];
        if in_str {
            if ch == b'\\' {
                i += 1;
            } else if ch == b'"' {
                in_str = false;
            }
        } else if ch == b'"' {
            in_str = true;
        } else if ch == o {
            depth += 1;
        } else if ch == c {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// Split on commas outside brackets and strings; empty trailing parts dropped.
fn split_top(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut in_str = false;
    let mut cur = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if in_str {
            cur.push(c);
            if c == '\\' {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(std::mem::take(&mut cur));
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    parts.push(cur);
    parts.into_iter().map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn findings(src: &str) -> Vec<Finding> {
        parse_files(&[("lib.rs".into(), src.into())])
    }

    #[test]
    fn seeds_without_a_bump_are_reported() {
        let f = findings(
            r#"
            pub fn init_list(ctx: Context<I>) -> Result<()> {
                let mint_key = ctx.accounts.mint.key();
                let signer_seeds: &[&[u8]] = &[b"extra-account-metas", mint_key.as_ref()];
                create_account(
                    CpiContext::new(a, b).with_signer(&[signer_seeds]),
                    1, 2, ctx.program_id,
                )?;
                Ok(())
            }
            "#,
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, Kind::SignerSeedsWithoutBump);
        assert_eq!(f[0].function, "init_list");
    }

    #[test]
    fn seeds_with_a_bump_pass() {
        let f = findings(
            r#"
            fn a(ctx: Context<A>) -> Result<()> {
                let bump = ctx.bumps.list;
                let seeds: &[&[u8]] = &[b"list", k.as_ref(), &[bump]];
                CpiContext::new(a, b).with_signer(&[seeds]);
                invoke_signed(&ix, &infos, &[&[b"vault", k.as_ref(), &[ctx.bumps.vault]]])?;
                let s = &[b"cfg".as_ref(), &[cfg_bump]];
                let signer = &[&s[..]];
                CpiContext::new_with_signer(p, accts, signer);
                invoke_signed(&ix, &infos, &[&[b"auth", &[self_nonce]]])?;
            }
            "#,
        );
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn seeds_from_a_call_or_parameter_are_not_judged() {
        let f = findings(
            r#"
            fn a(signer: &[&[&[u8]]]) {
                CpiContext::new(a, b).with_signer(signer);
                invoke_signed(&ix, &infos, &[&vault.signer_seeds()])?;
            }
            "#,
        );
        assert!(f.is_empty(), "{f:?}");
    }

    const HOOK: &str = r#"
        use spl_transfer_hook_interface::instruction::ExecuteInstruction;
        use spl_tlv_account_resolution::state::ExtraAccountMetaList;
        #[program]
        pub mod hook {
            use super::*;
            ATTR
            pub fn execute(ctx: Context<Execute>, amount: u64) -> Result<()> { check(&ctx)?; Ok(()) }
            FALLBACK
        }
    "#;

    fn hook(attr: &str, fallback: &str) -> Vec<Finding> {
        findings(&HOOK.replace("ATTR", attr).replace("FALLBACK", fallback))
    }

    const REGISTRY: &str = r#"
        #[program]
        pub mod kyc {
            pub fn add_to_whitelist(ctx: Context<AddToWhitelist>, params: P) -> Result<()> { Ok(()) }
        }
        #[derive(Accounts)]
        #[instruction(params: P)]
        pub struct AddToWhitelist<'info> {
            #[account(mut)]
            pub authority: Signer<'info>,
            #[account(
                seeds = [KycRegistry::SEED_PREFIX, registry.mint.as_ref()],
                bump,
                has_one = authority,
            )]
            pub registry: Account<'info, KycRegistry>,
            #[account(
                init,
                payer = authority,
                space = 8 + WhitelistEntry::INIT_SPACE,
                SEEDS
                bump,
            )]
            pub whitelist_entry: Account<'info, WhitelistEntry>,
            pub system_program: Program<'info, System>,
        }
    "#;

    #[test]
    fn entry_not_scoped_to_its_registry_is_reported() {
        let f = findings(&REGISTRY.replace("SEEDS", "seeds = [WhitelistEntry::SEED_PREFIX, params.wallet.as_ref()],"));
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].kind, Kind::EntryNotScopedToGate);
        assert_eq!(f[0].function, "add_to_whitelist");
        let f = findings(&REGISTRY.replace(
            "SEEDS",
            "seeds = [WhitelistEntry::SEED_PREFIX, registry.key().as_ref(), params.wallet.as_ref()],",
        ));
        assert!(f.is_empty(), "{f:?}");
        // The gate written on the signer instead.
        let src = REGISTRY
            .replace("has_one = authority,", "")
            .replace("#[account(mut)]\n            pub authority", "#[account(mut, constraint = authority.key() == registry.authority @ E::X)]\n            pub authority")
            .replace("SEEDS", "seeds = [WhitelistEntry::SEED_PREFIX, params.wallet.as_ref()],");
        assert_eq!(findings(&src).len(), 1, "{:?}", findings(&src));
    }

    #[test]
    fn singleton_gates_and_signer_owned_entries_pass() {
        // A config at a constant address has no peers.
        let src = REGISTRY
            .replace("seeds = [KycRegistry::SEED_PREFIX, registry.mint.as_ref()],", "seeds = [b\"config\"],")
            .replace("SEEDS", "seeds = [b\"entry\", params.wallet.as_ref()],");
        assert!(findings(&src).is_empty());
        // An entry seeded by the signer is the signer's own.
        let src = REGISTRY.replace("SEEDS", "seeds = [b\"entry\", authority.key().as_ref()],");
        assert!(findings(&src).is_empty());
        // Seeded by what the registry is derived from (its mint).
        let src = REGISTRY.replace("SEEDS", "seeds = [b\"entry\", registry.mint.as_ref(), params.wallet.as_ref()],");
        assert!(findings(&src).is_empty(), "{:?}", findings(&src));
    }

    fn ix(fields: &str) -> Vec<Finding> {
        findings(&format!(
            "#[program]\npub mod m {{ pub fn go(ctx: Context<Go>, params: P) -> Result<()> {{ Ok(()) }} }}\n\
             #[derive(Accounts)]\n#[instruction(params: P)]\npub struct Go<'info> {{\n{fields}\n}}"
        ))
        .into_iter()
        .filter(|f| f.kind == Kind::EntryNotScopedToGate)
        .collect()
    }

    #[test]
    fn review_shapes_for_unscoped_entries() {
        let signer = "#[account(mut)]\npub user: Signer<'info>,\n";
        // The gate's own constraint pins the entry (sigma settle_option).
        let f = ix(&format!("{signer}#[account(mut, constraint = option.owner == user.key(), constraint = option.vault == vault.key())]\npub option: Account<'info, Opt>,\n\
            #[account(mut, seeds = [b\"vault\", vault.underlying_mint.as_ref()], bump)]\npub vault: Account<'info, Vault>,"));
        assert!(f.is_empty(), "{f:?}");
        // A gate seeded by its signer is the signer's own (tensor margin_account).
        let f = ix(&format!("{signer}#[account(mut, seeds = [b\"margin\", user.key().as_ref()], bump, constraint = margin.owner == user.key())]\npub margin: Account<'info, Margin>,\n\
            /// CHECK: x\npub who: UncheckedAccount<'info>,\n#[account(mut, seeds = [b\"market\", who.key().as_ref()], bump)]\npub market: Account<'info, Market>,"));
        assert!(f.is_empty(), "{f:?}");
        // Module-path seeds and token accounts are not entries for a subject (klend).
        let f = ix(&format!("{signer}#[account(has_one = user)]\npub pool: Account<'info, Pool>,\n\
            #[account(init, payer = user, space = 8, seeds = [crate::seeds::ENTRY, pool.key().as_ref()], bump)]\npub a: Account<'info, A>,\n\
            #[account(init, payer = user, token::mint = m, token::authority = pool, seeds = [b\"v\", params.wallet.as_ref()], bump)]\npub v: InterfaceAccount<'info, TokenAccount>,"));
        assert!(f.is_empty(), "{f:?}");
        // A registry keyed by one argument field, an entry by another: still unscoped.
        let f = ix(&format!("{signer}#[account(seeds = [b\"reg\", params.registry_id.as_ref()], bump, has_one = user)]\npub registry: Account<'info, Reg>,\n\
            #[account(init, payer = user, space = 8, seeds = [b\"wl\", params.wallet.as_ref()], bump)]\npub entry: Account<'info, Entry>,"));
        assert_eq!(f.len(), 1, "{f:?}");
    }

    #[test]
    fn hook_with_the_spl_discriminator_passes() {
        assert!(hook("#[instruction(discriminator = ExecuteInstruction::SPL_DISCRIMINATOR_SLICE)]", "").is_empty());
        assert!(hook("#[interface(spl_transfer_hook_interface::execute)]", "").is_empty());
    }

    #[test]
    fn review_probes() {
        // Another name for the handler is still checked.
        let src = HOOK.replace("ATTR", "").replace("FALLBACK", "").replace("pub fn execute", "pub fn transfer_hook");
        let f = findings(&src);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].function, "transfer_hook");
        // A program that only imports a CPI helper is not a hook.
        let f = findings(
            "use spl_transfer_hook_interface::onchain::add_extra_accounts_for_execute_cpi;\n\
             #[program] mod m { pub fn execute(ctx: Context<E>, amount: u64) -> Result<()> { Ok(()) } }",
        );
        assert!(f.is_empty(), "{f:?}");
        // An `execute` outside the module, and a brace in a later attribute.
        let src = HOOK
            .replace("ATTR", "#[instruction(discriminator = ExecuteInstruction::SPL_DISCRIMINATOR_SLICE)]\n#[access_control(check(&ctx, Foo { a: 1 }))]")
            .replace("FALLBACK", "")
            .replace("#[program]", "impl Foo { pub fn execute(&self, amount: u64) {} }\n#[program]");
        assert!(findings(&src).is_empty());
        // Nested generics on the fallback.
        let src = HOOK.replace("ATTR", "").replace(
            "FALLBACK",
            "pub fn fallback<'info, T: Into<u8>>(p: &Pubkey, a: &'info [AccountInfo<'info>], d: &[u8]) -> Result<()> { __private::__global::execute(p, a, d) }",
        );
        assert!(findings(&src).is_empty());
    }

    #[test]
    fn shadowed_and_renamed_bumps_pass() {
        let f = findings(
            r#"
            fn a() {
                let seeds = &[b"vault".as_ref(), &[bump]];
                let seeds = &[&seeds[..]];
                invoke_signed(&ix, &infos, seeds)?;
                let b = [ctx.bumps.vault];
                let s2 = &[b"v".as_ref(), k.as_ref(), &b];
                invoke_signed(&ix, &infos, &[s2])?;
                invoke_signed(&ix, &infos, &[&[b"v", core::slice::from_ref(&b)]])?;
            }
            "#,
        );
        assert!(f.is_empty(), "{f:?}");
        // A seed literal that says "bump" is not a bump.
        let f = findings(r#"fn a() { invoke_signed(&ix, &infos, &[&[b"bump", k.as_ref()]])?; }"#);
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn hook_without_discriminator_or_fallback_is_unreachable() {
        let f = hook("", "");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, Kind::HookExecuteUnreachable);
    }

    #[test]
    fn fallback_that_only_logs_is_reported() {
        let f = hook(
            "",
            r#"pub fn fallback<'info>(_p: &Pubkey, _a: &'info [AccountInfo<'info>], data: &[u8]) -> Result<()> {
                if &data[..8] == ExecuteInstruction::SPL_DISCRIMINATOR.as_slice() {
                    msg!("execute with amount {}", 1);
                    Ok(())
                } else { Err(ProgramError::InvalidInstructionData.into()) }
            }"#,
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, Kind::HookFallbackSkipsExecute);
    }

    #[test]
    fn fallback_that_dispatches_passes() {
        let f = hook(
            "",
            r#"pub fn fallback<'info>(p: &Pubkey, a: &'info [AccountInfo<'info>], data: &[u8]) -> Result<()> {
                match TransferHookInstruction::unpack(data)? {
                    TransferHookInstruction::Execute { amount } => __private::__global::execute(p, a, &amount.to_le_bytes()),
                    _ => Err(ProgramError::InvalidInstructionData.into()),
                }
            }"#,
        );
        assert!(f.is_empty(), "{f:?}");
    }
}
