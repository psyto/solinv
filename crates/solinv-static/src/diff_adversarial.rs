//! Cases from an adversarial review of the rules that read a check as
//! kept elsewhere (a gate swapped on the same account, a check handed to
//! a fn): each a loosening that must stay a removal, or a warning that
//! asks the reviewer to confirm.

use super::*;

fn kinds(src: &str) -> SourceKinds {
    SourceKinds::parse_files(&[("programs/x/src/lib.rs".into(), src.into())])
}
fn show(tag: &str, b: &str, h: &str, slot: &str) -> Vec<Severity> {
    let ch: Vec<Change> = diff(&kinds(b), &kinds(h)).into_iter().filter(|c| c.slot() == slot).collect();
    for c in &ch {
        println!("[{tag}] {:?} {}: {}", c.severity, c.slot(), c.message);
    }
    if ch.is_empty() { println!("[{tag}] (nothing reported for {slot})"); }
    ch.into_iter().map(|c| c.severity).collect()
}

const GATE: &str = r#"
pub fn act(ctx: Context<Act>) -> Result<()> {}
#[derive(Accounts)]
pub struct Act<'info> {
    #[account(constraint = GATE @ Err::Halted)]
    pub group: AccountLoader<'info, Group>,
    pub owner: Signer<'info>,
}
"#;

#[test]
fn a1_negation_flip() {
    let b = GATE.replace("GATE", "!group.load()?.is_paused()");
    let h = GATE.replace("GATE", "group.load()?.is_paused()");
    assert_eq!(show("a1 negation flip", &b, &h, "act.group"), [Severity::Regression]);
}
#[test]
fn a2_literal_changed_via_eq_method() {
    let b = GATE.replace("GATE", "group.load()?.role.eq(\"admin\")");
    let h = GATE.replace("GATE", "group.load()?.role.eq(\"attacker\")");
    assert_eq!(show("a2 .eq literal", &b, &h, "act.group"), [Severity::Regression]);
    let b = GATE.replace("GATE", "group.load()?.version.ge(&3)");
    let h = GATE.replace("GATE", "group.load()?.version.ge(&0)");
    assert_eq!(show("a2b .ge literal", &b, &h, "act.group"), [Severity::Regression]);
}
#[test]
fn a3_matches_widened() {
    let b = GATE.replace("GATE", "matches!(group.load()?.state, State::Active)");
    let h = GATE.replace("GATE", "matches!(group.load()?.state, State::Active | State::Halted)");
    assert_eq!(show("a3 matches widened", &b, &h, "act.group"), [Severity::Regression]);
}
#[test]
fn a4_trivial_gate() {
    let b = GATE.replace("GATE", "group.load()?.is_operational()");
    let h = GATE.replace("GATE", "!group.data_is_empty()");
    assert_eq!(show("a4 trivially true", &b, &h, "act.group"), [Severity::Warning]);
}
#[test]
fn a5_one_new_gate_absorbs_two() {
    let b = GATE.replace("constraint = GATE @ Err::Halted", "constraint = group.load()?.is_operational(), constraint = !group.load()?.is_frozen()");
    let h = GATE.replace("GATE", "group.load()?.is_ix_enabled(IxGate::Act)");
    assert_eq!(show("a5 two gates -> one", &b, &h, "act.group"), [Severity::Regression, Severity::Warning]);
}

const HB: &str = r#"
pub fn swap(ctx: Context<Swap>) -> Result<()> {
    Ok(())
}
#[derive(Accounts)]
pub struct Swap<'info> {
    pub authority: Signer<'info>,
    pub whirlpool: Account<'info, Whirlpool>,
    #[account(mut, has_one = whirlpool)]
    pub tick_array: AccountLoader<'info, TickArray>,
}
"#;
fn unchecked(extra_fns: &str, call: &str) -> String {
    format!(
        "{}\n{}",
        HB.replace("    #[account(mut, has_one = whirlpool)]\n    pub tick_array: AccountLoader<'info, TickArray>,", "    /// CHECK: x\n    #[account(mut)]\n    pub tick_array: UncheckedAccount<'info>,")
            .replace("    Ok(())\n}\n#[derive", &format!("    {call}\n    Ok(())\n}}\n#[derive")),
        extra_fns
    )
}

#[test]
fn b1_discriminator_only_and_user_owner_field() {
    // Classic missing program-owner check: the discriminator bytes are
    // compared but not the program owner; `.owner` is the position's user.
    let fns = r#"
fn load_position(info: &AccountInfo, whirlpool: &Account<Whirlpool>, authority: &Signer) -> Result<Position> {
    let data = info.try_borrow_data()?;
    if data[..8] != Position::DISCRIMINATOR {
        return Err(ErrorCode::BadDisc.into());
    }
    let p = Position::deserialize(&data[8..])?;
    require!(p.owner == authority.key(), ErrorCode::NotOwner);
    Ok(p)
}
"#;
    let h = unchecked(fns, "let p = load_position(&ctx.accounts.tick_array.to_account_info(), &ctx.accounts.whirlpool, &ctx.accounts.authority)?;");
    assert_eq!(show("b1 disc only + user owner field", HB, &h, "swap.tick_array"), [Severity::Regression, Severity::Regression]);
}
#[test]
fn b2_rejects_when_initialized() {
    // An init guard: rejects when the account IS ours (opposite polarity).
    let fns = r#"
fn ensure_fresh(info: &AccountInfo, whirlpool: &Account<Whirlpool>) -> Result<()> {
    if info.owner == &crate::ID {
        return Err(ErrorCode::AlreadyInit.into());
    }
    if info.data.borrow()[..8] == TickArray::discriminator() {
        return Err(ErrorCode::AlreadyInit.into());
    }
    if info.key() == whirlpool.key() {
        return Err(ErrorCode::Same.into());
    }
    Ok(())
}
"#;
    let h = unchecked(fns, "ensure_fresh(&ctx.accounts.tick_array, &ctx.accounts.whirlpool)?;");
    assert_eq!(show("b2 reversed polarity", HB, &h, "swap.tick_array"), [Severity::Regression, Severity::Regression]);
}
#[test]
fn b3_only_key_passed() {
    // Only the key is handed: the callee cannot check its owner or data.
    let fns = r#"
fn log_swap(tick: Pubkey, whirlpool: &Account<Whirlpool>) -> Result<()> {
    let info = whirlpool.to_account_info();
    if info.owner != &crate::ID { return Err(E::Owner.into()); }
    if info.data.borrow()[..8] != Whirlpool::discriminator() { return Err(E::Disc.into()); }
    require!(whirlpool.key() != tick, E::Same);
    Ok(())
}
"#;
    let h = unchecked(fns, "log_swap(ctx.accounts.tick_array.key(), &ctx.accounts.whirlpool)?;");
    assert_eq!(show("b3 only key passed", HB, &h, "swap.tick_array"), [Severity::Regression, Severity::Regression]);
}
#[test]
fn b4_external_fn_same_name() {
    // `other_crate::validate` resolves to this source's unrelated `validate`.
    let fns = r#"
impl Config {
    pub fn validate(&self, info: &AccountInfo) -> Result<()> {
        if info.owner != &crate::ID { return Err(E::Owner.into()); }
        if info.data.borrow()[..8] != Config::discriminator() { return Err(E::Disc.into()); }
        require!(info.key() == self.admin, E::Key);
        Ok(())
    }
}
"#;
    let h = unchecked(fns, "other_crate::validate(&ctx.accounts.tick_array, &ctx.accounts.whirlpool)?;");
    assert_eq!(show("b4 external fn same name", HB, &h, "swap.tick_array"), [Severity::Regression, Severity::Regression]);
}
#[test]
fn b5_array_param_fn_skipped_wrong_pick() {
    // The real `check` has `[u8; 32]` in its signature and is not indexed;
    // the call resolves to the only other `check`, a method of another type.
    let fns = r#"
fn check(info: &AccountInfo, seed: [u8; 32]) -> Result<()> {
    Ok(())
}
impl Other {
    fn check(&self, info: &AccountInfo) -> Result<()> {
        if info.owner != &crate::ID { return Err(E::Owner.into()); }
        if info.data.borrow()[..8] != Other::discriminator() { return Err(E::Disc.into()); }
        require!(info.key() == self.whirlpool.key(), E::Key);
        Ok(())
    }
}
"#;
    let h = unchecked(fns, "check(&ctx.accounts.tick_array, [0u8; 32])?; let _ = &ctx.accounts.whirlpool;");
    assert_eq!(show("b5 skipped fn", HB, &h, "swap.tick_array"), [Severity::Regression, Severity::Regression]);
    let h = unchecked(fns, "check(&ctx.accounts.tick_array, ctx.accounts.whirlpool.key().to_bytes())?;");
    assert_eq!(show("b5b skipped fn with whirlpool", HB, &h, "swap.tick_array"), [Severity::Regression, Severity::Regression]);
}
#[test]
fn b6_shadowed_alias() {
    let fns = r#"
fn verify(info: &AccountInfo, w: &AccountInfo) -> Result<()> {
    if info.owner != &crate::ID { return Err(E::Owner.into()); }
    if info.data.borrow()[..8] != TickArray::discriminator() { return Err(E::Disc.into()); }
    require!(info.key() == w.key(), E::Key);
    Ok(())
}
"#;
    let h = unchecked(fns, "let t = &ctx.accounts.tick_array;\n    let t = &ctx.remaining_accounts[0];\n    verify(t, &ctx.accounts.whirlpool)?;");
    assert_eq!(show("b6 shadowed alias", HB, &h, "swap.tick_array"), [Severity::Regression, Severity::Regression]);
}
#[test]
fn b7_dead_branch() {
    let fns = r#"
fn verify(info: &AccountInfo, w: &AccountInfo) -> Result<()> {
    if info.owner != &crate::ID { return Err(E::Owner.into()); }
    if info.data.borrow()[..8] != TickArray::discriminator() { return Err(E::Disc.into()); }
    require!(info.key() == w.key(), E::Key);
    Ok(())
}
"#;
    let h = unchecked(fns, "if false { verify(&ctx.accounts.tick_array, &ctx.accounts.whirlpool)?; }");
    assert_eq!(show("b7 branch", HB, &h, "swap.tick_array"), [Severity::Warning, Severity::Warning]);
}
#[test]
fn b8_self_transfer_guard_as_has_one() {
    // has_one = authority removed; a transfer helper that rejects from == to.
    let b = r#"
pub fn pay(ctx: Context<Pay>) -> Result<()> {
    Ok(())
}
#[derive(Accounts)]
pub struct Pay<'info> {
    pub authority: Signer<'info>,
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub dest: Account<'info, Vault>,
}
"#;
    let h = format!("{}\n{}", b.replace("has_one = authority", "").replace("    Ok(())\n}\n#[derive", "    move_funds(&ctx.accounts.vault, &ctx.accounts.dest, &ctx.accounts.authority)?;\n    Ok(())\n}\n#[derive"), r#"
fn move_funds(from: &Account<Vault>, to: &Account<Vault>, auth: &Signer) -> Result<()> {
    require!(from.key() != to.key(), E::SelfTransfer);
    Ok(())
}
"#);
    assert_eq!(show("b8 from!=to guard", b, &h, "pay.vault"), [Severity::Regression]);
}
#[test]
fn c1_macro_rules_and_test_fn() {
    // A test helper of a unique name gives the call its checks.
    let fns = r#"
#[cfg(test)]
mod tests {
    pub fn assert_tick(info: &AccountInfo, w: &AccountInfo) -> Result<()> {
        if info.owner != &crate::ID { return Err(E::Owner.into()); }
        if info.data.borrow()[..8] != TickArray::discriminator() { return Err(E::Disc.into()); }
        require!(info.key() == w.key(), E::Key);
        Ok(())
    }
}
"#;
    let h = unchecked(fns, "msg!(\"{}\", assert_tick(&ctx.accounts.tick_array, &ctx.accounts.whirlpool).is_ok());");
    assert_eq!(show("c1 cfg(test) fn and result ignored", HB, &h, "swap.tick_array"), [Severity::Regression, Severity::Regression]);
}
#[test]
fn c2_result_discarded() {
    let fns = r#"
fn verify(info: &AccountInfo, w: &AccountInfo) -> Result<()> {
    if info.owner != &crate::ID { return Err(E::Owner.into()); }
    if info.data.borrow()[..8] != TickArray::discriminator() { return Err(E::Disc.into()); }
    require!(info.key() == w.key(), E::Key);
    Ok(())
}
"#;
    let h = unchecked(fns, "let _ = verify(&ctx.accounts.tick_array, &ctx.accounts.whirlpool);");
    assert_eq!(show("c2 result discarded", HB, &h, "swap.tick_array"), [Severity::Regression, Severity::Regression]);
}
#[test]
fn d1_nested_composite() {
    let b = r#"
pub fn pay(ctx: Context<Pay>) -> Result<()> {
    Ok(())
}
#[derive(Accounts)]
pub struct Pay<'info> {
    pub inner: Inner<'info>,
}
#[derive(Accounts)]
pub struct Inner<'info> {
    pub authority: Signer<'info>,
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,
}
"#;
    let f = r#"
fn verify(v: &Account<Vault>, a: &Signer) -> Result<()> {
    require!(v.authority.key() == a.key(), E::Auth);
    Ok(())
}
"#;
    for (tag, call, want) in [
        ("d1 full paths", "verify(&ctx.accounts.inner.vault, &ctx.accounts.inner.authority)?;", Severity::Warning),
        // Not followed: a composite aliased, or passed whole.
        ("d1 alias of composite", "let i = &ctx.accounts.inner;\n    verify(&i.vault, &i.authority)?;", Severity::Regression),
        ("d1 whole composite", "verify2(&ctx.accounts.inner)?;", Severity::Regression),
    ] {
        let h = format!("{}\n{}\nfn verify2(i: &Inner) -> Result<()> {{ require!(i.vault.authority.key() == i.authority.key(), E::A); Ok(()) }}", b.replace("has_one = authority", "").replace("    Ok(())\n}\n#[derive(Accounts)]\npub struct Pay", &format!("    {call}\n    Ok(())\n}}\n#[derive(Accounts)]\npub struct Pay")), f);
        assert_eq!(show(tag, b, &h, "pay.inner.vault"), [want]);
    }
}
#[test]
fn d2_self_call() {
    let fns = r#"
impl<'info> Swap<'info> {
    fn verify(&self, info: &AccountInfo) -> Result<()> {
        if info.owner != &crate::ID { return Err(E::Owner.into()); }
        if info.data.borrow()[..8] != TickArray::discriminator() { return Err(E::Disc.into()); }
        require!(info.key() == self.whirlpool.key(), E::Key);
        Ok(())
    }
}
"#;
    let h = unchecked(fns, "Self::verify(&ctx.accounts, &ctx.accounts.tick_array)?;");
    assert_eq!(show("d2 Self::", HB, &h, "swap.tick_array"), [Severity::Regression, Severity::Regression]);
    let h = unchecked(fns, "ctx.accounts.verify(&ctx.accounts.tick_array.to_account_info())?;");
    assert_eq!(show("d2 method on accounts", HB, &h, "swap.tick_array"), [Severity::Regression, Severity::Warning]);
}

