//! The second round of the adversarial review: conditions read as an
//! equality only in that shape, owner checks against this program's id on
//! the account's own parameter, a key check tying the two accounts, calls
//! followed only where the fn can be told.

use super::*;
fn kinds(src: &str) -> SourceKinds {
    SourceKinds::parse_files(&[("programs/x/src/lib.rs".into(), src.into())])
}
/// What each case must report on its slot. A check handed to a fn is
/// always a removal (the control h0 too); a warning only for a gate whose
/// argument changed by design (g4) and `!x` written `x.not()` (g6).
fn want(tag: &str) -> &'static [Severity] {
    let table: &[(&str, &[Severity])] = &[
        ("g1 ==false flip", &[Severity::Regression][..]),
        ("g2 load_mut flip", &[Severity::Regression][..]),
        ("g3 bool literal", &[Severity::Regression][..]),
        ("g4 enum arg", &[Severity::Warning][..]),
        ("g5 bool literal &&", &[Severity::Regression][..]),
        ("g6 not()", &[Severity::Warning][..]),
        ("h0 control", &[Severity::Regression][..]),
        ("h1 keyed pairs wrong", &[Severity::Regression][..]),
        ("h2 owner+disc on the other param", &[Severity::Regression][..]),
        ("h3 require!(!(..==..)) init guard", &[Severity::Regression][..]),
        ("h4 if !(a != b) init guard", &[Severity::Regression][..]),
        ("h5 single | bypass", &[Severity::Regression][..]),
        ("h6 user const ID", &[Severity::Regression][..]),
        ("h7 early return bypass", &[Severity::Regression][..]),
        ("p1 block tail discarded", &[Severity::Regression][..]),
        ("p2 if-else value discarded", &[Severity::Regression][..]),
        ("p3 closure never called", &[Severity::Regression][..]),
        ("p4 return unrelated", &[Severity::Regression][..]),
        ("m1 turbofish external", &[Severity::Regression][..]),
        ("m2 method on external value", &[Severity::Regression][..]),
        ("m3 local mod name == external", &[Severity::Regression][..]),
        ("a1 shadow via for", &[Severity::Regression][..]),
        ("a2 shadow via tuple", &[Severity::Regression][..]),
        ("t1 lt in args", &[Severity::Regression][..]),
        ("t2 closure arg", &[Severity::Regression][..]),
        ("t3 swapped args map", &[Severity::Regression][..]),
    ];
    table.iter().find(|(t, _)| *t == tag).map(|(_, w)| *w).unwrap_or_else(|| panic!("no expectation for {tag}"))
}
fn show(tag: &str, b: &str, h: &str, slot: &str) {
    let got: Vec<Severity> = diff(&kinds(b), &kinds(h)).into_iter().filter(|c| c.slot() == slot).map(|c| c.severity).collect();
    assert_eq!(got, want(tag), "{tag}");
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
fn g_gaps() {
    for (tag, b, h) in [
        ("g1 ==false flip", "group.load()?.paused == false", "group.load()?.paused"),
        ("g2 load_mut flip", "!group.load()?.is_paused()", "group.load_mut()?.is_paused()"),
        ("g3 bool literal", "group.load()?.allows(false)", "group.load()?.allows(true)"),
        ("g4 enum arg", "group.load()?.is_ix_enabled(IxGate::Swap)", "group.load()?.is_ix_enabled(IxGate::Noop)"),
        ("g5 bool literal &&", "group.load()?.is_operational()", "group.load()?.is_operational() ^ true"),
        ("g6 not()", "!group.load()?.is_paused()", "group.load()?.is_paused().not()"),
    ] {
        show(tag, &GATE.replace("GATE", b), &GATE.replace("GATE", h), "act.group");
    }
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
const GOOD: &str = r#"
fn verify(info: &AccountInfo, w: &AccountInfo) -> Result<()> {
    if info.owner != &crate::ID { return Err(E::Owner.into()); }
    if info.data.borrow()[..8] != TickArray::discriminator() { return Err(E::Disc.into()); }
    require_keys_eq!(load(info).whirlpool, w.key(), E::Key);
    Ok(())
}
"#;
#[test]
fn h_cases() {
    let cases: Vec<(&str, &str, &str)> = vec![
        ("h0 control", GOOD, "verify(&ctx.accounts.tick_array, &ctx.accounts.whirlpool)?;"),
        // keyed: the tied account's param is key-compared, but with authority, not with tick.
        ("h1 keyed pairs wrong", r#"
fn verify(info: &AccountInfo, w: &Account<Whirlpool>, a: &Signer) -> Result<()> {
    if info.owner != &crate::ID { return Err(E::Owner.into()); }
    if info.data.borrow()[..8] != TickArray::discriminator() { return Err(E::Disc.into()); }
    require_keys_eq!(w.authority, a.key(), E::Auth);
    Ok(())
}
"#, "verify(&ctx.accounts.tick_array, &ctx.accounts.whirlpool, &ctx.accounts.authority)?;"),
        // owner/disc checked on the other parameter.
        ("h2 owner+disc on the other param", r#"
fn verify(info: &AccountInfo, w: &AccountInfo) -> Result<()> {
    if w.owner != &crate::ID { return Err(E::Owner.into()); }
    if w.data.borrow()[..8] != Whirlpool::discriminator() { return Err(E::Disc.into()); }
    Ok(())
}
"#, "verify(&ctx.accounts.tick_array, &ctx.accounts.whirlpool)?;"),
        ("h3 require!(!(..==..)) init guard", r#"
fn verify(info: &AccountInfo, w: &AccountInfo) -> Result<()> {
    require!(!(info.owner == &crate::ID), E::Init);
    require!(!(info.data.borrow()[..8] == TickArray::discriminator()), E::Init);
    require!(!(info.key() == w.key()), E::Same);
    Ok(())
}
"#, "verify(&ctx.accounts.tick_array, &ctx.accounts.whirlpool)?;"),
        ("h4 if !(a != b) init guard", r#"
fn verify(info: &AccountInfo, w: &AccountInfo) -> Result<()> {
    if !(info.owner != &crate::ID) { return Err(E::Init.into()); }
    if !(info.data.borrow()[..8] != TickArray::discriminator()) { return Err(E::Init.into()); }
    if !(info.key() != w.key()) { return Err(E::Same.into()); }
    Ok(())
}
"#, "verify(&ctx.accounts.tick_array, &ctx.accounts.whirlpool)?;"),
        ("h5 single | bypass", r#"
fn verify(info: &AccountInfo, w: &AccountInfo, skip: bool) -> Result<()> {
    require!((info.owner == &crate::ID) | skip, E::Owner);
    require!((info.data.borrow()[..8] == TickArray::discriminator()) | skip, E::Disc);
    require!((load(info).whirlpool == w.key()) | skip, E::Key);
    Ok(())
}
"#, "verify(&ctx.accounts.tick_array, &ctx.accounts.whirlpool, true)?;"),
        ("h6 user const ID", r#"
pub mod admin { declare_id!("Adm1n11111111111111111111111111111111111111"); }
fn verify(info: &AccountInfo, w: &AccountInfo) -> Result<()> {
    let data = info.try_borrow_data()?;
    if data[..8] != TickArray::DISCRIMINATOR { return Err(E::Disc.into()); }
    let t = TickArray::deserialize(&data[8..])?;
    require!(t.owner == admin::ID, E::NotAdmin);
    require_keys_eq!(t.whirlpool, w.key(), E::Key);
    Ok(())
}
"#, "verify(&ctx.accounts.tick_array, &ctx.accounts.whirlpool)?;"),
        ("h7 early return bypass", r#"
fn verify(info: &AccountInfo, w: &AccountInfo, legacy: bool) -> Result<()> {
    if legacy { return Ok(()); }
    if info.owner != &crate::ID { return Err(E::Owner.into()); }
    if info.data.borrow()[..8] != TickArray::discriminator() { return Err(E::Disc.into()); }
    require_keys_eq!(load(info).whirlpool, w.key(), E::Key);
    Ok(())
}
"#, "verify(&ctx.accounts.tick_array, &ctx.accounts.whirlpool, true)?;"),
        ("p1 block tail discarded", GOOD, "let _ = { verify(&ctx.accounts.tick_array, &ctx.accounts.whirlpool) };"),
        ("p2 if-else value discarded", GOOD, "let r = if true { verify(&ctx.accounts.tick_array, &ctx.accounts.whirlpool) } else { Ok(()) };\n    msg!(\"{:?}\", r.is_ok());"),
        ("p3 closure never called", GOOD, "let c = || { verify(&ctx.accounts.tick_array, &ctx.accounts.whirlpool) };"),
        ("p4 return unrelated", GOOD, "if false { return verify(&ctx.accounts.tick_array, &ctx.accounts.whirlpool); }"),
        ("m1 turbofish external", r#"
fn try_from(info: &AccountInfo, w: &AccountInfo) -> Result<()> {
    if info.owner != &crate::ID { return Err(E::Owner.into()); }
    if info.data.borrow()[..8] != TickArray::discriminator() { return Err(E::Disc.into()); }
    require_keys_eq!(load(info).whirlpool, w.key(), E::Key);
    Ok(())
}
"#, "let x = ext::Thing::<u8>::try_from(&ctx.accounts.tick_array, &ctx.accounts.whirlpool)?;"),
        ("m2 method on external value", r#"
impl Config {
    pub fn validate(&self, info: &AccountInfo, w: &AccountInfo) -> Result<()> {
        if info.owner != &crate::ID { return Err(E::Owner.into()); }
        if info.data.borrow()[..8] != TickArray::discriminator() { return Err(E::Disc.into()); }
        require_keys_eq!(load(info).whirlpool, w.key(), E::Key);
        Ok(())
    }
}
"#, "ext_crate::oracle().validate(&ctx.accounts.tick_array, &ctx.accounts.whirlpool)?;"),
        ("m3 local mod name == external", r#"
pub mod token { pub fn noop() {} }
fn transfer(info: &AccountInfo, w: &AccountInfo) -> Result<()> {
    if info.owner != &crate::ID { return Err(E::Owner.into()); }
    if info.data.borrow()[..8] != TickArray::discriminator() { return Err(E::Disc.into()); }
    require_keys_eq!(load(info).whirlpool, w.key(), E::Key);
    Ok(())
}
"#, "token::transfer(&ctx.accounts.tick_array, &ctx.accounts.whirlpool)?;"),
        ("a1 shadow via for", GOOD, "let t = &ctx.accounts.tick_array;\n    for t in ctx.remaining_accounts.iter() { verify(t, &ctx.accounts.whirlpool)?; }"),
        ("a2 shadow via tuple", GOOD, "let t = &ctx.accounts.tick_array;\n    let (t, _) = (&ctx.remaining_accounts[0], 1);\n    verify(t, &ctx.accounts.whirlpool)?;"),
        // arg/param mapping: a `<` in an argument merges parts.
        ("t1 lt in args", r#"
fn verify(n: bool, info: &AccountInfo, m: bool, w: &AccountInfo) -> Result<()> {
    if info.owner != &crate::ID { return Err(E::Owner.into()); }
    if info.data.borrow()[..8] != TickArray::discriminator() { return Err(E::Disc.into()); }
    require_keys_eq!(load(info).whirlpool, w.key(), E::Key);
    Ok(())
}
"#, "verify(1 < 2, &ctx.accounts.tick_array, 3 > 2, &ctx.accounts.whirlpool)?;"),
        ("t2 closure arg", r#"
fn verify(f: impl Fn(u8, u8) -> bool, info: &AccountInfo, w: &AccountInfo) -> Result<()> {
    if info.owner != &crate::ID { return Err(E::Owner.into()); }
    if info.data.borrow()[..8] != TickArray::discriminator() { return Err(E::Disc.into()); }
    require_keys_eq!(load(info).whirlpool, w.key(), E::Key);
    Ok(())
}
"#, "verify(|a, b| a == b, &ctx.accounts.tick_array, &ctx.accounts.whirlpool)?;"),
        ("t3 swapped args map", r#"
fn verify(w: &AccountInfo, info: &AccountInfo) -> Result<()> {
    if info.owner != &crate::ID { return Err(E::Owner.into()); }
    if info.data.borrow()[..8] != TickArray::discriminator() { return Err(E::Disc.into()); }
    require_keys_eq!(load(info).whirlpool, w.key(), E::Key);
    Ok(())
}
"#, "verify(&ctx.accounts.whirlpool, &ctx.accounts.tick_array)?;"),
    ];
    for (tag, fns, call) in cases {
        show(tag, HB, &unchecked(fns, call), "swap.tick_array");
    }
}
