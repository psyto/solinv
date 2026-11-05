entrypoint!(process);
fn require_admin(stored: Pubkey, signer: &Pubkey) -> ProgramResult {
    Ok(())
}
fn set_fee(accounts: &[AccountInfo], cfg: &Config) -> ProgramResult {
    let [admin, config, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    require_admin(cfg.admin, admin.key)?;
    write(config, admin);
    Ok(())
}
