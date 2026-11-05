entrypoint!(process);
fn require_admin(stored: Pubkey, signer: &Pubkey) -> ProgramResult {
    if stored != *signer {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(())
}
fn set_fee(accounts: &[AccountInfo], cfg: &Config) -> ProgramResult {
    let [admin, config, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    write(config, admin);
    Ok(())
}
