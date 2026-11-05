entrypoint!(process);
fn check_admin(a: &AccountInfo) -> ProgramResult {
    if *a.key != ADMIN {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(())
}
fn set_fee(accounts: &[AccountInfo]) -> ProgramResult {
    let [admin, config, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    check_admin(admin)?;
    write(config, admin);
    Ok(())
}
