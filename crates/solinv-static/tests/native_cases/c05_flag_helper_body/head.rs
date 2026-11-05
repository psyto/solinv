entrypoint!(process);
fn check_account(a: &AccountInfo, must_sign: bool) -> ProgramResult {
    Ok(())
}
fn withdraw(accounts: &[AccountInfo]) -> ProgramResult {
    let [user, vault, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    check_account(user, true)?;
    transfer(vault, user);
    Ok(())
}
