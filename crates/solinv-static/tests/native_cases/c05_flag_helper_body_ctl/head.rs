entrypoint!(process);
fn check_account(a: &AccountInfo, must_sign: bool) -> ProgramResult {
    if must_sign && !a.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    Ok(())
}
fn withdraw(accounts: &[AccountInfo]) -> ProgramResult {
    let [user, vault, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    transfer(vault, user);
    Ok(())
}
