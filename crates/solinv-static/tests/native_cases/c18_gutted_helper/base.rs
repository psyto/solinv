entrypoint!(process);
fn require_signer(a: &AccountInfo) -> ProgramResult {
    if !a.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    Ok(())
}
fn withdraw(accounts: &[AccountInfo]) -> ProgramResult {
    let [user, vault, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    require_signer(user)?;
    transfer(vault, user);
    Ok(())
}
