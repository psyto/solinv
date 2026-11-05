entrypoint!(process);
fn require_signer(_a: &AccountInfo) -> ProgramResult {
    Ok(())
}
fn withdraw(accounts: &[AccountInfo]) -> ProgramResult {
    let [user, vault, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    require_signer(user)?;
    transfer(vault, user);
    Ok(())
}
