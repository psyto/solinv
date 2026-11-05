entrypoint!(process);
fn is_authorized(a: &AccountInfo) -> bool {
    a.is_signer()
}
fn withdraw(accounts: &[AccountInfo]) -> ProgramResult {
    let [user, vault, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    transfer(vault, user);
    Ok(())
}
