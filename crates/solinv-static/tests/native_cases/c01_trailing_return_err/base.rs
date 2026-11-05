entrypoint!(process);
fn withdraw(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let [user, vault, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    if !user.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if amount > 0 {
        transfer(vault, user, amount);
        return Ok(());
    }
    return Err(ProgramError::InvalidArgument);
}
