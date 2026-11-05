entrypoint!(process);
fn withdraw(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let [user, vault, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    if amount > 0 {
        transfer(vault, user, amount);
        return Ok(());
    }
    Err(ProgramError::InvalidArgument)
}
