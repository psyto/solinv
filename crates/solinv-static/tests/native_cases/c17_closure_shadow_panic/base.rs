entrypoint!(process);
fn verify(a: &AccountInfo, expected: &Pubkey) -> ProgramResult {
    if a.key != expected {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(())
}
fn one(accounts: &[AccountInfo]) -> ProgramResult {
    verify(&accounts[0], &ADMIN)?;
    Ok(())
}
fn two(accounts: &[AccountInfo]) -> ProgramResult {
    let verify = |x: &AccountInfo| -> ProgramResult { Ok(()) };
    verify(&accounts[1])?;
    Ok(())
}
