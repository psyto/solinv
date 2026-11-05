entrypoint!(process);
fn verify(a: &AccountInfo, expected: &Pubkey) -> ProgramResult {
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
