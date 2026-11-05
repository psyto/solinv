entrypoint!(process);
fn init(accounts: &[AccountInfo], name: &str) -> ProgramResult {
    let [payer, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    Ok(())
}
