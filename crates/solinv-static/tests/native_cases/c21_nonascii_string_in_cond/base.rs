entrypoint!(process);
fn init(accounts: &[AccountInfo], name: &str) -> ProgramResult {
    let [payer, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    if name == "café" || !payer.is_signer() {
        return Err(ProgramError::InvalidArgument);
    }
    Ok(())
}
