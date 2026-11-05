entrypoint!(process);
fn pause(accounts: &[AccountInfo]) -> ProgramResult {
    let authority = &accounts[0];
    let config = &accounts[1];
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    set_paused(config, true);
    Ok(())
}
