entrypoint!(process);
fn pause(accounts: &[AccountInfo]) -> ProgramResult {
    let [authority, config, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    set_paused(config, true);
    Ok(())
}
