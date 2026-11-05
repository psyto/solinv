entrypoint!(process);
fn pause(accounts: &[AccountInfo]) -> ProgramResult {
    let [authority, config, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    set_paused(config, true);
    Ok(())
}
