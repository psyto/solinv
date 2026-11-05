entrypoint!(process);
fn pause(accounts: &[AccountInfo]) -> ProgramResult {
    let authority = &accounts[0];
    let config = &accounts[1];
    set_paused(config, true);
    Ok(())
}
