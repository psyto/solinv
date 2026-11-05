entrypoint!(process);
fn pause(accounts: &[AccountInfo]) -> ProgramResult {
    let it = &mut accounts.iter();
    let authority = next_account_info(it)?;
    let config = next_account_info(it)?;
    set_paused(config, true);
    Ok(())
}
