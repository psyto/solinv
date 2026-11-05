entrypoint!(process);
fn set_admin(accounts: &[AccountInfo], new_admin: Pubkey) -> ProgramResult {
    let [authority, config, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    write_admin(config, authority, new_admin);
    Ok(())
}
