entrypoint!(process);
fn update(accounts: &[AccountInfo], state: &State) -> ProgramResult {
    let [authority, config, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    if state.authority != *authority.key {
        return Err(ProgramError::InvalidAccountData);
    }
    if !authority.is_signer { return Err(ProgramError::MissingRequiredSignature); }
    write(config, authority);
    Ok(())
}
