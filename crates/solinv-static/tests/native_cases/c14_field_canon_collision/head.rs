entrypoint!(process);
fn update(accounts: &[AccountInfo], state: &State) -> ProgramResult {
    let [delegate, config, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    if state.delegate != *delegate.key {
        return Err(ProgramError::InvalidAccountData);
    }
    if !delegate.is_signer { return Err(ProgramError::MissingRequiredSignature); }
    write(config, delegate);
    Ok(())
}
