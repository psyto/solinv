entrypoint!(process);
fn process(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [authority, config, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    match Ix::unpack(data)? {
        Ix::Pause => {
            if !authority.is_signer() { return Err(ProgramError::MissingRequiredSignature); }
            set_paused(config, true);
        }
        Ix::Resume => {
            if !authority.is_signer() { return Err(ProgramError::MissingRequiredSignature); }
            set_paused(config, false);
        }
    }
    Ok(())
}
