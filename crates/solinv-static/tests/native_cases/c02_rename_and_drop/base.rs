entrypoint!(process);
fn set_admin(accounts: &[AccountInfo], new_admin: Pubkey) -> ProgramResult {
    let [admin, config, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    if !admin.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    write_admin(config, admin, new_admin);
    Ok(())
}
