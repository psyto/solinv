entrypoint!(process);
fn set_admin(accounts: &[AccountInfo], new_admin: Pubkey) -> ProgramResult {
    let admin = &accounts[0];
    if !admin.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    write_admin(&accounts[1], admin, new_admin);
    Ok(())
}
