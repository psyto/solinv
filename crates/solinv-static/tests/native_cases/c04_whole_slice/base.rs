entrypoint!(process);
fn set_admin(accounts: &[AccountInfo], new_admin: Pubkey) -> ProgramResult {
    let admin = &accounts[0];
    if !admin.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    apply(accounts, new_admin);
    Ok(())
}
