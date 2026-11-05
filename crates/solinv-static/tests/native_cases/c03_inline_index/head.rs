entrypoint!(process);
fn set_admin(accounts: &[AccountInfo], new_admin: Pubkey) -> ProgramResult {
    write_admin(&accounts[1], &accounts[0], new_admin);
    Ok(())
}
