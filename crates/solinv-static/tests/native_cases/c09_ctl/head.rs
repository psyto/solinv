entrypoint!(process);
fn is_owned_by(account: &AccountInfo, id: &Pubkey) -> bool {
    account.owner == id
}
fn deposit(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let [user, vault, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    credit(vault, user);
    Ok(())
}
