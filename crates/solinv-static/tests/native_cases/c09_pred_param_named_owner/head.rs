entrypoint!(process);
fn is_owned_by(account: &AccountInfo, owner: &Pubkey) -> bool {
    account.owner == owner
}
fn deposit(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let [user, vault, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    credit(vault, user);
    Ok(())
}
