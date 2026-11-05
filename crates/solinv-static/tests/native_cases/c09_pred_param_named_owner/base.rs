entrypoint!(process);
fn is_owned_by(account: &AccountInfo, owner: &Pubkey) -> bool {
    account.owner == owner
}
fn deposit(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let [user, vault, ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    if !is_owned_by(vault, program_id) {
        return Err(ProgramError::IncorrectProgramId);
    }
    credit(vault, user);
    Ok(())
}
