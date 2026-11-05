entrypoint!(process);
fn process(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let user = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let vault = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;
    let mint = accounts.get(2).ok_or(ProgramError::NotEnoughAccountKeys)?;
    move_funds(user, vault)?;
    if mint.key != &MINT {
        sol_log("wrong mint )");
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(())
}
