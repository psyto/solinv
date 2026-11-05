entrypoint!(process);
fn process(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let user = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let vault = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;
    let mint = accounts.get(2).ok_or(ProgramError::NotEnoughAccountKeys)?;
    if !user.is_signer {
        msg!("deposit: user must sign (got {})", user.key);
        return Err(ProgramError::MissingRequiredSignature);
    }
    if vault.owner == program_id {
        move_funds(user, vault)?;
    } else {
        solana_program::msg!("vault not ours");
        sol_log("rejecting");
        return Err(ProgramError::IncorrectProgramId);
    }
    if mint.key != &MINT {
        sol_log("wrong mint )");
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(())
}
