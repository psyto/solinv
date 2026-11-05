entrypoint!(process);
fn process(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    match Ix::unpack(data)? {
        Ix::Deposit { amount } => {
            let user = &accounts[0];
            if !user.is_signer() { return Err(ProgramError::MissingRequiredSignature); }
            deposit(user, amount);
        }
        Ix::Withdraw { amount } => process_withdraw(accounts, amount)?,
    }
    Ok(())
}
fn process_withdraw(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let user = &accounts[0];
    withdraw(user, amount);
    Ok(())
}
