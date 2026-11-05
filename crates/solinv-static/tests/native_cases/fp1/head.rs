entrypoint!(process);
fn process(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let user = &accounts[0];
    if !user.is_signer() { return Err(ProgramError::MissingRequiredSignature); }
    match Ix::unpack(data)? {
        Ix::Deposit { amount } => {
            deposit(user, amount);
        }
        Ix::Withdraw { amount } => {
            withdraw(user, amount);
        }
    }
    Ok(())
}
