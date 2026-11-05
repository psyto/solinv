#[no_mangle]
pub unsafe extern "C" fn entrypoint(input: *mut u8) -> u64 {
    let (program_id, accounts, data) = deserialize(input);
    match process(&program_id, &accounts, &data) {
        Ok(()) => SUCCESS,
        Err(e) => e.into(),
    }
}
fn process(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let payer = &accounts[0];
    let Some(_) = payer.is_signer.then_some(()) else { return Err(ProgramError::MissingRequiredSignature) };
    Ok(())
}
