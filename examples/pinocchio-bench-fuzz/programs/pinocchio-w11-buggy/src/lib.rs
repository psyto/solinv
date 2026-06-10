//! pinocchio-w11-buggy — PLANTED-BUG variant of the public
//! `pinocchio-w11-oracle` publish program from psyto/pinocchio-bench.
//!
//! Two bugs targeting the Pinocchio-rewrite class.
//!
//! Bug ↔ invariant mapping:
//!   Bug A (`!publisher.is_signer()` check skipped)
//!     ↔ invariant_signer_skip_only  (solinv-core, rewrite-class)
//!   Bug B (`feed.last_slot = new_slot` skipped)
//!     ↔ invariant_last_slot_tracks_only  (inline structural)

#![no_std]

use pinocchio::{
    error::ProgramError, no_allocator, nostd_panic_handler, program_entrypoint, AccountView,
    Address, ProgramResult,
};

program_entrypoint!(process_instruction);
no_allocator!();
nostd_panic_handler!();

#[repr(C)]
pub struct PriceFeed {
    pub price: u64,
    pub conf: u64,
    pub ema_price: u64,
    pub last_slot: u64,
    pub publish_count: u64,
}

pub fn process_instruction(
    _program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    let [_publisher, price_feed_acc, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // ----- PLANTED BUG A (Pinocchio-rewrite-class: signer-skip) -----
    // Original: `if !_publisher.is_signer() { return Err(...); }`
    // Caught by solinv-core's signer_skip invariant.
    // (intentionally NOT writing back: `if !_publisher.is_signer() { ... }`)

    if instruction_data.len() < 24 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let new_price = u64::from_le_bytes(instruction_data[0..8].try_into().unwrap());
    let new_conf = u64::from_le_bytes(instruction_data[8..16].try_into().unwrap());
    let new_slot = u64::from_le_bytes(instruction_data[16..24].try_into().unwrap());

    let mut feed_data = price_feed_acc.try_borrow_mut()?;
    if feed_data.len() < core::mem::size_of::<PriceFeed>() {
        return Err(ProgramError::AccountDataTooSmall);
    }
    let feed = unsafe { &mut *(feed_data.as_mut_ptr() as *mut PriceFeed) };

    if new_slot <= feed.last_slot {
        return Err(ProgramError::InvalidArgument);
    }

    if feed.publish_count == 0 {
        feed.ema_price = new_price;
    } else {
        let ema_u128 = feed.ema_price as u128;
        let new_price_u128 = new_price as u128;
        let new_ema = ema_u128
            .saturating_mul(7)
            .saturating_add(new_price_u128)
            / 8;
        feed.ema_price = new_ema as u64;
    }

    feed.price = new_price;
    feed.conf = new_conf;
    // ----- PLANTED BUG B (last_slot tracking) -----
    // Original: `feed.last_slot = new_slot;`
    // Pinocchio mirror of the same bug in anchor-w11-buggy. The
    // `if new_slot <= feed.last_slot` guard above is what would
    // normally enforce monotonicity; with this bump skipped,
    // feed.last_slot stays at zero and every new_slot > 0 passes
    // the guard. But the per-call post-state check observes the
    // staleness directly.
    // (intentionally NOT writing back: `feed.last_slot = new_slot;`)
    feed.publish_count = feed.publish_count.saturating_add(1);

    Ok(())
}
