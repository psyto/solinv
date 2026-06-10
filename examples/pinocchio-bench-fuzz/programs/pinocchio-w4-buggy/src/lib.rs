//! pinocchio-w4-buggy — PLANTED-BUG variant of the public
//! `pinocchio-w4-matching` program from psyto/pinocchio-bench.
//!
//! Two bugs, both representative of the *Pinocchio-rewrite* class —
//! the bug shapes a customer would pay solinv-style fuzz to catch
//! after migrating an Anchor program to a Pinocchio rewrite. Both
//! are permanent in source; no cargo gating in the program itself.
//!
//! Bug ↔ invariant mapping:
//!   Bug A (`!signer.is_signer()` check skipped)
//!     ↔ invariant_signer_skip_only  (solinv-core, rewrite-class)
//!   Bug B (insert at `count` ignoring binary-search `lo`)
//!     ↔ invariant_tick_sort_only    (inline structural)

#![no_std]

use pinocchio::{
    error::ProgramError, no_allocator, nostd_panic_handler, program_entrypoint, AccountView,
    Address, ProgramResult,
};

program_entrypoint!(process_instruction);
no_allocator!();
nostd_panic_handler!();

pub const N_TICKS: usize = 32;
pub const TICK_DEPTH: usize = 4;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Order {
    pub owner_pk: [u8; 32],
    pub qty: u64,
    pub sequence: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Tick {
    pub price: u64,
    pub n_orders: u32,
    pub _pad: u32,
    pub orders: [Order; TICK_DEPTH],
}

#[repr(C)]
pub struct Market {
    pub sequence: u64,
    pub side: u8,
    pub _pad: [u8; 7],
}

#[repr(C)]
pub struct Book {
    pub count: u32,
    pub _pad: u32,
    pub ticks: [Tick; N_TICKS],
}

pub fn process_instruction(
    _program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    let [_signer, market_acc, book_acc, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // ----- PLANTED BUG A (Pinocchio-rewrite-class: signer-skip) -----
    // Original: `if !_signer.is_signer() { return Err(ProgramError::MissingRequiredSignature); }`
    // The Pinocchio rewriter who forgets this check loses every safety
    // property Anchor's `Signer<'info>` extractor provides for free.
    // This is THE modal Pinocchio-rewrite bug. Caught by solinv-core's
    // `signer_skip` invariant, which sends a duplicate of the ix with
    // is_signer cleared from the declared signer AccountMeta and
    // asserts the program rejects.
    // (intentionally NOT writing back: `if !_signer.is_signer() { ... }`)

    if instruction_data.len() < 16 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let price = u64::from_le_bytes(instruction_data[0..8].try_into().unwrap());
    let qty = u64::from_le_bytes(instruction_data[8..16].try_into().unwrap());

    let signer_pk = _signer.address().to_bytes();

    let mut market_data = market_acc.try_borrow_mut()?;
    if market_data.len() < core::mem::size_of::<Market>() {
        return Err(ProgramError::AccountDataTooSmall);
    }
    let market = unsafe { &mut *(market_data.as_mut_ptr() as *mut Market) };

    let mut book_data = book_acc.try_borrow_mut()?;
    if book_data.len() < core::mem::size_of::<Book>() {
        return Err(ProgramError::AccountDataTooSmall);
    }
    let book = unsafe { &mut *(book_data.as_mut_ptr() as *mut Book) };

    market.sequence = market.sequence.saturating_add(1);
    let seq = market.sequence;

    let count = book.count as usize;
    let mut lo = 0usize;
    let mut hi = count;
    while lo < hi {
        let mid = (lo + hi) / 2;
        if book.ticks[mid].price < price {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }

    if lo < count && book.ticks[lo].price == price {
        let tick = &mut book.ticks[lo];
        if (tick.n_orders as usize) >= TICK_DEPTH {
            return Err(ProgramError::InvalidArgument);
        }
        let idx = tick.n_orders as usize;
        tick.orders[idx] = Order {
            owner_pk: signer_pk,
            qty,
            sequence: seq,
        };
        tick.n_orders += 1;
    } else {
        if count >= N_TICKS {
            return Err(ProgramError::InvalidArgument);
        }
        // ----- PLANTED BUG B (tick-sort) -----
        // Original: shift `ticks[lo..count]` right then insert at `lo`.
        // Buggy variant always appends at `count`, ignoring the
        // binary-search position. The book stays internally consistent
        // on count + n_orders but loses its sort invariant the moment
        // any input price is smaller than the previously-inserted one.
        let insert_at = count;
        let first = Order { owner_pk: signer_pk, qty, sequence: seq };
        let zero = Order { owner_pk: [0u8; 32], qty: 0, sequence: 0 };
        book.ticks[insert_at] = Tick {
            price,
            n_orders: 1,
            _pad: 0,
            orders: [first, zero, zero, zero],
        };
        book.count = (count as u32) + 1;
    }
    Ok(())
}
