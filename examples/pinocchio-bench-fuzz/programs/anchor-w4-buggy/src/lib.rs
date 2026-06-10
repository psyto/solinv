//! anchor-w4-buggy — PLANTED-BUG variant of the public
//! `anchor-w4-matching` program from psyto/pinocchio-bench.
//!
//! Every Anchor protection and structural invariant the original
//! preserves has been deliberately broken in a different way here.
//! Four bugs, one per `_only` invariant variant the matching harness
//! exercises. The fuzzer is expected to surface each one independently
//! when its corresponding invariant_test feature is enabled.
//!
//! See examples/pinocchio-bench-fuzz/fuzz/matching-buggy/ for the
//! harness that exercises this program and verifies catches.

#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;

declare_id!("GtFb94asScD3ophzCbMwXuoH3rH2yjYVqkkShdHkf8Qt");

pub const N_TICKS: usize = 32;
pub const TICK_DEPTH: usize = 4;

#[program]
pub mod anchor_w4_buggy {
    use super::*;

    pub fn place_order(ctx: Context<PlaceOrder>, price: u64, qty: u64) -> Result<()> {
        let mut market = ctx.accounts.market.load_mut()?;
        let mut book = ctx.accounts.book.load_mut()?;
        let _signer_pk = ctx.accounts.signer.key().to_bytes();

        // ----- PLANTED BUG C (sequence-monotonic) -----
        // Original: `market.sequence = market.sequence.saturating_add(1);`
        // Flip-flops sequence between 0 and 1 across calls — the second
        // call writes a smaller value than it read (1 → 0), which is a
        // strict decrease and the Monotonic(NonDecreasing) state
        // invariant fires on it.
        let pre = market.sequence;
        if pre % 2 == 0 {
            market.sequence = pre + 1;
        } else {
            market.sequence = 0;
        }
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
            require!((tick.n_orders as usize) < TICK_DEPTH, BuggyErr::TickFull);
            let idx = tick.n_orders as usize;
            tick.orders[idx] = Order {
                // ----- PLANTED BUG D (owner-attribution) -----
                // Original: `owner_pk: signer_pk,`
                // Writing zeros instead of the signer pubkey: every
                // order looks anonymous on chain.
                owner_pk: [0u8; 32],
                qty,
                sequence: seq,
            };
            tick.n_orders += 1;
        } else {
            require!(count < N_TICKS, BuggyErr::BookFull);
            // ----- PLANTED BUG A (tick-sort) -----
            // Original: insert at `lo` (binary-search position) with a
            // right-shift of `ticks[lo..count]`. Buggy version ignores
            // `lo` and appends at `count`, breaking the array's sort
            // invariant the moment any input price is smaller than the
            // previous one. Shift loop intentionally a no-op (target
            // index equals `count`).
            let insert_at = count;
            let mut i = count;
            while i > insert_at {
                book.ticks[i] = book.ticks[i - 1];
                i -= 1;
            }
            let first = Order {
                // Bug D continues here on the new-tick path.
                owner_pk: [0u8; 32],
                qty,
                sequence: seq,
            };
            let zero = Order {
                owner_pk: [0u8; 32],
                qty: 0,
                sequence: 0,
            };
            book.ticks[insert_at] = Tick {
                price,
                // ----- PLANTED BUG B (count-consistency) -----
                // Original: `n_orders: 1,`
                // n_orders > TICK_DEPTH=4 violates the structural
                // invariant `n_orders <= TICK_DEPTH` on the new tick.
                n_orders: 5,
                _pad: 0,
                orders: [first, zero, zero, zero],
            };
            book.count = (count as u32) + 1;
        }
        Ok(())
    }
}

#[derive(Accounts)]
pub struct PlaceOrder<'info> {
    pub signer: Signer<'info>,
    #[account(mut)]
    pub market: AccountLoader<'info, Market>,
    #[account(mut)]
    pub book: AccountLoader<'info, Book>,
}

#[account(zero_copy)]
#[repr(C)]
pub struct Market {
    pub sequence: u64,
    pub side: u8,
    pub _pad: [u8; 7],
}

#[account(zero_copy)]
#[repr(C)]
pub struct Book {
    pub count: u32,
    pub _pad: u32,
    pub ticks: [Tick; N_TICKS],
}

#[zero_copy]
#[repr(C)]
pub struct Tick {
    pub price: u64,
    pub n_orders: u32,
    pub _pad: u32,
    pub orders: [Order; TICK_DEPTH],
}

#[zero_copy]
#[repr(C)]
pub struct Order {
    pub owner_pk: [u8; 32],
    pub qty: u64,
    pub sequence: u64,
}

#[error_code]
pub enum BuggyErr {
    #[msg("Tick full")]
    TickFull,
    #[msg("Book full")]
    BookFull,
}
