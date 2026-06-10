//! anchor-w9-buggy — PLANTED-BUG variant of the public
//! `anchor-w9-refresh` lending-refresh program from psyto/pinocchio-bench.
//!
//! Two bugs, both permanent. Each targets a distinct W9 invariant; the
//! plants don't interact because they touch independent fields.
//!
//! Bug ↔ invariant mapping:
//!   Bug A (reserve_a.last_update_slot skipped) ↔ invariant_reserve_slot_tracks_only
//!   Bug B (obligation.last_health forced to 0) ↔ invariant_health_positive_only

#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;

declare_id!("7UJrnvwb7Mnek8R1JrwKciVZhywDnEHEX46mwoaBy8MK");

#[program]
pub mod anchor_w9_buggy {
    use super::*;

    pub fn refresh(ctx: Context<Refresh>, current_slot: u64) -> Result<()> {
        let mut obligation = ctx.accounts.obligation.load_mut()?;
        let mut reserve_a = ctx.accounts.reserve_a.load_mut()?;
        let mut reserve_b = ctx.accounts.reserve_b.load_mut()?;
        let mut oracle_a = ctx.accounts.oracle_a.load_mut()?;
        let mut oracle_b = ctx.accounts.oracle_b.load_mut()?;

        let delta_a = current_slot.saturating_sub(reserve_a.last_update_slot);
        reserve_a.cumulative_borrow_rate = reserve_a
            .cumulative_borrow_rate
            .saturating_add(delta_a.saturating_mul(reserve_a.borrow_rate_bps as u64));
        // ----- PLANTED BUG A (reserve slot tracking) -----
        // Original: `reserve_a.last_update_slot = current_slot;`
        // Skipping the update leaves reserve_a's slot stale forever.
        // Real refresh callers (liquidation engines, oracle clients) use
        // last_update_slot as freshness telemetry — a stale slot tells
        // them this reserve hasn't been touched. Caught by inline
        // check_reserve_a_slot_tracks.

        let delta_b = current_slot.saturating_sub(reserve_b.last_update_slot);
        reserve_b.cumulative_borrow_rate = reserve_b
            .cumulative_borrow_rate
            .saturating_add(delta_b.saturating_mul(reserve_b.borrow_rate_bps as u64));
        reserve_b.last_update_slot = current_slot;

        oracle_a.last_update_slot = current_slot;
        oracle_b.last_update_slot = current_slot;

        let _collateral_value =
            (obligation.deposit_amount as u128).saturating_mul(oracle_a.price as u128);
        let _debt_value = (obligation.borrow_amount as u128)
            .saturating_mul(oracle_b.price as u128)
            .max(1);
        // ----- PLANTED BUG B (health positive) -----
        // Original: `obligation.last_health = (collateral_value * 10_000 / debt_value) as u64;`
        // Forcing last_health to 0 makes every position look insolvent
        // regardless of actual collateralization. Caught by inline
        // check_health_positive_when_collateral_positive.
        obligation.last_health = 0;
        obligation.last_update_slot = current_slot;

        Ok(())
    }
}

#[derive(Accounts)]
pub struct Refresh<'info> {
    pub signer: Signer<'info>,
    #[account(mut)]
    pub obligation: AccountLoader<'info, Obligation>,
    #[account(mut)]
    pub reserve_a: AccountLoader<'info, Reserve>,
    #[account(mut)]
    pub reserve_b: AccountLoader<'info, Reserve>,
    #[account(mut)]
    pub oracle_a: AccountLoader<'info, Oracle>,
    #[account(mut)]
    pub oracle_b: AccountLoader<'info, Oracle>,
}

#[account(zero_copy)]
#[repr(C)]
pub struct Obligation {
    pub deposit_amount: u64,
    pub borrow_amount: u64,
    pub last_health: u64,
    pub last_update_slot: u64,
}

#[account(zero_copy)]
#[repr(C)]
pub struct Reserve {
    pub total_liquidity: u64,
    pub total_borrows: u64,
    pub cumulative_borrow_rate: u64,
    pub borrow_rate_bps: u32,
    pub _pad: u32,
    pub last_update_slot: u64,
}

#[account(zero_copy)]
#[repr(C)]
pub struct Oracle {
    pub price: u64,
    pub conf: u64,
    pub last_update_slot: u64,
}
