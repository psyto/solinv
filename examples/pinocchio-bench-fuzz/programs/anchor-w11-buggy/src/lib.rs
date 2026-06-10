//! anchor-w11-buggy — PLANTED-BUG variant of the public
//! `anchor-w11-oracle` publish program from psyto/pinocchio-bench.
//!
//! Two bugs, both permanent. Plants target independent fields so they
//! don't interact.
//!
//! Bug ↔ invariant mapping:
//!   Bug A (feed.last_slot = new_slot skipped)
//!     ↔ invariant_last_slot_tracks_only
//!   Bug B (feed.publish_count flip-flops 0 ↔ 1 across calls)
//!     ↔ invariant_publish_count_strictly_increases_only

#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;

declare_id!("4Db9tz2hu7hBWapD6xqSJnaysV1A5pJtDuTwYpHJ7v2Q");

#[program]
pub mod anchor_w11_buggy {
    use super::*;

    pub fn publish_price(
        ctx: Context<PublishPrice>,
        new_price: u64,
        new_conf: u64,
        new_slot: u64,
    ) -> Result<()> {
        let mut feed = ctx.accounts.price_feed.load_mut()?;

        require!(new_slot > feed.last_slot, OracleErr::StaleSlot);

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
        // ----- PLANTED BUG A (last_slot tracks new_slot) -----
        // Original: `feed.last_slot = new_slot;`
        // Skipping the bump leaves feed.last_slot at whatever it was
        // before. The require! above would normally guarantee monotonic
        // last_slot, but with the bump skipped every publish keeps the
        // old value. Caught by inline check_last_slot_tracks.
        // (intentionally NOT writing back: feed.last_slot = new_slot)

        // ----- PLANTED BUG B (publish_count strictly increases) -----
        // Original: `feed.publish_count = feed.publish_count.saturating_add(1);`
        // Flip-flops between 0 and 1 across calls. First call: 0 → 1
        // (looks normal). Second call: 1 → 0 (visible decrement,
        // breaks strictly-increases invariant).
        let pre_count = feed.publish_count;
        feed.publish_count = if pre_count % 2 == 0 { pre_count + 1 } else { 0 };

        Ok(())
    }
}

#[derive(Accounts)]
pub struct PublishPrice<'info> {
    pub publisher: Signer<'info>,
    #[account(mut)]
    pub price_feed: AccountLoader<'info, PriceFeed>,
}

#[account(zero_copy)]
#[repr(C)]
pub struct PriceFeed {
    pub price: u64,
    pub conf: u64,
    pub ema_price: u64,
    pub last_slot: u64,
    pub publish_count: u64,
}

#[error_code]
pub enum OracleErr {
    #[msg("New slot must be strictly greater than the last published slot")]
    StaleSlot,
}
