//! anchor-w8-buggy — PLANTED-BUG variant of the public
//! `anchor-w8-amm` constant-product swap program from psyto/pinocchio-bench.
//!
//! Two bugs, one per `_only` invariant variant the amm-buggy harness
//! exercises. Both bugs are permanent in source — no cargo gating in
//! the program itself.
//!
//! Bug ↔ invariant mapping:
//!   Bug A (amount_out doubled)            ↔ invariant_k_non_decreasing_only
//!   Bug B (reserve_in credited twice)     ↔ invariant_reserve_vault_consistent_only

#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

declare_id!("8mpVGKhPT933rJ4pjoVQTtS8z5oB2fFFe1Gn3FGBh45C");

#[program]
pub mod anchor_w8_buggy {
    use super::*;

    pub fn swap(ctx: Context<Swap>, amount_in: u64, _min_out: u64) -> Result<()> {
        let amount_out_u128 = {
            let mut pool = ctx.accounts.pool.load_mut()?;

            let fee_bps = pool.fee_bps as u128;
            let amount_in_u128 = amount_in as u128;
            let amount_in_after_fee = amount_in_u128
                .saturating_mul(10_000u128.saturating_sub(fee_bps))
                / 10_000u128;
            let reserve_in = pool.reserve_in as u128;
            let reserve_out = pool.reserve_out as u128;
            let denom = reserve_in.saturating_add(amount_in_after_fee);
            require!(denom > 0, AmmErr::ZeroDenominator);

            // ----- PLANTED BUG A (k non-decreasing) -----
            // Original: `let amount_out = reserve_out * amount_in_after_fee / denom;`
            // Doubling amount_out means the user receives twice the
            // protocol-correct token-out amount. The pool's reserve_out
            // drops by 2× the right delta while reserve_in grows by
            // amount_in (the CPI moves only amount_in into the vault),
            // so the constant-product `k = reserve_in × reserve_out`
            // strictly decreases on every successful swap.
            let amount_out = reserve_out
                .saturating_mul(amount_in_after_fee)
                .saturating_mul(2)
                / denom;

            require!(amount_out > 0, AmmErr::ZeroOutput);
            // Slippage check left intact so the harness can still drive
            // successful swaps; min_out is irrelevant when the fuzzer
            // passes 0.
            require!((amount_out as u64) >= _min_out, AmmErr::SlippageExceeded);

            // ----- PLANTED BUG B (reserve-vault consistency) -----
            // Original: `pool.reserve_in = (reserve_in + amount_in_u128) as u64;`
            // Inflates reserve_in by a constant +1 per swap while the
            // SPL Token CPI below only transfers `amount_in` into
            // pool_vault_in. delta(reserve_in) drifts from
            // delta(vault_in.amount) by 1 on every successful swap.
            // The +1 is deliberately small so the inflation can't mask
            // Bug A's k-drop on the same call.
            pool.reserve_in = (reserve_in + amount_in_u128 + 1) as u64;
            pool.reserve_out = (reserve_out - amount_out) as u64;

            amount_out
        };
        let amount_out = amount_out_u128 as u64;

        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                Transfer {
                    from: ctx.accounts.user_src.to_account_info(),
                    to: ctx.accounts.pool_vault_in.to_account_info(),
                    authority: ctx.accounts.authority.to_account_info(),
                },
            ),
            amount_in,
        )?;

        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                Transfer {
                    from: ctx.accounts.pool_vault_out.to_account_info(),
                    to: ctx.accounts.user_dst.to_account_info(),
                    authority: ctx.accounts.authority.to_account_info(),
                },
            ),
            amount_out,
        )?;

        Ok(())
    }
}

#[derive(Accounts)]
pub struct Swap<'info> {
    pub authority: Signer<'info>,
    #[account(mut)]
    pub pool: AccountLoader<'info, Pool>,
    #[account(mut)]
    pub user_src: Account<'info, TokenAccount>,
    #[account(mut)]
    pub user_dst: Account<'info, TokenAccount>,
    #[account(mut)]
    pub pool_vault_in: Account<'info, TokenAccount>,
    #[account(mut)]
    pub pool_vault_out: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[account(zero_copy)]
#[repr(C)]
pub struct Pool {
    pub reserve_in: u64,
    pub reserve_out: u64,
    pub fee_bps: u16,
    pub _pad: [u8; 6],
}

#[error_code]
pub enum AmmErr {
    #[msg("Slippage exceeded")]
    SlippageExceeded,
    #[msg("Zero output")]
    ZeroOutput,
    #[msg("Zero denominator")]
    ZeroDenominator,
}
