// escrow-clean with one change to `Withdraw`, the kind a refactor makes:
// the vault loosened from Account<Vault> to UncheckedAccount and its
// `has_one = depositor` deleted. Anchor would no longer check the vault's
// owner or type, nor that it belongs to the signer. Only `solinv diff`
// reads this file (the README quickstart); it is not built, and the
// handler would need adjusting before it would compile.

#![allow(unexpected_cfgs)]
//! Timelock escrow with no planted bugs — the mutation-testing target.
//!
//! `escrow` next door exists to be caught: every detector solinv ships
//! has a handler in it built to trip that detector. That makes it a good
//! acceptance test and an unusable mutation target. Mutation testing
//! asks "does the detector notice a bug I just introduced?", and the
//! question is only answerable if the program was clean beforehand. On
//! `escrow` it is not: a campaign there scored 17 of 17 mutants killed
//! while none of the mutations caused a single one of those violations —
//! cu-dos and unchecked-math were firing on the planted bugs, seven
//! thousand times per run, whatever the mutant did.
//!
//! So this is the same escrow with the timelock bug fixed and every
//! `unsafe_*` handler dropped. Four handlers, all of them meant to be
//! correct. Every invariant solinv can express should hold here before
//! mutation, and the campaign's job is to break them one at a time.
//!
//! Keep it that way. A planted bug added here does not make a richer
//! example, it silently voids every score the target produces.
use anchor_lang::prelude::program::invoke;
use anchor_lang::prelude::*;

declare_id!("Esrcc11111111111111111111111111111111111111");

#[program]
pub mod escrow_clean_program {
    use super::*;

    pub fn initialize(
        ctx: Context<Initialize>,
        beneficiary: Pubkey,
        unlock_slot: u64,
    ) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.depositor = ctx.accounts.depositor.key();
        vault.beneficiary = beneficiary;
        vault.unlock_slot = unlock_slot;
        vault.amount = 0;
        Ok(())
    }

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        require!(amount > 0, EscrowError::InvalidAmount);
        invoke(
            &system_instruction::transfer(
                &ctx.accounts.depositor.key(),
                &ctx.accounts.vault.key(),
                amount,
            ),
            &[
                ctx.accounts.depositor.to_account_info(),
                ctx.accounts.vault.to_account_info(),
                ctx.accounts.system_program.to_account_info(),
            ],
        )?;
        let vault = &mut ctx.accounts.vault;
        vault.amount = vault
            .amount
            .checked_add(amount)
            .ok_or(EscrowError::Overflow)?;
        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let clock = Clock::get()?;
        let vault = &mut ctx.accounts.vault;
        // Strictly before unlock. `escrow` has `<=` here, which lets the
        // depositor drain the vault on the unlock slot itself and race
        // the beneficiary's claim. Both sides of that race are legal at
        // `slot == unlock_slot` under `<=`, and `claim` requires
        // `slot >= unlock_slot`; the two windows must not overlap.
        require!(clock.slot < vault.unlock_slot, EscrowError::AlreadyUnlocked);
        require!(
            amount > 0 && amount <= vault.amount,
            EscrowError::InvalidAmount
        );

        **vault.to_account_info().try_borrow_mut_lamports()? -= amount;
        **ctx
            .accounts
            .depositor
            .to_account_info()
            .try_borrow_mut_lamports()? += amount;
        vault.amount = vault
            .amount
            .checked_sub(amount)
            .ok_or(EscrowError::Overflow)?;
        Ok(())
    }

    pub fn claim(ctx: Context<Claim>) -> Result<()> {
        let clock = Clock::get()?;
        let vault = &mut ctx.accounts.vault;
        require!(clock.slot >= vault.unlock_slot, EscrowError::StillLocked);
        let amount = vault.amount;
        require!(amount > 0, EscrowError::EmptyVault);

        **vault.to_account_info().try_borrow_mut_lamports()? -= amount;
        **ctx
            .accounts
            .beneficiary
            .to_account_info()
            .try_borrow_mut_lamports()? += amount;
        vault.amount = 0;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = depositor,
        space = 8 + Vault::INIT_SPACE,
        seeds = [b"vault", depositor.key().as_ref()],
        bump,
    )]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub depositor: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(
        mut,
        seeds = [b"vault", depositor.key().as_ref()],
        bump,
        has_one = depositor,
    )]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub depositor: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(
        mut,
        seeds = [b"vault", depositor.key().as_ref()],
        bump,
    )]
    pub vault: UncheckedAccount<'info>,
    #[account(mut)]
    pub depositor: Signer<'info>,
}

#[derive(Accounts)]
pub struct Claim<'info> {
    #[account(
        mut,
        seeds = [b"vault", depositor.key().as_ref()],
        bump,
        has_one = beneficiary,
    )]
    pub vault: Account<'info, Vault>,
    /// CHECK: only used as a PDA seed. The seeds constraint ties this to
    /// the unique vault.
    pub depositor: UncheckedAccount<'info>,
    #[account(mut)]
    pub beneficiary: Signer<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct Vault {
    pub depositor: Pubkey,
    pub beneficiary: Pubkey,
    pub unlock_slot: u64,
    pub amount: u64,
}

#[error_code]
pub enum EscrowError {
    InvalidAmount,
    Overflow,
    AlreadyUnlocked,
    StillLocked,
    EmptyVault,
}
