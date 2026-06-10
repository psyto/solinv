#![allow(unexpected_cfgs)]
use anchor_lang::prelude::*;
use anchor_lang::prelude::program::invoke;

declare_id!("Esrcw11111111111111111111111111111111111111");

#[program]
pub mod escrow_program {
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
        // BUG: should be `<` (strictly before unlock). Using `<=` lets the depositor
        // drain the vault at the exact unlock slot, racing the beneficiary's claim.
        require!(
            clock.slot <= vault.unlock_slot,
            EscrowError::AlreadyUnlocked
        );
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
        vault.amount -= amount;
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

    // ----- PLANTED BUG for solinv Day 13 owner-skip unmask -----
    //
    // `unsafe_set_amount_from_source` reads bytes from an UncheckedAccount
    // `source` (no owner check) and writes the value into `target`'s
    // amount field. The attack pattern: attacker passes a fake `source`
    // with crafted bytes → program reads attacker-controlled value →
    // writes it to the legitimate `target` vault.
    //
    // CRITICAL: no lamport debit on `source`, only on `target` (which is
    // a real Account<Vault> owned by escrow program). This avoids the
    // Solana runtime's intrinsic debit-block protection that prevented
    // owner-skip detection on `unsafe_withdraw` (Days 10-12).
    pub fn unsafe_set_amount_from_source(
        ctx: Context<UnsafeSetAmountFromSource>,
    ) -> Result<()> {
        let source_data = ctx.accounts.source.data.borrow();
        if source_data.len() < 48 {
            return err!(EscrowError::InvalidAmount);
        }
        let synthetic_amount = u64::from_le_bytes(
            source_data[40..48].try_into().unwrap(),
        );
        ctx.accounts.target.amount = synthetic_amount;
        Ok(())
    }

    // ----- PLANTED BUG for solinv Day 37 cu-dos validation -----
    //
    // `unsafe_compute_dos` does an O(n) loop over an attacker-controlled
    // u32 `iterations` argument. Loop body is pure wrapping arithmetic
    // so it can't fault out under overflow-checks = true (escrow's
    // setting) and short-circuit detection. `msg!` lives OUTSIDE the
    // loop — one log per ix — so per-iter cost stays in the arithmetic
    // band (~5 CU/iter), not the logging band (>100 CU/iter, which
    // would consume the full 200K budget too quickly to leave detection
    // headroom).
    //
    // Real-world analogue: any "process all entries" ix without a
    // static MAX bound — order-cancel loops, position-iteration,
    // governance vote tallies, NFT batch claims.
    //
    // solinv detection: cu_budget = Some(5_000) on the InstructionSpec
    // (data_sample iterations = 5_000 → roughly 25-50K CU consumed,
    // well above cap, well below 200K runtime ceiling).
    //
    // NOT FOR PRODUCTION. Only for solinv self-validation.
    pub fn unsafe_compute_dos(
        _ctx: Context<UnsafeComputeDos>,
        iterations: u32,
    ) -> Result<()> {
        let mut acc: u64 = 0;
        for i in 0..iterations {
            acc = acc.wrapping_add(i as u64).wrapping_mul(3);
        }
        msg!("acc={}", acc);
        Ok(())
    }

    // ----- PLANTED BUG for solinv Day 33 unchecked-math validation -----
    //
    // `unsafe_accumulate_yield` is the canonical unchecked-math fixture:
    // pretends to compound interest on the vault but uses wrapping
    // arithmetic on u64 so `vault.amount` overflows when (amount * rate_bps)
    // exceeds 2^64. Real-world analogue: any Solana program that does
    // `amount = amount + yield(amount, rate)` without `checked_mul +
    // checked_add` or explicit `rate_bps < MAX_BPS` bound.
    //
    // Uses `wrapping_mul` / `wrapping_add` explicitly so the bug fires
    // regardless of the program's `overflow-checks` profile setting
    // (escrow currently has `overflow-checks = true` for safety on the
    // non-planted handlers; `*` / `+` would panic there instead of
    // wrapping silently).
    //
    // solinv detection: Bounded { 0, 10_000_000_000_000 } on vault.amount
    // post-ix. Wrap with rate_bps = u64::MAX trivially exceeds the cap
    // for any pre.amount >= 1.
    //
    // NOT FOR PRODUCTION. Only for solinv self-validation.
    pub fn unsafe_accumulate_yield(
        ctx: Context<UnsafeAccumulateYield>,
        rate_bps: u64,
    ) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        let yield_amount = vault.amount.wrapping_mul(rate_bps) / 10_000;
        vault.amount = vault.amount.wrapping_add(yield_amount);
        Ok(())
    }

    // ----- PLANTED BUG for solinv Day 60 bump-seed-canonicalization -----
    //
    // `unsafe_withdraw_with_bump` accepts `bump: u8` from ix data and
    // uses `Pubkey::create_program_address(seeds + [bump])` to "verify"
    // the vault PDA. The program does NOT check that `bump` matches
    // the canonical bump produced by `Pubkey::find_program_address`.
    // An attacker who supplies an alt PDA + alt bump bypasses the check.
    //
    // Real-world analogue: any program with
    //   `#[account(seeds = [...], bump = arg)]`
    // pre-Anchor-0.29 (before `seeds::canonical_bumps_only` became
    // the default). Solana docs warned about this since 2022.
    //
    // solinv detection: spec carries
    //   `bump_seed_check: Some(BumpSeedCheckConfig {
    //       bump_data_offset: Some(16) })`
    // — detector finds alt bump for [b"vault", depositor], pre-creates
    // alt PDA with cloned canonical state, patches ix data byte 16
    // (after sighash[8] + amount[8]) to alt bump, sends. If success
    // (no canonical-bump check) → violation fires.
    //
    // NOT FOR PRODUCTION. Only for solinv self-validation.
    pub fn unsafe_withdraw_with_bump(
        ctx: Context<UnsafeWithdrawWithBump>,
        amount: u64,
        bump: u8,
    ) -> Result<()> {
        let derived = Pubkey::create_program_address(
            &[
                b"vault",
                ctx.accounts.depositor.key().as_ref(),
                &[bump],
            ],
            ctx.program_id,
        )
        .map_err(|_| EscrowError::InvalidAmount)?;
        require_keys_eq!(
            derived,
            ctx.accounts.vault.key(),
            EscrowError::InvalidAmount
        );
        let vault_lamports = **ctx.accounts.vault.try_borrow_lamports()?;
        if amount == 0 || amount > vault_lamports {
            return err!(EscrowError::InvalidAmount);
        }
        **ctx.accounts.vault.try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.depositor.try_borrow_mut_lamports()? += amount;
        Ok(())
    }

    // ----- PLANTED BUG for solinv Day 59 realloc-race validation -----
    //
    // `unsafe_realloc_grow` grows the vault account's data buffer by
    // an attacker-controllable `delta` bytes WITHOUT depositing
    // additional lamports to keep the rent-exempt invariant satisfied.
    // Real-world analogue: NFT marketplace order-list grow, position-
    // add in lending/perps, any handler that uses raw `info.realloc()`
    // instead of Anchor's `#[account(realloc, realloc::payer)]`
    // constraint pair.
    //
    // `delta` is capped to MAX_PERMITTED_DATA_INCREASE (10_240 bytes)
    // so the runtime doesn't reject the realloc itself — we want the
    // rent invariant break to surface, not a runtime increase-cap
    // error. The detector then observes post-ix that
    //   post.data.len() > pre.data.len()
    //   AND post.lamports < rent_for(post.data.len())
    // and fires.
    //
    // NOT FOR PRODUCTION. Only for solinv self-validation.
    pub fn unsafe_realloc_grow(
        ctx: Context<UnsafeReallocGrow>,
        delta: u32,
    ) -> Result<()> {
        let info = ctx.accounts.vault.to_account_info();
        let pre_len = info.data_len();
        let raw_new_len = pre_len.saturating_add(delta as usize);
        // Cap at pre_len + 10_240 to stay within the per-ix data-
        // increase ceiling Solana enforces. Without this cap, large
        // fuzz-derived `delta` values would runtime-error before the
        // rent-invariant violation could land.
        let new_len = raw_new_len.min(pre_len + 10_240);
        // Solana 3.x: `realloc(new_len, zero_init)` was renamed to
        // `resize(new_len)` (always zero-init). Same semantics for
        // the grow path. The bug is the missing lamport top-up,
        // unchanged from the realloc-era API.
        info.resize(new_len)?;
        // INTENTIONAL BUG: no system_program::transfer to top up
        // lamports. Account is now rent-deficient at the new size.
        Ok(())
    }

    // ----- PLANTED BUG for solinv Day 58 cpi-reentrancy validation -----
    //
    // `unsafe_self_reentry` is the canonical self-CPI re-entry fixture:
    // the outer handler reads `vault.amount`, then CPIs back into the
    // same escrow program (via `invoke` with `crate::ID` as the target)
    // to call `unsafe_inner_mutate`, which overwrites `vault.amount`.
    // The Solana runtime logs both frames at distinct CPI depths:
    //   Program <ESCROW> invoke [1]     ← outer (unsafe_self_reentry)
    //   Program <ESCROW> invoke [2]     ← inner (unsafe_inner_mutate)
    //   Program <ESCROW> success
    //   Program <ESCROW> success
    // solinv's cpi_reentrancy detector parses these logs, builds the
    // active CPI stack, and fires when the escrow program ID appears
    // at two depths simultaneously. Real-world analogue: Token-2022
    // transfer hooks, governance vote delegation, Mango v3 insurance
    // fund re-entry ($114M, 2022). See docs/invariants/cpi-reentrancy.md.
    //
    // The bug shape is the cycle itself — even though here the inner
    // mutation is "intentional" within the planted fixture, real
    // re-entry bugs arise when the outer handler reads state before
    // CPI and operates on stale state after; the detector's job is
    // to surface the cycle so a human triages the state-coherence
    // implication.
    //
    // NOT FOR PRODUCTION. Only for solinv self-validation.
    pub fn unsafe_self_reentry(ctx: Context<UnsafeSelfReentry>) -> Result<()> {
        // Pre-CPI state read (the value the outer handler would
        // "trust" if there were a post-CPI invariant assertion).
        let _pre_amount = ctx.accounts.vault.amount;

        // Inner ix sighash = sha256("global:unsafe_inner_mutate")[..8]
        // Hardcoded as a constant byte array — no runtime hash dep
        // pulled into the SBF build for the planted handler.
        const UNSAFE_INNER_MUTATE_SIGHASH: [u8; 8] =
            [158, 203, 192, 149, 204, 238, 59, 124];
        let mut data: Vec<u8> = UNSAFE_INNER_MUTATE_SIGHASH.to_vec();
        data.extend_from_slice(&12_345u64.to_le_bytes());

        let inner_ix = anchor_lang::solana_program::instruction::Instruction {
            program_id: crate::ID,
            accounts: vec![
                anchor_lang::solana_program::instruction::AccountMeta::new(
                    ctx.accounts.vault.key(),
                    false,
                ),
                anchor_lang::solana_program::instruction::AccountMeta::new_readonly(
                    ctx.accounts.depositor.key(),
                    true,
                ),
            ],
            data,
        };

        invoke(
            &inner_ix,
            &[
                ctx.accounts.vault.to_account_info(),
                ctx.accounts.depositor.to_account_info(),
                ctx.accounts.escrow_program.to_account_info(),
            ],
        )?;

        Ok(())
    }

    /// Inner handler — re-entered via the helper CPI. Just overwrites
    /// `vault.amount` to a fixed value (the post-CPI state divergence
    /// the outer handler would not anticipate in a real bug).
    pub fn unsafe_inner_mutate(
        ctx: Context<UnsafeInnerMutate>,
        new_value: u64,
    ) -> Result<()> {
        ctx.accounts.vault.amount = new_value;
        Ok(())
    }

    // ----- PLANTED BUGS for solinv Day 10 acceptance test -----
    //
    // `unsafe_withdraw` is a deliberately vulnerable version of `withdraw`
    // with all 5 Critical bug classes present:
    //   1. signer-skip:        depositor is UncheckedAccount, not Signer
    //   2. owner-skip:         vault is UncheckedAccount, no Anchor owner check
    //   3. discriminator-skip: vault is UncheckedAccount, no disc check
    //   4. pda-forge:          no `seeds = [...]` constraint on vault
    //   5. account-swap:       no `has_one = depositor` constraint
    //
    // solinv invariants (signer_skip, owner_skip, discriminator_skip,
    // pda_forge, account_swap) should each detect their respective bug
    // when this ix is included in InstructionSpec metadata.
    //
    // NOT FOR PRODUCTION. Only for solinv self-validation.
    pub fn unsafe_withdraw(ctx: Context<UnsafeWithdraw>, amount: u64) -> Result<()> {
        let vault_lamports = **ctx.accounts.vault.try_borrow_lamports()?;
        if amount == 0 || amount > vault_lamports {
            return err!(EscrowError::InvalidAmount);
        }
        **ctx.accounts.vault.try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.depositor.try_borrow_mut_lamports()? += amount;
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
        has_one = depositor,
    )]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub depositor: Signer<'info>,
}

// PLANTED-BUG context for cu-dos detection (Day 37). Minimal: just a
// Signer so the ix is permissioned (any authority can call). No state
// touched — the bug is purely the O(n) loop, not account validation.
#[derive(Accounts)]
pub struct UnsafeComputeDos<'info> {
    pub authority: Signer<'info>,
}

// PLANTED-BUG context for unchecked-math detection (Day 33).
// Standard Anchor account context — uses `has_one = depositor` and seeds
// constraint, no other holes. The bug is in the handler body's arithmetic,
// not the account validation. Lets solinv detect via Bounded post-state.
#[derive(Accounts)]
pub struct UnsafeAccumulateYield<'info> {
    #[account(
        mut,
        seeds = [b"vault", depositor.key().as_ref()],
        bump,
        has_one = depositor,
    )]
    pub vault: Account<'info, Vault>,
    pub depositor: Signer<'info>,
}

// PLANTED-BUG context for owner-skip detection (Day 13).
// `source` is UncheckedAccount = no owner check; `target` is real Vault
// (owned by program, so writes succeed). Attack pattern requires only
// READ from source (no debit), avoiding Solana runtime's wrong-owner
// debit-block protection.
#[derive(Accounts)]
pub struct UnsafeSetAmountFromSource<'info> {
    /// CHECK: BUG — source should be Account<Vault> with owner check
    pub source: UncheckedAccount<'info>,
    #[account(mut)]
    pub target: Account<'info, Vault>,
}

// PLANTED-BUG context for bump-seed-canonicalization detection (Day 60).
// Both vault and depositor are UncheckedAccount so the handler can be
// called with any pubkey at either slot (the bug is the missing
// canonical-bump check on the vault PDA, not signer enforcement).
#[derive(Accounts)]
pub struct UnsafeWithdrawWithBump<'info> {
    /// CHECK: BUG — vault validated via user-supplied bump in handler body
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
    /// CHECK: BUG — depositor used only as PDA seed; signature not enforced
    #[account(mut)]
    pub depositor: UncheckedAccount<'info>,
}

// PLANTED-BUG context for realloc-race detection (Day 59).
// Standard Anchor vault context — uses `has_one = depositor` and the
// seeds constraint; no other holes. The bug is in the handler body's
// raw `info.realloc()` without the matching lamport top-up, not in
// account validation. Lets solinv detect via the pre/post-ix data-
// length + lamports state comparison.
#[derive(Accounts)]
pub struct UnsafeReallocGrow<'info> {
    #[account(
        mut,
        seeds = [b"vault", depositor.key().as_ref()],
        bump,
        has_one = depositor,
    )]
    pub vault: Account<'info, Vault>,
    pub depositor: Signer<'info>,
}

// PLANTED-BUG contexts for cpi-reentrancy detection (Day 58).
// Both outer (UnsafeSelfReentry) and inner (UnsafeInnerMutate) share
// the same vault + depositor accounts so the inner CPI can mutate
// the exact state the outer handler read pre-CPI. The outer adds
// `escrow_program` (an AccountInfo to the escrow program itself) so
// `invoke` has the program info for the self-CPI target.
#[derive(Accounts)]
pub struct UnsafeSelfReentry<'info> {
    #[account(
        mut,
        seeds = [b"vault", depositor.key().as_ref()],
        bump,
        has_one = depositor,
    )]
    pub vault: Account<'info, Vault>,
    pub depositor: Signer<'info>,
    /// CHECK: AccountInfo for the escrow program itself, used as the
    /// CPI target for the self-invocation. Address must match crate::ID;
    /// if it doesn't, the inner invoke fails at runtime.
    pub escrow_program: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct UnsafeInnerMutate<'info> {
    #[account(
        mut,
        seeds = [b"vault", depositor.key().as_ref()],
        bump,
        has_one = depositor,
    )]
    pub vault: Account<'info, Vault>,
    pub depositor: Signer<'info>,
}

// PLANTED-BUG context: every Anchor protection deliberately removed.
#[derive(Accounts)]
pub struct UnsafeWithdraw<'info> {
    /// CHECK: BUG — vault should be Account<Vault> with seeds + has_one
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
    /// CHECK: BUG — depositor should be Signer
    #[account(mut)]
    pub depositor: UncheckedAccount<'info>,
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
    /// CHECK: only used as a PDA seed. The seeds constraint ties this to the unique vault.
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
