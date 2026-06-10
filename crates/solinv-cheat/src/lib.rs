//! # solinv-cheat
//!
//! Cheatcode module. Foundry-API mirror for Solana:
//!
//! Foundry parity:
//! - `warp_slot(n)` / `warp_unix(ts)`
//! - `fund(pubkey, lamports)`
//! - `impersonate(pubkey)` (signer privilege injection)
//! - `set_account_data(pubkey, &[u8])`
//! - `expect_error(ProgramError)`
//! - `expect_log(pattern)` / `expect_cpi(program, ix)`
//! - `snapshot()` / `revert_to(id)`
//! - `mock_program_return(program, ix, data)`
//!
//! Solana-native extras (no EVM equivalent):
//! - `set_clock(slot, epoch, unix_ts)` — Clock sysvar override
//! - `set_rent_exempt(pubkey)` — Rent state override
//! - `upgrade_program(pubkey, &elf)` — program upgrade testing
//! - `advance_slot(n)` — slot progression
//! - `assert_signer(pubkey, ix_idx)` — auth assertion helper
//! - `assert_owned_by(pubkey, program)` — ownership assertion
