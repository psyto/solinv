//! Helpers for programs.
//!
//! ```ignore
//! entrypoint!(process_instruction);
//! ```
pub fn pda(seed: &[u8]) -> Pubkey { find(seed) }
