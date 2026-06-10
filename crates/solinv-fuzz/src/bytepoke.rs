//! # bytepoke — Anchor account pre-construction helpers
//!
//! Reusable primitives for the byte-poke pattern that unblocks Anchor
//! 0.x post-init reachability under LiteSVM 0.9.1 (per
//! `docs/phase5-day56-gateA-result.md`). The pattern:
//!
//! 1. Hand-construct a byte buffer matching an Anchor account's
//!    `#[repr(C)]` layout (8-byte discriminator + body).
//! 2. Pre-write that buffer via `TestContext::write_account`, skipping
//!    the program's init ix.
//! 3. Fuzz the post-init attack surface (swap/deposit/withdraw/etc).
//!
//! Before this module, every harness using the pattern (klend Day
//! 23-24, sanctum-unstake Day 56) duplicated the discriminator/sighash
//! computation + the rent helper + the byte-offset writers. This
//! module collects them so a harness implements only the
//! target-specific mirror struct + field assignments.
//!
//! ## Quick example
//!
//! ```ignore
//! use solinv_fuzz::bytepoke::{anchor_account_disc, AnchorAccountBuilder, write_u64_at, write_pubkey_at};
//!
//! // Build a 4664-byte LendingMarket buffer (8 disc + 4656 body)
//! let mut body = vec![0u8; 4656];
//! write_u64_at(&mut body, 0, 1);                 // version
//! write_u64_at(&mut body, 8, bump as u64);       // bump_seed
//! write_pubkey_at(&mut body, 16, &owner);        // lending_market_owner
//!
//! let account = AnchorAccountBuilder::new("LendingMarket", body)
//!     .owned_by(program_id)
//!     .build();
//! ctx.write_account(&lending_market_key, account)?;
//! ```
//!
//! ## When NOT to use bytepoke
//!
//! - The target is **Native** (no Anchor discriminator) — write raw bytes
//!   directly.
//! - The target is **Anchor 1.0+** — Anchor's own init ix works under
//!   LiteSVM 0.9.1; only the 0.x init→CPI path is broken (H1).
//! - The harness wants **end-to-end coverage from setup-to-attack** —
//!   byte-poke skips the program's own init path, so init-side bugs
//!   (wrong discriminator, missing seeds, signer-skip in init) won't
//!   surface. Use byte-poke when init is *unreachable*, not when init
//!   is *uninteresting*.

use sha2::{Digest, Sha256};
use solana_account::Account as SolAccount;
use solana_pubkey::Pubkey;

// ============================================================================
// Anchor wire-format helpers
// ============================================================================

/// Anchor account discriminator: `sha256("account:{type_name}")[..8]`.
///
/// Used as the 8-byte prefix of every Anchor account when pre-creating
/// accounts via `TestContext::write_account`. Format identical from
/// anchor-lang 0.27 through 1.0.x.
pub fn anchor_account_disc(type_name: &str) -> [u8; 8] {
    let mut hasher = Sha256::new();
    hasher.update(b"account:");
    hasher.update(type_name.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

/// Anchor instruction sighash: `sha256("global:{ix_name}")[..8]`.
///
/// The 8-byte prefix every Anchor ix data buffer starts with. Format
/// identical from anchor-lang 0.27 through 1.0.x — this is the
/// foundation of the Day 15 raw_call pattern.
pub fn anchor_ix_sighash(ix_name: &str) -> [u8; 8] {
    let mut hasher = Sha256::new();
    hasher.update(b"global:");
    hasher.update(ix_name.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

// ============================================================================
// Rent helpers
// ============================================================================

/// Rent-exempt lamports for an account holding `bytes` of data
/// (NOT including the Anchor discriminator — pass the full byte
/// count of what the SVM will store).
///
/// Matches `solana_rent::Rent::default().minimum_balance(bytes)`
/// without pulling in the solana_rent dep, since harnesses
/// typically only need it for write_account sizing.
pub const fn rent_for_raw(bytes: usize) -> u64 {
    (128 + bytes) as u64 * 3480 * 2
}

/// Rent-exempt lamports for an Anchor account whose body (excluding the
/// 8-byte discriminator) is `body_size` bytes. Always pair with a
/// builder/buffer whose total length is `8 + body_size`.
pub const fn rent_for_anchor_body(body_size: usize) -> u64 {
    rent_for_raw(8 + body_size)
}

// ============================================================================
// Byte-offset writers
// ============================================================================

/// Write `val` as a single byte at `offset`.
pub fn write_u8_at(buf: &mut [u8], offset: usize, val: u8) {
    buf[offset] = val;
}

/// Write `val` as 2 little-endian bytes at `offset`.
pub fn write_u16_at(buf: &mut [u8], offset: usize, val: u16) {
    buf[offset..offset + 2].copy_from_slice(&val.to_le_bytes());
}

/// Write `val` as 4 little-endian bytes at `offset`.
pub fn write_u32_at(buf: &mut [u8], offset: usize, val: u32) {
    buf[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
}

/// Write `val` as 8 little-endian bytes at `offset`.
pub fn write_u64_at(buf: &mut [u8], offset: usize, val: u64) {
    buf[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
}

/// Write `val` as 16 little-endian bytes at `offset`.
pub fn write_u128_at(buf: &mut [u8], offset: usize, val: u128) {
    buf[offset..offset + 16].copy_from_slice(&val.to_le_bytes());
}

/// Write `val` as 8 little-endian bytes (two's-complement) at `offset`.
pub fn write_i64_at(buf: &mut [u8], offset: usize, val: i64) {
    buf[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
}

/// Write the 32-byte representation of `pk` at `offset`.
pub fn write_pubkey_at(buf: &mut [u8], offset: usize, pk: &Pubkey) {
    buf[offset..offset + 32].copy_from_slice(&pk.to_bytes());
}

/// Write the raw bytes of `src` at `offset`. Caller is responsible for
/// length safety (panics if `offset + src.len() > buf.len()`).
pub fn write_bytes_at(buf: &mut [u8], offset: usize, src: &[u8]) {
    buf[offset..offset + src.len()].copy_from_slice(src);
}

// ============================================================================
// Account builder
// ============================================================================

/// Anchor account builder — combines a type-name (→ discriminator), a
/// body buffer, an owner, and lamports into a `SolAccount` ready for
/// `TestContext::write_account`.
///
/// The body buffer should be `body_size` bytes; the builder prepends
/// the 8-byte discriminator for you. Lamports default to the rent
/// minimum for `8 + body_size` bytes; override via `.lamports(...)`.
///
/// ```ignore
/// let pool_body = build_pool_body(...);  // 1024 bytes
/// let account = AnchorAccountBuilder::new("Pool", pool_body)
///     .owned_by(program_id)
///     .build();
/// ctx.write_account(&pool_key, account)?;
/// ```
pub struct AnchorAccountBuilder {
    type_name: String,
    body: Vec<u8>,
    owner: Pubkey,
    lamports: Option<u64>,
    executable: bool,
}

impl AnchorAccountBuilder {
    /// Start a builder for an Anchor account of the given type name and
    /// body buffer (excludes the 8-byte discriminator — the builder
    /// prepends it). Owner defaults to `Pubkey::default()`; chain
    /// `.owned_by(program_id)` for a program-owned account.
    pub fn new(type_name: impl Into<String>, body: Vec<u8>) -> Self {
        Self {
            type_name: type_name.into(),
            body,
            owner: Pubkey::default(),
            lamports: None,
            executable: false,
        }
    }

    /// Set the account owner. For Anchor program-owned accounts, pass
    /// the program ID.
    pub fn owned_by(mut self, owner: Pubkey) -> Self {
        self.owner = owner;
        self
    }

    /// Override the computed rent-exempt lamports. Default is
    /// `rent_for_anchor_body(body.len())`.
    pub fn lamports(mut self, l: u64) -> Self {
        self.lamports = Some(l);
        self
    }

    /// Mark the account executable. Default `false`; rarely needed for
    /// data accounts.
    pub fn executable(mut self, e: bool) -> Self {
        self.executable = e;
        self
    }

    /// Construct the final `SolAccount`. The returned data is
    /// `8 + body.len()` bytes (8-byte Anchor discriminator + body).
    pub fn build(self) -> SolAccount {
        let mut data = Vec::with_capacity(8 + self.body.len());
        data.extend_from_slice(&anchor_account_disc(&self.type_name));
        data.extend_from_slice(&self.body);
        let lamports = self.lamports.unwrap_or_else(|| rent_for_anchor_body(self.body.len()));
        SolAccount {
            lamports,
            data,
            owner: self.owner,
            executable: self.executable,
            rent_epoch: 0,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Known-good vectors verified against anchor-lang's own
    // `Discriminator` / `InstructionData` impls on anchor 1.0.1 +
    // klend's Day 23 implementation (which uses the same formula).

    #[test]
    fn account_disc_known_lending_market() {
        // sha256("account:LendingMarket")[..8] — verified against
        // klend Day 23 build_lending_market_bytes output.
        let d = anchor_account_disc("LendingMarket");
        assert_eq!(d, [246, 114, 50, 98, 72, 157, 28, 120]);
    }

    #[test]
    fn account_disc_known_pool() {
        // sha256("account:Pool")[..8] — sanctum Day 56 reference.
        let d = anchor_account_disc("Pool");
        assert_eq!(d, [241, 154, 109, 4, 17, 177, 109, 188]);
    }

    #[test]
    fn ix_sighash_known_initialize() {
        // sha256("global:initialize")[..8] — Anchor canonical example.
        let d = anchor_ix_sighash("initialize");
        assert_eq!(d, [175, 175, 109, 31, 13, 152, 155, 237]);
    }

    #[test]
    fn ix_sighash_known_swap() {
        // sha256("global:swap")[..8] — appears in many AMM IDLs.
        let d = anchor_ix_sighash("swap");
        assert_eq!(d, [248, 198, 158, 145, 225, 117, 135, 200]);
    }

    #[test]
    fn rent_for_raw_no_overflow_at_typical_sizes() {
        // Typical Anchor account sizes: 8 disc + (small body 100, mid 4664, big 10000+).
        assert_eq!(rent_for_raw(100), (128 + 100) * 3480 * 2);
        assert_eq!(rent_for_raw(10_000), (128 + 10_000) * 3480 * 2);
    }

    #[test]
    fn rent_for_anchor_body_adds_discriminator() {
        assert_eq!(rent_for_anchor_body(100), rent_for_raw(108));
        assert_eq!(rent_for_anchor_body(0), rent_for_raw(8));
    }

    #[test]
    fn write_u64_at_writes_little_endian() {
        let mut buf = vec![0u8; 16];
        write_u64_at(&mut buf, 4, 0x0102030405060708);
        // Little-endian: least significant byte first.
        assert_eq!(&buf[4..12], &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn write_pubkey_at_writes_32_bytes() {
        let mut buf = vec![0u8; 64];
        let pk = Pubkey::new_from_array([7u8; 32]);
        write_pubkey_at(&mut buf, 16, &pk);
        assert_eq!(&buf[16..48], &[7u8; 32]);
        assert_eq!(&buf[0..16], &[0u8; 16]); // before is untouched
        assert_eq!(&buf[48..64], &[0u8; 16]); // after is untouched
    }

    #[test]
    fn write_bytes_at_copies_arbitrary_slice() {
        let mut buf = vec![0u8; 32];
        write_bytes_at(&mut buf, 8, b"USDC");
        assert_eq!(&buf[8..12], b"USDC");
        assert_eq!(&buf[12..32], &[0u8; 20]);
    }

    #[test]
    fn builder_prepends_discriminator() {
        let body = vec![0xAAu8; 100];
        let acct = AnchorAccountBuilder::new("Pool", body.clone()).build();
        assert_eq!(acct.data.len(), 108);
        assert_eq!(&acct.data[..8], &anchor_account_disc("Pool"));
        assert_eq!(&acct.data[8..], &body[..]);
    }

    #[test]
    fn builder_owner_defaults_then_overrides() {
        let acct1 = AnchorAccountBuilder::new("X", vec![0u8; 10]).build();
        assert_eq!(acct1.owner, Pubkey::default());

        let owner = Pubkey::new_from_array([9u8; 32]);
        let acct2 = AnchorAccountBuilder::new("X", vec![0u8; 10])
            .owned_by(owner)
            .build();
        assert_eq!(acct2.owner, owner);
    }

    #[test]
    fn builder_lamports_default_is_rent_for_body_plus_disc() {
        let acct = AnchorAccountBuilder::new("X", vec![0u8; 100]).build();
        assert_eq!(acct.lamports, rent_for_anchor_body(100));
        assert_eq!(acct.lamports, rent_for_raw(108));
    }

    #[test]
    fn builder_lamports_override_takes_precedence() {
        let acct = AnchorAccountBuilder::new("X", vec![0u8; 100])
            .lamports(1234)
            .build();
        assert_eq!(acct.lamports, 1234);
    }

    #[test]
    fn builder_executable_default_false() {
        let acct = AnchorAccountBuilder::new("X", vec![0u8; 10]).build();
        assert!(!acct.executable);
    }
}
