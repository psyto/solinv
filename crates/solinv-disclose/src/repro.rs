//! # repro — the self-contained bundle a third party needs to re-run
//!
//! A divergence report that only says *what* diverged is an assertion.
//! One that also carries *everything needed to reproduce the run* is
//! evidence: the reader can re-execute and reach the same place
//! themselves, and does not have to take the finder's word.
//!
//! Solana makes the difference sharp. There is no state root and no
//! receipt trie, so no one can prove after the fact what a transaction
//! did against a commitment — the only way to check a claim about
//! execution is to execute it again. That makes the input bundle the
//! load-bearing part of the report, not an appendix.
//!
//! ## What has to be in the bundle
//!
//! - **The code, by hash.** Program IDs alone are not enough: the
//!   binary at an address is upgradeable, so an ID identifies a slot in
//!   time, not a program. [`ProgramRef::code_sha256`] pins the actual
//!   `.so` bytes that ran.
//! - **The pre-state, by hash.** Same reason, for accounts.
//! - **The feature set.** Solana runtime semantics are gated by
//!   feature flags that activate at epoch boundaries, so "same
//!   instruction, same accounts" can still mean two different
//!   executions on two different days. A bundle without
//!   [`ReproBundle::feature_set`] has an undefined comparison target.
//! - **The action sequence.** The minimal instruction sequence that
//!   reaches the divergence, as produced by the shrinker.
//!
//! ## Hashing is part of the spec
//!
//! Reproduction only works if the reader hashes the same way the
//! reporter did, so [`sha256_hex`] is exported rather than left to each
//! caller. Digests are lowercase hex of SHA-256 over the raw bytes.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Lowercase-hex SHA-256 of `bytes`.
///
/// Used for every digest in a bundle, so a third party reproducing the
/// run hashes identically without having to guess the encoding.
///
/// ```
/// use solinv_disclose::sha256_hex;
///
/// assert_eq!(
///     sha256_hex(b""),
///     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
/// );
/// ```
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// One program that participated in the compared run.
///
/// Both sides of a differential get one of these — the whole point is
/// that the two `code_sha256` values differ while the observable
/// behaviour is claimed not to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramRef {
    /// Which side this binary belongs to (matches a `Sides` field).
    pub side: String,
    /// Base58 program ID, as the caller renders it.
    pub program_id: String,
    /// SHA-256 of the `.so` bytes that were loaded.
    pub code_sha256: String,
}

impl ProgramRef {
    /// Build from the raw `.so` bytes, hashing them here so the digest
    /// is always computed the documented way.
    pub fn from_code(side: impl Into<String>, program_id: impl Into<String>, code: &[u8]) -> Self {
        Self {
            side: side.into(),
            program_id: program_id.into(),
            code_sha256: sha256_hex(code),
        }
    }
}

/// One account in the pre-state of the compared run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountRef {
    /// Role in the harness (e.g. `"pool"`, `"user_src"`).
    pub label: String,
    /// Base58 pubkey, as the caller renders it.
    pub pubkey: String,
    /// Byte length of the account data before the run.
    pub len: usize,
    /// SHA-256 of the account data before the run.
    pub pre_state_sha256: String,
}

impl AccountRef {
    /// Build from the raw pre-state bytes.
    pub fn from_data(label: impl Into<String>, pubkey: impl Into<String>, data: &[u8]) -> Self {
        Self {
            label: label.into(),
            pubkey: pubkey.into(),
            len: data.len(),
            pre_state_sha256: sha256_hex(data),
        }
    }
}

/// Everything a third party needs to re-execute the compared run.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReproBundle {
    /// One entry per side of the comparison.
    pub programs: Vec<ProgramRef>,
    /// Pre-state of every account the run touched.
    pub accounts: Vec<AccountRef>,
    /// Mainnet slot the account snapshot was cloned from, when the
    /// fixture came from a real pool rather than synthetic setup.
    pub slot: Option<u64>,
    /// Identifier of the activated feature set the run assumed.
    ///
    /// Without this the comparison target is undefined — see the module
    /// docs. Left as a free-form string because there is no canonical
    /// feature-set identifier in the ecosystem to point at.
    pub feature_set: Option<String>,
    /// Minimal instruction sequence reaching the divergence, in order.
    pub actions: Vec<String>,
}

impl ReproBundle {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_program(mut self, program: ProgramRef) -> Self {
        self.programs.push(program);
        self
    }

    pub fn with_account(mut self, account: AccountRef) -> Self {
        self.accounts.push(account);
        self
    }

    pub fn with_slot(mut self, slot: u64) -> Self {
        self.slot = Some(slot);
        self
    }

    pub fn with_feature_set(mut self, feature_set: impl Into<String>) -> Self {
        self.feature_set = Some(feature_set.into());
        self
    }

    pub fn with_action(mut self, action: impl Into<String>) -> Self {
        self.actions.push(action.into());
        self
    }

    /// Whether this bundle is complete enough for someone else to
    /// reproduce the run.
    ///
    /// A bundle missing a feature set, or carrying fewer than two
    /// programs, still renders — but the report should say so rather
    /// than present itself as reproducible.
    pub fn is_reproducible(&self) -> bool {
        self.programs.len() >= 2 && self.feature_set.is_some() && !self.actions.is_empty()
    }

    /// Human-readable list of what is missing, for reports that are not
    /// yet reproducible. Empty when [`Self::is_reproducible`] holds.
    pub fn missing(&self) -> Vec<&'static str> {
        let mut gaps = Vec::new();
        if self.programs.len() < 2 {
            gaps.push("a program binary for each side");
        }
        if self.feature_set.is_none() {
            gaps.push("the activated feature set");
        }
        if self.actions.is_empty() {
            gaps.push("the action sequence");
        }
        gaps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_matches_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn program_ref_hashes_the_code() {
        let a = ProgramRef::from_code("anchor", "Anch111", b"\x7fELF-anchor");
        let p = ProgramRef::from_code("pinocchio", "Pino111", b"\x7fELF-pino");
        // Different binaries is the premise of the comparison, not a bug.
        assert_ne!(a.code_sha256, p.code_sha256);
        assert_eq!(a.code_sha256.len(), 64);
    }

    #[test]
    fn account_ref_records_length_and_digest() {
        let acct = AccountRef::from_data("pool", "Pool111", &[0u8; 6664]);
        assert_eq!(acct.len, 6664);
        assert_eq!(acct.pre_state_sha256, sha256_hex(&[0u8; 6664]));
    }

    fn full_bundle() -> ReproBundle {
        ReproBundle::new()
            .with_program(ProgramRef::from_code("anchor", "Anch111", b"a"))
            .with_program(ProgramRef::from_code("pinocchio", "Pino111", b"p"))
            .with_feature_set("mainnet-beta@epoch-812")
            .with_action("swap(100, 0)")
    }

    #[test]
    fn complete_bundle_is_reproducible() {
        let bundle = full_bundle();
        assert!(bundle.is_reproducible());
        assert!(bundle.missing().is_empty());
    }

    #[test]
    fn missing_feature_set_blocks_reproducibility() {
        let mut bundle = full_bundle();
        bundle.feature_set = None;
        assert!(!bundle.is_reproducible());
        assert_eq!(bundle.missing(), vec!["the activated feature set"]);
    }

    #[test]
    fn empty_bundle_lists_every_gap() {
        let bundle = ReproBundle::new();
        assert_eq!(bundle.missing().len(), 3);
    }

    #[test]
    fn bundle_round_trips_through_json() {
        let bundle = full_bundle().with_slot(300_000_000);
        let encoded = serde_json::to_string(&bundle).unwrap();
        let decoded: ReproBundle = serde_json::from_str(&encoded).unwrap();
        assert_eq!(bundle, decoded);
    }
}
