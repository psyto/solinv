//! # repro — the inputs of a compared run, and how completely they travel
//!
//! A divergence report that only says *what* diverged is an assertion.
//! One that also carries the inputs is evidence: the reader can
//! re-execute and reach the same place, instead of taking the finder's
//! word.
//!
//! Solana makes the difference sharp. There is no state root and no
//! receipt trie, so no one can prove after the fact what a transaction
//! did against a commitment — the only way to check a claim about
//! execution is to execute it again. That makes the input bundle the
//! load-bearing part of the report, not an appendix.
//!
//! ## A digest identifies; it does not deliver
//!
//! This is the distinction the module is built around, and the one that
//! is easy to get wrong. A SHA-256 lets a reader confirm that bytes
//! they already hold are the right ones. It cannot hand them those
//! bytes. So a bundle carrying only digests describes what must be
//! supplied out of band — it is **not** by itself enough to re-execute
//! anything, and must not claim to be.
//!
//! [`Artifact`] makes the difference explicit per input, and
//! [`ReproBundle::completeness`] reports it for the bundle as a whole,
//! three-valued: [`Completeness::SelfContained`],
//! [`Completeness::IdentifiedOnly`], [`Completeness::Incomplete`].
//!
//! ## What has to be in the bundle
//!
//! - **The code.** Program IDs alone are not enough: the binary at an
//!   address is upgradeable, so an ID identifies a slot in time, not a
//!   program. [`ProgramRef::code`] pins the actual `.so` bytes.
//! - **The pre-state, with its metadata.** Same reason, for accounts —
//!   and owner, lamports and the executable flag are part of the state
//!   a caller can observe, not decoration.
//! - **The feature set.** Solana runtime semantics are gated by
//!   feature flags that activate at epoch boundaries, so "same
//!   instruction, same accounts" can still mean two different
//!   executions on two different days. A bundle without
//!   [`ReproBundle::feature_set`] has an undefined comparison target.
//! - **The action sequence, encoded.** A label describes a step;
//!   [`ActionRef::encoded`] is what lets anyone replay it.
//!
//! ## Hashing is part of the spec
//!
//! Verification only works if the reader hashes the same way the
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

/// How an input is carried by the bundle.
///
/// This distinction is the difference between a report that can be
/// checked and one that only *looks* checkable. A SHA-256 lets a reader
/// confirm that bytes they already hold are the right ones. It cannot
/// hand them those bytes. A bundle carrying digests alone therefore
/// describes what must be supplied out of band — it is not, by itself,
/// enough to re-execute anything.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "carrier", rename_all = "snake_case")]
pub enum Artifact {
    /// The bytes are named but not carried. Verifiable against a copy
    /// obtained elsewhere; not sufficient to reproduce the run.
    Digest { sha256: String, len: usize },
    /// The bytes travel with the report, base64-encoded.
    Inline {
        sha256: String,
        len: usize,
        base64: String,
    },
}

impl Artifact {
    /// Name the bytes without carrying them.
    pub fn digest(bytes: &[u8]) -> Self {
        Artifact::Digest {
            sha256: sha256_hex(bytes),
            len: bytes.len(),
        }
    }

    /// Carry the bytes.
    pub fn inline(bytes: &[u8]) -> Self {
        Artifact::Inline {
            sha256: sha256_hex(bytes),
            len: bytes.len(),
            base64: b64(bytes),
        }
    }

    pub fn sha256(&self) -> &str {
        match self {
            Artifact::Digest { sha256, .. } | Artifact::Inline { sha256, .. } => sha256,
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Artifact::Digest { len, .. } | Artifact::Inline { len, .. } => *len,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether the bytes travel with the report.
    pub fn is_carried(&self) -> bool {
        matches!(self, Artifact::Inline { .. })
    }

    /// Whether a carried payload actually matches what it claims to be.
    ///
    /// A `Digest` artifact is trivially intact — it asserts only a hash,
    /// and there is nothing carried to contradict it. An `Inline`
    /// artifact asserts three things at once (bytes, length, hash) and
    /// they can disagree: hand-assembled, truncated in transit, or
    /// re-serialized by something that did not recompute the digest.
    ///
    /// Checking this is the difference between "the report says it
    /// carries the program" and "the report carries the program". The
    /// first is a claim; only the second can be executed.
    pub fn is_intact(&self) -> bool {
        match self {
            Artifact::Digest { .. } => true,
            Artifact::Inline {
                sha256,
                len,
                base64,
            } => match b64_decode(base64) {
                Some(bytes) => bytes.len() == *len && &sha256_hex(&bytes) == sha256,
                None => false,
            },
        }
    }

    /// The carried bytes, when they are present and self-consistent.
    pub fn bytes(&self) -> Option<Vec<u8>> {
        match self {
            Artifact::Digest { .. } => None,
            Artifact::Inline { .. } if !self.is_intact() => None,
            Artifact::Inline { base64, .. } => b64_decode(base64),
        }
    }
}

/// Decode RFC 4648 base64. `None` on any malformed input — wrong
/// length, stray character, or padding in the wrong place.
fn b64_decode(text: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a') as u32 + 26,
            b'0'..=b'9' => (c - b'0') as u32 + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    }
    let raw = text.as_bytes();
    if !raw.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(raw.len() / 4 * 3);
    for chunk in raw.chunks(4) {
        let pad = chunk.iter().filter(|&&c| c == b'=').count();
        // Padding is only legal as the final one or two characters.
        if pad > 2 || chunk[..4 - pad].contains(&b'=') {
            return None;
        }
        let mut n = 0u32;
        for &c in &chunk[..4 - pad] {
            n = (n << 6) | val(c)?;
        }
        n <<= 6 * pad;
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&bytes[..3 - pad]);
    }
    Some(out)
}

/// Minimal base64 (RFC 4648, padded) so the crate keeps its
/// serde+sha2-only dependency footprint.
fn b64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for c in bytes.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// One program that participated in the compared run.
///
/// Both sides of a differential get one of these — the whole point is
/// that the two binaries differ while the observable behaviour is
/// claimed not to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramRef {
    /// Which side this binary belongs to (matches a `Sides` field).
    pub side: String,
    /// Base58 program ID, as the caller renders it.
    ///
    /// An ID names an address, not a binary: the program at an address
    /// is upgradeable. `code` is what actually pins what ran.
    pub program_id: String,
    /// The `.so` bytes, named or carried.
    pub code: Artifact,
}

impl ProgramRef {
    /// Name the binary by digest without carrying it.
    pub fn from_code(side: impl Into<String>, program_id: impl Into<String>, code: &[u8]) -> Self {
        Self {
            side: side.into(),
            program_id: program_id.into(),
            code: Artifact::digest(code),
        }
    }

    /// Carry the binary with the report.
    pub fn with_code_inline(
        side: impl Into<String>,
        program_id: impl Into<String>,
        code: &[u8],
    ) -> Self {
        Self {
            side: side.into(),
            program_id: program_id.into(),
            code: Artifact::inline(code),
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
    /// Account data before the run, named or carried.
    pub pre_state: Artifact,
    /// Owner program, base58. Part of the observable account state and
    /// required to reconstruct it.
    pub owner: Option<String>,
    pub lamports: Option<u64>,
    pub executable: Option<bool>,
}

impl AccountRef {
    /// Name the pre-state by digest without carrying it.
    pub fn from_data(label: impl Into<String>, pubkey: impl Into<String>, data: &[u8]) -> Self {
        Self {
            label: label.into(),
            pubkey: pubkey.into(),
            pre_state: Artifact::digest(data),
            owner: None,
            lamports: None,
            executable: None,
        }
    }

    /// Carry the pre-state with the report.
    pub fn with_data_inline(
        label: impl Into<String>,
        pubkey: impl Into<String>,
        data: &[u8],
    ) -> Self {
        Self {
            label: label.into(),
            pubkey: pubkey.into(),
            pre_state: Artifact::inline(data),
            owner: None,
            lamports: None,
            executable: None,
        }
    }

    /// Attach the account metadata that is part of its observable state.
    pub fn with_metadata(
        mut self,
        owner: impl Into<String>,
        lamports: u64,
        executable: bool,
    ) -> Self {
        self.owner = Some(owner.into());
        self.lamports = Some(lamports);
        self.executable = Some(executable);
        self
    }

    /// Whether this account is reconstructible from the report alone.
    ///
    /// Requires the data *and* the full metadata triple. `executable` is
    /// included because it is not cosmetic: it decides whether the
    /// runtime will treat the account as a program, so an account
    /// restored without it is not the account that ran.
    fn is_complete(&self) -> bool {
        self.pre_state.is_carried()
            && self.pre_state.is_intact()
            && self.owner.is_some()
            && self.lamports.is_some()
            && self.executable.is_some()
    }
}

/// One instruction in the reproducing sequence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionRef {
    /// Human label, as it appears in divergence headlines.
    pub label: String,
    /// Base58 program the instruction targets.
    pub program_id: Option<String>,
    /// Base64 instruction data — the executable encoding. Without it
    /// the label is a description, not something anyone can replay.
    pub data_base64: Option<String>,
    /// Ordered account metas: `(pubkey, is_signer, is_writable)`.
    pub accounts: Vec<(String, bool, bool)>,
}

impl ActionRef {
    /// A label only — describes the step, does not encode it.
    pub fn described(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            program_id: None,
            data_base64: None,
            accounts: Vec::new(),
        }
    }

    /// A replayable instruction.
    pub fn encoded(
        label: impl Into<String>,
        program_id: impl Into<String>,
        data: &[u8],
        accounts: Vec<(String, bool, bool)>,
    ) -> Self {
        Self {
            label: label.into(),
            program_id: Some(program_id.into()),
            data_base64: Some(b64(data)),
            accounts,
        }
    }

    fn is_replayable(&self) -> bool {
        self.program_id.is_some() && self.data_base64.is_some()
    }
}

/// The inputs of the compared run, and how completely they travel.
///
/// Named a *bundle* aspirationally: whether it actually bundles enough
/// to reproduce anything depends on how it was filled in. See
/// [`ReproBundle::completeness`].
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
    /// Instruction sequence reaching the divergence, in order.
    pub actions: Vec<ActionRef>,
}

/// How much of the run a bundle actually carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Completeness {
    /// Program bytes, account pre-state with metadata, encoded
    /// instructions, and a feature set all travel with the report. A
    /// reader can re-execute from this alone.
    SelfContained,
    /// Everything is identified — digests, program IDs, labels — but
    /// the bytes do not travel. A reader who independently obtains the
    /// artifacts can confirm they are the right ones and then re-run;
    /// a reader who cannot obtain them can do nothing.
    IdentifiedOnly,
    /// Something required to define the comparison at all is absent.
    Incomplete,
    /// A carried payload does not match its own declared length or
    /// digest. Worse than absent: the bundle asserts it holds the
    /// inputs and the assertion is false.
    Corrupt,
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

    pub fn with_action(mut self, action: ActionRef) -> Self {
        self.actions.push(action);
        self
    }

    /// What this bundle is actually good for.
    ///
    /// Deliberately three-valued. The earlier boolean conflated "we
    /// know what the inputs were" with "we can hand them to you", and a
    /// digest-only bundle satisfied it — which meant a report could
    /// announce itself reproducible while carrying nothing anyone could
    /// execute.
    pub fn completeness(&self) -> Completeness {
        // Checked before anything else: a bundle that carries bytes
        // contradicting their own digest is not merely under-filled,
        // it is lying, and no other verdict should mask that.
        if !self.integrity_failures().is_empty() {
            return Completeness::Corrupt;
        }
        if !self.defines_a_comparison() {
            return Completeness::Incomplete;
        }
        let carried = self.programs.iter().all(|p| p.code.is_carried())
            && self.accounts.iter().all(|a| a.is_complete())
            && self.actions.iter().all(|a| a.is_replayable())
            && !self.accounts.is_empty();
        if carried {
            Completeness::SelfContained
        } else {
            Completeness::IdentifiedOnly
        }
    }

    /// Carried payloads whose bytes disagree with their declared length
    /// or SHA-256. Empty for a bundle that carries nothing.
    pub fn integrity_failures(&self) -> Vec<String> {
        let mut bad = Vec::new();
        for p in &self.programs {
            if !p.code.is_intact() {
                bad.push(format!("{} program bytes", p.side));
            }
        }
        for a in &self.accounts {
            if !a.pre_state.is_intact() {
                bad.push(format!("`{}` account data", a.label));
            }
        }
        bad
    }

    /// Whether the bundle pins the comparison target at all: a binary
    /// per side, a feature set, and at least one action.
    fn defines_a_comparison(&self) -> bool {
        self.programs.len() >= 2 && self.feature_set.is_some() && !self.actions.is_empty()
    }

    /// Whether a reader can re-execute from the report alone.
    pub fn is_self_contained(&self) -> bool {
        self.completeness() == Completeness::SelfContained
    }

    /// Human-readable list of what is missing before the bundle would
    /// define a comparison. Empty once [`Self::defines_a_comparison`]
    /// holds — it does **not** report what is missing before the bundle
    /// would be self-contained; use [`Self::not_carried`] for that.
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

    /// What is identified but not carried, for a bundle that defines a
    /// comparison without being self-contained.
    pub fn not_carried(&self) -> Vec<String> {
        let mut gaps = Vec::new();
        for p in &self.programs {
            if !p.code.is_carried() {
                gaps.push(format!("{} program bytes", p.side));
            }
        }
        if self.accounts.is_empty() {
            gaps.push("account pre-state".to_string());
        }
        for a in &self.accounts {
            if !a.pre_state.is_carried() {
                gaps.push(format!("`{}` account data", a.label));
            } else if a.owner.is_none() || a.lamports.is_none() || a.executable.is_none() {
                gaps.push(format!(
                    "`{}` account metadata (owner/lamports/executable)",
                    a.label
                ));
            }
        }
        for a in &self.actions {
            if !a.is_replayable() {
                gaps.push(format!("encoding for action `{}`", a.label));
            }
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
    fn base64_matches_known_vectors() {
        assert_eq!(b64(b""), "");
        assert_eq!(b64(b"f"), "Zg==");
        assert_eq!(b64(b"fo"), "Zm8=");
        assert_eq!(b64(b"foo"), "Zm9v");
        assert_eq!(b64(b"foob"), "Zm9vYg==");
        assert_eq!(b64(b"fooba"), "Zm9vYmE=");
        assert_eq!(b64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn digest_artifact_names_but_does_not_carry() {
        let a = Artifact::digest(b"\x7fELF");
        assert!(!a.is_carried());
        assert_eq!(a.len(), 4);
        assert_eq!(a.sha256(), sha256_hex(b"\x7fELF"));
    }

    #[test]
    fn inline_artifact_carries_the_bytes() {
        let a = Artifact::inline(b"foobar");
        assert!(a.is_carried());
        match a {
            Artifact::Inline { base64, .. } => assert_eq!(base64, "Zm9vYmFy"),
            _ => panic!("expected inline"),
        }
    }

    #[test]
    fn program_ref_distinguishes_the_two_binaries() {
        let a = ProgramRef::from_code("anchor", "Anch111", b"\x7fELF-anchor");
        let p = ProgramRef::from_code("pinocchio", "Pino111", b"\x7fELF-pino");
        // Different binaries is the premise of the comparison, not a bug.
        assert_ne!(a.code.sha256(), p.code.sha256());
        assert_eq!(a.code.sha256().len(), 64);
    }

    fn identified_bundle() -> ReproBundle {
        ReproBundle::new()
            .with_program(ProgramRef::from_code("anchor", "Anch111", b"a"))
            .with_program(ProgramRef::from_code("pinocchio", "Pino111", b"p"))
            .with_account(AccountRef::from_data("pool", "Pool111", &[0u8; 24]))
            .with_feature_set("mainnet-beta@epoch-812")
            .with_action(ActionRef::described("swap(100, 0)"))
    }

    fn self_contained_bundle() -> ReproBundle {
        ReproBundle::new()
            .with_program(ProgramRef::with_code_inline("anchor", "Anch111", b"a"))
            .with_program(ProgramRef::with_code_inline("pinocchio", "Pino111", b"p"))
            .with_account(
                AccountRef::with_data_inline("pool", "Pool111", &[0u8; 24])
                    .with_metadata("Owner111", 5_000_000, false),
            )
            .with_feature_set("mainnet-beta@epoch-812")
            .with_action(ActionRef::encoded(
                "swap(100, 0)",
                "Anch111",
                &[1, 2, 3],
                vec![("Pool111".into(), false, true)],
            ))
    }

    #[test]
    fn digest_only_bundle_is_not_self_contained() {
        // The regression this guards: hashes verify artifacts a reader
        // already holds; they cannot deliver them. A bundle of digests
        // must never announce itself reproducible.
        let b = identified_bundle();
        assert_eq!(b.completeness(), Completeness::IdentifiedOnly);
        assert!(!b.is_self_contained());
        assert!(b.missing().is_empty(), "it does define a comparison");
        let gaps = b.not_carried();
        assert!(
            gaps.iter().any(|g| g.contains("anchor program bytes")),
            "{gaps:?}"
        );
        assert!(
            gaps.iter().any(|g| g.contains("`pool` account data")),
            "{gaps:?}"
        );
        assert!(
            gaps.iter().any(|g| g.contains("encoding for action")),
            "{gaps:?}"
        );
    }

    #[test]
    fn fully_carried_bundle_is_self_contained() {
        let b = self_contained_bundle();
        assert_eq!(b.completeness(), Completeness::SelfContained);
        assert!(b.is_self_contained());
        assert!(b.not_carried().is_empty(), "{:?}", b.not_carried());
    }

    #[test]
    fn base64_round_trips_including_awkward_tails() {
        for n in 0..40usize {
            let bytes: Vec<u8> = (0..n).map(|i| (i * 37 % 251) as u8).collect();
            assert_eq!(b64_decode(&b64(&bytes)).as_deref(), Some(&bytes[..]), "n={n}");
        }
    }

    #[test]
    fn base64_rejects_malformed_input() {
        assert!(b64_decode("Zg=").is_none(), "length not a multiple of 4");
        assert!(b64_decode("Z*==").is_none(), "stray character");
        assert!(b64_decode("Z=g=").is_none(), "padding in the wrong place");
        assert!(b64_decode("====").is_none(), "all padding");
    }

    #[test]
    fn tampered_inline_payload_is_not_intact() {
        // The regression this guards: a bundle that *says* it carries
        // the program, whose carried bytes are not the program.
        let good = Artifact::inline(b"the real program");
        assert!(good.is_intact());
        assert_eq!(good.bytes().as_deref(), Some(&b"the real program"[..]));

        let tampered = match good.clone() {
            Artifact::Inline { sha256, len, .. } => Artifact::Inline {
                sha256,
                len,
                base64: b64(b"something else!!"),
            },
            _ => unreachable!(),
        };
        assert!(!tampered.is_intact(), "digest mismatch must be caught");
        assert!(tampered.bytes().is_none(), "corrupt bytes must not be handed out");

        let wrong_len = match good {
            Artifact::Inline { sha256, base64, .. } => Artifact::Inline {
                sha256,
                len: 999,
                base64,
            },
            _ => unreachable!(),
        };
        assert!(!wrong_len.is_intact(), "length mismatch must be caught");
    }

    #[test]
    fn corrupt_payload_outranks_every_other_verdict() {
        let mut b = self_contained_bundle();
        b.programs[0].code = match &b.programs[0].code {
            Artifact::Inline { sha256, len, .. } => Artifact::Inline {
                sha256: sha256.clone(),
                len: *len,
                base64: b64(b"not the program"),
            },
            other => other.clone(),
        };
        assert_eq!(b.completeness(), Completeness::Corrupt);
        assert!(!b.is_self_contained());
        assert_eq!(b.integrity_failures(), vec!["anchor program bytes"]);
    }

    #[test]
    fn account_without_executable_is_not_self_contained() {
        // `executable` decides whether the runtime treats the account as
        // a program, so an account restored without it is not the
        // account that ran.
        let b = ReproBundle::new()
            .with_program(ProgramRef::with_code_inline("anchor", "Anch111", b"a"))
            .with_program(ProgramRef::with_code_inline("pinocchio", "Pino111", b"p"))
            .with_account({
                let mut a = AccountRef::with_data_inline("pool", "Pool111", &[0u8; 24]);
                a.owner = Some("Owner111".into());
                a.lamports = Some(5_000_000);
                a
            })
            .with_feature_set("mainnet-beta@epoch-812")
            .with_action(ActionRef::encoded("swap", "Anch111", &[1], vec![]));
        assert_eq!(b.completeness(), Completeness::IdentifiedOnly);
        assert!(b
            .not_carried()
            .iter()
            .any(|g| g.contains("owner/lamports/executable")));
    }

    #[test]
    fn carried_bytes_without_account_metadata_are_not_enough() {
        let b = ReproBundle::new()
            .with_program(ProgramRef::with_code_inline("anchor", "Anch111", b"a"))
            .with_program(ProgramRef::with_code_inline("pinocchio", "Pino111", b"p"))
            // data carried, but owner/lamports absent
            .with_account(AccountRef::with_data_inline("pool", "Pool111", &[0u8; 24]))
            .with_feature_set("mainnet-beta@epoch-812")
            .with_action(ActionRef::encoded("swap", "Anch111", &[1], vec![]));
        assert_eq!(b.completeness(), Completeness::IdentifiedOnly);
        assert!(b
            .not_carried()
            .iter()
            .any(|g| g.contains("account metadata")));
    }

    #[test]
    fn missing_feature_set_leaves_the_comparison_undefined() {
        let mut b = self_contained_bundle();
        b.feature_set = None;
        assert_eq!(b.completeness(), Completeness::Incomplete);
        assert_eq!(b.missing(), vec!["the activated feature set"]);
    }

    #[test]
    fn empty_bundle_lists_every_gap() {
        let b = ReproBundle::new();
        assert_eq!(b.completeness(), Completeness::Incomplete);
        assert_eq!(b.missing().len(), 3);
    }

    #[test]
    fn bundle_round_trips_through_json() {
        let b = self_contained_bundle().with_slot(300_000_000);
        let encoded = serde_json::to_string(&b).unwrap();
        let decoded: ReproBundle = serde_json::from_str(&encoded).unwrap();
        assert_eq!(b, decoded);
    }
}
