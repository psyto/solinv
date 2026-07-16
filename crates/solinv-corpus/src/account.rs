//! # account — clone-and-mutate mainnet account state
//!
//! The state-fixture counterpart to the transaction-corpus pipeline.
//! Harnesses today hand-build every account they inject (see
//! `solinv-fuzz`'s `bytepoke`), which is fine for small structs but
//! painful for a real Raydium/Kamino pool with dozens of fields whose
//! layout must be mirrored exactly. This module fetches the *live*
//! bytes of such an account once, caches them, and hands them back as a
//! [`solana_account::Account`] ready for crucible's `write_account`.
//!
//! The adversarial edge is what you do *after* cloning: take the real
//! baseline and drive one field to an extreme (pool liquidity → 0,
//! oracle price → 10x) with the `bytepoke` byte-writers, then fuzz the
//! CPI against that state. Those are exactly the states a Mainnet clone
//! *as-is* (Surfpool-style) never reaches, because the live account is
//! healthy — you have to perturb it.
//!
//! ## Cache-first, offline-reproducible
//!
//! [`clone_account`] hits the network at most once per pubkey and
//! persists the snapshot under `<cache_dir>/accounts/<pubkey>.json`.
//! Every subsequent run — and every CI run — loads from disk with no
//! RPC dependency, so a committed snapshot is a deterministic fixture,
//! not a flaky network call.
//!
//! ```no_run
//! use std::path::Path;
//! use solinv_corpus::account;
//! use solana_pubkey::Pubkey;
//! use std::str::FromStr;
//!
//! let pool = Pubkey::from_str("58oQChx4yWmvKdwLLZzBi4ChoCc2fqCUWBkwMihLYQo2").unwrap();
//! let mut snap = account::clone_account(
//!     account::MAINNET_BETA,
//!     Path::new(".solinv/cache"),
//!     &pool,
//! ).unwrap();
//!
//! // Perturb the baseline (illustrative offset) before injecting:
//! // solinv_fuzz::bytepoke::write_u64_at(snap.data_mut(), 0, 0);
//! let account = snap.into_account().unwrap();
//! // ctx.write_account(&pool, account).unwrap();
//! # let _ = account;
//! ```

use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use solana_account::Account;
use solana_pubkey::Pubkey;

/// Solana mainnet-beta public RPC endpoint.
pub const MAINNET_BETA: &str = "https://api.mainnet-beta.solana.com";

fn b64_standard() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// serde adapter: store `Vec<u8>` as a base64 string on disk while
/// keeping the in-memory representation raw bytes (so `bytepoke`
/// writers can mutate it directly).
mod b64 {
    use super::b64_standard;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&b64_standard().encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        b64_standard()
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// A point-in-time snapshot of a mainnet account, portable across runs.
///
/// `pubkey`/`owner` are base58 strings so the on-disk JSON is
/// human-readable and matches RPC conventions; `data` serializes as
/// base64 but is raw bytes in memory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountSnapshot {
    /// Address this account lives at (base58).
    pub pubkey: String,
    /// Slot the snapshot was observed at.
    pub slot: u64,
    pub lamports: u64,
    /// Owning program (base58).
    pub owner: String,
    pub executable: bool,
    pub rent_epoch: u64,
    #[serde(with = "b64")]
    pub data: Vec<u8>,
}

impl AccountSnapshot {
    /// Parse the account address.
    pub fn pubkey(&self) -> Result<Pubkey> {
        Pubkey::from_str(&self.pubkey).map_err(|e| anyhow!("invalid pubkey {:?}: {e}", self.pubkey))
    }

    /// Parse the owning program.
    pub fn owner(&self) -> Result<Pubkey> {
        Pubkey::from_str(&self.owner).map_err(|e| anyhow!("invalid owner {:?}: {e}", self.owner))
    }

    /// Mutable access to the raw account bytes — the perturbation
    /// surface. Feed to `solinv_fuzz::bytepoke::write_*_at` to drive a
    /// field to an adversarial value before injecting.
    pub fn data_mut(&mut self) -> &mut Vec<u8> {
        &mut self.data
    }

    /// Materialize a `solana_account::Account` for `ctx.write_account`.
    pub fn into_account(&self) -> Result<Account> {
        Ok(Account {
            lamports: self.lamports,
            data: self.data.clone(),
            owner: self.owner()?,
            executable: self.executable,
            rent_epoch: self.rent_epoch,
        })
    }

    /// Materialize an `Account` but force the owner to `owner` instead of
    /// the on-chain program. This is the LiteSVM clone pattern: inject a
    /// mainnet account's real bytes under a *locally deployed* program id
    /// (same bytecode, different address) so a harness can execute against
    /// production state without redeploying under the mainnet address.
    pub fn into_account_owned_by(&self, owner: Pubkey) -> Account {
        Account {
            lamports: self.lamports,
            data: self.data.clone(),
            owner,
            executable: self.executable,
            rent_epoch: self.rent_epoch,
        }
    }

    /// Deserialize a snapshot from its on-disk JSON form. Handy for
    /// `include_str!`-embedded committed fixtures (offline, no I/O).
    pub fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s).context("parsing AccountSnapshot JSON")
    }
}

/// Parse a `getAccountInfo` (encoding=base64) JSON-RPC response into a
/// snapshot. Pure — no I/O — so it is unit-testable against canned
/// responses. Split out from [`fetch_account`] deliberately.
pub fn parse_account_info(pubkey: &Pubkey, resp: &serde_json::Value) -> Result<AccountSnapshot> {
    if let Some(err) = resp.get("error") {
        return Err(anyhow!("RPC returned error for {pubkey}: {err}"));
    }
    let result = resp
        .get("result")
        .ok_or_else(|| anyhow!("RPC response missing `result`"))?;
    let slot = result
        .get("context")
        .and_then(|c| c.get("slot"))
        .and_then(|s| s.as_u64())
        .ok_or_else(|| anyhow!("RPC response missing `result.context.slot`"))?;

    let value = result
        .get("value")
        .ok_or_else(|| anyhow!("RPC response missing `result.value`"))?;
    if value.is_null() {
        return Err(anyhow!("account {pubkey} does not exist on chain"));
    }

    let lamports = value
        .get("lamports")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow!("account {pubkey} missing `lamports`"))?;
    let owner = value
        .get("owner")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("account {pubkey} missing `owner`"))?
        .to_string();
    let executable = value
        .get("executable")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let rent_epoch = value.get("rentEpoch").and_then(|v| v.as_u64()).unwrap_or(0);

    // `data` is `["<base64>", "base64"]` when encoding=base64 was
    // requested. A bare object means the RPC returned jsonParsed —
    // reject it so the caller fixes the request rather than silently
    // getting empty bytes.
    let data_arr = value.get("data").and_then(|v| v.as_array()).ok_or_else(|| {
        anyhow!("account {pubkey} data is not base64-encoded; request encoding=base64")
    })?;
    let encoding = data_arr.get(1).and_then(|v| v.as_str()).unwrap_or("");
    if encoding != "base64" {
        return Err(anyhow!(
            "account {pubkey} data encoding is {encoding:?}, expected \"base64\""
        ));
    }
    let payload = data_arr
        .first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("account {pubkey} missing base64 data payload"))?;
    let data = b64_standard()
        .decode(payload)
        .with_context(|| format!("decoding base64 data for {pubkey}"))?;

    Ok(AccountSnapshot {
        pubkey: pubkey.to_string(),
        slot,
        lamports,
        owner,
        executable,
        rent_epoch,
        data,
    })
}

/// Fetch an account's current state directly from an RPC endpoint
/// (always hits the network). Prefer [`clone_account`] for the
/// cache-first path.
pub fn fetch_account(rpc_url: &str, pubkey: &Pubkey) -> Result<AccountSnapshot> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getAccountInfo",
        "params": [ pubkey.to_string(), { "encoding": "base64" } ],
    });
    let resp: serde_json::Value = ureq::post(rpc_url)
        .send_json(body)
        .map_err(|e| anyhow!("getAccountInfo request to {rpc_url} failed: {e}"))?
        .into_json()
        .context("reading getAccountInfo response body as JSON")?;
    parse_account_info(pubkey, &resp)
}

fn cache_file(cache_dir: &Path, pubkey: &Pubkey) -> PathBuf {
    cache_dir.join("accounts").join(format!("{pubkey}.json"))
}

/// Load a cached snapshot without touching the network. Returns
/// `Ok(None)` on a cache miss.
pub fn load_snapshot(cache_dir: &Path, pubkey: &Pubkey) -> Result<Option<AccountSnapshot>> {
    let path = cache_file(cache_dir, pubkey);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&path).with_context(|| format!("reading cache {}", path.display()))?;
    let snap = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing cached snapshot {}", path.display()))?;
    Ok(Some(snap))
}

/// Persist a snapshot to `<cache_dir>/accounts/<pubkey>.json`.
pub fn save_snapshot(cache_dir: &Path, snap: &AccountSnapshot) -> Result<()> {
    let pubkey = snap.pubkey()?;
    let path = cache_file(cache_dir, &pubkey);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating cache dir {}", parent.display()))?;
    }
    let json = serde_json::to_vec_pretty(snap).context("serializing snapshot")?;
    fs::write(&path, json).with_context(|| format!("writing cache {}", path.display()))?;
    Ok(())
}

/// Cache-first clone: return the cached snapshot if present, otherwise
/// fetch once from `rpc_url` and persist it. This is the entry point a
/// harness fixture should call.
pub fn clone_account(
    rpc_url: &str,
    cache_dir: &Path,
    pubkey: &Pubkey,
) -> Result<AccountSnapshot> {
    if let Some(snap) = load_snapshot(cache_dir, pubkey)? {
        return Ok(snap);
    }
    let snap = fetch_account(rpc_url, pubkey)?;
    save_snapshot(cache_dir, &snap)?;
    Ok(snap)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Canonical, valid base58 addresses — deterministic, no new_unique.
    const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
    const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";

    fn sample_snapshot(data: Vec<u8>) -> AccountSnapshot {
        AccountSnapshot {
            pubkey: TOKEN_PROGRAM.to_string(),
            slot: 250_000_000,
            lamports: 42,
            owner: SYSTEM_PROGRAM.to_string(),
            executable: false,
            rent_epoch: u64::MAX,
            data,
        }
    }

    #[test]
    fn json_roundtrip_preserves_bytes() {
        let snap = sample_snapshot(vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
        let json = serde_json::to_vec(&snap).unwrap();
        // data must be stored as base64, not a raw byte array.
        let as_value: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert!(as_value["data"].is_string(), "data should serialize as base64 string");
        let back: AccountSnapshot = serde_json::from_slice(&json).unwrap();
        assert_eq!(snap, back);
    }

    #[test]
    fn into_account_maps_every_field() {
        let snap = sample_snapshot(vec![1, 2, 3]);
        let acct = snap.into_account().unwrap();
        assert_eq!(acct.lamports, 42);
        assert_eq!(acct.data, vec![1, 2, 3]);
        assert_eq!(acct.owner, Pubkey::from_str(SYSTEM_PROGRAM).unwrap());
        assert!(!acct.executable);
        assert_eq!(acct.rent_epoch, u64::MAX);
    }

    #[test]
    fn into_account_owned_by_overrides_owner() {
        let snap = sample_snapshot(vec![1, 2, 3]);
        let local = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
        let acct = snap.into_account_owned_by(local);
        assert_eq!(acct.owner, local); // NOT the snapshot's SYSTEM_PROGRAM owner
        assert_eq!(acct.data, vec![1, 2, 3]);
    }

    #[test]
    fn from_json_roundtrips() {
        let snap = sample_snapshot(vec![0xca, 0xfe]);
        let json = serde_json::to_string(&snap).unwrap();
        assert_eq!(AccountSnapshot::from_json(&json).unwrap(), snap);
    }

    // Real Raydium AMM v4 SOL-USDC pool, fetched from mainnet-beta and
    // committed under the raydium harness. Proves the clone-and-mutate
    // data path on *production* state rather than a hand-built fixture.
    #[test]
    fn clone_and_mutate_on_real_raydium_pool() {
        const RAY: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../examples/raydium-amm-fuzz/snapshots/accounts/",
            "58oQChx4yWmvKdwLLZzBi4ChoCc2fqCUWBkwMihLYQo2.json"
        ));
        let snap = AccountSnapshot::from_json(RAY).unwrap();

        // AmmInfo is a 752-byte account owned by the Raydium AMM v4 program.
        assert_eq!(snap.data.len(), 752, "AmmInfo layout is 752 bytes");
        assert_eq!(snap.owner, "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8");
        assert_ne!(snap.data, vec![0u8; 752], "baseline carries real state, not zeros");

        // Inject under a locally-deployed program id (LiteSVM clone pattern).
        let local_program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
        let acct = snap.into_account_owned_by(local_program);
        assert_eq!(acct.owner, local_program);
        assert_eq!(acct.data.len(), 752);

        // Perturb the real baseline to an adversarial value before injection —
        // the edge a healthy mainnet clone never reaches on its own.
        let mut mutated = snap.clone();
        let before = mutated.data[128];
        mutated.data_mut()[128] ^= 0xFF;
        assert_ne!(mutated.data[128], before, "perturbation reaches the cloned bytes");
    }

    #[test]
    fn parse_valid_base64_response() {
        let pubkey = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
        let payload = b64_standard().encode(b"hello");
        let resp = serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "result": {
                "context": { "apiVersion": "2.0.0", "slot": 250_000_000u64 },
                "value": {
                    "data": [payload, "base64"],
                    "executable": false,
                    "lamports": 1_000_000u64,
                    "owner": SYSTEM_PROGRAM,
                    "rentEpoch": u64::MAX,
                    "space": 5
                }
            }
        });
        let snap = parse_account_info(&pubkey, &resp).unwrap();
        assert_eq!(snap.data, b"hello");
        assert_eq!(snap.slot, 250_000_000);
        assert_eq!(snap.lamports, 1_000_000);
        assert_eq!(snap.rent_epoch, u64::MAX);
        assert_eq!(snap.owner().unwrap(), Pubkey::from_str(SYSTEM_PROGRAM).unwrap());
    }

    #[test]
    fn parse_null_value_is_account_not_found() {
        let pubkey = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
        let resp = serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "context": { "slot": 1u64 }, "value": serde_json::Value::Null }
        });
        let err = parse_account_info(&pubkey, &resp).unwrap_err().to_string();
        assert!(err.contains("does not exist"), "got: {err}");
    }

    #[test]
    fn parse_rejects_non_base64_encoding() {
        let pubkey = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
        // jsonParsed-style object instead of the [data, "base64"] array.
        let resp = serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "result": {
                "context": { "slot": 1u64 },
                "value": {
                    "data": { "program": "spl-token", "parsed": {} },
                    "executable": false, "lamports": 1u64,
                    "owner": SYSTEM_PROGRAM, "rentEpoch": 0u64
                }
            }
        });
        let err = parse_account_info(&pubkey, &resp).unwrap_err().to_string();
        assert!(err.contains("base64"), "got: {err}");
    }

    #[test]
    fn parse_surfaces_rpc_error() {
        let pubkey = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
        let resp = serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "error": { "code": -32602, "message": "Invalid param" }
        });
        assert!(parse_account_info(&pubkey, &resp).is_err());
    }

    #[test]
    fn cache_save_then_load_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let pubkey = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
        assert!(load_snapshot(dir.path(), &pubkey).unwrap().is_none());

        let snap = sample_snapshot(vec![9, 8, 7, 6]);
        save_snapshot(dir.path(), &snap).unwrap();
        let loaded = load_snapshot(dir.path(), &pubkey).unwrap().unwrap();
        assert_eq!(snap, loaded);
    }

    #[test]
    fn clone_account_uses_cache_and_never_touches_network() {
        let dir = tempfile::tempdir().unwrap();
        let pubkey = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
        let snap = sample_snapshot(vec![0xaa, 0xbb]);
        save_snapshot(dir.path(), &snap).unwrap();

        // A cache hit must return before any RPC. The bogus endpoint
        // would fail loudly if the network path were taken.
        let got = clone_account("http://127.0.0.1:1", dir.path(), &pubkey).unwrap();
        assert_eq!(got, snap);
    }

    #[test]
    #[ignore = "hits public mainnet-beta RPC; run explicitly with --ignored"]
    fn live_fetch_token_program_account() {
        let pubkey = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
        let snap = fetch_account(MAINNET_BETA, &pubkey).unwrap();
        assert!(snap.executable, "token program account should be executable");
        assert!(snap.slot > 0);
    }
}
