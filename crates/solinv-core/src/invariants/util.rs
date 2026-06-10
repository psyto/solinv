//! Shared utilities for invariant detection.

use crucible_test_context::TestContext;
use solana_account::Account;
use solana_pubkey::Pubkey;
use std::collections::HashSet;
use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

/// Hash a snapshot of accounts. Used to detect state changes between
/// pre- and post-attack send.
///
/// Captures the load-bearing fields: data, lamports, owner. Pubkey is
/// included so two equal-content accounts at different addresses don't
/// collide.
pub(crate) fn hash_accounts(saves: &[(Pubkey, Account)]) -> u64 {
    let mut h = DefaultHasher::new();
    for (pk, acct) in saves {
        h.write(pk.as_ref());
        h.write(&acct.data);
        h.write_u64(acct.lamports);
        h.write(acct.owner.as_ref());
        h.write_u8(u8::from(acct.executable));
        h.write_u64(acct.rent_epoch);
    }
    h.finish()
}

/// Re-read the given pubkeys' current accounts from ctx and hash them.
/// Used post-attack to detect state changes vs the pre-attack hash.
///
/// Pubkeys not present in ctx are skipped (account may have been
/// closed by the attack, which itself is a state change but is
/// detectable via pre/post diff).
pub(crate) fn hash_accounts_now<I>(ctx: &TestContext, pubkeys: I) -> u64
where
    I: IntoIterator<Item = Pubkey>,
{
    let saves: Vec<_> = pubkeys
        .into_iter()
        .filter_map(|pk| ctx.get_account(&pk).ok().map(|a| (pk, a)))
        .collect();
    hash_accounts(&saves)
}

/// Save the accounts an invariant is about to mutate. Returns
/// `(pubkey, Account)` tuples suitable for restoring via
/// `write_account()` after the attack.
///
/// Day 3 finding: do NOT use `TestContext::take_snapshot` /
/// `restore_snapshot` here. Those are iteration-scoped and restoring
/// would undo prior actions' state. Manual per-account save/restore
/// is the right pattern inside an invariant body.
pub(crate) fn save_accounts(ctx: &TestContext, pubkeys: &[Pubkey]) -> Vec<(Pubkey, Account)> {
    pubkeys
        .iter()
        .filter_map(|pk| ctx.get_account(pk).ok().map(|a| (*pk, a)))
        .collect()
}

/// Restore previously-saved accounts. Day 3 finding: write_account
/// (test-context lib.rs:2009) marks dirty automatically. Touching only
/// the accounts the invariant cares about keeps cost to O(5-10) writes
/// per detection instead of O(all dirty accounts) for restore_snapshot.
pub(crate) fn restore_accounts(ctx: &mut TestContext, saves: Vec<(Pubkey, Account)>) {
    for (pk, acct) in saves {
        let _ = ctx.write_account(&pk, acct);
    }
}

/// Read a little-endian unsigned integer field from an account's data,
/// widened to u128 so all supported widths share one return type.
///
/// Returns `None` if the requested range is out of bounds or the size
/// is neither 8 (u64) nor 16 (u128). Other widths are deliberately not
/// supported in v1 — the spec scopes unchecked-math detection to
/// 8/16-byte monetary fields.
pub(crate) fn read_field_widened(data: &[u8], offset: usize, size: usize) -> Option<u128> {
    let end = offset.checked_add(size)?;
    if end > data.len() {
        return None;
    }
    match size {
        8 => {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&data[offset..end]);
            Some(u64::from_le_bytes(buf) as u128)
        }
        16 => {
            let mut buf = [0u8; 16];
            buf.copy_from_slice(&data[offset..end]);
            Some(u128::from_le_bytes(buf))
        }
        _ => None,
    }
}

/// Best-effort cleanup for temporary fake accounts created by invariants.
/// We overwrite with a tiny inert system-owned account to keep memory
/// pressure bounded during long fuzz campaigns.
pub(crate) fn cleanup_temp_account(ctx: &mut TestContext, pubkey: &Pubkey) {
    let _ = ctx.write_account(
        pubkey,
        Account {
            lamports: 0,
            data: Vec::new(),
            owner: Pubkey::default(),
            executable: false,
            rent_epoch: 0,
        },
    );
}

static TRANSITION_FINGERPRINTS: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
static LAST_REPORTED_COUNT: AtomicUsize = AtomicUsize::new(0);

fn fingerprint_store() -> &'static Mutex<HashSet<String>> {
    TRANSITION_FINGERPRINTS.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Record one state-transition fingerprint and return whether it is new.
pub(crate) fn record_transition_fingerprint(key: String) -> bool {
    let guard = fingerprint_store().lock();
    let mut set = match guard {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    let is_new = set.insert(key);
    if is_new {
        maybe_report_transition_metrics(set.len());
    }
    is_new
}

/// Number of unique transition fingerprints seen in this process.
pub fn unique_transition_fingerprint_count() -> usize {
    let guard = fingerprint_store().lock();
    let set = match guard {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    set.len()
}

/// Clear accumulated transition fingerprints.
pub fn reset_transition_fingerprints() {
    let guard = fingerprint_store().lock();
    let mut set = match guard {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    set.clear();
    LAST_REPORTED_COUNT.store(0, Ordering::Relaxed);
}

fn maybe_report_transition_metrics(current: usize) {
    if std::env::var("SOLINV_TRANSITION_METRICS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        // Emit low-noise milestones only (1,2,4,8,16,...).
        if current.is_power_of_two() {
            let prev = LAST_REPORTED_COUNT.load(Ordering::Relaxed);
            if current > prev {
                LAST_REPORTED_COUNT.store(current, Ordering::Relaxed);
                eprintln!(
                    "[solinv][transition-coverage] unique_fingerprints={}",
                    current
                );
            }
        }
    }
}
