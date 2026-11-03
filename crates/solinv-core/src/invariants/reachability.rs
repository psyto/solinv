//! # Reachability ledger — which instructions a campaign actually drove
//!
//! A mutation campaign needs to distinguish two runs that look
//! identical from outside: one where a detector was asked about the
//! mutated code and said nothing, and one where the mutated code never
//! executed at all. The first is a detector blind spot. The second is
//! a campaign that never asked, and counting it against the detector is
//! how a mutation score turns into a confident wrong answer.
//!
//! solinv has already measured this from the other direction —
//! `bump-seed-canonicalization` detects its planted bug at roughly 2%
//! because the substitution attack needs the canonical vault to exist
//! first. Reachability, not sensitivity, sets that rate.
//!
//! ## What is recorded, and what it can prove
//!
//! An entry is made when solinv sends a **canonical** (untampered)
//! instruction and the runtime accepts it — the four detectors that do
//! so are `unchecked-math`, `cu-dos`, `cpi-reentrancy` and
//! `realloc-race`. The five Critical detectors deliberately send
//! *tampered* instructions and expect them to fail, so their sends say
//! nothing about whether the program's happy path ran.
//!
//! The resulting signal is asymmetric, and the asymmetry is the whole
//! point:
//!
//! - **An ix that never appears here certainly did not execute.** That
//!   is a sound negative, and it is what licenses classifying a mutant
//!   as `not_reached`.
//! - **An ix that appears here executed, but that does not prove the
//!   mutated *line* ran** — the mutation may sit in a branch the run
//!   never took.
//!
//! So a consumer may use this to demote a mutant to `not_reached`,
//! never to promote one to `survived`. Counting a possibly-unreached
//! mutant as a survivor errs against the detector, which is the
//! direction an honest score should err in.
//!
//! ## Emission
//!
//! The ledger is always maintained — it is a small set — but the
//! stderr line is opt-in via `SOLINV_REACHABILITY=1`, matching
//! `SOLINV_BANDIT_METRICS` and `SOLINV_TRANSITION_METRICS`. Unlike the
//! declaration diagnostics in `util`, this is campaign telemetry rather
//! than a report that the harness is broken, so gating it is right.
//!
//! ```text
//! [solinv][reached] ix=swap program=675kPX9M...
//! ```
//!
//! One line per distinct instruction, on first successful canonical
//! execution.

use solana_pubkey::Pubkey;
use std::collections::BTreeSet;
use std::sync::{Mutex, OnceLock};

static REACHED: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();

fn ledger() -> &'static Mutex<BTreeSet<String>> {
    REACHED.get_or_init(|| Mutex::new(BTreeSet::new()))
}

fn with_ledger<R>(f: impl FnOnce(&mut BTreeSet<String>) -> R) -> R {
    let guard = ledger().lock();
    let mut set = match guard {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    f(&mut set)
}

/// Record that a canonical instruction executed successfully.
///
/// Idempotent per `(program_id, ix_name)`: the ledger answers "did this
/// ever run", not "how often", because that is all a reachability
/// verdict needs and a counter would invite reading a frequency into
/// it.
pub fn record_ix_reached(program_id: &Pubkey, ix_name: &str) {
    let key = format!("{program_id}:{ix_name}");
    let is_new = with_ledger(|set| set.insert(key));
    if is_new && emission_enabled() {
        eprintln!("[solinv][reached] ix={ix_name} program={program_id}");
    }
}

/// Whether a given instruction has been recorded as reached.
pub fn is_ix_reached(program_id: &Pubkey, ix_name: &str) -> bool {
    let key = format!("{program_id}:{ix_name}");
    with_ledger(|set| set.contains(&key))
}

/// Every `program_id:ix_name` recorded so far, sorted.
pub fn reached_ixs() -> Vec<String> {
    with_ledger(|set| set.iter().cloned().collect())
}

/// Clear the ledger. Test-support hook — a fresh process starts empty.
pub fn reset_reachability() {
    with_ledger(|set| set.clear());
}

fn emission_enabled() -> bool {
    std::env::var("SOLINV_REACHABILITY")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The ledger is process-global, so these tests coordinate through
    // one lock rather than each resetting it — parallel test threads
    // would otherwise clear each other's entries.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn pid(byte: u8) -> Pubkey {
        Pubkey::new_from_array([byte; 32])
    }

    #[test]
    fn records_and_reports_an_ix() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        reset_reachability();
        assert!(!is_ix_reached(&pid(1), "swap"));
        record_ix_reached(&pid(1), "swap");
        assert!(is_ix_reached(&pid(1), "swap"));
    }

    #[test]
    fn distinguishes_ixs_by_program() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        reset_reachability();
        record_ix_reached(&pid(1), "swap");
        assert!(!is_ix_reached(&pid(2), "swap"), "same name, other program");
    }

    #[test]
    fn recording_is_idempotent() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        reset_reachability();
        record_ix_reached(&pid(3), "deposit");
        record_ix_reached(&pid(3), "deposit");
        record_ix_reached(&pid(3), "deposit");
        assert_eq!(reached_ixs().len(), 1);
    }

    #[test]
    fn unrecorded_ixs_read_as_unreached() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        reset_reachability();
        record_ix_reached(&pid(4), "swap");
        // The sound negative: absence means it certainly did not run.
        assert!(!is_ix_reached(&pid(4), "withdraw"));
    }
}
