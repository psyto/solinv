//! # solinv-fuzz capability traits
//!
//! User fixtures implement these traits in addition to Crucible's
//! `#[fuzz_fixture]` requirements, allowing solinv invariants to
//! introspect the instruction set + program registry without competing
//! with Crucible's macro vocabulary.
//!
//! ## Hard fixture requirements (from Day 3 internals deep-read)
//!
//! 1. **Fixture MUST have literal `pub ctx: TestContext` field.**
//!    `#[fuzz_fixture]` macro hard-codes `fixture.ctx.send_batch()`
//!    in `__auto_flush` and `fixture.ctx.svm` / `.dirty_tracker` in
//!    replay paths. `HasContext` trait is **ADDITIVE** — does NOT
//!    substitute for the field. Both required.
//!
//! 2. **solinv invariants execute via `ctx.raw_call(Instruction)`,**
//!    NOT Anchor's `ProgramBuilder.accounts()` path. The typed builder
//!    overwrites the AccountMeta vec, defeating signer-skip detection.
//!    `InstructionSpec::to_instruction()` produces the right shape.

use crucible_test_context::TestContext;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use std::sync::Arc;

/// Fixture provides access to its underlying `TestContext`, the list
/// of program IDs registered, and a tx fee-payer keypair.
///
/// `program_ids()` is needed because `TestContext.programs` is a private
/// field (test-context lib.rs:1332). owner-skip invariant needs this
/// to know which programs are valid owner candidates.
///
/// `fee_payer()` is needed so signer-skip detection can drop the business
/// signer (the account whose `is_signer` flag is being attacked) while
/// keeping a separate fee-paying signer in the tx — otherwise Solana
/// rejects the tx before reaching the program for "no fee payer" reasons
/// rather than the program's missing signer check.
pub trait HasContext {
    fn ctx(&self) -> &TestContext;
    fn ctx_mut(&mut self) -> &mut TestContext;

    /// Programs registered in this fixture's TestContext. Drives owner-
    /// check invariants. Implementor returns the program IDs they passed
    /// to `ctx.add_program(...)` plus any well-known programs (e.g.
    /// SPL Token, sysvars) the fixture relies on.
    fn program_ids(&self) -> Vec<Pubkey>;

    /// Returns a fee-payer keypair that always signs for tx fees but is
    /// never the target of solinv invariant attacks. signer-skip drops
    /// other signers but keeps this one so the tx can reach the program.
    /// The fixture's `setup()` should fund this keypair with sufficient
    /// lamports for the campaign.
    fn fee_payer(&self) -> Arc<Keypair>;
}

/// Fixture enumerates the instructions it knows how to build, with
/// per-account metadata that drives the 5 Critical invariants
/// (signer-skip, owner-skip, discriminator-skip, pda-forge, account-swap).
///
/// Anchor IDL auto-generation should fill `signer_indices`,
/// `expected_owners`, `expected_discriminators`, and `expected_pda_seeds`
/// for Anchor programs. `swap_alternates` requires manual context-binding
/// declaration — semantic relationship that's not IDL-introspectable.
pub trait HasInstructionSet {
    fn instructions(&self) -> Vec<InstructionSpec>;
}

/// Per-instruction specification declaring metadata for solinv's invariant
/// detectors.
///
/// Carries `signers: Vec<Rc<Keypair>>` so solinv invariants can reconstruct
/// the canonical `ctx.raw_call(ix).signers(&...).send()` call path.
#[derive(Clone)]
pub struct InstructionSpec {
    /// Program that this instruction targets.
    pub program_id: Pubkey,

    /// Human-readable instruction name for violation messages.
    pub name: String,

    /// AccountMeta list as the canonical untampered ix would specify.
    /// solinv invariants clone this and mutate per their attack vector
    /// (e.g. `is_signer = false` for signer-skip).
    pub accounts: Vec<AccountMeta>,

    /// Indices into `accounts` declared as signer-required (per IDL
    /// or capability trait implementor's domain knowledge).
    pub signer_indices: Vec<usize>,

    /// Indices that may be signer OR unsigned (instruction supports both
    /// forms — e.g. a crank with optional admin override). Excluded from
    /// signer-skip detection because flipping is not a real bug.
    pub optional_signer_indices: Vec<usize>,

    /// Per-account expected owner program.
    /// `None` = no owner expectation (e.g., user wallet, externally-
    /// controlled account, intentional any-owner ix).
    /// `Some(pk)` = account MUST be owned by `pk`; owner-skip verifies
    /// the program checks this.
    pub expected_owners: Vec<Option<Pubkey>>,

    /// Per-account expected account discriminator (first 8 bytes of
    /// account data). `None` = no discriminator convention for this
    /// account (e.g., raw SOL accounts, custom layouts).
    /// `Some([..])` = data MUST start with these bytes; discriminator-
    /// skip verifies the program checks this.
    pub expected_discriminators: Vec<Option<[u8; 8]>>,

    /// Per-account PDA seed declaration. Each Vec<u8> in seeds is one
    /// seed component (literal bytes, pubkey as_ref, etc.).
    /// `None` = account is not a PDA (e.g., user wallet, ATA, sysvar).
    /// `Some(seeds)` = account MUST be derivable via
    /// `Pubkey::find_program_address(seeds, program_id)`; pda-forge
    /// verifies the program checks this.
    pub expected_pda_seeds: Vec<Option<Vec<Vec<u8>>>>,

    /// Indices being created (allocated) during this ix. Excluded from
    /// pda-forge testing — runtime auto-verifies seed correctness via
    /// `invoke_signed` at account creation time.
    pub creates_indices: Vec<usize>,

    /// Per-account alternate-context pubkeys (real legitimate accounts
    /// from different contexts) for account-swap detection.
    /// Each entry: list of legitimate alternates with same owner +
    /// discriminator + PDA derivation, but representing a different
    /// context (different user, market, epoch, etc.).
    /// Empty inner vec = no swap testing for that account (e.g., caller's
    /// own wallet, permissionless ix accepting any context).
    pub swap_alternates: Vec<Vec<Pubkey>>,

    /// Sample instruction data sufficient to exercise the auth path.
    /// Fuzzer mutates this; user provides at least one valid sample.
    pub data_sample: Vec<u8>,

    /// Keypairs that sign the canonical (untampered) instruction.
    /// solinv signer-skip detection drops the target signer from this
    /// list when constructing the attack:
    /// `signers.iter().enumerate().filter(|(i, _)| *i != sig_idx)`.
    ///
    /// `Arc` (not `Rc`) so the type is `Send + Sync` — enables LibAFL
    /// multi-thread workers and future async fuzzing. Same API at
    /// negligible atomic-op cost (keypair clone is per-test, not hot).
    pub signers: Vec<Arc<Keypair>>,

    /// State-transition invariants for the unchecked-math detector
    /// (Day 31+ High-tier addition). Empty for ix where the user has
    /// not declared monetary-state checks. See
    /// `docs/invariants/unchecked-math.md` for the design and the
    /// kill criterion gating Phase 3 expansion.
    pub state_invariants: Vec<StateInvariant>,

    /// Compute-unit cap for the cu-dos detector (Day 35+ High-tier
    /// addition). `None` = opt out (default, no cu-dos check).
    /// `Some(N)` = ix must complete in ≤ N CU; consumption above
    /// fires a violation. See `docs/invariants/cu-dos.md` for cap
    /// selection guidance + §9 kill criterion.
    pub cu_budget: Option<u64>,

    /// CPI re-entrancy detector config (Day 58+ High-tier addition).
    /// `None` = opt out (default, no re-entrancy check).
    /// `Some(cfg)` = parse TxOutcome.logs for "Program {pid} invoke
    /// [depth]" entries, fire if any pid appears at two depths
    /// simultaneously. `cfg.allowlist` exempts intentional re-entry
    /// patterns (governance nested votes, delegation chains).
    /// See `docs/invariants/cpi-reentrancy.md` for design + §9 / §10
    /// Phase 2.5 framing transition.
    pub cpi_reentrancy: Option<CpiReentrancyConfig>,

    /// Realloc-race detector config (Day 59+ High-tier addition).
    /// `None` = opt out (default, no realloc check).
    /// `Some(cfg)` = pre/post ix state snapshot of every account's
    /// `data.len()` + `lamports`, fire if any account grew without
    /// the lamport balance covering the new rent-exempt minimum
    /// (`(128 + new_len) * 3480 * 2`). v1 config is empty; future
    /// versions may carry per-account rent-rate overrides or
    /// "allow temporary shortfall" toggles for staged top-up patterns.
    /// See `docs/invariants/realloc-race.md` for design + §9 / §10.
    pub realloc_check: Option<ReallocCheckConfig>,

    /// Bump-seed-canonicalization detector config (Day 60+ High-tier
    /// addition). `None` = opt out. `Some(cfg)` = for each PDA account
    /// in `expected_pda_seeds`, find a non-canonical bump that yields
    /// a different valid PDA, substitute it in the AccountMeta (and
    /// optionally in `data_sample` if `cfg.bump_data_offset` is
    /// `Some`), fire if the ix still succeeds. See
    /// `docs/invariants/bump-seed-canonicalization.md` for design +
    /// §9 / §10.
    pub bump_seed_check: Option<BumpSeedCheckConfig>,

    /// Preconditions the instruction must satisfy to be *allowed* to
    /// succeed. Empty = opt out.
    ///
    /// Every other capability here describes what an instruction may
    /// not do to state. These describe when it may run at all — the
    /// `require!` at the top of a handler, restated where a detector
    /// can check it. A mutation campaign on escrow-clean located the
    /// gap: five of its nine survivors were dropped `require!` guards
    /// on timelocks and amount bounds, and no invariant in the catalog
    /// modelled that shape, including the timelock race that
    /// escrow-demo plants as its flagship bug.
    pub guards: Vec<GuardCondition>,
}

/// Per-ix configuration for the cpi-reentrancy detector. Carried
/// inside `InstructionSpec.cpi_reentrancy` as `Some(cfg)` to opt
/// in. See `docs/invariants/cpi-reentrancy.md` §3 + §5.
#[derive(Clone, Debug, Default)]
pub struct CpiReentrancyConfig {
    /// Program IDs explicitly permitted to re-enter the spec's
    /// `program_id`. Empty (default) = no re-entry allowed; any
    /// observed cycle through this program fires. Non-empty =
    /// re-entry through any listed pid is silently accepted.
    pub allowlist: Vec<Pubkey>,
}

/// Per-ix configuration for the realloc-race detector. Carried
/// inside `InstructionSpec.realloc_check` as `Some(cfg)` to opt
/// in. v1 is config-free — Default is sufficient. See
/// `docs/invariants/realloc-race.md` §3.
#[derive(Clone, Debug, Default)]
pub struct ReallocCheckConfig {
    // v1 reserved for future per-account rent-rate overrides and
    // "allow temporary shortfall" toggles for staged top-up patterns.
}

/// Per-ix configuration for the bump-seed-canonicalization detector.
/// A precondition that must hold whenever the instruction succeeds.
///
/// Read it as: "`withdraw` may only succeed while `slot <
/// vault.unlock_slot`". The detector evaluates the comparison against
/// the *pre*-state and fires when the instruction was accepted anyway.
/// Restating the guard rather than inferring it is deliberate — a
/// handler's `require!` is a claim about intent, and intent is the one
/// thing a detector cannot read off the binary.
///
/// A guard that is merely *hard* to satisfy is not a violation. Only a
/// success while the condition was false is, which is why the pre-state
/// is captured before the send: evaluating afterwards would compare
/// against state the instruction itself moved.
#[derive(Clone, Debug)]
pub struct GuardCondition {
    /// Name surfaced in the violation message. Say what the rule is —
    /// "withdraw only before unlock" reads better in a report than
    /// "guard_1".
    pub name: String,
    pub lhs: GuardOperand,
    pub op: GuardOp,
    pub rhs: GuardOperand,
}

/// One side of a [`GuardCondition`].
#[derive(Clone, Debug)]
pub enum GuardOperand {
    /// Unsigned little-endian field in an account's data. `account_index`
    /// indexes `InstructionSpec.accounts`; widths follow the same 8/16
    /// rule as `StateInvariant`.
    Field {
        account_index: usize,
        field_offset: usize,
        field_size: usize,
    },
    /// The cluster clock's slot at the moment of the send. The operand
    /// that makes timelocks expressible.
    Slot,
    /// Unsigned little-endian value read out of the instruction data,
    /// for guards on an argument — `amount <= vault.amount`. Offsets
    /// are from the start of the data, so an Anchor argument starts at
    /// 8, after the sighash.
    IxData { offset: usize, size: usize },
    Const(u128),
}

/// Comparison operator for a [`GuardCondition`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardOp {
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
    Ne,
}

impl GuardOp {
    /// Apply the operator. Kept next to the enum so a new variant
    /// cannot be added without an arm here.
    pub fn holds(self, lhs: u128, rhs: u128) -> bool {
        match self {
            GuardOp::Lt => lhs < rhs,
            GuardOp::Le => lhs <= rhs,
            GuardOp::Gt => lhs > rhs,
            GuardOp::Ge => lhs >= rhs,
            GuardOp::Eq => lhs == rhs,
            GuardOp::Ne => lhs != rhs,
        }
    }

    /// Rendering for violation messages.
    pub fn symbol(self) -> &'static str {
        match self {
            GuardOp::Lt => "<",
            GuardOp::Le => "<=",
            GuardOp::Gt => ">",
            GuardOp::Ge => ">=",
            GuardOp::Eq => "==",
            GuardOp::Ne => "!=",
        }
    }
}

/// Carried inside `InstructionSpec.bump_seed_check` as `Some(cfg)`
/// to opt in. See `docs/invariants/bump-seed-canonicalization.md` §3.
#[derive(Clone, Debug, Default)]
pub struct BumpSeedCheckConfig {
    /// Offset into `data_sample` where the bump byte lives, if the
    /// ix takes a bump as an explicit argument. `None` = no ix-data
    /// bump (the program reads the bump from the targeted account's
    /// data, hardcodes it, or uses no bump). When `Some(offset)`,
    /// the detector patches `data[offset] = alt_bump` before sending
    /// — surfaces the ix-data-bump sub-pattern from the spec §1.
    pub bump_data_offset: Option<usize>,
}

/// User-declared assertion about how a monetary state field should
/// evolve across an ix execution. Carried inside `InstructionSpec`
/// so the same per-ix declaration drives the detector.
#[derive(Clone, Debug)]
pub struct StateInvariant {
    /// Human-readable name surfaced in violation messages.
    pub name: String,

    /// The shape of the invariant.
    pub kind: StateInvariantKind,

    /// Indices into the parent `InstructionSpec.accounts` list naming
    /// which accounts the field should be read from. Single-element
    /// for Monotonic / Bounded per-account checks; multi-element for
    /// SumConservation across a related account set.
    pub accounts: Vec<usize>,
}

/// Kinds of state invariant the unchecked-math detector understands.
///
/// The first three read a fixed-size field (u64 or u128) from each
/// declared account's `data` at `field_offset`. v1 supports 8- and
/// 16-byte widths; lamports / sysvar / signed-int reads are out of
/// scope and can be added in a v2 extension.
///
/// `Relation` is the one kind that does NOT use the parent
/// `StateInvariant.accounts` list — it carries its own per-term
/// account indices, because a relation spans accounts that each
/// contribute a *different* field.
///
/// This enum is deliberately a **closed grammar**. Every variant is a
/// small struct of integers plus an operator, so a candidate invariant
/// can be validated before it is ever executed. Adding a general
/// expression language would buy expressiveness at the cost of the one
/// property that makes generated invariants checkable — see
/// `docs/invariants/field-schema.md` §2.
#[derive(Clone, Debug)]
pub enum StateInvariantKind {
    /// The unsigned sum of `field` across `accounts` is unchanged by
    /// the ix, modulo `tolerance` (covers expected fee dust /
    /// 1-wei rounding). Drift beyond tolerance fires.
    SumConservation {
        field_offset: usize,
        field_size: usize,
        tolerance: u64,
    },
    /// The field in each declared account is monotonic across the ix
    /// in the chosen direction. Catches counters that wrap and
    /// balances that should only ever grow / only ever shrink under
    /// a given ix.
    Monotonic {
        field_offset: usize,
        field_size: usize,
        direction: MonotonicDir,
    },
    /// The field in each declared account stays within `[min, max]`
    /// post-ix. Catches wrap-to-near-MAX after underflow without
    /// requiring a pre-state baseline.
    Bounded {
        field_offset: usize,
        field_size: usize,
        min: u128,
        max: u128,
    },
    /// An arithmetic relation between two sides, each the unsigned sum
    /// of its terms: `sum(lhs) <op> sum(rhs)`.
    ///
    /// This is the shape most protocol-specific invariants actually
    /// take — `reserve.liquidity + reserve.borrowed == reserve.total`,
    /// `sum(user.deposits) <= vault.balance` — and it is the one the
    /// other three kinds cannot express, because they read a *single*
    /// field geometry across a *uniform* account list.
    ///
    /// Semantics are pre-gated: the detector fires only when the
    /// relation **held before the ix and failed after it**. A relation
    /// that was already false pre-ix indicts the declaration or the
    /// fixture, not the instruction, so firing on it would be a false
    /// positive attributed to the wrong cause. That case is reported
    /// separately as a declaration diagnostic rather than silently
    /// dropped — see `docs/invariants/field-schema.md` §4.
    ///
    /// `tolerance` applies to `RelOp::Eq` only (fee dust / rounding),
    /// matching `SumConservation`; it is ignored by the ordering
    /// operators, where a slack allowance would silently widen the
    /// property being asserted.
    Relation {
        lhs: Vec<RelTerm>,
        op: RelOp,
        rhs: Vec<RelTerm>,
        tolerance: u64,
    },
}

/// One addend on either side of a [`StateInvariantKind::Relation`].
///
/// Terms are summed, never multiplied — see the closed-grammar note on
/// [`StateInvariantKind`]. A ratio property (`fee <= total / 100`) is
/// deliberately not expressible in v1.
#[derive(Clone, Debug)]
pub enum RelTerm {
    /// Read a field from one account named by index into the parent
    /// `InstructionSpec.accounts` list.
    Field {
        account: usize,
        field_offset: usize,
        field_size: usize,
    },
    /// A literal constant, for relations with a fixed bound that also
    /// carry field terms (a constant-only bound belongs in `Bounded`).
    Const(u128),
}

/// Comparison operator for [`StateInvariantKind::Relation`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelOp {
    /// `sum(lhs) == sum(rhs)`, modulo the relation's `tolerance`.
    Eq,
    /// `sum(lhs) <= sum(rhs)`.
    Le,
    /// `sum(lhs) < sum(rhs)`.
    Lt,
    /// `sum(lhs) >= sum(rhs)`.
    Ge,
    /// `sum(lhs) > sum(rhs)`.
    Gt,
}

impl RelOp {
    /// Evaluate the operator over two already-summed sides.
    ///
    /// `tolerance` is honored by `Eq` only; the ordering operators
    /// ignore it so that a tolerance set for an equality relation
    /// cannot silently loosen an inequality one.
    pub fn holds(&self, lhs: u128, rhs: u128, tolerance: u64) -> bool {
        match self {
            RelOp::Eq => lhs.abs_diff(rhs) <= tolerance as u128,
            RelOp::Le => lhs <= rhs,
            RelOp::Lt => lhs < rhs,
            RelOp::Ge => lhs >= rhs,
            RelOp::Gt => lhs > rhs,
        }
    }

    /// Infix symbol for violation messages.
    pub fn symbol(&self) -> &'static str {
        match self {
            RelOp::Eq => "==",
            RelOp::Le => "<=",
            RelOp::Lt => "<",
            RelOp::Ge => ">=",
            RelOp::Gt => ">",
        }
    }
}

/// Direction for a `Monotonic` invariant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MonotonicDir {
    /// Field must not decrease across the ix (e.g. cumulative
    /// reward index, total deposits, monotonic counter).
    NonDecreasing,
    /// Field must not increase across the ix (e.g. remaining
    /// allocation, vesting countdown).
    NonIncreasing,
}

impl MonotonicDir {
    /// Past-tense adverb describing a *violation* of this direction,
    /// for use in violation messages.
    pub fn violation_word(&self) -> &'static str {
        match self {
            MonotonicDir::NonDecreasing => "decreased",
            MonotonicDir::NonIncreasing => "increased",
        }
    }
}

impl InstructionSpec {
    /// Lower to a runtime `Instruction` suitable for `ctx.raw_call(...)`.
    ///
    /// Day 3 finding: solinv MUST use `raw_call`, not Anchor's typed
    /// `ProgramBuilder.accounts()` path. The typed path takes a value
    /// implementing `ToAccountMetas` and always overwrites the
    /// AccountMeta vec — destroying any signer/writable flags solinv
    /// has mutated. `raw_call(Instruction)` preserves the vec as-is.
    pub fn to_instruction(&self) -> Instruction {
        Instruction {
            program_id: self.program_id,
            accounts: self.accounts.clone(),
            data: self.data_sample.clone(),
        }
    }
}
