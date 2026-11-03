//! # solinv-fuzz
//!
//! Capability traits + InstructionSpec for solinv invariants. Plugin
//! layer on top of Crucible (asymmetric-research) — re-exports
//! Crucible's public API and adds solinv-specific extension surfaces.
//!
//! See `docs/research-crucible-integration.md` for the integration
//! architecture rationale, and `docs/implementation-day3-crucible-internals.md`
//! for the 7 design corrections this crate implements.

// Re-export Crucible's full public surface.
pub use crucible_fuzzer::*;

// Day 3 finding: these exist in crucible-test-context but are NOT
// re-exported by crucible-fuzzer/src/lib.rs (48-line file is incomplete).
// solinv-fuzz adds them so user harnesses get them via one import.
pub use crucible_test_context::{
    clear_violation_tracking, get_violation_action_index, has_violation, record_violation,
    set_violation_action_index, take_violation, TxError, TxOutcome,
};

pub mod bytepoke;
pub mod capability;
pub mod differential;
pub mod idl;
pub mod schema;
pub mod state_coverage;
pub use bytepoke::{
    anchor_account_disc, anchor_ix_sighash, rent_for_anchor_body, rent_for_raw, write_bytes_at,
    write_i64_at, write_pubkey_at, write_u128_at, write_u16_at, write_u32_at, write_u64_at,
    write_u8_at, AnchorAccountBuilder,
};
pub use capability::{
    BumpSeedCheckConfig, CpiReentrancyConfig, GuardCondition, GuardOp, GuardOperand, HasContext,
    HasInstructionSet, InstructionSpec, MonotonicDir, ReallocCheckConfig, RelOp, RelTerm,
    StateInvariant, StateInvariantKind,
};
pub use schema::{
    relation, AccountSchema, SchemaError, SchemaField, ANCHOR_DISCRIMINATOR_LEN, READABLE_WIDTHS,
};
pub use idl::{Idl, IdlError, IdlSpec, Inferred, InferredKind, SpecBuilder, Unresolved};
pub use differential::{
    check_all_pairs, check_pair_equivalent, read_pair_bodies, BodyDivergence, CuComparison,
    DiffAccountPair, DifferentialFixture, ParityDivergence, SendFailure, SideResult,
};
pub use state_coverage::{fingerprint_key, TokenFlowShape, TransitionObservation};

/// Single-import prelude for solinv harness users.
///
/// ```ignore
/// use solinv_fuzz::prelude::*;
/// ```
pub mod prelude {
    pub use crate::bytepoke::{
        anchor_account_disc, anchor_ix_sighash, rent_for_anchor_body, rent_for_raw, write_bytes_at,
        write_i64_at, write_pubkey_at, write_u128_at, write_u16_at, write_u32_at, write_u64_at,
        write_u8_at, AnchorAccountBuilder,
    };
    pub use crate::capability::{
        HasContext, HasInstructionSet, InstructionSpec, MonotonicDir, RelOp, RelTerm,
        StateInvariant, StateInvariantKind,
    };
    pub use crate::idl::{Idl, IdlError, IdlSpec, Inferred, InferredKind, SpecBuilder, Unresolved};
    pub use crate::schema::{relation, AccountSchema, SchemaError, SchemaField};
    pub use crate::differential::{
        check_all_pairs, check_pair_equivalent, read_pair_bodies, BodyDivergence, CuComparison,
        DiffAccountPair, DifferentialFixture, ParityDivergence, SendFailure, SideResult,
    };
    pub use crate::state_coverage::{fingerprint_key, TokenFlowShape, TransitionObservation};
    pub use crucible_fuzzer::*;
    pub use crucible_test_context::{
        clear_violation_tracking, get_violation_action_index, has_violation, record_violation,
        set_violation_action_index, take_violation, TxError, TxOutcome,
    };
}
