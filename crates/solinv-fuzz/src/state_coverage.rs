//! State-transition coverage fingerprinting utilities.
//!
//! Crucible edge coverage saturates early on some surfaces. This module
//! provides a second novelty signal: semantic transition fingerprints
//! derived from `InstructionSpec` + lightweight runtime observations.

use crate::capability::InstructionSpec;

/// Coarse token-flow shape observed during one ix execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenFlowShape {
    Unknown,
    InboundOnly,
    OutboundOnly,
    Bidirectional,
    NoMovement,
}

/// Optional runtime observations attached to one execution attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransitionObservation {
    pub cpi_depth: u8,
    pub token_flow: TokenFlowShape,
}

impl Default for TransitionObservation {
    fn default() -> Self {
        Self {
            cpi_depth: 0,
            token_flow: TokenFlowShape::Unknown,
        }
    }
}

/// Stable, hashable-ish fingerprint key for novelty tracking.
///
/// Intended usage:
/// - maintain `HashSet<String>` per campaign
/// - reward inputs that add unseen keys
pub fn fingerprint_key(spec: &InstructionSpec, obs: TransitionObservation) -> String {
    let acct_total = spec.accounts.len();
    let signer_required = spec.signer_indices.len();
    let signer_optional = spec.optional_signer_indices.len();
    let writable = spec.accounts.iter().filter(|m| m.is_writable).count();
    let owner_scoped = spec.expected_owners.iter().filter(|o| o.is_some()).count();
    let discr_scoped = spec
        .expected_discriminators
        .iter()
        .filter(|d| d.is_some())
        .count();
    let pda_scoped = spec
        .expected_pda_seeds
        .iter()
        .filter(|s| s.is_some())
        .count();
    let swap_surface = spec.swap_alternates.iter().filter(|alts| !alts.is_empty()).count();
    let cpi_bucket = bucket_cpi_depth(obs.cpi_depth);
    let flow = token_flow_code(obs.token_flow);

    format!(
        "pid:{}|acct:{}|wr:{}|sig:{}+{}|own:{}|disc:{}|pda:{}|swap:{}|cpi:{}|flow:{}",
        spec.program_id,
        acct_total,
        writable,
        signer_required,
        signer_optional,
        owner_scoped,
        discr_scoped,
        pda_scoped,
        swap_surface,
        cpi_bucket,
        flow
    )
}

fn bucket_cpi_depth(depth: u8) -> u8 {
    match depth {
        0 => 0,
        1 => 1,
        2..=3 => 2,
        4..=7 => 3,
        _ => 4,
    }
}

fn token_flow_code(flow: TokenFlowShape) -> &'static str {
    match flow {
        TokenFlowShape::Unknown => "unk",
        TokenFlowShape::InboundOnly => "in",
        TokenFlowShape::OutboundOnly => "out",
        TokenFlowShape::Bidirectional => "bi",
        TokenFlowShape::NoMovement => "none",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_instruction::AccountMeta;
    use solana_keypair::Keypair;
    use solana_pubkey::Pubkey;
    use std::sync::Arc;

    fn sample_spec() -> InstructionSpec {
        let pid = Pubkey::new_unique();
        let user = Pubkey::new_unique();
        let vault = Pubkey::new_unique();
        InstructionSpec {
            program_id: pid,
            name: "swap".to_string(),
            accounts: vec![
                AccountMeta::new(user, true),
                AccountMeta::new(vault, false),
                AccountMeta::new_readonly(Pubkey::new_unique(), false),
            ],
            signer_indices: vec![0],
            optional_signer_indices: vec![],
            expected_owners: vec![None, Some(pid), None],
            expected_discriminators: vec![None, Some([1u8; 8]), None],
            expected_pda_seeds: vec![None, Some(vec![b"vault".to_vec()]), None],
            creates_indices: vec![],
            swap_alternates: vec![vec![], vec![Pubkey::new_unique()], vec![]],
            data_sample: vec![1, 2, 3],
            signers: vec![Arc::new(Keypair::new())],
            state_invariants: vec![],
            cu_budget: None,
            cpi_reentrancy: None,
            realloc_check: None,
            bump_seed_check: None,
        }
    }

    #[test]
    fn fingerprint_changes_with_observation() {
        let spec = sample_spec();
        let k1 = fingerprint_key(
            &spec,
            TransitionObservation {
                cpi_depth: 0,
                token_flow: TokenFlowShape::Unknown,
            },
        );
        let k2 = fingerprint_key(
            &spec,
            TransitionObservation {
                cpi_depth: 5,
                token_flow: TokenFlowShape::Bidirectional,
            },
        );
        assert_ne!(k1, k2);
    }
}
