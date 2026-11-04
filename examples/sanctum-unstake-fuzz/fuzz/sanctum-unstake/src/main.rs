//! # sanctum-unstake-fuzz — Phase 4 N=2 protocol-variety harness
//!
//! Targets `igneous-labs/sanctum-unstake-program` (Anchor 0.28). N=2
//! protocol-size axis re-test — same code-quality class as Slumlord
//! N=1 (igneous-labs team) but ~6.5× the binary size and 15 ix vs 4.
//!
//! Phase 4 protocol-variety stopping rule: 2 protocol-size negatives
//! close the axis and bind the protocol-variety pivot.
//!
//! Day 45 scope: minimum-viable compiling scaffold. setup() loads
//! the program and calls `init_protocol_fee` (permissionless,
//! creates the global ProtocolFee PDA). Day 46+ adds CreatePool +
//! first attackable InstructionSpec.

use crucible_fuzzer::*;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use std::str::FromStr;
use std::sync::Arc;

use solinv_fuzz::{
    anchor_account_disc, anchor_ix_sighash, HasContext, HasInstructionSet, InstructionSpec,
};

// ---------------------------------------------------------------------
// Sanctum unstake on-chain identity
// ---------------------------------------------------------------------

/// Mainnet program ID. The unstake program has two `declare_id!`
/// calls (lib.rs:6,9): `6KBz9djJAH3gRHscq9ujMpyZ5bCK9a27o3ybDtJLXowz`
/// under the `local-testing` feature flag and
/// `unpXTU2Ndrc7WWNyEhQWe4udTzSibLPi25SXv2xbCHQ` otherwise. We build
/// without `local-testing` (Day 44 build smoke), so the deployed .so
/// is hard-coded with the mainnet ID. Loading it at the localnet ID
/// triggers Anchor's `DeclaredProgramIdMismatch (4100)` check.
const SANCTUM_UNSTAKE_PROGRAM_ID_STR: &str = "unpXTU2Ndrc7WWNyEhQWe4udTzSibLPi25SXv2xbCHQ";

const SANCTUM_UNSTAKE_SO_PATH: &str =
    env!("SANCTUM_UNSTAKE_SO", "set SANCTUM_UNSTAKE_SO to the mainnet unstake.so — see this example's README");

/// Per `programs/unstake/src/state/protocol_fee.rs` PROTOCOL_FEE_SEED.
/// The global ProtocolFee PDA is at seeds=[b"protocol-fee"].
const PROTOCOL_FEE_SEED: &[u8] = b"protocol-fee";

/// Per `programs/unstake/src/state/fee.rs` FEE_SEED_SUFFIX.
/// The Fee PDA per pool is at seeds=[pool_account.key(), b"fee"].
const FEE_SEED_SUFFIX: &[u8] = b"fee";

const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);

const FEE_PAYER_BALANCE: u64 = 10_000_000_000;

const FEE_AUTHORITY_BALANCE: u64 = 1_000_000_000;

// Anchor wire-format helpers (anchor_ix_sighash / anchor_account_disc)
// come from solinv_fuzz::bytepoke — see crates/solinv-fuzz/src/bytepoke.rs
// + docs/phase5-day57-bytepoke-helper.md.

// ---------------------------------------------------------------------
// ix constructors — Day 46 adds CreatePool + SetFee.
// AddLiquidity / Unstake scheduled for Day 47+ if budget allows.
// ---------------------------------------------------------------------

fn build_init_protocol_fee_ix(
    program_id: Pubkey,
    payer: Pubkey,
    protocol_fee_pda: Pubkey,
) -> Instruction {
    let data = anchor_ix_sighash("init_protocol_fee").to_vec();
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(protocol_fee_pda, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data,
    }
}

/// Borsh-encoded `Fee { fee: FeeEnum::Flat { ratio: Rational { num, denom } } }`.
///
/// Anchor serialization of the wrapper struct + enum + inner struct
/// produces a flat byte sequence: enum-variant-tag (u8) + variant
/// body. Flat body = Rational = num (u64 LE) + denom (u64 LE).
/// Result: 17 bytes total.
fn flat_fee_borsh(num: u64, denom: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(17);
    bytes.push(0u8); // FeeEnum::Flat variant tag
    bytes.extend_from_slice(&num.to_le_bytes());
    bytes.extend_from_slice(&denom.to_le_bytes());
    bytes
}

fn build_create_pool_ix(
    program_id: Pubkey,
    payer: Pubkey,
    fee_authority: Pubkey,
    pool_account: Pubkey,
    pool_sol_reserves: Pubkey,
    fee_account: Pubkey,
    lp_mint: Pubkey,
    token_program: Pubkey,
    rent_sysvar: Pubkey,
    fee_num: u64,
    fee_denom: u64,
) -> Instruction {
    let mut data = anchor_ix_sighash("create_pool").to_vec();
    data.extend_from_slice(&flat_fee_borsh(fee_num, fee_denom));
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(fee_authority, true),
            AccountMeta::new(pool_account, true), // fresh keypair, init
            AccountMeta::new_readonly(pool_sol_reserves, false),
            AccountMeta::new(fee_account, false),
            AccountMeta::new(lp_mint, true), // fresh keypair, init mint
            AccountMeta::new_readonly(token_program, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            AccountMeta::new_readonly(rent_sysvar, false),
        ],
        data,
    }
}

fn build_set_fee_ix(
    program_id: Pubkey,
    fee_authority: Pubkey,
    pool_account: Pubkey,
    fee_account: Pubkey,
    rent_sysvar: Pubkey,
    fee_num: u64,
    fee_denom: u64,
) -> Instruction {
    let mut data = anchor_ix_sighash("set_fee").to_vec();
    data.extend_from_slice(&flat_fee_borsh(fee_num, fee_denom));
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(fee_authority, true),
            AccountMeta::new_readonly(pool_account, false),
            AccountMeta::new(fee_account, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            AccountMeta::new_readonly(rent_sysvar, false),
        ],
        data,
    }
}

// ---------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------

#[derive(Clone)]
struct SanctumUnstakeFixture {
    pub ctx: TestContext,
    program_id: Pubkey,
    fee_payer: Arc<Keypair>,
    #[allow(dead_code)]
    protocol_fee_pda: Pubkey,
    fee_authority: Arc<Keypair>,
    pool_account: Arc<Keypair>,
    pool_sol_reserves: Pubkey,
    fee_account: Pubkey,
    #[allow(dead_code)]
    lp_mint: Arc<Keypair>,
    rent_sysvar: Pubkey,
}

#[fuzz_fixture]
impl SanctumUnstakeFixture {
    pub fn setup() -> Self {
        let mut ctx = TestContext::new();

        let program_id = Pubkey::from_str(SANCTUM_UNSTAKE_PROGRAM_ID_STR)
            .expect("valid base58 program id");
        ctx.add_program(&program_id, SANCTUM_UNSTAKE_SO_PATH)
            .expect("load unstake.so — see examples/sanctum-unstake-fuzz/README.md");

        let (protocol_fee_pda, _bump) =
            Pubkey::find_program_address(&[PROTOCOL_FEE_SEED], &program_id);

        let fee_payer = Arc::new(Keypair::new());
        let fee_authority = Arc::new(Keypair::new());
        for (kp, lamports) in [
            (&fee_payer, FEE_PAYER_BALANCE),
            (&fee_authority, FEE_AUTHORITY_BALANCE),
        ] {
            ctx.create_account()
                .pubkey(kp.pubkey())
                .lamports(lamports)
                .owner(SYSTEM_PROGRAM_ID)
                .create()
                .unwrap();
        }

        // Step 1 — init_protocol_fee. Must succeed: an earlier version
        // ignored the outcome here and ran for weeks against a program
        // whose first ix always failed (docs/phase5-day56-gateA-result.md,
        // corrected in docs/phase5-day61-h1-was-the-build.md).
        let outcome = ctx
            .raw_call(build_init_protocol_fee_ix(
                program_id,
                fee_payer.pubkey(),
                protocol_fee_pda,
            ))
            .fee_payer(&*fee_payer)
            .signers(&[&*fee_payer])
            .send()
            .expect("init_protocol_fee send");
        assert!(outcome.is_success(), "init_protocol_fee failed: {outcome:?}");

        // Step 2 — create_pool. Fresh keypairs for pool_account and
        // lp_mint per Anchor `#[account(init)]` semantics (signing
        // account creation). pool_sol_reserves + fee_account are
        // PDAs derived from pool_account.
        let pool_account = Arc::new(Keypair::new());
        let lp_mint = Arc::new(Keypair::new());

        let (pool_sol_reserves, _bump) = Pubkey::find_program_address(
            &[pool_account.pubkey().as_ref()],
            &program_id,
        );
        let (fee_account, _bump) = Pubkey::find_program_address(
            &[pool_account.pubkey().as_ref(), FEE_SEED_SUFFIX],
            &program_id,
        );

        // SPL Token program ID = TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
        let token_program =
            Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
        // Rent sysvar = SysvarRent111111111111111111111111111111111
        let rent_sysvar =
            Pubkey::from_str("SysvarRent111111111111111111111111111111111").unwrap();

        // Step 3 — create_pool. Must succeed too; the actions below
        // need an initialized Pool / Fee / LP mint.
        let outcome = ctx
            .raw_call(build_create_pool_ix(
                program_id,
                fee_payer.pubkey(),
                fee_authority.pubkey(),
                pool_account.pubkey(),
                pool_sol_reserves,
                fee_account,
                lp_mint.pubkey(),
                token_program,
                rent_sysvar,
                0,     // 0% Flat fee
                10_000,
            ))
            .fee_payer(&*fee_payer)
            .signers(&[&*fee_payer, &*fee_authority, &*pool_account, &*lp_mint])
            .send()
            .expect("create_pool send");
        assert!(outcome.is_success(), "create_pool failed: {outcome:?}");

        Self {
            ctx,
            program_id,
            fee_payer,
            protocol_fee_pda,
            fee_authority,
            pool_account,
            pool_sol_reserves,
            fee_account,
            lp_mint,
            rent_sysvar,
        }
    }

    /// Day 46 — re-executable SetFee action. fee_authority signs;
    /// the only validation surface besides the signer constraint is
    /// `has_one = fee_authority` on pool_account + `seeds = [pool_account, "fee"]`
    /// on fee_account. Solinv invariants attack each: signer-skip
    /// drops the authority signer, owner-skip substitutes wrong-owner
    /// pool, pda-forge substitutes non-PDA fee_account.
    pub fn action_set_fee(
        &mut self,
        #[range(0..u64::MAX)] _fee_num: u64,
    ) -> bool {
        // Use 0% Flat fee (num=0, denom=10_000) so set_fee always
        // validates (Fee::validate requires ratio <= 1). The
        // `_fee_num` arg is purely fuzzer-bait so Crucible has
        // something to mutate per iteration.
        self.ctx
            .raw_call(build_set_fee_ix(
                self.program_id,
                self.fee_authority.pubkey(),
                self.pool_account.pubkey(),
                self.fee_account,
                self.rent_sysvar,
                0,
                10_000,
            ))
            .fee_payer(&*self.fee_payer)
            .signers(&[&*self.fee_payer, &*self.fee_authority])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false)
    }
}

// ---------------------------------------------------------------------
// solinv integration
// ---------------------------------------------------------------------

impl HasContext for SanctumUnstakeFixture {
    fn ctx(&self) -> &TestContext {
        &self.ctx
    }
    fn ctx_mut(&mut self) -> &mut TestContext {
        &mut self.ctx
    }
    fn program_ids(&self) -> Vec<Pubkey> {
        vec![self.program_id]
    }
    fn fee_payer(&self) -> Arc<Keypair> {
        Arc::clone(&self.fee_payer)
    }
}

impl HasInstructionSet for SanctumUnstakeFixture {
    fn instructions(&self) -> Vec<InstructionSpec> {
        // Day 46 — SetFee is the first attackable InstructionSpec.
        // Re-executable (pool already created in setup, fee_authority
        // stored in fixture). Anchor 0.28 account constraints:
        //  - fee_authority: Signer at index 0
        //  - pool_account: Account<Pool> at index 1 (Anchor checks owner = program_id, disc = Pool discriminant)
        //  - fee_account:  Account<Fee>  at index 2 (PDA seeds = [pool, "fee"], owner = program_id)
        //  - system_program + rent: passive sysvars
        let mut set_fee_data = anchor_ix_sighash("set_fee").to_vec();
        set_fee_data.extend_from_slice(&flat_fee_borsh(0, 10_000));

        let set_fee_spec = InstructionSpec {
            program_id: self.program_id,
            name: "set_fee".into(),
            accounts: vec![
                AccountMeta::new_readonly(self.fee_authority.pubkey(), true),
                AccountMeta::new_readonly(self.pool_account.pubkey(), false),
                AccountMeta::new(self.fee_account, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
                AccountMeta::new_readonly(self.rent_sysvar, false),
            ],
            signer_indices: vec![0], // fee_authority
            optional_signer_indices: vec![],
            expected_owners: vec![
                None,                       // fee_authority: system_program signer
                Some(self.program_id),      // pool_account: Anchor program-owned
                Some(self.program_id),      // fee_account: Anchor program-owned
                None,                       // system_program
                None,                       // rent sysvar
            ],
            expected_discriminators: vec![
                None,
                Some(anchor_account_disc("Pool")),
                Some(anchor_account_disc("Fee")),
                None,
                None,
            ],
            expected_pda_seeds: vec![
                None,
                None, // pool_account is a fresh keypair, not a PDA
                Some(vec![
                    self.pool_account.pubkey().to_bytes().to_vec(),
                    FEE_SEED_SUFFIX.to_vec(),
                ]),
                None,
                None,
            ],
            creates_indices: vec![],
            swap_alternates: vec![vec![], vec![], vec![], vec![], vec![]],
            data_sample: set_fee_data,
            signers: vec![Arc::clone(&self.fee_authority)],
            state_invariants: vec![],
            cu_budget: Some(20_000),
            guards: vec![],
            cpi_reentrancy: None,
            realloc_check: None,
            bump_seed_check: None,            };

        vec![set_fee_spec]
    }
}

// ---------------------------------------------------------------------
// Invariant variants — wired for compile-time check, no-op until
// Day 46 InstructionSpecs land.
// ---------------------------------------------------------------------

#[invariant_test]
fn invariant_sanctum_unstake_smoke(fixture: &mut SanctumUnstakeFixture) {
    solinv_core::invariants::signer_skip::check(fixture);
    solinv_core::invariants::owner_skip::check(fixture);
    solinv_core::invariants::discriminator_skip::check(fixture);
    solinv_core::invariants::pda_forge::check(fixture);
    solinv_core::invariants::account_swap::check(fixture);
    solinv_core::invariants::unchecked_math::check(fixture);
    solinv_core::invariants::cu_dos::check(fixture);
}

#[invariant_test]
fn invariant_signer_skip_only(fixture: &mut SanctumUnstakeFixture) {
    solinv_core::invariants::signer_skip::check(fixture);
}

#[invariant_test]
fn invariant_owner_skip_only(fixture: &mut SanctumUnstakeFixture) {
    solinv_core::invariants::owner_skip::check(fixture);
}

#[invariant_test]
fn invariant_discriminator_skip_only(fixture: &mut SanctumUnstakeFixture) {
    solinv_core::invariants::discriminator_skip::check(fixture);
}

#[invariant_test]
fn invariant_pda_forge_only(fixture: &mut SanctumUnstakeFixture) {
    solinv_core::invariants::pda_forge::check(fixture);
}

#[invariant_test]
fn invariant_account_swap_only(fixture: &mut SanctumUnstakeFixture) {
    solinv_core::invariants::account_swap::check(fixture);
}

#[invariant_test]
fn invariant_unchecked_math_only(fixture: &mut SanctumUnstakeFixture) {
    solinv_core::invariants::run_with_transition_metrics("unchecked-math", || {
        solinv_core::invariants::unchecked_math::check(fixture);
    });
}

#[invariant_test]
fn invariant_cu_dos_only(fixture: &mut SanctumUnstakeFixture) {
    solinv_core::invariants::run_with_transition_metrics("cu-dos", || {
        solinv_core::invariants::cu_dos::check(fixture);
    });
}
