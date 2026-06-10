//! vault-buggy — solinv acceptance harness for anchor-w10-buggy.so
//!
//! Mirrors amm-buggy. Bug ↔ invariant mapping:
//!   Bug A (user_position.share_amount += shares skipped)
//!     ↔ invariant_share_supply_consistent_only
//!   Bug B (vault.total_assets += deposit_amount + 1)
//!     ↔ invariant_assets_vault_consistent_only

use crucible_fuzzer::*;
use sha2::{Digest, Sha256};
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solinv_fuzz::HasContext;
use std::str::FromStr;
use std::sync::Arc;

const BUGGY_PROGRAM_ID_STR: &str = "6Y2id2yw2p4YrvMTFqseR7FtY6tVxc2XHXh7qU3VKDnB";
const BUGGY_SO_PATH: &str =
    "../../programs/anchor-w10-buggy/target/deploy/anchor_w10_buggy.so";

const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);
const TOKEN_PROGRAM_ID_STR: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

const ANCHOR_DISC_LEN: usize = 8;
const VAULT_BODY: usize = 16; // total_assets u64 + total_shares u64
const USER_POSITION_BODY: usize = 16; // share_amount u64 + deposit_count u64
const MINT_LEN: usize = 82;
const TOKEN_ACCOUNT_LEN: usize = 165;

const FEE_PAYER_BALANCE: u64 = 100_000_000_000;
const USER_BALANCE: u64 = 10_000_000_000;
const ACCT_LAMPORTS: u64 = 5_000_000;
const TOKEN_LAMPORTS: u64 = 2_500_000;
const MINT_LAMPORTS: u64 = 2_000_000;
const INITIAL_USER_UNDERLYING: u64 = 1_000_000_000;

fn anchor_acc_disc(name: &str) -> [u8; 8] {
    let h = Sha256::digest(format!("account:{name}").as_bytes());
    h[..8].try_into().unwrap()
}
fn anchor_ix_disc(name: &str) -> [u8; 8] {
    let h = Sha256::digest(format!("global:{name}").as_bytes());
    h[..8].try_into().unwrap()
}

fn make_mint(authority: &Pubkey, supply: u64, decimals: u8) -> Vec<u8> {
    let mut buf = vec![0u8; MINT_LEN];
    buf[0..4].copy_from_slice(&1u32.to_le_bytes());
    buf[4..36].copy_from_slice(authority.as_ref());
    buf[36..44].copy_from_slice(&supply.to_le_bytes());
    buf[44] = decimals;
    buf[45] = 1;
    buf
}

fn make_token_account(mint: &Pubkey, owner: &Pubkey, amount: u64) -> Vec<u8> {
    let mut buf = vec![0u8; TOKEN_ACCOUNT_LEN];
    buf[0..32].copy_from_slice(mint.as_ref());
    buf[32..64].copy_from_slice(owner.as_ref());
    buf[64..72].copy_from_slice(&amount.to_le_bytes());
    buf[108] = 1;
    buf
}

fn build_deposit_ix(
    program_id: Pubkey,
    authority: Pubkey,
    vault: Pubkey,
    user_position: Pubkey,
    user_underlying: Pubkey,
    vault_underlying: Pubkey,
    token_program: Pubkey,
    deposit_amount: u64,
) -> Instruction {
    let mut data = anchor_ix_disc("deposit").to_vec();
    data.extend_from_slice(&deposit_amount.to_le_bytes());
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(vault, false),
            AccountMeta::new(user_position, false),
            AccountMeta::new(user_underlying, false),
            AccountMeta::new(vault_underlying, false),
            AccountMeta::new_readonly(token_program, false),
        ],
        data,
    }
}

#[derive(Clone)]
struct VaultBuggyFixture {
    pub ctx: TestContext,
    program_id: Pubkey,
    token_program: Pubkey,
    vault: Pubkey,
    user_position: Pubkey,
    user_underlying: Pubkey,
    vault_underlying: Pubkey,
    user: Arc<Keypair>,
    fee_payer: Arc<Keypair>,

    pre_total_assets: u64,
    pre_total_shares: u64,
    pre_share_amount: u64,
    pre_vault_underlying_amount: u64,
    last_deposit_succeeded: bool,
}

#[fuzz_fixture]
impl VaultBuggyFixture {
    pub fn setup() -> Self {
        let mut ctx = TestContext::new();
        let program_id = Pubkey::from_str(BUGGY_PROGRAM_ID_STR).expect("valid base58");
        let token_program = Pubkey::from_str(TOKEN_PROGRAM_ID_STR).expect("valid base58");
        ctx.add_program(&program_id, BUGGY_SO_PATH)
            .expect("build programs/anchor-w10-buggy first");

        let user = Arc::new(Keypair::new());
        let fee_payer = Arc::new(Keypair::new());
        for (kp, lamports) in [(&user, USER_BALANCE), (&fee_payer, FEE_PAYER_BALANCE)] {
            ctx.create_account()
                .pubkey(kp.pubkey())
                .lamports(lamports)
                .owner(SYSTEM_PROGRAM_ID)
                .create()
                .unwrap();
        }

        let mint = Keypair::new().pubkey();
        ctx.write_account(
            &mint,
            Account {
                lamports: MINT_LAMPORTS,
                data: make_mint(&user.pubkey(), 1_000_000_000_000, 6),
                owner: token_program,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        let vault_kp = Keypair::new();
        let mut vault_data = vec![0u8; ANCHOR_DISC_LEN + VAULT_BODY];
        vault_data[..8].copy_from_slice(&anchor_acc_disc("Vault"));
        ctx.write_account(
            &vault_kp.pubkey(),
            Account {
                lamports: ACCT_LAMPORTS,
                data: vault_data,
                owner: program_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        let user_position_kp = Keypair::new();
        let mut user_position_data = vec![0u8; ANCHOR_DISC_LEN + USER_POSITION_BODY];
        user_position_data[..8].copy_from_slice(&anchor_acc_disc("UserPosition"));
        ctx.write_account(
            &user_position_kp.pubkey(),
            Account {
                lamports: ACCT_LAMPORTS,
                data: user_position_data,
                owner: program_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        let mut make_acc = |amount: u64| -> Pubkey {
            let kp = Keypair::new();
            ctx.write_account(
                &kp.pubkey(),
                Account {
                    lamports: TOKEN_LAMPORTS,
                    data: make_token_account(&mint, &user.pubkey(), amount),
                    owner: token_program,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
            kp.pubkey()
        };
        let user_underlying = make_acc(INITIAL_USER_UNDERLYING);
        let vault_underlying = make_acc(0);

        Self {
            ctx,
            program_id,
            token_program,
            vault: vault_kp.pubkey(),
            user_position: user_position_kp.pubkey(),
            user_underlying,
            vault_underlying,
            user,
            fee_payer,
            pre_total_assets: 0,
            pre_total_shares: 0,
            pre_share_amount: 0,
            pre_vault_underlying_amount: 0,
            last_deposit_succeeded: false,
        }
    }

    pub fn action_deposit(
        &mut self,
        #[range(1..1_000_000)] deposit_amount: u64,
    ) -> bool {
        // Pre-state snapshot.
        let vault_pre = self.ctx.get_account(&self.vault).map(|a| a.data).unwrap_or_default();
        let pos_pre = self.ctx.get_account(&self.user_position).map(|a| a.data).unwrap_or_default();
        self.pre_total_assets = read_u64(&vault_pre, ANCHOR_DISC_LEN);
        self.pre_total_shares = read_u64(&vault_pre, ANCHOR_DISC_LEN + 8);
        self.pre_share_amount = read_u64(&pos_pre, ANCHOR_DISC_LEN);
        self.pre_vault_underlying_amount = token_amount(&self.ctx, &self.vault_underlying);

        let ix = build_deposit_ix(
            self.program_id,
            self.user.pubkey(),
            self.vault,
            self.user_position,
            self.user_underlying,
            self.vault_underlying,
            self.token_program,
            deposit_amount,
        );
        let ok = self
            .ctx
            .raw_call(ix)
            .fee_payer(&*self.fee_payer)
            .signers(&[&*self.fee_payer, &*self.user])
            .send()
            .map(|o| o.is_success())
            .unwrap_or(false);
        self.last_deposit_succeeded = ok;
        ok
    }
}

impl HasContext for VaultBuggyFixture {
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

fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

fn token_amount(ctx: &TestContext, addr: &Pubkey) -> u64 {
    ctx.get_account(addr)
        .ok()
        .and_then(|a| {
            if a.data.len() >= 72 {
                Some(read_u64(&a.data, 64))
            } else {
                None
            }
        })
        .unwrap_or(0)
}

// delta(vault.total_shares) must equal delta(user_position.share_amount)
// — both should grow by the same `shares` value on a successful deposit.
fn check_share_supply_consistent(fixture: &mut VaultBuggyFixture) {
    if !fixture.last_deposit_succeeded {
        return;
    }
    let vault_post = match fixture.ctx().get_account(&fixture.vault) {
        Ok(a) => a.data,
        Err(_) => return,
    };
    let pos_post = match fixture.ctx().get_account(&fixture.user_position) {
        Ok(a) => a.data,
        Err(_) => return,
    };
    let total_shares_post = read_u64(&vault_post, ANCHOR_DISC_LEN + 8);
    let share_amount_post = read_u64(&pos_post, ANCHOR_DISC_LEN);
    let dts = total_shares_post as i128 - fixture.pre_total_shares as i128;
    let dsa = share_amount_post as i128 - fixture.pre_share_amount as i128;
    fuzz_assert!(
        dts == dsa,
        "share-supply drift: Δvault.total_shares={} vs Δuser_position.share_amount={} (pre total={} pos_share={}, post total={} pos_share={})",
        dts, dsa,
        fixture.pre_total_shares, fixture.pre_share_amount,
        total_shares_post, share_amount_post,
    );
}

// delta(vault.total_assets) must equal delta(vault_underlying.amount)
// — the program's bookkeeping field must track the on-chain truth.
fn check_assets_vault_consistent(fixture: &mut VaultBuggyFixture) {
    if !fixture.last_deposit_succeeded {
        return;
    }
    let vault_post = match fixture.ctx().get_account(&fixture.vault) {
        Ok(a) => a.data,
        Err(_) => return,
    };
    let total_assets_post = read_u64(&vault_post, ANCHOR_DISC_LEN);
    let vault_underlying_post = token_amount(fixture.ctx(), &fixture.vault_underlying);
    let dta = total_assets_post as i128 - fixture.pre_total_assets as i128;
    let dvu = vault_underlying_post as i128 - fixture.pre_vault_underlying_amount as i128;
    fuzz_assert!(
        dta == dvu,
        "assets/vault drift: Δvault.total_assets={} vs Δvault_underlying.amount={} (pre total={} vault={}, post total={} vault={})",
        dta, dvu,
        fixture.pre_total_assets, fixture.pre_vault_underlying_amount,
        total_assets_post, vault_underlying_post,
    );
}

#[invariant_test]
fn invariant_vault_buggy_smoke(fixture: &mut VaultBuggyFixture) {
    check_share_supply_consistent(fixture);
    check_assets_vault_consistent(fixture);
}

#[invariant_test]
fn invariant_share_supply_consistent_only(fixture: &mut VaultBuggyFixture) {
    check_share_supply_consistent(fixture);
}

#[invariant_test]
fn invariant_assets_vault_consistent_only(fixture: &mut VaultBuggyFixture) {
    check_assets_vault_consistent(fixture);
}
