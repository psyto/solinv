//! # Anchor IDL → `InstructionSpec`
//!
//! Hand-filling an `InstructionSpec` is the slowest step of adopting
//! solinv: fourteen fields per instruction, most of which the program
//! has already declared once in its `#[derive(Accounts)]` structs. The
//! Anchor IDL (0.30+ format, with PDA resolution on) carries most of it:
//!
//! | spec field                | source                                   |
//! |---------------------------|------------------------------------------|
//! | `accounts`                | IDL order + `writable` / `signer`        |
//! | `signer_indices`          | IDL `signer`                             |
//! | `expected_pda_seeds`      | IDL `pda.seeds` (const / account / arg)  |
//! | `data_sample`             | IDL discriminator + caller's arg bytes   |
//! | `expected_owners`         | runtime: owner == program, known disc    |
//! | `expected_discriminators` | runtime: data starts with an IDL disc    |
//! | `creates_indices`         | runtime: account absent before the send  |
//!
//! The last three are not in the instruction's IDL entry (it names
//! accounts, not their types), so they are read off the fixture's state
//! after `setup()` with [`IdlSpec::infer_from_state`]. An account owned
//! by the program whose data starts with a discriminator the IDL
//! declares is a typed `Account<'info, T>` in every Anchor program; that
//! is what the owner and discriminator detectors attack.
//!
//! ## Why the state pass matters more than the IDL pass
//!
//! What the IDL declares, Anchor enforces: `signer: true` comes from a
//! `Signer<'info>`, `pda.seeds` from a `seeds = [...]` constraint. A spec
//! built from the IDL alone asks the program to honour checks its own
//! macros already generated, and on Anchor it finds nothing. The bugs
//! live where the IDL is *silent* — an `UncheckedAccount` slot. So the
//! state pass also adds expectations the IDL does not make, each one
//! backed by evidence, and lists them in [`IdlSpec::inferred`]:
//!
//! - **owner / discriminator** — the slot holds a program-owned account
//!   carrying an IDL discriminator, whatever the IDL calls the slot.
//! - **pda seeds** — a seed pattern the IDL declares on another
//!   instruction re-derives this slot's exact address. Matching a
//!   32-byte address is proof, not a guess.
//! - **signer** — the instruction has no signer at all, writes a
//!   program-owned account, and that account's data stores this slot's
//!   pubkey: the stored key is the only candidate authority. Needs the
//!   slot's keypair bound with [`SpecBuilder::signer`].
//!
//! What the IDL cannot supply stays empty and is listed in
//! [`IdlSpec::unresolved`]: `swap_alternates` (a semantic relation, see
//! the `HasInstructionSet` docs), seeds that read another account's
//! data, and seeds derived under a different program.
//!
//! ```ignore
//! let idl = Idl::from_json(include_str!("../idl/escrow.json"))?;
//! let spec = idl
//!     .spec("deposit", program_id)?
//!     .account("vault", vault_pda)
//!     .signer("depositor", Arc::clone(&depositor))
//!     .args(&50_000u64.to_le_bytes())
//!     .build()?
//!     .infer_from_state(|pk| ctx.get_account(pk).ok())
//!     .into_spec();
//! ```

use crate::capability::InstructionSpec;
use serde::Deserialize;
use solana_account::Account;
use solana_instruction::AccountMeta;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

/// The subset of an Anchor IDL solinv reads. Unknown fields are ignored,
/// so any IDL `anchor build` writes to `target/idl/` parses.
#[derive(Clone, Debug, Deserialize)]
pub struct Idl {
    #[serde(default)]
    pub address: String,
    pub instructions: Vec<IdlInstruction>,
    /// Account types and their discriminators.
    #[serde(default)]
    pub accounts: Vec<IdlAccountType>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct IdlInstruction {
    pub name: String,
    pub discriminator: Vec<u8>,
    pub accounts: Vec<IdlAccountItem>,
    #[serde(default)]
    pub args: Vec<IdlArg>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct IdlArg {
    pub name: String,
    /// Kept as raw JSON: only printed, never decoded.
    #[serde(rename = "type")]
    pub ty: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize)]
pub struct IdlAccountType {
    pub name: String,
    pub discriminator: Vec<u8>,
}

/// One entry of an instruction's account list. A composite entry is a
/// nested `#[derive(Accounts)]` struct; its accounts are flattened in
/// order, which is how Anchor lays them out on the wire.
#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum IdlAccountItem {
    Composite {
        name: String,
        accounts: Vec<IdlAccountItem>,
    },
    Single(IdlAccount),
}

#[derive(Clone, Debug, Deserialize)]
pub struct IdlAccount {
    pub name: String,
    #[serde(default)]
    pub writable: bool,
    #[serde(default)]
    pub signer: bool,
    #[serde(default)]
    pub optional: bool,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub pda: Option<IdlPda>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct IdlPda {
    pub seeds: Vec<IdlSeed>,
    /// Set when the PDA is derived under another program (e.g. an ATA).
    #[serde(default)]
    pub program: Option<IdlSeed>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum IdlSeed {
    Const { value: Vec<u8> },
    Account { path: String },
    Arg { path: String },
}

#[derive(Debug)]
pub enum IdlError {
    Parse(String),
    UnknownInstruction(String),
    /// Accounts the IDL lists with no fixed address that were not bound.
    MissingAccounts { ix: String, names: Vec<String> },
    /// Signer accounts with no keypair bound.
    MissingSigners { ix: String, names: Vec<String> },
    BadAddress { account: String, address: String },
}

impl fmt::Display for IdlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdlError::Parse(e) => write!(f, "IDL does not parse: {e}"),
            IdlError::UnknownInstruction(n) => write!(f, "IDL has no instruction `{n}`"),
            IdlError::MissingAccounts { ix, names } => {
                write!(f, "`{ix}`: bind these accounts with .account(): {}", names.join(", "))
            }
            IdlError::MissingSigners { ix, names } => {
                write!(f, "`{ix}`: bind these signers with .signer(): {}", names.join(", "))
            }
            IdlError::BadAddress { account, address } => {
                write!(f, "account `{account}` has an unparseable address `{address}`")
            }
        }
    }
}

impl std::error::Error for IdlError {}

fn compact(ty: &serde_json::Value) -> String {
    match ty {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

impl Idl {
    /// The account-validation surface of every instruction, as the IDL
    /// declares it. Static: no fixture needed, so it is the first thing
    /// to run on a program.
    pub fn report(&self) -> String {
        let types: Vec<&str> = self
            .accounts
            .iter()
            .map(|a| a.name.rsplit("::").next().unwrap_or(&a.name))
            .collect();
        let mut out = format!(
            "program {} — {} instructions, account types: {}\n\n\
             S signer  W writable  P pda seeds  A fixed address  \
             · nothing declared (state pass decides)\n",
            if self.address.is_empty() { "(no address)" } else { &self.address },
            self.instructions.len(),
            if types.is_empty() { "none".into() } else { types.join(", ") },
        );
        let width = self
            .instructions
            .iter()
            .flat_map(|ix| ix.flat_accounts())
            .map(|a| a.name.len())
            .max()
            .unwrap_or(0);
        let mut unsigned = Vec::new();
        let mut silent = 0;
        for ix in &self.instructions {
            let flag = if ix.is_unsigned_writer() {
                unsigned.push(ix.name.as_str());
                "   ! no signer, writes an unconstrained slot"
            } else {
                ""
            };
            out += &format!("\n{}{}\n", ix.name, flag);
            for (i, a) in ix.flat_accounts().iter().enumerate() {
                let marks: String = [
                    (a.signer, 'S'),
                    (a.writable, 'W'),
                    (a.pda.is_some(), 'P'),
                    (a.address.is_some(), 'A'),
                ]
                .iter()
                .map(|&(on, c)| if on { c } else { ' ' })
                .collect();
                let quiet = if a.is_silent() {
                    silent += 1;
                    " ·"
                } else {
                    ""
                };
                out += &format!("  {i:>2} {:<width$}  {marks}{quiet}\n", a.name);
            }
        }
        out += &format!(
            "\n{silent} slots declare nothing in the IDL; owner, discriminator and \
             seeds for them come from state (`infer_from_state`).\n"
        );
        if unsigned.is_empty() {
            out += "Every instruction that writes an unconstrained slot has a signer.\n";
        } else {
            out += &format!(
                "{} instruction(s) with no signer write an unconstrained slot: {}\n\
                 Start there — signer-skip needs the stored authority's keypair bound.\n",
                unsigned.len(),
                unsigned.join(", ")
            );
        }
        out
    }

    pub fn from_json(json: &str) -> Result<Self, IdlError> {
        serde_json::from_str(json).map_err(|e| IdlError::Parse(e.to_string()))
    }

    pub fn instruction(&self, name: &str) -> Result<&IdlInstruction, IdlError> {
        self.instructions
            .iter()
            .find(|ix| ix.name == name)
            .ok_or_else(|| IdlError::UnknownInstruction(name.to_string()))
    }

    /// Start building the spec for one instruction.
    pub fn spec(&self, ix_name: &str, program_id: Pubkey) -> Result<SpecBuilder<'_>, IdlError> {
        Ok(SpecBuilder {
            idl: self,
            ix: self.instruction(ix_name)?,
            program_id,
            accounts: HashMap::new(),
            signers: HashMap::new(),
            arg_seeds: HashMap::new(),
            args: Vec::new(),
        })
    }

    /// Discriminators of every account type the IDL declares.
    pub fn account_discriminators(&self) -> Vec<[u8; 8]> {
        self.accounts
            .iter()
            .filter_map(|a| a.discriminator.as_slice().try_into().ok())
            .collect()
    }
}

impl IdlAccount {
    /// Nothing in the IDL constrains this slot: not a signer, no seeds,
    /// no fixed address. Either an `UncheckedAccount` or a typed account
    /// without seeds — the IDL cannot tell which, the state pass can.
    pub fn is_silent(&self) -> bool {
        !self.signer && self.pda.is_none() && self.address.is_none()
    }
}

impl IdlInstruction {
    /// No signer at all, and at least one writable slot the IDL leaves
    /// unconstrained. The shape of a missing authority check.
    pub fn is_unsigned_writer(&self) -> bool {
        let flat = self.flat_accounts();
        !flat.iter().any(|a| a.signer) && flat.iter().any(|a| a.writable && a.is_silent())
    }

    /// A `SpecBuilder` call chain for this instruction with every binding
    /// left as a `todo!`, for pasting into a fixture.
    pub fn rust_bindings(&self) -> String {
        let mut out = format!("idl.spec(\"{}\", program_id)?\n", self.name);
        let unsigned = self.is_unsigned_writer();
        for a in self.flat_accounts() {
            if a.address.is_some() {
                continue;
            }
            if a.signer {
                out += &format!("    .signer(\"{0}\", todo!(\"{0}: Arc<Keypair>\"))\n", a.name);
            } else if unsigned && a.is_silent() {
                out += &format!(
                    "    // no signer on this ix: binding {0}'s keypair with .signer() lets\n    \
                     // the state pass test it as the authority\n    \
                     .account(\"{0}\", todo!(\"{0}: Pubkey\"))\n",
                    a.name
                );
            } else {
                out += &format!("    .account(\"{0}\", todo!(\"{0}: Pubkey\"))\n", a.name);
            }
        }
        if !self.args.is_empty() {
            let args: Vec<String> =
                self.args.iter().map(|a| format!("{}: {}", a.name, compact(&a.ty))).collect();
            out += &format!("    .args(&todo!(\"borsh: {}\"))\n", args.join(", "));
        }
        out += "    .build()?\n    .infer_from_state(|pk| ctx.get_account(pk).ok())\n";
        out
    }

    /// The instruction's accounts in wire order, composites flattened.
    pub fn flat_accounts(&self) -> Vec<&IdlAccount> {
        fn walk<'a>(items: &'a [IdlAccountItem], out: &mut Vec<&'a IdlAccount>) {
            for item in items {
                match item {
                    IdlAccountItem::Single(a) => out.push(a),
                    IdlAccountItem::Composite { accounts, .. } => walk(accounts, out),
                }
            }
        }
        let mut out = Vec::new();
        walk(&self.accounts, &mut out);
        out
    }
}

/// Binds the fixture's concrete pubkeys and keypairs to IDL account
/// names. Accounts with a fixed IDL `address` (system program, sysvars)
/// need no binding.
pub struct SpecBuilder<'a> {
    idl: &'a Idl,
    ix: &'a IdlInstruction,
    program_id: Pubkey,
    accounts: HashMap<String, Pubkey>,
    signers: HashMap<String, Arc<Keypair>>,
    arg_seeds: HashMap<String, Vec<u8>>,
    args: Vec<u8>,
}

impl<'a> SpecBuilder<'a> {
    pub fn account(mut self, name: &str, pubkey: Pubkey) -> Self {
        self.accounts.insert(name.to_string(), pubkey);
        self
    }

    /// Bind an account by keypair; its pubkey comes from the keypair.
    /// Required for IDL signers. On a slot the IDL does not mark as a
    /// signer, the keypair lets the state pass test it as one when the
    /// evidence says it should have been.
    pub fn signer(mut self, name: &str, keypair: Arc<Keypair>) -> Self {
        use solana_signer::Signer;
        self.accounts.insert(name.to_string(), keypair.pubkey());
        self.signers.insert(name.to_string(), keypair);
        self
    }

    /// Borsh-encoded instruction args, appended after the discriminator.
    pub fn args(mut self, bytes: &[u8]) -> Self {
        self.args = bytes.to_vec();
        self
    }

    /// Seed bytes for a PDA seed of kind `arg` (`path` as in the IDL,
    /// e.g. `"market_id"`). Unbound arg seeds leave that PDA undeclared.
    pub fn seed_arg(mut self, path: &str, bytes: &[u8]) -> Self {
        self.arg_seeds.insert(path.to_string(), bytes.to_vec());
        self
    }

    pub fn build(self) -> Result<IdlSpec, IdlError> {
        let flat = self.ix.flat_accounts();
        let ix_name = self.ix.name.clone();

        let mut pubkeys = Vec::with_capacity(flat.len());
        let mut missing = Vec::new();
        for acc in &flat {
            if let Some(pk) = self.accounts.get(&acc.name) {
                pubkeys.push(*pk);
            } else if let Some(addr) = &acc.address {
                let pk = addr.parse::<Pubkey>().map_err(|_| IdlError::BadAddress {
                    account: acc.name.clone(),
                    address: addr.clone(),
                })?;
                pubkeys.push(pk);
            } else if acc.optional {
                // Anchor encodes an omitted optional account as the
                // program id in that slot.
                pubkeys.push(self.program_id);
            } else {
                missing.push(acc.name.clone());
                pubkeys.push(Pubkey::default());
            }
        }
        if !missing.is_empty() {
            return Err(IdlError::MissingAccounts { ix: ix_name, names: missing });
        }

        let missing_signers: Vec<String> = flat
            .iter()
            .filter(|a| a.signer && !self.signers.contains_key(&a.name))
            .map(|a| a.name.clone())
            .collect();
        if !missing_signers.is_empty() {
            return Err(IdlError::MissingSigners { ix: ix_name, names: missing_signers });
        }

        let by_name: HashMap<&str, Pubkey> = flat
            .iter()
            .zip(&pubkeys)
            .map(|(a, pk)| (a.name.as_str(), *pk))
            .collect();

        let mut unresolved = vec![Unresolved {
            account: None,
            what: "swap_alternates: name a second, legitimate account per context-bound slot"
                .into(),
        }];
        let mut accounts = Vec::with_capacity(flat.len());
        let mut signer_indices = Vec::new();
        let mut signers = Vec::new();
        let mut expected_pda_seeds = Vec::with_capacity(flat.len());

        for (i, (acc, pk)) in flat.iter().zip(&pubkeys).enumerate() {
            accounts.push(if acc.writable {
                AccountMeta::new(*pk, acc.signer)
            } else {
                AccountMeta::new_readonly(*pk, acc.signer)
            });
            if acc.signer {
                signer_indices.push(i);
                signers.push(Arc::clone(&self.signers[&acc.name]));
            }
            expected_pda_seeds.push(acc.pda.as_ref().and_then(|pda| {
                match self.resolve_seeds(pda, &by_name) {
                    Ok(seeds) => Some(seeds),
                    Err(why) => {
                        unresolved.push(Unresolved {
                            account: Some(acc.name.clone()),
                            what: format!("pda seeds: {why}"),
                        });
                        None
                    }
                }
            }));
        }

        let mut data_sample = self.ix.discriminator.clone();
        data_sample.extend_from_slice(&self.args);

        let keypairs = flat
            .iter()
            .map(|a| if a.signer { None } else { self.signers.get(&a.name).cloned() })
            .collect();
        let names = flat.iter().map(|a| a.name.clone()).collect();
        let pda_patterns = self
            .idl
            .instructions
            .iter()
            .flat_map(|ix| ix.flat_accounts())
            .filter_map(|a| a.pda.as_ref())
            .filter(|pda| pda.program.is_none())
            .map(|pda| pda.seeds.clone())
            .collect();

        let n = accounts.len();
        Ok(IdlSpec {
            spec: InstructionSpec {
                program_id: self.program_id,
                name: ix_name,
                accounts,
                signer_indices,
                optional_signer_indices: vec![],
                expected_owners: vec![None; n],
                expected_discriminators: vec![None; n],
                expected_pda_seeds,
                creates_indices: vec![],
                swap_alternates: vec![vec![]; n],
                data_sample,
                signers,
                state_invariants: vec![],
                cu_budget: None,
                cpi_reentrancy: None,
                realloc_check: None,
                bump_seed_check: None,
                guards: vec![],
            },
            account_discs: self.idl.account_discriminators(),
            names,
            keypairs,
            pda_patterns,
            unresolved,
            inferred: vec![],
        })
    }

    fn resolve_seeds(
        &self,
        pda: &IdlPda,
        by_name: &HashMap<&str, Pubkey>,
    ) -> Result<Vec<Vec<u8>>, String> {
        if pda.program.is_some() {
            return Err("derived under another program; pda-forge checks this program only".into());
        }
        pda.seeds
            .iter()
            .map(|seed| match seed {
                IdlSeed::Const { value } => Ok(value.clone()),
                IdlSeed::Account { path } => match by_name.get(path.as_str()) {
                    Some(pk) => Ok(pk.to_bytes().to_vec()),
                    None => Err(format!("seed reads account data `{path}`")),
                },
                IdlSeed::Arg { path } => self
                    .arg_seeds
                    .get(path)
                    .cloned()
                    .ok_or_else(|| format!("bind arg seed `{path}` with .seed_arg()")),
            })
            .collect()
    }
}

/// Something the IDL could not supply. Printed by `solinv idl` so the
/// gap is visible instead of silently weakening a detector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unresolved {
    pub account: Option<String>,
    pub what: String,
}

/// An expectation the state pass added beyond what the IDL declares.
/// On an Anchor program these are the slots worth attacking.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inferred {
    pub account: String,
    pub what: InferredKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InferredKind {
    Owner,
    Discriminator,
    PdaSeeds,
    Signer,
}

/// A spec built from the IDL, before and after state inference.
pub struct IdlSpec {
    spec: InstructionSpec,
    account_discs: Vec<[u8; 8]>,
    /// IDL name per slot, for reports.
    names: Vec<String>,
    /// Keypairs bound to slots the IDL does not mark as signers.
    keypairs: Vec<Option<Arc<Keypair>>>,
    /// Every program-local seed pattern declared anywhere in the IDL.
    pda_patterns: Vec<Vec<IdlSeed>>,
    unresolved: Vec<Unresolved>,
    inferred: Vec<Inferred>,
}

impl IdlSpec {
    /// Fill owners, discriminators and created accounts from the
    /// fixture's pre-send state. `get` is usually
    /// `|pk| ctx.get_account(pk).ok()`.
    ///
    /// Call it after `setup()` has created the accounts the instruction
    /// reads — an account absent at this point is recorded as created by
    /// the instruction, which excludes it from pda-forge.
    pub fn infer_from_state(mut self, get: impl Fn(&Pubkey) -> Option<Account>) -> Self {
        let program_id = self.spec.program_id;
        let state: Vec<Option<Account>> =
            self.spec.accounts.iter().map(|m| get(&m.pubkey)).collect();
        // Discriminator of each slot that holds a program-owned account
        // of a type the IDL declares.
        let owned: Vec<Option<[u8; 8]>> = state
            .iter()
            .map(|acct| {
                let acct = acct.as_ref()?;
                let head: [u8; 8] = acct.data.get(..8)?.try_into().ok()?;
                (acct.owner == program_id && self.account_discs.contains(&head)).then_some(head)
            })
            .collect();

        for i in 0..self.spec.accounts.len() {
            if state[i].is_none() {
                if self.spec.expected_pda_seeds[i].is_some() {
                    self.spec.creates_indices.push(i);
                }
                continue;
            }
            if let Some(head) = owned[i] {
                self.spec.expected_owners[i] = Some(program_id);
                self.spec.expected_discriminators[i] = Some(head);
                // A slot with IDL seeds is constrained, so a typed
                // `Account<'info, T>` already enforces both; anything
                // else may be an `UncheckedAccount` and is worth listing.
                if self.spec.expected_pda_seeds[i].is_none() {
                    self.note(i, InferredKind::Owner);
                    self.note(i, InferredKind::Discriminator);
                }
            }
            if self.spec.expected_pda_seeds[i].is_none() {
                if let Some(seeds) = self.rederive_pda(i) {
                    self.spec.expected_pda_seeds[i] = Some(seeds);
                    self.note(i, InferredKind::PdaSeeds);
                }
            }
        }

        if self.spec.signer_indices.is_empty() {
            let written: Vec<&Account> = (0..state.len())
                .filter(|&i| self.spec.accounts[i].is_writable && owned[i].is_some())
                .filter_map(|i| state[i].as_ref())
                .collect();
            for i in 0..self.spec.accounts.len() {
                let key = self.spec.accounts[i].pubkey.to_bytes();
                let stored = written.iter().any(|a| a.data.windows(32).any(|w| w == key));
                let Some(kp) = self.keypairs[i].clone() else {
                    if stored {
                        self.unresolved.push(Unresolved {
                            account: Some(self.names[i].clone()),
                            what: "no signer on this ix, and its key is stored in written state: \
                                   bind its keypair with .signer() to test signer-skip"
                                .into(),
                        });
                    }
                    continue;
                };
                if stored {
                    self.spec.accounts[i].is_signer = true;
                    self.spec.signer_indices.push(i);
                    self.spec.signers.push(kp);
                    self.note(i, InferredKind::Signer);
                }
            }
        }
        self
    }

    fn rederive_pda(&self, i: usize) -> Option<Vec<Vec<u8>>> {
        let target = self.spec.accounts[i].pubkey;
        self.pda_patterns.iter().find_map(|pattern| {
            let seeds: Option<Vec<Vec<u8>>> = pattern
                .iter()
                .map(|seed| match seed {
                    IdlSeed::Const { value } => Some(value.clone()),
                    IdlSeed::Account { path } => self
                        .names
                        .iter()
                        .position(|n| n == path)
                        .map(|j| self.spec.accounts[j].pubkey.to_bytes().to_vec()),
                    IdlSeed::Arg { .. } => None,
                })
                .collect();
            let seeds = seeds?;
            let refs: Vec<&[u8]> = seeds.iter().map(|s| s.as_slice()).collect();
            (Pubkey::find_program_address(&refs, &self.spec.program_id).0 == target)
                .then_some(seeds)
        })
    }

    fn note(&mut self, i: usize, what: InferredKind) {
        self.inferred.push(Inferred { account: self.names[i].clone(), what });
    }

    pub fn inferred(&self) -> &[Inferred] {
        &self.inferred
    }

    pub fn unresolved(&self) -> &[Unresolved] {
        &self.unresolved
    }

    pub fn spec(&self) -> &InstructionSpec {
        &self.spec
    }

    pub fn into_spec(self) -> InstructionSpec {
        self.spec
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytepoke::{anchor_account_disc, anchor_ix_sighash};
    use solana_signer::Signer;

    const ESCROW_IDL: &str = include_str!("../../../examples/escrow-demo/idl/escrow_clean.json");

    fn idl() -> Idl {
        Idl::from_json(ESCROW_IDL).unwrap()
    }

    fn program_id() -> Pubkey {
        idl().address.parse().unwrap()
    }

    fn vault_account(owner: Pubkey, disc: [u8; 8]) -> Account {
        let mut data = disc.to_vec();
        data.resize(8 + 89, 0);
        Account { lamports: 1_000_000, data, owner, executable: false, rent_epoch: 0 }
    }

    #[test]
    fn deposit_matches_the_hand_written_spec() {
        let pid = program_id();
        let depositor = Arc::new(Keypair::new());
        let (vault, _) =
            Pubkey::find_program_address(&[b"vault", depositor.pubkey().as_ref()], &pid);

        let built = idl()
            .spec("deposit", pid)
            .unwrap()
            .account("vault", vault)
            .signer("depositor", Arc::clone(&depositor))
            .args(&50_000u64.to_le_bytes())
            .build()
            .unwrap()
            .infer_from_state(|pk| {
                (*pk == vault).then(|| vault_account(pid, anchor_account_disc("Vault")))
            });
        let s = built.spec();

        // The hand-written escrow_clean harness, field for field.
        assert_eq!(
            s.accounts,
            vec![
                AccountMeta::new(vault, false),
                AccountMeta::new(depositor.pubkey(), true),
                AccountMeta::new_readonly(Pubkey::default(), false),
            ]
        );
        assert_eq!(s.signer_indices, vec![1]);
        assert_eq!(s.expected_owners, vec![Some(pid), None, None]);
        assert_eq!(
            s.expected_discriminators,
            vec![Some(anchor_account_disc("Vault")), None, None]
        );
        assert_eq!(
            s.expected_pda_seeds,
            vec![Some(vec![b"vault".to_vec(), depositor.pubkey().to_bytes().to_vec()]), None, None]
        );
        assert!(s.creates_indices.is_empty());
        let mut data = anchor_ix_sighash("deposit").to_vec();
        data.extend_from_slice(&50_000u64.to_le_bytes());
        assert_eq!(s.data_sample, data);
    }

    /// The IDL of escrow's `unsafe_withdraw` declares nothing: both slots
    /// are `UncheckedAccount`. Every Critical-5 expectation on it has to
    /// come from state, and each must say so.
    #[test]
    fn unchecked_slots_get_expectations_from_state() {
        let idl = Idl::from_json(include_str!("../../../examples/escrow-demo/idl/escrow.json"))
            .unwrap();
        let pid: Pubkey = idl.address.parse().unwrap();
        let depositor = Arc::new(Keypair::new());
        let (vault, _) =
            Pubkey::find_program_address(&[b"vault", depositor.pubkey().as_ref()], &pid);
        let mut vault_state = vault_account(pid, anchor_account_disc("Vault"));
        vault_state.data[8..40].copy_from_slice(depositor.pubkey().as_ref());

        let bare = idl
            .spec("unsafe_withdraw", pid)
            .unwrap()
            .account("vault", vault)
            .signer("depositor", Arc::clone(&depositor))
            .build()
            .unwrap();
        assert!(bare.spec().signer_indices.is_empty());
        assert_eq!(bare.spec().expected_pda_seeds, vec![None, None]);

        let built = bare.infer_from_state(|pk| (*pk == vault).then(|| vault_state.clone()));
        let s = built.spec();
        assert_eq!(s.expected_owners, vec![Some(pid), None]);
        assert_eq!(
            s.expected_pda_seeds[0],
            Some(vec![b"vault".to_vec(), depositor.pubkey().to_bytes().to_vec()])
        );
        assert_eq!(s.signer_indices, vec![1]);
        assert!(s.accounts[1].is_signer);
        assert_eq!(s.signers.len(), 1);
        let kinds: Vec<_> = built.inferred().iter().map(|i| (i.account.as_str(), i.what)).collect();
        assert_eq!(
            kinds,
            vec![
                ("vault", InferredKind::Owner),
                ("vault", InferredKind::Discriminator),
                ("vault", InferredKind::PdaSeeds),
                ("depositor", InferredKind::Signer),
            ]
        );
    }

    /// `claim` has a signer (the beneficiary), so the stored depositor
    /// key is not promoted — the clean program does not require it.
    #[test]
    fn stored_key_is_not_a_signer_when_the_ix_has_one() {
        let pid = program_id();
        let depositor = Keypair::new();
        let beneficiary = Arc::new(Keypair::new());
        let (vault, _) =
            Pubkey::find_program_address(&[b"vault", depositor.pubkey().as_ref()], &pid);
        let mut vault_state = vault_account(pid, anchor_account_disc("Vault"));
        vault_state.data[8..40].copy_from_slice(depositor.pubkey().as_ref());
        let s = idl()
            .spec("claim", pid)
            .unwrap()
            .account("vault", vault)
            .signer("depositor", Arc::new(depositor))
            .signer("beneficiary", beneficiary)
            .build()
            .unwrap()
            .infer_from_state(|pk| (*pk == vault).then(|| vault_state.clone()))
            .into_spec();
        assert_eq!(s.signer_indices, vec![2]);
        assert!(!s.accounts[1].is_signer);
    }

    #[test]
    fn report_points_at_the_unsigned_writers() {
        let idl = Idl::from_json(include_str!("../../../examples/escrow-demo/idl/escrow.json"))
            .unwrap();
        let r = idl.report();
        assert!(r.contains(
            "3 instruction(s) with no signer write an unconstrained slot: \
             unsafe_set_amount_from_source, unsafe_withdraw_with_bump, unsafe_withdraw"
        ));
        // Clean program: every writer is signed.
        assert!(super::tests::idl().report().contains("Every instruction that writes"));
    }

    #[test]
    fn bindings_skip_fixed_addresses_and_name_args() {
        let b = idl().instruction("initialize").unwrap().rust_bindings();
        assert!(b.contains(".account(\"vault\""));
        assert!(b.contains(".signer(\"depositor\""));
        assert!(!b.contains("system_program"));
        assert!(b.contains("borsh: beneficiary: pubkey, unlock_slot: u64"));
    }

    #[test]
    fn idl_discriminator_is_the_anchor_one() {
        // The IDL's `escrow_clean::Vault` name is path-qualified; the
        // bytes must still equal sha256("account:Vault")[..8].
        assert_eq!(idl().account_discriminators(), vec![anchor_account_disc("Vault")]);
    }

    #[test]
    fn absent_pda_is_recorded_as_created() {
        let pid = program_id();
        let depositor = Arc::new(Keypair::new());
        let (vault, _) =
            Pubkey::find_program_address(&[b"vault", depositor.pubkey().as_ref()], &pid);
        let s = idl()
            .spec("initialize", pid)
            .unwrap()
            .account("vault", vault)
            .signer("depositor", depositor)
            .build()
            .unwrap()
            .infer_from_state(|_| None)
            .into_spec();
        assert_eq!(s.creates_indices, vec![0]);
        assert_eq!(s.expected_owners, vec![None, None, None]);
    }

    #[test]
    fn foreign_owner_or_unknown_disc_is_not_declared() {
        let pid = program_id();
        let other = Pubkey::new_unique();
        for acct in [
            vault_account(other, anchor_account_disc("Vault")),
            vault_account(pid, anchor_account_disc("NotInIdl")),
        ] {
            let depositor = Arc::new(Keypair::new());
            let vault = Pubkey::new_unique();
            let s = idl()
                .spec("withdraw", pid)
                .unwrap()
                .account("vault", vault)
                .signer("depositor", depositor)
                .build()
                .unwrap()
                .infer_from_state(|pk| (*pk == vault).then(|| acct.clone()))
                .into_spec();
            assert_eq!(s.expected_owners, vec![None, None]);
            assert_eq!(s.expected_discriminators, vec![None, None]);
        }
    }

    #[test]
    fn missing_bindings_are_named() {
        let pid = program_id();
        let err = idl().spec("claim", pid).unwrap().build().err().unwrap();
        assert_eq!(err.to_string(), "`claim`: bind these accounts with .account(): vault, depositor, beneficiary");

        let err = idl()
            .spec("claim", pid)
            .unwrap()
            .account("vault", Pubkey::new_unique())
            .account("depositor", Pubkey::new_unique())
            .account("beneficiary", Pubkey::new_unique())
            .build()
            .err()
            .unwrap();
        assert!(matches!(err, IdlError::MissingSigners { names, .. } if names == ["beneficiary"]));
    }

    #[test]
    fn unbound_arg_seed_is_reported_not_guessed() {
        let json = r#"{"instructions":[{"name":"open","discriminator":[1,2,3,4,5,6,7,8],
            "accounts":[{"name":"market","writable":true,
              "pda":{"seeds":[{"kind":"const","value":[109]},{"kind":"arg","path":"id"}]}},
              {"name":"ata","pda":{"seeds":[{"kind":"const","value":[1]}],
                "program":{"kind":"const","value":[2]}}},
              {"name":"inner","accounts":[{"name":"auth","signer":true}]}]}]}"#;
        let idl = Idl::from_json(json).unwrap();
        let pid = Pubkey::new_unique();
        let auth = Arc::new(Keypair::new());
        let base = || {
            idl.spec("open", pid)
                .unwrap()
                .account("market", Pubkey::new_unique())
                .account("ata", Pubkey::new_unique())
                .signer("auth", Arc::clone(&auth))
        };

        let built = base().build().unwrap();
        assert_eq!(built.spec().expected_pda_seeds, vec![None, None, None]);
        // Composite `inner.auth` is flattened into slot 2.
        assert_eq!(built.spec().signer_indices, vec![2]);
        let accounts: Vec<_> =
            built.unresolved().iter().filter_map(|u| u.account.clone()).collect();
        assert_eq!(accounts, vec!["market", "ata"]);

        let built = base().seed_arg("id", &7u64.to_le_bytes()).build().unwrap();
        assert_eq!(
            built.spec().expected_pda_seeds[0],
            Some(vec![b"m".to_vec(), 7u64.to_le_bytes().to_vec()])
        );
    }
}
