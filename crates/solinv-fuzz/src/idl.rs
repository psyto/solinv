//! # Anchor IDL → `InstructionSpec`
//!
//! Hand-filling an `InstructionSpec` is the slowest step of adopting
//! solinv: fourteen fields per instruction, most of which the program
//! has already declared once in its `#[derive(Accounts)]` structs. The
//! Anchor IDL (0.30+ format, with PDA resolution on; legacy IDLs without
//! discriminators are rejected) carries most of it:
//!
//! | spec field                | source                                   |
//! |---------------------------|------------------------------------------|
//! | `accounts`                | IDL order + `writable` / `signer`        |
//! | `signer_indices`          | IDL `signer`                             |
//! | `expected_pda_seeds`      | IDL `pda.seeds` (const / account / arg)  |
//! | `data_sample`             | IDL discriminator + caller's arg bytes   |
//! | `expected_owners`         | state, on slots with IDL seeds           |
//! | `expected_discriminators` | state, on slots with IDL seeds           |
//! | `creates_indices`         | state: seeded account absent pre-send    |
//!
//! The last three are not in the instruction's IDL entry (it names
//! accounts, not their types), so [`IdlSpec::infer_from_state`] reads
//! them off the fixture after `setup()`. A seeded slot pins one address,
//! so the account found there is taken to be the type the instruction
//! expects — an assumption that fails only for a seeded slot meant to
//! hold different types at different times.
//!
//! ## Candidates: where the bugs are
//!
//! What the IDL declares, Anchor enforces: `signer: true` comes from a
//! `Signer<'info>`, `pda.seeds` from a `seeds = [...]` constraint. A spec
//! built from the IDL alone asks the program to honour checks its own
//! macros already generated, and on Anchor it finds nothing. The bugs
//! live where the IDL is *silent* — typically an `UncheckedAccount`.
//!
//! [`IdlSpec::infer_candidates`] adds expectations for those slots from
//! what the fixture put there, and lists each in [`IdlSpec::candidates`]:
//!
//! - **owner / discriminator** — the slot holds a program-owned account
//!   carrying an IDL discriminator.
//! - **pda seeds** — a seed pattern the IDL declares elsewhere re-derives
//!   the slot's exact address.
//! - **signer** — the instruction has no signer, writes a program-owned
//!   account, and that account's data contains the slot's pubkey.
//!
//! These are hypotheses about intent, not facts. The evidence shows what
//! the fixture passed, not what the instruction must require: a
//! permissionless crank that pays a stored `beneficiary` matches the
//! signer rule and is correct. A finding on a candidate slot is a lead
//! to confirm against the program's intent, which is why the two passes
//! are separate and the candidates are listed.
//!
//! What neither pass can supply stays empty and is listed in
//! [`IdlSpec::unresolved`]: `swap_alternates` (a semantic relation, see
//! the `HasInstructionSet` docs), seeds that read another account's
//! data, seeds derived under a different program, discriminators that
//! are not 8 bytes long.
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
//!     .infer_candidates(|pk| ctx.get_account(pk).ok())
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
    /// 8 bytes by default; any length since Anchor 0.31.
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
    Const {
        value: Vec<u8>,
    },
    /// `path` names an account (`"authority"`), or a field of one
    /// (`"vault.authority"`, with `account` naming its type).
    Account {
        path: String,
        #[serde(default)]
        account: Option<String>,
    },
    Arg {
        path: String,
    },
}

/// One slot of a flattened account list. `path` is dotted for accounts
/// inside a composite (`"group_a.authority"`).
#[derive(Clone, Debug)]
pub struct FlatAccount<'a> {
    pub account: &'a IdlAccount,
    /// Path of the enclosing composite, `""` at top level.
    prefix: String,
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
            IdlError::Parse(e) => write!(
                f,
                "IDL does not parse (solinv reads the Anchor 0.30+ format): {e}"
            ),
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

/// Accounts bound by name when the IDL gives no address — IDLs built
/// without PDA resolution omit even `system_program`'s. A name is a
/// convention, not a declaration, so the list is the two names a program
/// is least likely to reuse for an account of its own. Sysvar names
/// (`clock`, `rent`, `instructions`) are left out: a program-owned
/// `Account<'info, ClockState>` named `clock` is ordinary. So is
/// `token_program`, which may be SPL Token or Token-2022. A wrong guess
/// here would still be visible — Anchor checks a `Program<'info, _>`'s
/// address, so the canonical send fails — and every binding is listed in
/// [`IdlSpec::defaulted`].
pub const WELL_KNOWN: &[(&str, &str)] = &[
    ("system_program", "11111111111111111111111111111111"),
    ("associated_token_program", "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"),
];

fn well_known(name: &str) -> Option<Pubkey> {
    WELL_KNOWN.iter().find(|(n, _)| *n == name).and_then(|(_, a)| a.parse().ok())
}

fn compact(ty: &serde_json::Value) -> String {
    match ty {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

impl Idl {
    /// The account-validation surface of every instruction, as the IDL
    /// declares it. Static: no fixture needed, so it is the first thing
    /// to run on a program. The IDL cannot tell a typed `Account<'_, T>`
    /// from an `UncheckedAccount` (Anchor strips the `/// CHECK:` line
    /// from `docs`), so a slot that declares nothing is only "silent";
    /// [`Idl::report_with`] takes the declared types from source.
    pub fn report(&self) -> String {
        self.report_with(|_, _| None)
    }

    /// [`Idl::report`], with each slot's declared Rust type from `kind`
    /// (instruction name, dotted slot path), so the slots whose owner and
    /// type checks are hand-written are counted apart from typed ones.
    pub fn report_with(&self, kind: impl Fn(&str, &str) -> Option<SlotKind>) -> String {
        self.report_with_bound(kind, |_, _| true)
    }

    /// [`Idl::report_with`], with `bound` saying whether some declared
    /// constraint fixes a typed slot's identity (`has_one`, `seeds`,
    /// `address`, a `.key()` comparison, …). A typed slot none fixes is
    /// marked `t`: Anchor checks its owner and type, so unless the
    /// handler compares its key, a caller may pass any account of the
    /// type — where `account-swap` should look.
    pub fn report_with_bound(
        &self,
        kind: impl Fn(&str, &str) -> Option<SlotKind>,
        bound: impl Fn(&str, &str) -> bool,
    ) -> String {
        let types: Vec<&str> = self
            .accounts
            .iter()
            .map(|a| a.name.rsplit("::").next().unwrap_or(&a.name))
            .collect();
        let mut out = format!(
            "program {} — {} instructions, account types: {}\n\n\
             S signer  W writable  P pda seeds  A fixed address  \
             · nothing declared  U unchecked in source  T typed in source  \
             t typed, identity not fixed by a constraint\n",
            if self.address.is_empty() { "(no address)" } else { &self.address },
            self.instructions.len(),
            if types.is_empty() { "none".into() } else { types.join(", ") },
        );
        let width = self
            .instructions
            .iter()
            .flat_map(|ix| ix.flat_accounts())
            .map(|a| a.path().len())
            .max()
            .unwrap_or(0);
        let mut unsigned = Vec::new();
        let mut loose = Vec::new();
        let (mut silent, mut unchecked, mut known) = (0, 0, false);
        for ix in &self.instructions {
            let kinds: Vec<Option<SlotKind>> =
                ix.flat_accounts().iter().map(|f| kind(&ix.name, &f.path())).collect();
            known |= kinds.iter().any(Option::is_some);
            // Judged on IDL constraints, not declared types: a missing
            // authority check is just as missing on a typed account
            // (escrow's unsafe_set_amount_from_source writes a typed
            // Vault with no signer at all).
            let flag = if ix.is_unsigned_writer() {
                unsigned.push(ix.name.as_str());
                "   ! no signer, writes an unconstrained slot"
            } else {
                ""
            };
            out += &format!("\n{}{}\n", ix.name, flag);
            for (i, flat) in ix.flat_accounts().iter().enumerate() {
                let a = flat.account;
                let marks: String = [
                    (a.signer, 'S'),
                    (a.writable, 'W'),
                    (a.pda.is_some(), 'P'),
                    (a.address.is_some(), 'A'),
                ]
                .iter()
                .map(|&(on, c)| if on { c } else { ' ' })
                .collect();
                let quiet = match (a.is_silent(), kinds[i]) {
                    (_, Some(SlotKind::Unchecked)) => {
                        unchecked += 1;
                        " U"
                    }
                    (true, Some(SlotKind::Typed)) if !bound(&ix.name, &flat.path()) => {
                        if a.writable {
                            loose.push(format!("{}.{}", ix.name, flat.path()));
                        }
                        " t"
                    }
                    (true, Some(SlotKind::Typed)) => " T",
                    (true, None) => {
                        silent += 1;
                        " ·"
                    }
                    _ => "",
                };
                out += &format!("  {i:>2} {:<width$}  {marks}{quiet}\n", flat.path());
            }
        }
        if known {
            out += &format!(
                "\n{unchecked} slots are UncheckedAccount / AccountInfo in source: their \
                 checks are hand-written, which is where the Critical 5 can find something.\n"
            );
            if !loose.is_empty() {
                out += &format!(
                    "! {} writable typed accounts have no declared constraint fixing which \
                     account they are (no seeds, address, has_one, associated_token:: or \
                     .key() comparison; the handler body is not read). Unless the handler \
                     checks the key, a caller may pass any account of the type: expected for \
                     their own token accounts, a hole for a vault, escrow or pool the program \
                     owns. account-swap candidates: {}\n",
                    loose.len(),
                    loose.join(", ")
                );
            }
            if silent > 0 {
                out += &format!("{silent} slots declare nothing and were not found in source.\n");
            }
        } else {
            out += &format!(
                "\n{silent} slots declare nothing in the IDL: typed accounts or \
                 UncheckedAccount, which the IDL cannot tell apart (pass --src to read the \
                 declared types). `infer_candidates` proposes checks for them from fixture \
                 state.\n"
            );
        }
        if unsigned.is_empty() {
            out += "Every instruction that writes an unconstrained slot has a signer.\n";
        } else {
            out += &format!(
                "{} instruction(s) with no signer write an unconstrained slot: {}\n\
                 Start there: either they are meant to be permissionless, or an \
                 authority check is missing.\n",
                unsigned.len(),
                unsigned.join(", ")
            );
        }
        out
    }

    pub fn from_json(json: &str) -> Result<Self, IdlError> {
        serde_json::from_str(json).map_err(|e| IdlError::Parse(Self::diagnose(json, e)))
    }

    /// Name the two formats that most often fail to parse, with the fix.
    fn diagnose(json: &str, err: serde_json::Error) -> String {
        let raw: serde_json::Value = match serde_json::from_str(json) {
            Ok(v) => v,
            Err(_) => return err.to_string(),
        };
        let first_ix = raw.get("instructions").and_then(|ixs| ixs.get(0));
        if first_ix.is_some_and(|ix| ix.get("discriminant").is_some()) {
            return "this is a Shank IDL (native program, `discriminant` per instruction); \
                    solinv reads Anchor IDLs only"
                .into();
        }
        if first_ix.is_some_and(|ix| ix.get("discriminator").is_none()) {
            return "this is a legacy (pre-0.30) Anchor IDL; convert it first with \
                    `anchor idl convert <path> -p <program id> -o <out>`"
                .into();
        }
        err.to_string()
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
    pub fn account_discriminators(&self) -> Vec<Vec<u8>> {
        self.accounts.iter().map(|a| a.discriminator.clone()).collect()
    }
}

/// A slot's declared type in the program source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotKind {
    /// `UncheckedAccount` / `AccountInfo`: checks are hand-written.
    Unchecked,
    /// `Account`, `AccountLoader`, `InterfaceAccount`, `Signer`,
    /// `Program`, `Interface`, `Sysvar`: Anchor checks owner and type.
    Typed,
}

impl IdlAccount {
    /// Nothing in the IDL constrains this slot: not a signer, no seeds,
    /// no fixed address. Either an `UncheckedAccount` or a typed account
    /// without seeds; the IDL cannot tell which.
    pub fn is_silent(&self) -> bool {
        !self.signer && self.pda.is_none() && self.address.is_none()
    }
}

impl FlatAccount<'_> {
    /// Dotted path from the instruction's account struct.
    pub fn path(&self) -> String {
        if self.prefix.is_empty() {
            self.account.name.clone()
        } else {
            format!("{}.{}", self.prefix, self.account.name)
        }
    }

    fn prefix(&self) -> &str {
        &self.prefix
    }
}

impl IdlInstruction {
    /// No signer at all, and at least one writable slot the IDL leaves
    /// unconstrained. The shape of a missing authority check — or of a
    /// deliberately permissionless instruction.
    pub fn is_unsigned_writer(&self) -> bool {
        let flat = self.flat_accounts();
        !flat.iter().any(|a| a.account.signer)
            && flat.iter().any(|a| a.account.writable && a.account.is_silent())
    }

    /// A `SpecBuilder` call chain for this instruction with every binding
    /// left as a `todo!`, for pasting into a fixture.
    pub fn rust_bindings(&self) -> String {
        let mut out = format!("idl.spec(\"{}\", program_id)?\n", self.name);
        let unsigned = self.is_unsigned_writer();
        for flat in self.flat_accounts() {
            let (a, path) = (flat.account, flat.path());
            if a.address.is_some() {
                continue;
            }
            let optional = if a.optional { " (optional: omit to leave it out)" } else { "" };
            if a.signer {
                out += &format!(
                    "    .signer(\"{path}\", todo!(\"{path}: Arc<Keypair>{optional}\"))\n"
                );
            } else if unsigned && a.is_silent() {
                out += &format!(
                    "    // no signer on this ix: binding {path}'s keypair with .signer()\n    \
                     // lets infer_candidates test it as the authority\n    \
                     .account(\"{path}\", todo!(\"{path}: Pubkey{optional}\"))\n"
                );
            } else {
                out += &format!("    .account(\"{path}\", todo!(\"{path}: Pubkey{optional}\"))\n");
            }
        }
        if !self.args.is_empty() {
            let args: Vec<String> =
                self.args.iter().map(|a| format!("{}: {}", a.name, compact(&a.ty))).collect();
            out += &format!("    .args(&todo!(\"borsh: {}\"))\n", args.join(", "));
        }
        out += "    .build()?\n    \
                .infer_from_state(|pk| ctx.get_account(pk).ok())\n    \
                // leads, not facts: confirm each finding on a listed candidate\n    \
                .infer_candidates(|pk| ctx.get_account(pk).ok())\n";
        out
    }

    /// The instruction's accounts in wire order, composites flattened.
    pub fn flat_accounts(&self) -> Vec<FlatAccount<'_>> {
        fn walk<'a>(
            items: &'a [IdlAccountItem],
            prefix: &mut Vec<&'a str>,
            out: &mut Vec<(Vec<&'a str>, &'a IdlAccount)>,
        ) {
            for item in items {
                match item {
                    IdlAccountItem::Single(a) => out.push((prefix.clone(), a)),
                    IdlAccountItem::Composite { name, accounts } => {
                        prefix.push(name);
                        walk(accounts, prefix, out);
                        prefix.pop();
                    }
                }
            }
        }
        let mut raw = Vec::new();
        walk(&self.accounts, &mut Vec::new(), &mut raw);
        raw.into_iter()
            .map(|(prefix, account)| FlatAccount { account, prefix: prefix.join(".") })
            .collect()
    }
}

/// Find the slot a name refers to: the exact dotted path, else a leaf
/// name that is unique in the instruction.
fn slot_of(paths: &[String], name: &str) -> Option<usize> {
    if let Some(i) = paths.iter().position(|p| p == name) {
        return Some(i);
    }
    let mut leaf = paths
        .iter()
        .enumerate()
        .filter(|(_, p)| p.rsplit('.').next() == Some(name));
    match (leaf.next(), leaf.next()) {
        (Some((i, _)), None) => Some(i),
        _ => None,
    }
}

/// Resolve an `account` seed path relative to the composite a slot sits
/// in. `Err` names why: account-data seeds (`vault.authority` where
/// `vault` is an account) need the account's layout, which the IDL's
/// type section has and solinv does not decode.
fn seed_slot(paths: &[String], prefix: &str, path: &str) -> Result<usize, String> {
    if !prefix.is_empty() {
        if let Some(i) = slot_of(paths, &format!("{prefix}.{path}")) {
            return Ok(i);
        }
    }
    slot_of(paths, path).ok_or_else(|| format!("seed reads account data `{path}`"))
}

/// Binds the fixture's concrete pubkeys and keypairs to IDL account
/// names. Name a slot by its dotted path (`"group_a.authority"`) or, when
/// unambiguous, by its leaf name. Accounts with a fixed IDL `address`
/// (system program, sysvars) need no binding.
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
    /// signer, the keypair lets `infer_candidates` test it as one.
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

    /// The binding for a slot, by full path or leaf name.
    fn bound<'m, T>(&self, map: &'m HashMap<String, T>, flat: &FlatAccount) -> Option<&'m T> {
        map.get(&flat.path()).or_else(|| {
            let leaf = &flat.account.name;
            let unique = self
                .ix
                .flat_accounts()
                .iter()
                .filter(|f| &f.account.name == leaf)
                .count()
                == 1;
            if unique { map.get(leaf) } else { None }
        })
    }

    pub fn build(self) -> Result<IdlSpec, IdlError> {
        let flat = self.ix.flat_accounts();
        let paths: Vec<String> = flat.iter().map(|f| f.path()).collect();
        let ix_name = self.ix.name.clone();

        // An optional slot left unbound is omitted: Anchor encodes that
        // as the program id in the slot, and it signs nothing.
        let omitted: Vec<bool> = flat
            .iter()
            .map(|f| f.account.optional && self.bound(&self.accounts, f).is_none())
            .collect();

        let mut pubkeys = Vec::with_capacity(flat.len());
        let mut missing = Vec::new();
        let mut defaulted = Vec::new();
        for (i, f) in flat.iter().enumerate() {
            if let Some(pk) = self.bound(&self.accounts, f) {
                pubkeys.push(*pk);
            } else if let Some(addr) = &f.account.address {
                let pk = addr.parse::<Pubkey>().map_err(|_| IdlError::BadAddress {
                    account: paths[i].clone(),
                    address: addr.clone(),
                })?;
                pubkeys.push(pk);
            } else if omitted[i] {
                pubkeys.push(self.program_id);
            } else if let Some(pk) = well_known(&f.account.name) {
                defaulted.push((paths[i].clone(), pk));
                pubkeys.push(pk);
            } else {
                missing.push(paths[i].clone());
                pubkeys.push(Pubkey::default());
            }
        }
        if !missing.is_empty() {
            return Err(IdlError::MissingAccounts { ix: ix_name, names: missing });
        }

        let signs: Vec<bool> =
            flat.iter().zip(&omitted).map(|(f, &o)| f.account.signer && !o).collect();
        let missing_signers: Vec<String> = flat
            .iter()
            .enumerate()
            .filter(|&(i, f)| signs[i] && self.bound(&self.signers, f).is_none())
            .map(|(i, _)| paths[i].clone())
            .collect();
        if !missing_signers.is_empty() {
            return Err(IdlError::MissingSigners { ix: ix_name, names: missing_signers });
        }

        let mut unresolved = vec![Unresolved {
            account: None,
            what: "swap_alternates: name a second, legitimate account per context-bound slot"
                .into(),
        }];
        if let Ok(idl_id) = self.idl.address.parse::<Pubkey>() {
            if idl_id != self.program_id {
                unresolved.push(Unresolved {
                    account: None,
                    what: format!(
                        "the IDL's address is {idl_id} but the spec targets {}: the loaded .so \
                         must declare_id! the latter, or Anchor rejects every instruction with \
                         DeclaredProgramIdMismatch (4100) — usually a .so built with different \
                         features (mainnet/devnet) than the IDL",
                        self.program_id
                    ),
                });
            }
        }
        let mut accounts = Vec::with_capacity(flat.len());
        let mut signer_indices = Vec::new();
        let mut signers = Vec::new();
        let mut expected_pda_seeds = Vec::with_capacity(flat.len());

        for (i, (f, pk)) in flat.iter().zip(&pubkeys).enumerate() {
            accounts.push(if f.account.writable && !omitted[i] {
                AccountMeta::new(*pk, signs[i])
            } else {
                AccountMeta::new_readonly(*pk, signs[i])
            });
            if signs[i] {
                signer_indices.push(i);
                signers.push(Arc::clone(self.bound(&self.signers, f).unwrap()));
            }
            let seeds = match (&f.account.pda, omitted[i]) {
                (Some(pda), false) => {
                    match self.resolve_seeds(pda, &paths, &pubkeys, f.prefix()) {
                        Ok(seeds) => Some(seeds),
                        Err(why) => {
                            unresolved.push(Unresolved {
                                account: Some(paths[i].clone()),
                                what: format!("pda seeds: {why}"),
                            });
                            None
                        }
                    }
                }
                _ => None,
            };
            expected_pda_seeds.push(seeds);
        }

        let mut data_sample = self.ix.discriminator.clone();
        data_sample.extend_from_slice(&self.args);

        let keypairs = flat
            .iter()
            .enumerate()
            .map(|(i, f)| if signs[i] { None } else { self.bound(&self.signers, f).cloned() })
            .collect();
        let pda_patterns = self
            .idl
            .instructions
            .iter()
            .flat_map(|ix| ix.flat_accounts())
            .filter_map(|f| {
                let pda = f.account.pda.as_ref().filter(|p| p.program.is_none())?;
                Some((f.prefix().to_string(), pda.seeds.clone()))
            })
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
            defaulted,
            names: paths,
            idl_seeded: flat.iter().map(|f| f.account.pda.is_some()).collect(),
            omitted,
            keypairs,
            pda_patterns,
            arg_seeds: self.arg_seeds,
            unresolved,
            candidates: vec![],
        })
    }

    fn resolve_seeds(
        &self,
        pda: &IdlPda,
        paths: &[String],
        pubkeys: &[Pubkey],
        prefix: &str,
    ) -> Result<Vec<Vec<u8>>, String> {
        if pda.program.is_some() {
            return Err("derived under another program; pda-forge checks this program only".into());
        }
        pda.seeds
            .iter()
            .map(|seed| match seed {
                IdlSeed::Const { value } => Ok(value.clone()),
                IdlSeed::Account { path, .. } => {
                    seed_slot(paths, prefix, path).map(|j| pubkeys[j].to_bytes().to_vec())
                }
                IdlSeed::Arg { path } => self
                    .arg_seeds
                    .get(path)
                    .cloned()
                    .ok_or_else(|| format!("bind arg seed `{path}` with .seed_arg()")),
            })
            .collect()
    }
}

/// Something the IDL could not supply. Printed so the gap is visible
/// instead of silently weakening a detector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unresolved {
    pub account: Option<String>,
    pub what: String,
}

/// An expectation [`IdlSpec::infer_candidates`] proposed for a slot the
/// IDL leaves unconstrained. A finding on it is a lead to confirm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub account: String,
    pub what: CandidateKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateKind {
    Owner,
    Discriminator,
    PdaSeeds,
    Signer,
}

/// A spec built from the IDL, before and after the state passes.
pub struct IdlSpec {
    spec: InstructionSpec,
    account_discs: Vec<Vec<u8>>,
    /// Dotted IDL path per slot, for reports.
    names: Vec<String>,
    /// Slot carries IDL `pda` seeds (resolved or not).
    idl_seeded: Vec<bool>,
    /// Optional slot left out of this instruction.
    omitted: Vec<bool>,
    /// Keypairs bound to slots the IDL does not mark as signers.
    keypairs: Vec<Option<Arc<Keypair>>>,
    /// Every program-local seed pattern declared anywhere in the IDL,
    /// with the composite path it was declared in.
    pda_patterns: Vec<(String, Vec<IdlSeed>)>,
    arg_seeds: HashMap<String, Vec<u8>>,
    unresolved: Vec<Unresolved>,
    candidates: Vec<Candidate>,
    /// Slots bound from [`WELL_KNOWN`] because the IDL gave no address.
    defaulted: Vec<(String, Pubkey)>,
}

/// What a slot's pre-send state says about its type.
enum Held<'a> {
    Absent,
    /// Program-owned with this IDL discriminator.
    Typed(&'a [u8]),
    Other,
}

impl IdlSpec {
    fn held<'s>(&'s self, acct: Option<&Account>) -> Held<'s> {
        let Some(acct) = acct else { return Held::Absent };
        if acct.owner != self.spec.program_id {
            return Held::Other;
        }
        // Longest match first: a 1-byte discriminator is a prefix of
        // many 8-byte ones.
        self.account_discs
            .iter()
            .filter(|d| !d.is_empty() && acct.data.starts_with(d))
            .max_by_key(|d| d.len())
            .map_or(Held::Other, |d| Held::Typed(d))
    }

    /// Record the owner, and the discriminator when the detector can
    /// carry it (it compares exactly 8 bytes).
    fn expect_type(&mut self, i: usize, disc: &[u8]) -> bool {
        self.spec.expected_owners[i] = Some(self.spec.program_id);
        match <[u8; 8]>::try_from(disc) {
            Ok(d) => {
                self.spec.expected_discriminators[i] = Some(d);
                true
            }
            Err(_) => {
                self.unresolved.push(Unresolved {
                    account: Some(self.names[i].clone()),
                    what: format!(
                        "discriminator is {} bytes; discriminator-skip compares 8",
                        disc.len()
                    ),
                });
                false
            }
        }
    }

    /// Facts from the fixture's pre-send state, for slots the IDL seeds:
    /// a seeded slot pins one address, so the account found there is
    /// the one the instruction expects (owner + discriminator), and one
    /// not there yet is one it creates. `get` is usually
    /// `|pk| ctx.get_account(pk).ok()`; call after `setup()`.
    pub fn infer_from_state(mut self, get: impl Fn(&Pubkey) -> Option<Account>) -> Self {
        for i in 0..self.spec.accounts.len() {
            if !self.idl_seeded[i] || self.omitted[i] {
                continue;
            }
            let acct = get(&self.spec.accounts[i].pubkey);
            let disc = match self.held(acct.as_ref()) {
                Held::Absent => {
                    self.spec.creates_indices.push(i);
                    continue;
                }
                Held::Typed(d) => d.to_vec(),
                Held::Other => continue,
            };
            self.expect_type(i, &disc);
        }
        self
    }

    /// Hypotheses for slots the IDL leaves unconstrained, from what the
    /// fixture put there. Each one is listed in [`IdlSpec::candidates`];
    /// see the module docs for why they are leads and not facts.
    pub fn infer_candidates(mut self, get: impl Fn(&Pubkey) -> Option<Account>) -> Self {
        let state: Vec<Option<Account>> =
            self.spec.accounts.iter().map(|m| get(&m.pubkey)).collect();
        let typed: Vec<Option<Vec<u8>>> = state
            .iter()
            .map(|a| match self.held(a.as_ref()) {
                Held::Typed(d) => Some(d.to_vec()),
                _ => None,
            })
            .collect();

        for i in 0..self.spec.accounts.len() {
            if self.idl_seeded[i] || self.omitted[i] || state[i].is_none() {
                continue;
            }
            if self.spec.accounts[i].is_signer || self.spec.expected_owners[i].is_some() {
                continue;
            }
            if let Some(disc) = &typed[i] {
                self.note(i, CandidateKind::Owner);
                if self.expect_type(i, disc) {
                    self.note(i, CandidateKind::Discriminator);
                }
            }
            match self.rederive_pda(i) {
                Ok(seeds) => {
                    self.spec.expected_pda_seeds[i] = Some(seeds);
                    self.note(i, CandidateKind::PdaSeeds);
                }
                Err(skipped) if skipped > 0 && typed[i].is_some() => {
                    self.unresolved.push(Unresolved {
                        account: Some(self.names[i].clone()),
                        what: format!(
                            "no seed pattern re-derives this address; {skipped} pattern(s) \
                             could not be evaluated (unbound arg or account-data seeds)"
                        ),
                    });
                }
                Err(_) => {}
            }
        }

        if self.spec.signer_indices.is_empty() {
            let written: Vec<&Account> = (0..state.len())
                .filter(|&i| self.spec.accounts[i].is_writable && typed[i].is_some())
                .filter_map(|i| state[i].as_ref())
                .collect();
            for i in 0..self.spec.accounts.len() {
                if self.omitted[i] {
                    continue;
                }
                let key = self.spec.accounts[i].pubkey.to_bytes();
                if !written.iter().any(|a| a.data.windows(32).any(|w| w == key)) {
                    continue;
                }
                let Some(kp) = self.keypairs[i].clone() else {
                    self.unresolved.push(Unresolved {
                        account: Some(self.names[i].clone()),
                        what: "no signer on this ix, and written state stores this key: \
                               bind its keypair with .signer() to test it as the authority"
                            .into(),
                    });
                    continue;
                };
                self.spec.accounts[i].is_signer = true;
                self.spec.signer_indices.push(i);
                self.spec.signers.push(kp);
                self.note(i, CandidateKind::Signer);
            }
        }
        self
    }

    /// Seeds of the first IDL pattern that re-derives slot `i`'s address,
    /// or how many patterns could not be evaluated.
    fn rederive_pda(&self, i: usize) -> Result<Vec<Vec<u8>>, usize> {
        let target = self.spec.accounts[i].pubkey;
        let mut skipped = 0;
        for (source_prefix, pattern) in &self.pda_patterns {
            let seeds: Option<Vec<Vec<u8>>> = pattern
                .iter()
                .map(|seed| match seed {
                    IdlSeed::Const { value } => Some(value.clone()),
                    IdlSeed::Account { path, .. } => seed_slot(&self.names, source_prefix, path)
                        .ok()
                        .map(|j| self.spec.accounts[j].pubkey.to_bytes().to_vec()),
                    IdlSeed::Arg { path } => self.arg_seeds.get(path).cloned(),
                })
                .collect();
            let Some(seeds) = seeds else {
                skipped += 1;
                continue;
            };
            let refs: Vec<&[u8]> = seeds.iter().map(|s| s.as_slice()).collect();
            if Pubkey::find_program_address(&refs, &self.spec.program_id).0 == target {
                return Ok(seeds);
            }
        }
        Err(skipped)
    }

    fn note(&mut self, i: usize, what: CandidateKind) {
        self.candidates.push(Candidate { account: self.names[i].clone(), what });
    }

    pub fn candidates(&self) -> &[Candidate] {
        &self.candidates
    }

    /// One `[SOLINV_CANDIDATES]` line per candidate, for a harness to log
    /// once when it builds the spec. Detector findings name the
    /// instruction and account index but cannot know an expectation was
    /// a candidate (the `InstructionSpec` carries no provenance, and its
    /// `name` keys the reachability ledger), so the log is where a
    /// finding on a candidate is told apart from one on a fact.
    pub fn candidate_log(&self) -> Vec<String> {
        self.candidates
            .iter()
            .map(|c| {
                let idx = self.names.iter().position(|n| *n == c.account).unwrap_or(usize::MAX);
                format!(
                    "[SOLINV_CANDIDATES] ix={} account={} path={} kind={:?} \
                     (lead: confirm against the program's intent)",
                    self.spec.name, idx, c.account, c.what
                )
            })
            .collect()
    }

    /// Slots bound by name from [`WELL_KNOWN`], with the address used.
    pub fn defaulted(&self) -> &[(String, Pubkey)] {
        &self.defaulted
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

        // Nothing on these slots is a fact: the facts pass adds nothing.
        let get = |pk: &Pubkey| (*pk == vault).then(|| vault_state.clone());
        let bare = bare.infer_from_state(get);
        assert_eq!(bare.spec().expected_owners, vec![None, None]);
        let built = bare.infer_candidates(get);
        let s = built.spec();
        assert_eq!(s.expected_owners, vec![Some(pid), None]);
        assert_eq!(
            s.expected_pda_seeds[0],
            Some(vec![b"vault".to_vec(), depositor.pubkey().to_bytes().to_vec()])
        );
        assert_eq!(s.signer_indices, vec![1]);
        assert!(s.accounts[1].is_signer);
        assert_eq!(s.signers.len(), 1);
        let kinds: Vec<_> = built.candidates().iter().map(|i| (i.account.as_str(), i.what)).collect();
        assert_eq!(
            kinds,
            vec![
                ("vault", CandidateKind::Owner),
                ("vault", CandidateKind::Discriminator),
                ("vault", CandidateKind::PdaSeeds),
                ("depositor", CandidateKind::Signer),
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
            .infer_candidates(|pk| (*pk == vault).then(|| vault_state.clone()))
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

    /// An IDL built without resolution, like Jito's shipped ones: no
    /// address on system_program. Bound by name, and said so.
    #[test]
    fn unambiguous_well_known_accounts_are_bound_by_name() {
        let idl = json_idl(
            r#"[{"name":"state","writable":true},{"name":"system_program"},
                {"name":"token_program"}]"#,
            "[]",
        );
        let pid = Pubkey::new_unique();
        let err = idl.spec("ix", pid).unwrap().account("state", Pubkey::new_unique()).build();
        // token_program could be SPL Token or Token-2022: never guessed.
        assert!(matches!(err, Err(IdlError::MissingAccounts { names, .. }) if names == ["token_program"]));

        let built = idl
            .spec("ix", pid)
            .unwrap()
            .account("state", Pubkey::new_unique())
            .account("token_program", Pubkey::new_unique())
            .build()
            .unwrap();
        assert_eq!(built.spec().accounts[1].pubkey, Pubkey::default());
        assert_eq!(built.defaulted(), &[("system_program".to_string(), Pubkey::default())]);
    }

    /// Jito's tip-distribution: the IDL says mainnet, the .so built
    /// without `--features mainnet` declares testnet.
    #[test]
    fn idl_address_mismatch_is_reported() {
        let other = Pubkey::new_unique();
        let built = idl()
            .spec("withdraw", other)
            .unwrap()
            .account("vault", Pubkey::new_unique())
            .signer("depositor", Arc::new(Keypair::new()))
            .build()
            .unwrap();
        assert!(built.unresolved().iter().any(|u| u.what.contains("DeclaredProgramIdMismatch")));
        let same = idl()
            .spec("withdraw", program_id())
            .unwrap()
            .account("vault", Pubkey::new_unique())
            .signer("depositor", Arc::new(Keypair::new()))
            .build()
            .unwrap();
        assert!(!same.unresolved().iter().any(|u| u.what.contains("DeclaredProgramIdMismatch")));
    }

    #[test]
    fn report_with_source_kinds_marks_and_counts_unchecked_slots() {
        let idl = Idl::from_json(include_str!("../../../examples/escrow-demo/idl/escrow.json"))
            .unwrap();
        let r = idl.report_with(|ix, path| match (ix, path) {
            ("unsafe_set_amount_from_source", "source") => Some(SlotKind::Unchecked),
            (_, _) => Some(SlotKind::Typed),
        });
        assert!(r.contains("1 slots are UncheckedAccount / AccountInfo in source"));
        assert!(r.contains("   0 source               U"));
        // The unsigned-writer flag does not depend on declared types.
        assert!(r.contains("3 instruction(s) with no signer write an unconstrained slot"));
        assert!(idl.report().contains("which the IDL cannot tell apart"));
        assert!(!r.contains(" t\n") && !r.contains("typed accounts have no declared"));

        let loose = idl.report_with_bound(
            |_, _| Some(SlotKind::Typed),
            |ix, path| (ix, path) != ("unsafe_set_amount_from_source", "target"),
        );
        assert!(loose.contains("! 1 writable typed accounts have no declared constraint"));
        assert!(loose.contains("account-swap candidates: unsafe_set_amount_from_source.target\n"));
    }

    #[test]
    fn legacy_and_shank_idls_get_a_next_step() {
        let legacy = r#"{"version":"0.1.0","name":"p","instructions":[{"name":"go",
            "accounts":[{"name":"a","isMut":true,"isSigner":false}],"args":[]}]}"#;
        let shank = r#"{"name":"p","instructions":[{"name":"Go","accounts":[],
            "discriminant":{"type":"u8","value":0}}]}"#;
        let msg = |j: &str| Idl::from_json(j).err().unwrap().to_string();
        assert!(msg(legacy).contains("anchor idl convert <path> -p <program id>"));
        assert!(msg(shank).contains("Shank IDL"));
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

    fn json_idl(accounts: &str, types: &str) -> Idl {
        Idl::from_json(&format!(
            r#"{{"instructions":[{{"name":"ix","discriminator":[1,2,3,4,5,6,7,8],
                "accounts":{accounts}}}],"accounts":{types}}}"#
        ))
        .unwrap()
    }

    #[test]
    fn composite_paths_keep_duplicate_leaves_apart() {
        let idl = json_idl(
            r#"[{"name":"group_a","accounts":[{"name":"authority","signer":true},
                  {"name":"pool","writable":true,"pda":{"seeds":[{"kind":"account","path":"authority"}]}}]},
                {"name":"group_b","accounts":[{"name":"authority","signer":true}]}]"#,
            "[]",
        );
        let pid = Pubkey::new_unique();
        let (a, b) = (Arc::new(Keypair::new()), Arc::new(Keypair::new()));
        // The leaf alone is ambiguous: nothing binds.
        let err = idl.spec("ix", pid).unwrap().signer("authority", Arc::clone(&a)).build();
        assert!(matches!(err, Err(IdlError::MissingAccounts { .. })));

        let built = idl
            .spec("ix", pid)
            .unwrap()
            .signer("group_a.authority", Arc::clone(&a))
            .account("pool", Pubkey::new_unique())
            .signer("group_b.authority", Arc::clone(&b))
            .build()
            .unwrap();
        let s = built.spec();
        assert_eq!(s.accounts[0].pubkey, a.pubkey());
        assert_eq!(s.accounts[2].pubkey, b.pubkey());
        // The seed  inside group_a resolves to group_a's.
        assert_eq!(s.expected_pda_seeds[1], Some(vec![a.pubkey().to_bytes().to_vec()]));
        let stub = idl.instruction("ix").unwrap().rust_bindings();
        assert!(stub.contains(".signer(\"group_b.authority\""));
    }

    #[test]
    fn rederive_keeps_the_source_composite() {
        let idl = Idl::from_json(
            r#"{"instructions":[
              {"name":"open","discriminator":[1,1,1,1,1,1,1,1],"accounts":[{"name":"group_a","accounts":[
                {"name":"authority","signer":true},
                {"name":"pool","writable":true,"pda":{"seeds":[{"kind":"account","path":"authority"}]}}]}]},
              {"name":"use","discriminator":[2,2,2,2,2,2,2,2],"accounts":[
                {"name":"group_a","accounts":[{"name":"authority"}]},
                {"name":"group_b","accounts":[{"name":"authority"}]},
                {"name":"pool","writable":true}]}],
             "accounts":[{"name":"Pool","discriminator":[3,3,3,3,3,3,3,3]}]}"#,
        )
        .unwrap();
        let pid = Pubkey::new_unique();
        let (a, b) = (Pubkey::new_unique(), Pubkey::new_unique());
        let (pool, _) = Pubkey::find_program_address(&[a.as_ref()], &pid);
        let acct = Account { lamports: 1, data: vec![3; 8], owner: pid, executable: false, rent_epoch: 0 };
        let built = idl
            .spec("use", pid)
            .unwrap()
            .account("group_a.authority", a)
            .account("group_b.authority", b)
            .account("pool", pool)
            .build()
            .unwrap()
            .infer_candidates(|pk| (*pk == pool).then(|| acct.clone()));
        assert_eq!(built.spec().expected_pda_seeds[2], Some(vec![a.to_bytes().to_vec()]));
        assert!(built.candidate_log().iter().any(|l| l.starts_with(
            "[SOLINV_CANDIDATES] ix=use account=2 path=pool kind=PdaSeeds"
        )));
    }

    #[test]
    fn account_data_seed_is_unresolved() {
        let idl = json_idl(
            r#"[{"name":"vault"},{"name":"pool","pda":{"seeds":
                [{"kind":"account","path":"vault.authority","account":"Vault"}]}}]"#,
            "[]",
        );
        let built = idl
            .spec("ix", Pubkey::new_unique())
            .unwrap()
            .account("vault", Pubkey::new_unique())
            .account("pool", Pubkey::new_unique())
            .build()
            .unwrap();
        assert_eq!(built.spec().expected_pda_seeds[1], None);
        assert!(built
            .unresolved()
            .iter()
            .any(|u| u.what == "pda seeds: seed reads account data `vault.authority`"));
    }

    #[test]
    fn omitted_optional_signer_builds_without_a_keypair() {
        let idl = json_idl(
            r#"[{"name":"admin","signer":true,"optional":true},{"name":"state","writable":true}]"#,
            "[]",
        );
        let pid = Pubkey::new_unique();
        let s = idl
            .spec("ix", pid)
            .unwrap()
            .account("state", Pubkey::new_unique())
            .build()
            .unwrap()
            .into_spec();
        assert_eq!(s.accounts[0], AccountMeta::new_readonly(pid, false));
        assert!(s.signer_indices.is_empty() && s.signers.is_empty());
    }

    #[test]
    fn short_discriminator_sets_owner_and_says_why_not_disc() {
        let idl = json_idl(
            r#"[{"name":"cfg","pda":{"seeds":[{"kind":"const","value":[99]}]}}]"#,
            r#"[{"name":"Config","discriminator":[1]}]"#,
        );
        let pid = Pubkey::new_unique();
        let (cfg, _) = Pubkey::find_program_address(&[b"c"], &pid);
        let acct = Account { lamports: 1, data: vec![1, 0, 0], owner: pid, executable: false, rent_epoch: 0 };
        let built = idl
            .spec("ix", pid)
            .unwrap()
            .account("cfg", cfg)
            .build()
            .unwrap()
            .infer_from_state(|_| Some(acct.clone()));
        assert_eq!(built.spec().expected_owners, vec![Some(pid)]);
        assert_eq!(built.spec().expected_discriminators, vec![None]);
        assert!(built.unresolved().iter().any(|u| u.what.contains("discriminator is 1 bytes")));
    }

    #[test]
    fn rederive_uses_bound_arg_seeds_and_reports_skips() {
        let idl = Idl::from_json(
            r#"{"instructions":[
              {"name":"open","discriminator":[1,1,1,1,1,1,1,1],"accounts":[{"name":"receipt",
                "writable":true,"pda":{"seeds":[{"kind":"const","value":[114]},{"kind":"arg","path":"id"}]}}]},
              {"name":"settle","discriminator":[2,2,2,2,2,2,2,2],"accounts":[{"name":"receipt","writable":true}]}],
             "accounts":[{"name":"Receipt","discriminator":[9,9,9,9,9,9,9,9]}]}"#,
        )
        .unwrap();
        let pid = Pubkey::new_unique();
        let id = 7u64.to_le_bytes();
        let (receipt, _) = Pubkey::find_program_address(&[b"r", &id], &pid);
        let acct = Account { lamports: 1, data: vec![9; 16], owner: pid, executable: false, rent_epoch: 0 };
        let get = |_: &Pubkey| Some(acct.clone());
        let base = || idl.spec("settle", pid).unwrap().account("receipt", receipt);

        let unbound = base().build().unwrap().infer_candidates(get);
        assert_eq!(unbound.spec().expected_pda_seeds, vec![None]);
        assert!(unbound.unresolved().iter().any(|u| u.what.contains("1 pattern(s) could not be evaluated")));

        let bound = base().seed_arg("id", &id).build().unwrap().infer_candidates(get);
        assert_eq!(bound.spec().expected_pda_seeds, vec![Some(vec![b"r".to_vec(), id.to_vec()])]);
    }

    /// The counterexample to the signer rule: a correct permissionless
    /// crank that pays a stored beneficiary. The rule fires, and the
    /// result must be visible as a candidate, never silently a fact.
    #[test]
    fn crank_beneficiary_is_only_ever_a_candidate() {
        let idl = json_idl(
            r#"[{"name":"job","writable":true},{"name":"beneficiary","writable":true}]"#,
            r#"[{"name":"Job","discriminator":[5,5,5,5,5,5,5,5]}]"#,
        );
        let pid = Pubkey::new_unique();
        let (job, ben) = (Pubkey::new_unique(), Arc::new(Keypair::new()));
        let mut data = vec![5u8; 8];
        data.extend_from_slice(ben.pubkey().as_ref());
        let acct = Account { lamports: 1, data, owner: pid, executable: false, rent_epoch: 0 };
        let get = |pk: &Pubkey| (*pk == job).then(|| acct.clone());
        let build = || {
            idl.spec("ix", pid).unwrap().account("job", job).signer("beneficiary", Arc::clone(&ben)).build().unwrap()
        };
        assert!(build().infer_from_state(get).spec().signer_indices.is_empty());
        let c = build().infer_from_state(get).infer_candidates(get);
        assert_eq!(c.spec().signer_indices, vec![1]);
        assert!(c.candidates().contains(&Candidate { account: "beneficiary".into(), what: CandidateKind::Signer }));
    }
}
