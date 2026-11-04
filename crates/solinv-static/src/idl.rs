//! # Anchor IDL: the parts that need no Solana types
//!
//! Reading an IDL and reporting its account-validation surface (`solinv idl`)
//! needs only JSON. This module is that half, so it builds anywhere — including
//! `wasm32` for the browser check. Building an `InstructionSpec` from it lives in
//! `solinv-fuzz::idl`, which re-exports everything here.

use serde::Deserialize;
use std::fmt;
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
    /// Converted from the legacy (pre-0.30) format, which has no fixed `address` on any slot.
    #[serde(skip)]
    pub legacy: bool,
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
    /// `has_one` targets, by slot name.
    #[serde(default)]
    pub relations: Vec<String>,
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
/// `solinv_fuzz::IdlSpec::defaulted`.
pub const WELL_KNOWN: &[(&str, &str)] = &[
    ("system_program", "11111111111111111111111111111111"),
    ("associated_token_program", "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"),
];

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
                     .key() comparison, in the attributes or at the top of the handler). \
                     Unless a function the handler calls checks the key, a caller may pass any account of the type: expected for \
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

    /// Like [`Idl::from_json`], and also reads a legacy (pre-0.30) IDL by
    /// converting it the way `anchor idl convert` does (see
    /// [`crate::legacy`]). The flag says which format it was.
    pub fn from_json_any(json: &str) -> Result<(Self, bool), IdlError> {
        match Self::from_json(json) {
            Ok(idl) => Ok((idl, false)),
            Err(e) => {
                let raw: Option<serde_json::Value> = serde_json::from_str(json).ok();
                let first = |key: &str| raw.as_ref().and_then(|r| r.get(key)).and_then(|v| v.get(0));
                // Legacy entries carry no discriminator; Shank instructions carry a
                // `discriminant`. An IDL with no instructions is told by its accounts.
                let legacy = match first("instructions") {
                    Some(ix) => ix.get("discriminator").is_none() && ix.get("discriminant").is_none(),
                    None => first("accounts").is_some_and(|a| a.get("discriminator").is_none()),
                };
                if !legacy {
                    return Err(e);
                }
                crate::legacy::convert(json)
                    .map(|idl| (idl, true))
                    .map_err(|e| IdlError::Parse(format!("legacy (pre-0.30) Anchor IDL: {e}")))
            }
        }
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

    /// Dotted path of the enclosing composite, `""` at top level.
    pub fn prefix(&self) -> &str {
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
        let mut out = format!(
            "// use solinv_fuzz::IdlSpecExt; (or solinv_fuzz::prelude::*) for .spec\nidl.spec(\"{}\", program_id)?\n",
            self.name
        );
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
