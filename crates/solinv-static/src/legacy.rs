//! Legacy (pre-0.30) Anchor IDLs, read into the current [`Idl`] shape.
//!
//! Programs deployed before Anchor 0.30 still carry the old format on
//! chain, and a program's IDL history often starts in it. The conversion
//! follows `anchor idl convert` (anchor-lang-idl's `convert.rs`): names
//! become snake_case, discriminators are `sha256("global:<ix>")` and
//! `sha256("account:<Type>")`, `isMut` / `isSigner` / `isOptional` map to
//! `writable` / `signer` / `optional`, and `relations` carry over. Two
//! differences, both so that a legacy version compares cleanly against a
//! current one of the same program:
//!
//! - a string `const` seed becomes its UTF-8 bytes. `anchor idl convert`
//!   0.1.2 writes the JSON-quoted string (`"vault"` with the quotes),
//!   which no program derives with;
//! - `relations` point the other way. The legacy format lists them on
//!   the slot that declares `has_one` (`vault: ["authority"]`); the current
//!   one lists them on the slot named (`authority: ["vault"]`), and so does
//!   everything here. `anchor idl convert` copies them unchanged, so its
//!   output reads every legacy `has_one` backwards. Both are snake_cased,
//!   as are seed paths.
//!
//! Reported upstream: otter-sec/anchor#5255 (seed quotes) and #5256
//! (relations). Drop the differences here once they are fixed there.
//!
//! A `const` seed of any other type is dropped with its PDA, as
//! `anchor idl convert` does, and the slot reads as having no seeds.

use crate::idl::{Idl, IdlAccount, IdlAccountItem, IdlAccountType, IdlArg, IdlInstruction, IdlPda, IdlSeed};
use heck::ToSnakeCase;
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
struct Legacy {
    #[serde(default)]
    metadata: Option<LegacyMetadata>,
    instructions: Vec<LegacyInstruction>,
    #[serde(default)]
    accounts: Vec<LegacyTypeDef>,
}

#[derive(Deserialize)]
struct LegacyMetadata {
    #[serde(default)]
    address: Option<String>,
}

#[derive(Deserialize)]
struct LegacyInstruction {
    name: String,
    accounts: Vec<LegacyAccountItem>,
    #[serde(default)]
    args: Vec<LegacyArg>,
}

#[derive(Deserialize)]
struct LegacyArg {
    name: String,
    #[serde(rename = "type")]
    ty: serde_json::Value,
}

#[derive(Deserialize)]
struct LegacyTypeDef {
    name: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum LegacyAccountItem {
    Composite { name: String, accounts: Vec<LegacyAccountItem> },
    Single(LegacyAccount),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyAccount {
    name: String,
    is_mut: bool,
    is_signer: bool,
    #[serde(default)]
    is_optional: Option<bool>,
    #[serde(default)]
    pda: Option<LegacyPda>,
    #[serde(default)]
    relations: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyPda {
    seeds: Vec<LegacySeed>,
    #[serde(default)]
    program_id: Option<LegacySeed>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum LegacySeed {
    Const {
        #[serde(rename = "type")]
        ty: serde_json::Value,
        value: serde_json::Value,
    },
    Account {
        path: String,
        #[serde(default)]
        account: Option<String>,
    },
    Arg {
        path: String,
    },
}

fn disc(prefix: &str, name: &str) -> Vec<u8> {
    Sha256::digest(format!("{prefix}:{name}"))[..8].to_vec()
}

fn snake_path(path: &str) -> String {
    path.split('.').map(|s| s.to_snake_case()).collect::<Vec<_>>().join(".")
}

fn seed(s: LegacySeed) -> Option<IdlSeed> {
    Some(match s {
        LegacySeed::Const { ty, value } => match (ty.as_str(), value) {
            (Some("string"), serde_json::Value::String(v)) => IdlSeed::Const { value: v.into_bytes() },
            _ => return None,
        },
        LegacySeed::Account { path, account } => IdlSeed::Account { path: snake_path(&path), account },
        LegacySeed::Arg { path } => IdlSeed::Arg { path: snake_path(&path) },
    })
}

fn pda(p: LegacyPda) -> Option<IdlPda> {
    Some(IdlPda {
        seeds: p.seeds.into_iter().map(seed).collect::<Option<_>>()?,
        program: match p.program_id {
            Some(s) => Some(seed(s)?),
            None => None,
        },
    })
}

/// One struct level: convert each item, then move each `has_one` from the
/// declaring slot onto the sibling it names.
fn items(list: Vec<LegacyAccountItem>) -> Vec<IdlAccountItem> {
    let mut declared: Vec<(String, Vec<String>)> = Vec::new();
    let mut out: Vec<IdlAccountItem> = list
        .into_iter()
        .map(|i| {
            if let LegacyAccountItem::Single(a) = &i {
                declared.push((a.name.to_snake_case(), a.relations.iter().map(|r| r.to_snake_case()).collect()));
            }
            item(i)
        })
        .collect();
    for slot in &mut out {
        if let IdlAccountItem::Single(a) = slot {
            a.relations = declared
                .iter()
                .filter(|(_, targets)| targets.contains(&a.name))
                .map(|(by, _)| by.clone())
                .collect();
        }
    }
    out
}

fn item(i: LegacyAccountItem) -> IdlAccountItem {
    match i {
        LegacyAccountItem::Composite { name, accounts } => IdlAccountItem::Composite {
            name: name.to_snake_case(),
            accounts: items(accounts),
        },
        LegacyAccountItem::Single(a) => IdlAccountItem::Single(IdlAccount {
            name: a.name.to_snake_case(),
            writable: a.is_mut,
            signer: a.is_signer,
            optional: a.is_optional.unwrap_or_default(),
            address: None,
            pda: a.pda.and_then(pda),
            relations: Vec::new(), // set by `items`, on the slot the has_one names
        }),
    }
}

pub(crate) fn convert(json: &str) -> Result<Idl, serde_json::Error> {
    let l: Legacy = serde_json::from_str(json)?;
    Ok(Idl {
        address: l.metadata.and_then(|m| m.address).unwrap_or_default(),
        instructions: l
            .instructions
            .into_iter()
            .map(|ix| {
                let name = ix.name.to_snake_case();
                IdlInstruction {
                    discriminator: disc("global", &name),
                    name,
                    accounts: items(ix.accounts),
                    args: ix.args.into_iter().map(|a| IdlArg { name: a.name.to_snake_case(), ty: a.ty }).collect(),
                }
            })
            .collect(),
        accounts: l
            .accounts
            .into_iter()
            .map(|a| IdlAccountType { discriminator: disc("account", &a.name), name: a.name })
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use crate::idl::{Idl, IdlAccountItem, IdlSeed};

    const LEGACY: &str = r#"{
        "version": "0.1.0", "name": "demo",
        "instructions": [{
            "name": "lendingAccountWithdraw",
            "accounts": [
                {"name": "marginfiAccount", "isMut": true, "isSigner": false, "relations": ["signer"]},
                {"name": "signer", "isMut": false, "isSigner": true},
                {"name": "bankVault", "isMut": true, "isSigner": false, "isOptional": true,
                 "pda": {"seeds": [
                    {"kind": "const", "type": "string", "value": "vault"},
                    {"kind": "account", "type": "publicKey", "account": "Bank", "path": "bank"},
                    {"kind": "arg", "type": "u64", "path": "bankSeed"}]}},
                {"name": "feeVault", "isMut": true, "isSigner": false,
                 "pda": {"seeds": [{"kind": "const", "type": {"array": ["u8", 2]}, "value": [1, 2]}]}},
                {"name": "inner", "accounts": [{"name": "tokenProgram", "isMut": false, "isSigner": false}]}
            ],
            "args": [{"name": "amountIn", "type": "u64"}]
        }],
        "accounts": [{"name": "MarginfiAccount", "type": {"kind": "struct", "fields": []}}],
        "metadata": {"address": "MFv2hWf31Z9kbCa1snEPYctwafyhdvnV7FZnsebVacA"}
    }"#;

    #[test]
    fn current_format_is_not_read_as_legacy() {
        let current = r#"{"instructions":[{"name":"a","discriminator":[0,0,0,0,0,0,0,0],"accounts":[]}]}"#;
        assert!(!Idl::from_json_any(current).unwrap().1);
        assert!(Idl::from_json(LEGACY).is_err(), "the strict reader still rejects legacy");
    }

    #[test]
    fn converts_like_anchor_idl_convert() {
        let (idl, legacy) = Idl::from_json_any(LEGACY).unwrap();
        assert!(legacy);
        assert_eq!(idl.address, "MFv2hWf31Z9kbCa1snEPYctwafyhdvnV7FZnsebVacA");
        let ix = &idl.instructions[0];
        assert_eq!(ix.name, "lending_account_withdraw");
        // sha256("global:lending_account_withdraw")[..8]
        use sha2::{Digest, Sha256};
        assert_eq!(ix.discriminator, Sha256::digest("global:lending_account_withdraw")[..8].to_vec());
        assert_eq!(idl.accounts[0].discriminator, Sha256::digest("account:MarginfiAccount")[..8].to_vec());
        assert_eq!(ix.args[0].name, "amount_in");

        let flat = ix.flat_accounts();
        let paths: Vec<String> = flat.iter().map(|f| f.path()).collect();
        assert_eq!(paths, ["marginfi_account", "signer", "bank_vault", "fee_vault", "inner.token_program"]);
        assert!(flat[0].account.writable && !flat[0].account.signer);
        // Legacy: `marginfiAccount` declares has_one = signer. Current: listed on `signer`.
        assert!(flat[0].account.relations.is_empty());
        assert_eq!(flat[1].account.relations, ["marginfi_account"]);
        assert!(flat[2].account.optional);
        let seeds = &flat[2].account.pda.as_ref().unwrap().seeds;
        assert!(matches!(&seeds[0], IdlSeed::Const { value } if value == b"vault"), "UTF-8 bytes, no quotes");
        assert!(matches!(&seeds[1], IdlSeed::Account { path, .. } if path == "bank"));
        assert!(matches!(&seeds[2], IdlSeed::Arg { path } if path == "bank_seed"));
        // A non-string const seed drops the PDA, as `anchor idl convert` does.
        assert!(flat[3].account.pda.is_none());
        assert!(matches!(&ix.accounts[4], IdlAccountItem::Composite { name, .. } if name == "inner"));
    }
}
