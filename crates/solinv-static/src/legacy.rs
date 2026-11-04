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
//! `const` seeds convert to the bytes Anchor derives from: a string's UTF-8,
//! a byte array as is, an integer little-endian at its width, a public key's
//! 32 bytes. A type this does not convert is kept as a marked seed, not
//! dropped: dropping it would drop the PDA, and a later loss of those seeds
//! would go unseen (`anchor idl convert` fails on such a seed instead).
//!
//! A legacy IDL has no fixed `address` on any slot; [`Idl::legacy`] tells
//! the IDL diff not to read that absence as a removal.

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

/// Marks a `const` seed whose legacy type this reader does not convert. It keeps the PDA (the
/// slot still has seeds). The IDL diff reads the mark only on a side converted from legacy
/// (`Idl::legacy`), so a current IDL that happens to hold these bytes is not mistaken for it,
/// and an unconverted seed never equals a real one. Anchor's converter fails on these instead.
pub(crate) const UNCONVERTED: &[u8] = b"\0solinv:unconverted-const-seed:";

fn base58(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut out: Vec<u8> = Vec::new(); // little-endian base-256
    for c in s.bytes() {
        let mut carry = ALPHABET.iter().position(|&a| a == c)? as u32;
        for b in out.iter_mut() {
            carry += (*b as u32) * 58;
            *b = carry as u8;
            carry >>= 8;
        }
        while carry > 0 {
            out.push(carry as u8);
            carry >>= 8;
        }
    }
    out.extend(s.bytes().take_while(|&c| c == b'1').map(|_| 0));
    out.reverse();
    Some(out)
}

/// The bytes a legacy `const` seed contributes, as Anchor derives them: a string's UTF-8, a byte
/// array as is, an integer little-endian at its width, a public key's 32 bytes.
fn const_bytes(ty: &serde_json::Value, value: &serde_json::Value) -> Option<Vec<u8>> {
    use serde_json::Value;
    // Up to 128 bits. JSON keeps integers past u64 as strings (or loses them as floats), so a
    // numeric string is read too.
    let int = |width: usize, signed: bool| -> Option<Vec<u8>> {
        let text = match value {
            Value::Number(n) => n.to_string(),
            Value::String(v) => v.clone(),
            _ => return None,
        };
        let bits = width * 8;
        if signed {
            let v: i128 = text.parse().ok()?;
            let fits = bits == 128 || (v >= -(1i128 << (bits - 1)) && v < (1i128 << (bits - 1)));
            fits.then(|| v.to_le_bytes()[..width].to_vec())
        } else {
            let v: u128 = text.parse().ok()?;
            let fits = bits == 128 || v < (1u128 << bits);
            fits.then(|| v.to_le_bytes()[..width].to_vec())
        }
    };
    match (ty, value) {
        (Value::String(t), Value::String(v)) if t == "string" => Some(v.clone().into_bytes()),
        (Value::String(t), Value::String(v)) if t == "publicKey" || t == "pubkey" => base58(v).filter(|b| b.len() == 32),
        (Value::String(t), _) => match t.as_str() {
            "u8" => int(1, false),
            "u16" => int(2, false),
            "u32" => int(4, false),
            "u64" => int(8, false),
            "u128" => int(16, false),
            "i8" => int(1, true),
            "i16" => int(2, true),
            "i32" => int(4, true),
            "i64" => int(8, true),
            "i128" => int(16, true),
            "bytes" => bytes_of(value),
            _ => None,
        },
        // `{"array": ["u8", N]}`
        (Value::Object(o), _) if o.get("array").and_then(|a| a.get(0)).and_then(Value::as_str) == Some("u8") => bytes_of(value),
        _ => None,
    }
}

fn bytes_of(value: &serde_json::Value) -> Option<Vec<u8>> {
    value.as_array()?.iter().map(|b| b.as_u64().filter(|&b| b <= 255).map(|b| b as u8)).collect()
}

fn seed(s: LegacySeed) -> IdlSeed {
    match s {
        LegacySeed::Const { ty, value } => IdlSeed::Const {
            value: const_bytes(&ty, &value).unwrap_or_else(|| [UNCONVERTED, format!("{ty}={value}").as_bytes()].concat()),
        },
        LegacySeed::Account { path, account } => IdlSeed::Account { path: snake_path(&path), account },
        LegacySeed::Arg { path } => IdlSeed::Arg { path: snake_path(&path) },
    }
}

fn pda(p: LegacyPda) -> IdlPda {
    IdlPda { seeds: p.seeds.into_iter().map(seed).collect(), program: p.program_id.map(seed) }
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
            pda: a.pda.map(pda),
            relations: Vec::new(), // set by `items`, on the slot the has_one names
        }),
    }
}

pub(crate) fn convert(json: &str) -> Result<Idl, serde_json::Error> {
    let l: Legacy = serde_json::from_str(json)?;
    Ok(Idl {
        legacy: true,
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
    fn const_seeds_convert_to_the_bytes_anchor_derives_from() {
        use serde_json::json;
        let b = |ty, v| super::const_bytes(&ty, &v);
        assert_eq!(b(json!("string"), json!("vault")), Some(b"vault".to_vec()));
        assert_eq!(b(json!({"array": ["u8", 2]}), json!([118, 49])), Some(vec![118, 49]));
        assert_eq!(b(json!("bytes"), json!([1, 2, 3])), Some(vec![1, 2, 3]));
        assert_eq!(b(json!("u16"), json!(258)), Some(vec![2, 1]));
        assert_eq!(b(json!("u8"), json!(256)), None, "out of range");
        assert_eq!(b(json!("i8"), json!(-1)), Some(vec![255]));
        assert_eq!(b(json!("u64"), json!(1)), Some(vec![1, 0, 0, 0, 0, 0, 0, 0]));
        assert_eq!(b(json!("u128"), json!(1)), Some([vec![1], vec![0; 15]].concat()));
        assert_eq!(b(json!("u128"), json!("340282366920938463463374607431768211455")), Some(vec![255; 16]));
        assert_eq!(b(json!("i128"), json!(-1)), Some(vec![255; 16]));
        assert_eq!(b(json!("publicKey"), json!("11111111111111111111111111111111")), Some(vec![0; 32]));
        assert_eq!(b(json!({"defined": "Thing"}), json!(1)), None);
    }

    #[test]
    fn an_unconverted_const_seed_keeps_the_pda() {
        let legacy = r#"{"version":"0.1.0","name":"d","instructions":[{"name":"a","accounts":[
            {"name":"vault","isMut":true,"isSigner":false,"pda":{"seeds":[{"kind":"const","type":{"defined":"Thing"},"value":1}]}}],"args":[]}]}"#;
        let (idl, _) = Idl::from_json_any(legacy).unwrap();
        let seeds = &idl.instructions[0].flat_accounts()[0].account.pda.as_ref().unwrap().seeds;
        assert!(matches!(&seeds[0], IdlSeed::Const { value } if value.starts_with(super::UNCONVERTED)));
    }

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
        // A byte-array const seed is its bytes (anchor idl convert would fail here).
        let fee = &flat[3].account.pda.as_ref().unwrap().seeds;
        assert!(matches!(&fee[0], IdlSeed::Const { value } if value == &[1, 2]));
        assert!(idl.legacy);
        assert!(matches!(&ix.accounts[4], IdlAccountItem::Composite { name, .. } if name == "inner"));
    }
}
