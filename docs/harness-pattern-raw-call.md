# Harness raw_call Pattern — Anchor-Version-Independent

Date: 2026-05-25 (Day 15)
Status: Proven against escrow-demo. Ready for application to klend
(Anchor 0.29) and Raydium AMM (Native).

## Why this pattern exists

Day 14 architectural discovery: production Solana DeFi protocols use
**Anchor 0.28-0.32** (or Native), while solinv's workspace pins
**anchor-lang = "1.0.1"** (inherited from Crucible v0.1.0). If the
harness uses Anchor IDL-driven typed builders, the harness's
`Cargo.toml` must depend on the **same anchor-lang version as the
target program** — which is incompatible with the solinv workspace pin.

See `docs/phase2-day14-anchor-version-mismatch.md` for the full
finding.

This document captures the fix: **construct `Instruction` values
manually**, with `sha256`-derived sighashes and explicit `AccountMeta`
lists, then submit via `ctx.raw_call(ix)`. No Anchor types in harness
code = no version dependency = harness works against **any** Anchor
program regardless of its anchor-lang version, plus all Native
programs.

## Pattern summary (canonical 4-element)

A harness's `action_*` method or setup call has 4 elements when
written in raw_call form:

```rust
fn build_<ix_name>_ix(
    program_id: Pubkey,
    /* per-account Pubkey args */
    /* per-borsh-field arg values */
) -> Instruction {
    // 1. Sighash — 8 bytes, sha256("global:<ix_name>")[..8]
    let mut data = ix_sighash("<ix_name>").to_vec();

    // 2. Borsh-encoded args — extend in declaration order, le_bytes for
    //    primitives, .as_ref() for Pubkeys, etc.
    data.extend_from_slice(&arg1.to_le_bytes());
    data.extend_from_slice(arg2.as_ref());
    // ...

    Instruction {
        program_id,
        // 3. AccountMeta list — order matches #[derive(Accounts)] in
        //    program source, with correct (writable, signer) flags.
        accounts: vec![
            AccountMeta::new(account1_pubkey, false),          // mut, !signer
            AccountMeta::new(account2_pubkey, true),           // mut, signer
            AccountMeta::new_readonly(account3_pubkey, false), // !mut, !signer
        ],
        data,
    }
}

// 4. Submit via raw_call (no Anchor types touched anywhere):
self.ctx.raw_call(build_<ix_name>_ix(...))
    .signers(&[&kp])
    .send()
    .map(|o| o.is_success())
    .unwrap_or(false)
```

## Required harness-local helpers

These two free functions replace `anchor_lang::Discriminator` trait
usage. They are version-independent because the Anchor sighash
algorithm is stable across all anchor-lang versions:

```rust
use sha2::{Digest, Sha256};

/// Anchor instruction sighash: sha256("global:{ix_name}")[..8]
pub fn ix_sighash(ix_name: &str) -> [u8; 8] {
    let mut hasher = Sha256::new();
    hasher.update(b"global:");
    hasher.update(ix_name.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

/// Anchor account discriminator: sha256("account:{Name}")[..8]
pub fn account_disc(name: &str) -> [u8; 8] {
    let mut hasher = Sha256::new();
    hasher.update(b"account:");
    hasher.update(name.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}
```

Add to harness `Cargo.toml`:
```toml
sha2 = "0.10"
```

## System Program ID (since we drop anchor_lang::system_program)

```rust
// 32 zero bytes — Solana System Program ID literal.
const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);
```

## Sourcing sighash + arg layout for production protocols

For klend, Raydium, Save, etc., the source-of-truth for the three
pieces of information (ix name, arg layout, account layout) is the
protocol's published IDL JSON. Workflow:

1. **ix name → sighash**: snake_case name from IDL → `ix_sighash(name)`.
   Anchor's `Discriminator` macro internally converts PascalCase struct
   name (`DepositReserveLiquidity`) to snake_case (`deposit_reserve_liquidity`)
   before hashing. Use the snake_case form directly.

2. **arg layout → borsh bytes**: read IDL's `args: [{name, type}, ...]`
   for the ix. Borsh primitives: `u8`/`u16`/`u32`/`u64`/`i64` →
   `to_le_bytes()`; `Pubkey` → `.as_ref()` (32 bytes); `bool` →
   `[u8; 1]`; `Option<T>` → `[u8; 1]` discriminant + payload;
   `Vec<T>` → `u32 len LE` + payload.

3. **account layout → AccountMeta list**: read IDL's `accounts: [{name,
   isMut, isSigner}, ...]` for the ix. Order matters. `isMut` →
   `AccountMeta::new`; `!isMut` → `AccountMeta::new_readonly`. Same
   for `isSigner`.

No Anchor runtime needed in harness — pure mechanical translation.

## What stays Anchor-dependent (and why that's OK)

- **The deployed `.so` binary** of the target program is still built
  by Anchor (anchor 0.29 for klend, etc.). Harness does NOT need to
  reproduce that build environment — it only needs the `.so`. Use
  `cargo build-sbf` (Anchor's underlying SBF builder) once to produce
  the binary, then `ctx.add_program(&id, "path/to/program.so")`.

- **Account state encoded in account data** is still Borsh-encoded
  per Anchor's account layout. Harness reading account state for
  `InstructionSpec.expected_discriminators` or post-tx state checks
  needs to know the layout. Two approaches:
  - For checks of fixed-prefix fields (discriminator, owner,
    lamports), parse manually from raw bytes.
  - For full deserialization, use the protocol's `*-sdk` crate if
    it's standalone (no anchor 0.29 transitive). Often it isn't —
    accept manual parsing.

- **PDA derivation**: `Pubkey::find_program_address(&[seeds], &pid)`
  is in `solana-pubkey`, NOT Anchor. Always usable.

## Trade-off: verbosity

raw_call construction is ~3-5x more lines per ix than Anchor's
typed builder. For an N-ix harness this is real boilerplate.
Mitigation: a per-protocol `build_*_ix` helper module keeps the
verbosity contained at construction site, and `action_*` methods
remain clean.

For protocols with >20 ix in scope, consider a code-generator
script that reads IDL JSON and emits `build_*_ix` functions. Not
needed for first integration (5-8 critical ix per target).

## Validation

This pattern was applied to `examples/escrow-demo/fuzz/escrow/src/main.rs`
on Day 15. All 5 Critical invariants continue to detect their planted
bugs post-refactor — see the bottom of the Day 14 implementation log
for regression results.

## Apply this pattern to:

- **Raydium AMM** (Day 18-22): Native, no Anchor types at all but the
  ix layout convention is similar (first byte = ix discriminant by
  enum tag, then args). `ix_sighash` doesn't apply (use ix tag byte
  instead), but `AccountMeta` construction + `raw_call` flow is the
  same.

- **klend** (Day 23-27): Anchor 0.29. Pure application of this pattern —
  `ix_sighash("deposit_reserve_liquidity")`, etc.

- **Save** (later): Anchor 0.28. Same.

- **Raydium CLMM** (later): Anchor 0.32. Same.

## Sources

- Anchor sighash spec: `anchor_lang::Discriminator` macro derivation
  (sha256 with "global:" / "account:" prefix). Unchanged 0.28 → 1.0.x.
- raw_call API: `crucible_test_context::TestContext::raw_call()` →
  `RawCallBuilder` → `.fee_payer(&Keypair)` / `.signers(&[&Keypair])` /
  `.send() -> Result<TxOutcome, _>`.
- Day 3 invariant pattern (already raw_call-based) — see
  `crates/solinv-core/src/invariants/signer_skip.rs:64-98`.
