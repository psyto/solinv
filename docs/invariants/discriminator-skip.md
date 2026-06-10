# Invariant: discriminator-skip

> **Severity**: Critical
> **Bug class**: Missing account discriminator check, enabling type confusion within the same program's account types
> **Status**: Spec written 2026-05-24. Implementation: Phase 1 Days 21-22.

## 1. Bug class

A `discriminator-skip` vulnerability exists when a Solana program reads
an account and deserializes its data as a specific type without first
verifying the account's discriminator (the 8-byte prefix identifying
the account type). Even when the [owner-skip](owner-skip.md) check
passes (the account is owned by the calling program), without a
discriminator check the attacker can substitute an account of a
**different type owned by the same program**.

Solana programs typically own multiple account types — a perp DEX might
have `Market`, `Position`, `UserAccount`, `TradingVault`, `BuilderProfile`,
all owned by the program. Owner check alone proves "this account belongs
to me"; it does NOT prove "this account is the type I expect".

### The discriminator convention

Anchor uses the first 8 bytes of account data as a discriminator,
computed as `sha256("account:<TypeName>")[..8]`. Native programs often
adopt the same pattern with a `discriminator: [u8; 8]` field as the
first struct field. The check is:

```rust
if account_data[0..8] != EXPECTED_DISCRIMINATOR {
    return Err(ProgramError::InvalidAccountData);
}
```

This 8-byte comparison is what stands between type safety and arbitrary
type confusion.

### Combined with owner-skip

The three checks form a layered defense:

1. **Owner check** — account belongs to expected program (owner-skip)
2. **Discriminator check** — account is the expected type within program (discriminator-skip)
3. **Field validation** — account contents make semantic sense (case-by-case)

Skipping #1 lets attackers substitute *anything*. Skipping #2 (with #1
passing) lets attackers substitute *another type from the same program*
— still catastrophic because crafted bytes of one type can satisfy
the bit-level layout of another.

### Why Solana-specific (vs EVM)

EVM contracts have storage layout determined at compile time and tied
to the contract address; there is no "wrong type loaded into the slot"
possibility. Solana programs receive raw byte buffers as account data
and must parse them — type identity is a runtime check, not a compile-
time guarantee.

### Anchor specifics

Anchor's `Account<'info, T>` and `AccountLoader<'info, T>` check
discriminators automatically. `UncheckedAccount<'info>`, `AccountInfo<'info>`,
and manual `try_from_slice` deserialization do NOT.

`AccountLoader::load_init()` writes a new discriminator;
`AccountLoader::load()` and `load_mut()` verify the existing one.
Mixing these incorrectly is a subtle source of discriminator-skip
bugs in zero-copy code.

## 2. Mainnet precedent and audit findings

### Direct precedent

Like signer-skip and owner-skip, discriminator-skip is **a textbook
audit finding** that rarely makes mainnet exploit headlines individually
— but it routinely appears in pre-mainnet audit reports:

- Trail of Bits' Anchor security guidelines explicitly call out account
  type confusion as a top concern when developers use
  `UncheckedAccount<'info>` or perform manual deserialization
- Neodyme audit reports include discriminator-skip as standard finding
  category for native Solana programs without Anchor
- Sec3 / OtterSec audit retrospectives reference type confusion as the
  natural attack vector when owner check is present but discriminator
  check is missing

### Adjacent mainnet incidents

- **Crema Finance (Jul 2022, $8.7M)** — partial root cause involved
  type confusion through insufficient account validation
- **Various Anchor zero-copy bugs** — `AccountLoader::load_init()`
  vs `load_mut()` misuse has caused multiple audit findings (less
  publicized than oracle exploits)

### Type confusion attack mechanics

Given a program with types:
```rust
struct Market    { disc: [u8; 8], market_idx: u64, oracle: Pubkey, ... }
struct Position  { disc: [u8; 8], trader: Pubkey, size_held: i64, ... }
```

If `process_close_position` reads `position` without discriminator
check, attacker:
1. Creates a `Market` account (legitimately, via the program's market
   creation ix)
2. Calls `process_close_position` passing the `Market` account where
   `Position` is expected
3. Program reads `market_idx` as `trader` and `oracle.first_8_bytes`
   as `size_held`
4. Depending on field layout, arbitrary PnL computation results
5. Funds transferred to attacker

The attacker's craft window depends on field layout overlap — but
programs often have enough overlap to enable real exploits, especially
with many account types sharing similar leading fields (discriminator
+ Pubkey + amounts).

### solinv positioning

Same as owner-skip: audit-firm-rate detection at zero marginal cost.
Bug bounty payouts for Critical pre-mainnet type-confusion findings
sit in the $100K-$500K range.

## 3. Detection algorithm

### High-level pseudocode

```
for each instruction in program:
    for each account index with declared expected_discriminator:
        snapshot = ctx.snapshot()
        pre_hash = ctx.program_state_hash(program_id)

        real_account = ctx.get_account(ix.accounts[idx].pubkey)
        if real_account.data.len() < 8: skip

        // Corrupt discriminator while preserving owner and other data
        fake_account = real_account.clone()
        fake_account.data[0..8] = WRONG_DISCRIMINATOR   // 0xDEADBEEF... or another type's disc

        fake_pubkey = Pubkey::new_unique()
        ctx.set_account(fake_pubkey, fake_account)

        modified_accounts = ix.accounts.clone()
        modified_accounts[idx].pubkey = fake_pubkey

        result = ctx.send(ix.program, ix.data, modified_accounts)
        post_hash = ctx.program_state_hash(program_id)

        if result.success and post_hash != pre_hash:
            REPORT discriminator-skip violation

        ctx.revert_to(snapshot)
    end
end
```

### Why preserve owner

If the fake account's `owner` is also flipped, the violation report
becomes ambiguous (could be owner-skip OR discriminator-skip). By
keeping `owner` correct and only corrupting the discriminator, the
violation isolates the discriminator check specifically.

This is the key design choice that makes owner-skip and discriminator-skip
**orthogonal invariants** — each catches its own bug, neither masks the
other.

### Choice of wrong discriminator

Three patterns to try (most useful first):

1. **Random / sentinel** (`0xDEADBEEF00000000`) — catches programs that
   compare against a hardcoded expected value
2. **Another known type's discriminator** — catches programs that
   dispatch on discriminator but with a missing default-case error
3. **All zeros** (`0x0000000000000000`) — catches programs that treat
   default-initialized accounts as valid

solinv runs all three; first to fire reports the violation.

### Combined-attack detection (with owner-skip)

The most realistic attack flow is "wrong owner AND wrong discriminator"
— the attacker controls both. solinv's two invariants run independently:

- owner-skip: wrong owner, correct discriminator preserved → fires if
  owner check missing
- discriminator-skip: correct owner preserved, wrong discriminator →
  fires if discriminator check missing

A program missing BOTH checks reports both violations. A program with
EITHER check passing reports only the missing one. Diagnostic clarity.

## 4. Capability trait + implementation

### Extended InstructionSpec

```rust
// solinv-core/src/traits.rs (updated)

#[derive(Clone, Debug)]
pub struct InstructionSpec {
    pub program_id: Pubkey,
    pub name: String,
    pub accounts: Vec<AccountMeta>,
    pub signer_indices: Vec<usize>,
    pub optional_signer_indices: Vec<usize>,
    pub expected_owners: Vec<Option<Pubkey>>,

    /// Per-account expected discriminator (first 8 bytes of account data).
    /// None = no discriminator expectation (e.g., raw SOL accounts,
    /// custom layouts that use first-byte tagging).
    /// Some([u8; 8]) = account data MUST start with these bytes.
    pub expected_discriminators: Vec<Option<[u8; 8]>>,

    pub data_sample: Vec<u8>,
}
```

Anchor IDL auto-fill: every `Account<'info, T>` → `Some(sha256("account:T")[..8])`.
`AccountLoader<'info, T>` → same.
`UncheckedAccount` / `AccountInfo` / SPL Token accounts / sysvars → `None`
(user declares manually if needed).

### Invariant function

```rust
// solinv-core/src/invariants/discriminator_skip.rs

use crate::traits::{HasContext, HasInstructionSet};
use crucible_fuzzer::fuzz_assert;
use solana_sdk::{account::Account, pubkey::Pubkey};

const WRONG_DISCRIMINATORS: &[[u8; 8]] = &[
    [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00],
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],  // all zeros
    [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],  // all ones
];

/// Detects missing discriminator checks on accounts that should be
/// validated by type.
///
/// For each instruction with declared `expected_discriminators`,
/// substitutes a fake account containing identical bytes EXCEPT the
/// first 8 bytes (discriminator), keeping the owner correct. If the
/// instruction succeeds and state changes, report discriminator-skip
/// violation (owner-skip is excluded by design).
pub fn discriminator_skip<F>(fixture: &mut F)
where
    F: HasInstructionSet + HasContext,
{
    let ixs = fixture.instructions();
    for ix in &ixs {
        for (idx, expected) in ix.expected_discriminators.iter().enumerate() {
            let Some(expected_disc) = expected else { continue };

            for wrong_disc in WRONG_DISCRIMINATORS {
                if wrong_disc == expected_disc { continue; }

                let ctx = fixture.ctx_mut();
                let snapshot = ctx.snapshot();
                let pre_hash = ctx.program_state_hash(&ix.program_id);

                let real_pubkey = ix.accounts[idx].pubkey;
                let Some(real_account) = ctx.get_account(&real_pubkey)
                else {
                    ctx.revert_to(snapshot);
                    continue;
                };
                if real_account.data.len() < 8 {
                    ctx.revert_to(snapshot);
                    continue;
                }

                // Clone data, corrupt discriminator only
                let mut fake_data = real_account.data.clone();
                fake_data[0..8].copy_from_slice(wrong_disc);

                let fake_pubkey = Pubkey::new_unique();
                ctx.set_account(fake_pubkey, Account {
                    owner: real_account.owner,    // PRESERVE correct owner
                    data: fake_data,
                    lamports: real_account.lamports,
                    executable: false,
                    rent_epoch: real_account.rent_epoch,
                });

                let mut accounts = ix.accounts.clone();
                accounts[idx].pubkey = fake_pubkey;

                let result = ctx.send(
                    ix.program_id,
                    ix.data_sample.clone(),
                    accounts,
                );

                let post_hash = ctx.program_state_hash(&ix.program_id);
                let state_changed = pre_hash != post_hash;

                ctx.revert_to(snapshot);

                fuzz_assert!(
                    !(result.is_ok() && state_changed),
                    "discriminator-skip detected: instruction {} (program {}) \
                     succeeded with account {} discriminator {:02x?} \
                     instead of expected {:02x?}",
                    ix.name,
                    ix.program_id,
                    idx,
                    wrong_disc,
                    expected_disc,
                );
            }
        }
    }
}
```

### Usage from user harness

```rust
use solinv_fuzz::prelude::*;
use openhl_core::ID as OPENHL_ID;
use openhl_core::state::{Market, Position};

impl HasInstructionSet for OpenHLFixture {
    fn instructions(&self) -> Vec<InstructionSpec> {
        vec![
            InstructionSpec {
                program_id: OPENHL_ID,
                name: "ClosePosition".into(),
                accounts: vec![
                    AccountMeta::new(self.trader, true),
                    AccountMeta::new(self.position, false),
                    AccountMeta::new(self.market, false),
                ],
                signer_indices: vec![0],
                optional_signer_indices: vec![],
                expected_owners: vec![
                    None,
                    Some(OPENHL_ID),
                    Some(OPENHL_ID),
                ],
                expected_discriminators: vec![
                    None,                              // trader = wallet
                    Some(Position::DISCRIMINATOR),     // position
                    Some(Market::DISCRIMINATOR),       // market
                ],
                data_sample: vec![/* ... */],
            },
        ]
    }
}

#[invariant_test]
fn solinv_all(f: &mut OpenHLFixture) {
    solinv_core::invariants::signer_skip(f);
    solinv_core::invariants::owner_skip(f);
    solinv_core::invariants::discriminator_skip(f);
}
```

## 5. False-positive risks and mitigations

| Risk | Cause | Mitigation |
|---|---|---|
| **Programs without discriminator convention** | Some native Solana programs don't use 8-byte discriminators (e.g., use first-byte instruction tag style for accounts too) | `expected_discriminators[i] = None` for those account indices. Conservative default |
| **Single-type programs** | Program owns only one account type; type confusion isn't possible within program | Still flag — defense in depth. Programmer documents waiver via attribute if desired |
| **Account length-based dispatching** | Some programs check `account.data.len()` and dispatch on length, not discriminator. Different types accidentally have different lengths | Length check is incomplete defense (collision possible); solinv still flags. Programmer hardens with discriminator |
| **Anchor zero-copy `AccountLoader::load_init()`** | First call creates discriminator; second call reads it. solinv may flag the `load_mut()` path if it doesn't re-check | `load_mut()` does check discriminator in current Anchor — verify in CI; if not, document |
| **Custom serialization without discriminator** | Borsh/Bincode struct without leading discriminator field | Use `expected_discriminators[i] = None` and add structural check via different invariant (future: schema-validation) |
| **Discriminator at non-zero offset** | Program puts discriminator at byte offset N > 0 | Trait extension needed: `expected_discriminator_offset` per account. v0.2+ feature |
| **Pre-init accounts** | Newly allocated accounts have zero discriminator until program writes it | Skip account indices that are created mid-ix (via `creates_indices` field — same exclusion as owner-skip) |

### Distinguishing discriminator-skip vs owner-skip vs account-swap

Three orthogonal invariants:

- **owner-skip**: wrong owner program, correct discriminator preserved
- **discriminator-skip**: correct owner preserved, wrong discriminator
- **account-swap**: correct owner AND discriminator, wrong specific
  account (e.g., user A's account where user B's is expected)

Each catches a distinct check failure. A program missing all three
reports three violations. A program with only owner check missing
reports owner-skip only.

### When all three fail simultaneously

Realistic attack uses owner + discriminator + specific account
flexibility. solinv's diagnostic approach is "report each missing
check independently" rather than "report the combined attack" because:

1. Programmer fixes ONE check at a time and re-runs solinv to confirm
2. Combined-attack report doesn't tell programmer which check to add
3. Separated reports map directly to source code locations needing
   `assert!(account.owner == ...)`, `assert!(disc == ...)`, etc.

## 6. Severity classification

**Critical** baseline. Reasoning:

- Combined with owner check passing, enables direct fund theft via
  type confusion (read wrong-type bytes as expected fields)
- Particularly dangerous in programs with multiple account types
  sharing similar leading fields
- Exploit complexity: moderate. Requires understanding of target
  type layouts but no special access
- Mainnet precedent in account-confusion family: Crema $8.7M

Bug bounty reference (Critical):
- Drift / Marginfi: $150K-$500K
- Kamino: $250K-$1M
- Jupiter: $250K-$500K

Severity adjustment:
- State change affects only metadata (e.g., increment counter) → **High**
- Program has only one account type → **High** (still bad practice;
  refactoring may introduce new types)
- Discriminator dispatch path leads to read-only ix → **Medium**

## 7. Test fixture in openhl-solana

Plant discriminator-skip bug in `process_close_position` which reads
the Market account to derive funding/fee rates. With owner check
passing but discriminator check missing, attacker can pass another
program-owned account type (e.g., `TradingVault`) where `Market` is
expected. Field overlap between the two structs (both have leading
pubkeys and u64s) causes arbitrary funding rate computation.

```rust
// programs/openhl-core/src/lib.rs

// BEFORE (correct):
fn process_close_position<'a>(
    program_id: &Pubkey,
    accounts: &'a [AccountInfo<'a>],
    data: &[u8],
) -> ProgramResult {
    let market_ai = &accounts[2];

    if market_ai.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }

    let market_data = market_ai.data.borrow();
    if &market_data[0..8] != &Market::DISCRIMINATOR {
        msg!("close_position: market account discriminator mismatch");
        return Err(ProgramError::InvalidAccountData);
    }

    let market = Market::try_from_slice(&market_data)?;
    // ... use market.funding_rate, market.oracle ...
}

// PLANTED BUG (for solinv validation):
fn process_close_position<'a>(
    program_id: &Pubkey,
    accounts: &'a [AccountInfo<'a>],
    data: &[u8],
) -> ProgramResult {
    let market_ai = &accounts[2];

    if market_ai.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }

    // BUG: discriminator check intentionally removed
    let market = Market::try_from_slice(&market_ai.data.borrow())?;
    // attacker passes TradingVault account → fields interpreted as
    // Market fields → arbitrary funding/oracle values
}
```

Expected solinv output:

```
[VIOLATION] discriminator-skip detected
Instruction: ClosePosition
Program: openhl-core (8KxK...)
Account: 2 (market, pubkey GfHe...)
Wrong discriminator used: deadbeef00000000
Expected discriminator: 7a8c3d9e1f2b4a56  (Market)
Tx outcome: Success (state changed)

Reproduction: see findings/2026-05-24-disc-skip-closepos.json
```

This is the **third acceptance test** for solinv-core. Pass criterion:
solinv detects within 30 seconds.

### Triple-bug fixture for orthogonality validation

To validate that signer-skip, owner-skip, and discriminator-skip are
truly orthogonal, plant all three in `process_close_position`
simultaneously:

```rust
fn process_close_position<'a>(...) -> ProgramResult {
    let trader_ai = &accounts[0];
    // BUG 1: signer check removed
    let position_ai = &accounts[1];
    // BUG 2: owner check removed
    let market_ai = &accounts[2];
    // BUG 3: discriminator check removed (already missing)
    // ...
}
```

solinv must report **three independent violations** without conflation.
This validates the design choice that each invariant isolates one
check failure.

## 8. References

### Audit firm guidance
- Trail of Bits Anchor security guidelines (UncheckedAccount,
  manual deserialization warnings)
  https://github.com/trailofbits/publications
- Neodyme: "Common Pitfalls in Solana Programs"
  https://neodyme.io/blog/common-pitfalls/
- Sec3 public audit reports
  https://www.sec3.dev/
- OtterSec public retrospectives
  https://osec.io/

### Anchor / Solana documentation
- Anchor Account discriminator
  https://www.anchor-lang.com/docs/account-types
- AccountLoader load_init vs load_mut semantics
  https://docs.rs/anchor-lang/latest/anchor_lang/accounts/account_loader/struct.AccountLoader.html
- Sealevel attacks (type confusion examples)
  https://github.com/coral-xyz/sealevel-attacks

### Mainnet incidents (type-confusion family)
- Crema Finance post-mortem (Jul 2022, $8.7M)
  https://medium.com/@CremaFinance/
- Anchor security advisories
  https://github.com/coral-xyz/anchor/security/advisories

### Internal
- `docs/invariants/signer-skip.md` — template + shared traits
- `docs/invariants/owner-skip.md` — orthogonal invariant in the same
  account-validation family
- `docs/invariants/account-swap.md` (TODO) — completes the trio
  (same owner + same discriminator + wrong specific account)
- `docs/research-crucible-integration.md` — `TestContext` API for
  `get_account`, `set_account`, `snapshot`, `revert_to`
