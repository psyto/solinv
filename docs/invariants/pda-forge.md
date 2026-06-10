# Invariant: pda-forge

> **Severity**: Critical
> **Bug class**: Missing PDA seed verification, enabling attacker to substitute any account where a derived PDA was expected
> **Status**: Spec written 2026-05-24. Implementation: Phase 1 Days 23-24.

## 1. Bug class

A `pda-forge` vulnerability exists when a Solana program accepts an
account at a parameter slot that is supposed to be a Program Derived
Address (PDA), but the program does not verify that the account's
pubkey equals the address derived from the declared seeds. An attacker
can then substitute any account they control at that slot, bypassing
the program's intended account-identity discipline.

A PDA is an address computed deterministically from `seeds` (a list of
byte slices) and `program_id`. The standard derivation:

```rust
let (pda, bump) = Pubkey::find_program_address(
    &[b"vault", market.as_ref()],
    &program_id,
);
```

PDAs are off-curve (no private key can produce a signature for them),
so a program is the only entity that can sign for a PDA via
`invoke_signed`. This makes PDAs the standard mechanism for
"program-owned identity" — vaults, user accounts, configuration accounts,
all derived deterministically from context.

### The two halves of PDA correctness

PDAs require two distinct verifications:

1. **At account creation**: when a program creates a PDA-owned account
   via `system_instruction::create_account` followed by `invoke_signed`,
   the runtime validates the seeds match the address. **Auto-enforced**.
2. **At account read**: when a program receives an existing PDA account
   as an instruction parameter, **the runtime does NOT verify the
   pubkey matches the expected seeds**. The program must manually:
   ```rust
   let (expected_pda, _) = Pubkey::find_program_address(seeds, program_id);
   if account.key != &expected_pda {
       return Err(ProgramError::InvalidSeeds);
   }
   ```

The bug is the omission of step 2 at read time. The program accepts
any account the caller passes, assuming "if the caller gave me an
account in the PDA slot, it must be the right PDA". An attacker who
passes an attacker-controlled account at that slot can:

- **Read attack**: have the program read attacker-crafted data as if
  it were the real PDA state
- **Write attack**: have the program write protocol state to the
  attacker's chosen account, leaving the real PDA untouched (or vice
  versa — write to real PDA but read from fake PDA in a multi-step ix)
- **Identity spoofing**: claim to be the "admin config" PDA by
  substituting any account in the admin-config slot

### Why Solana-specific

EVM has no equivalent concept. Solidity contracts have storage tied to
their contract address; passing "a different storage" to a function is
impossible. Solana's account-passing model + PDA pattern combine to
create this distinct security responsibility.

### Anchor specifics

Anchor's `#[account(seeds = [...], bump)]` constraint auto-verifies
PDA derivation at read time:

```rust
#[derive(Accounts)]
#[instruction(market_idx: u64)]
pub struct OpenPosition<'info> {
    #[account(
        seeds = [b"position", trader.key().as_ref(), &market_idx.to_le_bytes()],
        bump,
    )]
    pub position: Account<'info, Position>,
}
```

The bug appears when developers use `AccountInfo<'info>`,
`UncheckedAccount<'info>`, or `AccountLoader<'info, T>` **without**
the `seeds = [...]` constraint. Native programs must write the
verification manually.

### Two attack variants

- **Variant 1: Missing verification entirely.** Program accepts any
  account at the PDA slot. solinv catches this with a random
  substitute pubkey.
- **Variant 2: Wrong-bump acceptance.** Program checks the seeds
  match but accepts any bump (rare; usually find_program_address
  returns canonical bump). solinv tests with non-canonical bumps as
  secondary pass.

solinv focuses on Variant 1 (the common case); Variant 2 is included
as a secondary check.

## 2. Mainnet precedent and audit findings

### Direct precedent

PDA-forge is a top finding in Solana audits, particularly in native
programs and Anchor programs using `UncheckedAccount<'info>`:

- Trail of Bits' Anchor security guidelines explicitly call out missing
  seeds-constraint verification as a top-3 finding category
- Neodyme audit reports include PDA verification in standard finding
  list for non-Anchor programs
- Sec3 / OtterSec audit retrospectives reference seed-verification
  omissions in approximately every audit of native Solana programs
- The Solana `sealevel-attacks` educational repo includes "missing-bump"
  and "missing-seed" attack examples as canonical Solana CTF challenges

### Public mainnet incidents (PDA-confusion family)

- **Solend incidents (2022-2023)** — multiple findings around lending
  reserve PDA validation in audit reports (most caught pre-mainnet)
- **Phantom Wallet "Loopscale" issue (Apr 2024)** — partial root cause
  involved insufficient PDA validation in account derivation
- **Various Anchor program post-mortems** — recurring family alongside
  owner-skip and discriminator-skip

### solinv positioning

Same as preceding invariants: audit-firm-rate detection, free per check.
Bug bounty payouts for Critical PDA-forge bugs in major protocols sit
in the same Critical tier ($100K-$500K range).

## 3. Detection algorithm

### High-level pseudocode

```
for each instruction in program:
    for each account index with declared expected_pda_seeds:
        // Re-derive expected PDA to validate fixture setup
        seed_slices = seeds.iter().map(|s| s.as_slice()).collect()
        (expected_pda, _) = Pubkey::find_program_address(seed_slices, program_id)

        if ix.accounts[idx].pubkey != expected_pda:
            REPORT setup error (user fixture is wrong)
            continue

        snapshot = ctx.snapshot()
        pre_hash = ctx.program_state_hash(program_id)

        real_account = ctx.get_account(expected_pda)

        // Attack: substitute a different account with identical content
        fake_pubkey = WRONG_PUBKEY_STRATEGY  // see below
        ctx.set_account(fake_pubkey, real_account.clone())

        modified_accounts = ix.accounts.clone()
        modified_accounts[idx].pubkey = fake_pubkey

        result = ctx.send(ix.program, ix.data, modified_accounts)
        post_hash = ctx.program_state_hash(program_id)

        if result.success and post_hash != pre_hash:
            REPORT pda-forge violation

        ctx.revert_to(snapshot)
    end
end
```

### Why preserve everything except the pubkey

The fake account is a **byte-for-byte clone** of the real PDA at a
different pubkey: same data (same discriminator + same fields), same
owner (the program), same lamports. This isolates the PDA seed
verification specifically:

- owner-skip would have caught wrong owner — preserved here
- discriminator-skip would have caught wrong discriminator — preserved
- Only the **pubkey mismatch** with the expected derivation can be
  detected by PDA verification

If the program checks `account.key == &expected_pda`, the substitution
fails (different pubkey). If the program skips this check, the
substitution succeeds with identical-looking data, and state changes
flow to/from the fake account.

### Wrong-pubkey strategies (multi-pass)

solinv tries each in order; first success reports violation:

1. **`Pubkey::new_unique()`** — most basic, catches "no PDA check at
   all" bugs. Random off-curve pubkey, no relationship to declared
   seeds
2. **PDA derived from different seeds in same program** — catches
   "checks PDA derivation but doesn't bind to expected context" bugs.
   E.g., expected `[b"position", trader_A, market]`, attack with
   `[b"position", trader_B, market]` — same shape but different trader
3. **Non-canonical bump for same seeds** — catches "doesn't validate
   bump" bugs. find_program_address yields canonical bump; attack uses
   bump-1

Strategy 1 is the primary attack; 2-3 catch subtler missing checks.

### Account creation vs account read

solinv targets the **read** case (existing PDA account passed to ix
that operates on it). The **create** case (ix that allocates the PDA)
is auto-protected by the runtime — `invoke_signed` fails if seeds
don't match the target address. solinv does NOT test creation
correctness.

InstructionSpec field `creates_indices` (used by owner-skip and
discriminator-skip to skip account-creation paths) is reused here:
solinv skips PDA forge testing for accounts being created mid-ix.

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
    pub expected_discriminators: Vec<Option<[u8; 8]>>,

    /// Per-account PDA seed declaration.
    /// None = account is not a PDA (e.g., user wallet, externally-
    /// controlled account).
    /// Some(seeds) = account is expected to be derivable via
    /// Pubkey::find_program_address(seeds, program_id); program must
    /// verify this.
    ///
    /// Each Vec<u8> in seeds is one seed component (e.g., literal
    /// bytes "position", or pubkey as_ref bytes).
    pub expected_pda_seeds: Vec<Option<Vec<Vec<u8>>>>,

    /// Indices being created (allocated) during this ix.
    /// Excluded from PDA-forge testing — runtime auto-verifies create.
    pub creates_indices: Vec<usize>,

    pub data_sample: Vec<u8>,
}
```

Anchor IDL auto-fill: every `#[account(seeds = [...], bump)]` populates
`expected_pda_seeds`. `Account<'info, T>` without seeds constraint
gets `None`. UncheckedAccount / AccountInfo defaults `None` — user
declares manually.

### Invariant function

```rust
// solinv-core/src/invariants/pda_forge.rs

use crate::traits::{HasContext, HasInstructionSet};
use crucible_fuzzer::fuzz_assert;
use solana_sdk::{account::Account, instruction::AccountMeta, pubkey::Pubkey};

/// Detects missing PDA seed verification on accounts that should be
/// derived from program-declared seeds.
///
/// For each instruction with declared `expected_pda_seeds`, substitutes
/// a fake account at a wrong pubkey with byte-identical content
/// (preserving owner and discriminator). If the instruction succeeds
/// and state changes, report pda-forge violation.
pub fn pda_forge<F>(fixture: &mut F)
where
    F: HasInstructionSet + HasContext,
{
    let ixs = fixture.instructions();
    for ix in &ixs {
        for (idx, expected_seeds) in ix.expected_pda_seeds.iter().enumerate() {
            let Some(seeds) = expected_seeds else { continue };
            if ix.creates_indices.contains(&idx) { continue; }

            // Re-derive expected PDA; verify fixture setup is correct
            let seed_slices: Vec<&[u8]> = seeds.iter()
                .map(|s| s.as_slice())
                .collect();
            let (expected_pda, _canonical_bump) =
                Pubkey::find_program_address(&seed_slices, &ix.program_id);

            if ix.accounts[idx].pubkey != expected_pda {
                eprintln!(
                    "solinv setup error: instruction {} declares PDA seeds \
                     for account {} but actual pubkey doesn't derive from \
                     them. Fix InstructionSpec.",
                    ix.name, idx
                );
                continue;
            }

            let ctx = fixture.ctx_mut();
            let snapshot = ctx.snapshot();
            let pre_hash = ctx.program_state_hash(&ix.program_id);

            let Some(real_account) = ctx.get_account(&expected_pda) else {
                ctx.revert_to(snapshot);
                continue;
            };

            // Attack pass 1: random pubkey (catches no-check-at-all)
            let fake_pubkey = Pubkey::new_unique();
            ctx.set_account(fake_pubkey, Account {
                owner: real_account.owner,          // preserve
                data: real_account.data.clone(),    // preserve
                lamports: real_account.lamports,    // preserve
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
                "pda-forge detected: instruction {} (program {}) succeeded \
                 with account {} at pubkey {} (random), expected PDA \
                 derived from seeds {:?}",
                ix.name,
                ix.program_id,
                idx,
                fake_pubkey,
                seeds.iter().map(|s| format!("{:02x?}", s)).collect::<Vec<_>>(),
            );

            // Attack pass 2: PDA from different seeds (catches
            // "verifies-derivation-but-not-context" bugs) — implementation
            // depends on user fixture providing alternative seed variants
            // via a future trait extension. Skipped in v0.1.
        }
    }
}
```

### Usage from user harness

```rust
use solinv_fuzz::prelude::*;
use openhl_core::ID as OPENHL_ID;

impl HasInstructionSet for OpenHLFixture {
    fn instructions(&self) -> Vec<InstructionSpec> {
        let (position_pda, _) = Pubkey::find_program_address(
            &[b"position", self.trader.as_ref(), &self.market_idx.to_le_bytes()],
            &OPENHL_ID,
        );
        let (vault_auth_pda, _) = Pubkey::find_program_address(
            &[b"vault_auth", self.market.as_ref()],
            &OPENHL_ID,
        );

        vec![
            InstructionSpec {
                program_id: OPENHL_ID,
                name: "OpenPosition".into(),
                accounts: vec![
                    AccountMeta::new(self.trader, true),
                    AccountMeta::new(position_pda, false),
                    AccountMeta::new(self.market, false),
                    AccountMeta::new(vault_auth_pda, false),
                ],
                signer_indices: vec![0],
                optional_signer_indices: vec![],
                expected_owners: vec![
                    None,
                    Some(OPENHL_ID),
                    Some(OPENHL_ID),
                    Some(OPENHL_ID),
                ],
                expected_discriminators: vec![
                    None,
                    Some(Position::DISCRIMINATOR),
                    Some(Market::DISCRIMINATOR),
                    None,
                ],
                expected_pda_seeds: vec![
                    None,
                    Some(vec![
                        b"position".to_vec(),
                        self.trader.to_bytes().to_vec(),
                        self.market_idx.to_le_bytes().to_vec(),
                    ]),
                    None,  // market is identified by config, not PDA-derived
                    Some(vec![
                        b"vault_auth".to_vec(),
                        self.market.to_bytes().to_vec(),
                    ]),
                ],
                creates_indices: vec![1],  // position is created here, skip
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
    solinv_core::invariants::pda_forge(f);
}
```

## 5. False-positive risks and mitigations

| Risk | Cause | Mitigation |
|---|---|---|
| **Non-PDA accounts** | Account is a regular wallet, ATA, or system account — not derived from PDA seeds | `expected_pda_seeds[i] = None` for those accounts |
| **PDA accounts created mid-ix** | Account is allocated during this instruction; runtime auto-verifies creation via invoke_signed | Mark in `creates_indices` field; skipped from forge testing |
| **PDA verification via signer privilege** | Program verifies PDA correctness implicitly by attempting `invoke_signed` with declared seeds (succeeds only if seeds match the account being signed-for) | True positive — but report is somewhat noisy since "real" check happens in a CPI. v0.2 could detect this pattern and downgrade severity |
| **Anchor `init_if_needed`** | Account may be created or already exist depending on state; PDA verification path differs | Skip if `init_if_needed` is detected via IDL; user can override |
| **Custom seed derivation (non-canonical bump)** | Program uses `Pubkey::create_program_address` with specific bump instead of `find_program_address` | Declare canonical bump in trait method; solinv compares to canonical |
| **Cross-program PDA derivation** | PDA derived from a DIFFERENT program's ID (e.g., for a CPI target's PDA) | Add per-account `expected_pda_program` field for cross-program PDAs (v0.2 feature) |
| **Hash-collision pubkeys** | Theoretical: another random pubkey accidentally derives from declared seeds. Probability ~2^-128, negligible | Not mitigated; statistically impossible |

### Distinguishing pda-forge vs owner-skip vs discriminator-skip vs account-swap

Four invariants in the account-validation family, orthogonal by design:

- **owner-skip**: wrong owner program → fires
- **discriminator-skip**: wrong type within program → fires
- **pda-forge**: right owner + right type, but account is NOT derived
  from declared seeds → fires
- **account-swap**: right owner + right type + IS a real PDA, but
  derived from wrong context (e.g., wrong trader/market) → fires

A program missing all four checks reports four independent violations.
Each maps to a different `assert!` location in source.

### Important nuance: pda-forge vs account-swap

The line between pda-forge and account-swap:

- **pda-forge**: random or unrelated pubkey passed. Program doesn't
  verify the pubkey relationship to declared seeds at all
- **account-swap**: a real PDA passed, but the seeds it was derived
  from don't match the current ix context (e.g., User A's position
  PDA passed where User B's position was expected)

pda-forge is upstream — it catches the most basic missing verification.
account-swap is downstream — it catches programs that verify "this is
a PDA" but don't verify "this is THE RIGHT PDA for this context".

In implementation: pda-forge uses `Pubkey::new_unique()` (no real PDA).
account-swap uses a legitimate PDA from a different context.

## 6. Severity classification

**Critical** baseline. Reasoning:

- Direct vault drainage path when PDA represents a treasury/vault
- Identity spoofing when PDA represents admin/config (attacker becomes
  admin)
- State corruption when program writes to attacker-chosen account
  instead of real PDA
- Exploit complexity: low. Once discovered, weaponization is one
  attacker-controlled account creation away

Bug bounty reference (Critical):
- Drift: $250K-$500K
- Marginfi: $150K-$250K
- Kamino: $250K-$1M

Severity adjustment:
- PDA is used only as read-context (e.g., reading a config PDA) and
  no state change occurs → **High** (information disclosure, less
  direct loss)
- PDA verification is partially present (e.g., bump checked but seed
  components not) → **High** (limited but exploitable)
- Affected PDA is purely cosmetic (e.g., metadata-only) → **Medium**

## 7. Test fixture in openhl-solana

Plant pda-forge bug in `process_open_position` Position PDA. The
handler should verify the position account's pubkey matches
`find_program_address([b"position", trader, market_idx], program_id)`.
Without this check, an attacker can pass any account (especially one
they control or own a private key for) as their "position" and have
the program write position data to it.

```rust
// programs/openhl-core/src/lib.rs

// BEFORE (correct):
fn process_open_position<'a>(
    program_id: &Pubkey,
    accounts: &'a [AccountInfo<'a>],
    data: &[u8],
) -> ProgramResult {
    let trader_ai = &accounts[0];
    let position_ai = &accounts[1];
    let market_ai = &accounts[2];

    // ... signer / owner / discriminator checks ...

    // PDA verification:
    let market_idx = read_market_idx(market_ai)?;
    let (expected_position, _bump) = Pubkey::find_program_address(
        &[b"position", trader_ai.key.as_ref(), &market_idx.to_le_bytes()],
        program_id,
    );
    if position_ai.key != &expected_position {
        msg!("open_position: position PDA derivation mismatch");
        return Err(ProgramError::InvalidSeeds);
    }

    // ... open position, write to position_ai ...
}

// PLANTED BUG (for solinv validation):
fn process_open_position<'a>(
    program_id: &Pubkey,
    accounts: &'a [AccountInfo<'a>],
    data: &[u8],
) -> ProgramResult {
    let trader_ai = &accounts[0];
    let position_ai = &accounts[1];
    let market_ai = &accounts[2];

    // BUG: PDA verification intentionally removed

    // ... opens position at ATTACKER-CHOSEN position_ai account ...
}
```

Expected solinv output when run against planted-bug version:

```
[VIOLATION] pda-forge detected
Instruction: OpenPosition
Program: openhl-core (8KxK...)
Account: 1 (position, expected PDA: pos-XYZ)
Fake pubkey used in attack: 4mTk... (random)
Expected seeds: ["position", trader_bytes, market_idx_bytes]
Tx outcome: Success (state changed: lamports moved, position created)

Reproduction: see findings/2026-05-24-pda-forge-openpos.json
```

This is the **fourth acceptance test** for solinv-core. Pass criterion:
detection within 30 seconds.

### Quadruple-bug fixture for full orthogonality validation

Plant signer-skip + owner-skip + discriminator-skip + pda-forge
simultaneously in `process_close_position`:

```rust
fn process_close_position<'a>(...) -> ProgramResult {
    let trader_ai = &accounts[0];
    // BUG 1: signer check removed
    let position_ai = &accounts[1];
    // BUG 2: owner check removed
    // BUG 3: discriminator check removed
    // BUG 4: PDA verification removed
    let position = Position::try_from_slice(&position_ai.data.borrow())?;
    // ... process with attacker-controlled state ...
}
```

solinv must report **four independent violations** without one masking
the others. This is the **full contract** for the account-validation
invariant family. Passing this acceptance test validates that all four
invariants work in isolation and compose cleanly.

## 8. References

### Audit firm guidance
- Trail of Bits Anchor security guidelines (seeds-constraint warnings)
  https://github.com/trailofbits/publications
- Neodyme: "Common Pitfalls in Solana Programs" — PDA verification
  https://neodyme.io/blog/common-pitfalls/
- Sec3 public audit reports
  https://www.sec3.dev/
- coral-xyz/sealevel-attacks — canonical PDA-forge CTF examples
  https://github.com/coral-xyz/sealevel-attacks

### Solana / Anchor documentation
- Pubkey::find_program_address
  https://docs.rs/solana-program/latest/solana_program/pubkey/struct.Pubkey.html#method.find_program_address
- Anchor seeds constraint
  https://www.anchor-lang.com/docs/space-and-constraints#seeds-and-bump
- invoke_signed semantics
  https://docs.rs/solana-program/latest/solana_program/program/fn.invoke_signed.html

### Adjacent precedent
- Solend audit reports — recurring PDA finding category
- Loopscale incident (Apr 2024) — partial PDA-validation root cause

### Internal
- `docs/invariants/signer-skip.md` — template + shared traits
- `docs/invariants/owner-skip.md` — first of account-validation trio
- `docs/invariants/discriminator-skip.md` — second of account-validation
  trio (combines with this one for type+identity confusion attacks)
- `docs/invariants/account-swap.md` (TODO) — fourth and final of
  account-validation family (covers right-PDA-wrong-context)
- `docs/research-crucible-integration.md` — `TestContext` API for
  `get_account`, `set_account`, `snapshot`, `revert_to`
