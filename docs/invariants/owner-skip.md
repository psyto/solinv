# Invariant: owner-skip

> **Severity**: Critical
> **Bug class**: Missing `account.owner == expected_program` check, enabling account-type confusion attacks
> **Status**: Spec written 2026-05-24. Implementation: Phase 1 Days 19-20.

## 1. Bug class

An `owner-skip` vulnerability exists when a Solana program reads or
mutates account data without verifying the account is owned by the
expected program. Every Solana account has an `owner: Pubkey` field
identifying the program that controls it. **Only the owner program
can mutate the account's `data` field or close it.** A correct program
reading an account it expects to control must verify
`account.owner == &program_id` before trusting the data.

The attack: an attacker passes an account they control (owned by a
different program, typically `system_program` or an attacker-deployed
program) but with bytes laid out to look like the legitimate account
type. The vulnerable program parses these bytes as the expected struct
and acts on attacker-controlled values — fake stake balance, fake
admin pubkey, fake oracle price, etc.

### Why Solana-specific (vs EVM)

EVM contract storage is intrinsically tied to the contract address —
you cannot pass "another contract's storage" to a function. In Solana,
accounts are passed as instruction parameters, and **any** account
can be passed to **any** program. The program must explicitly verify
ownership to ensure the account it's reading is the one it created or
expects to manage. This is the single most fundamental Solana security
discipline that has no EVM analogue.

### Account-type confusion (the canonical attack)

Programs often have multiple account types with similar byte layouts.
Without an owner check, an attacker can substitute a `UserPosition`
account for an `AdminConfig` account if the layouts overlap on the
critical fields. Combined with a missing discriminator check (see
[discriminator-skip](discriminator-skip.md)), this becomes trivial
privilege escalation.

### Anchor specifics

Anchor's `Account<'info, T>` constraint enforces the owner check
automatically — it verifies `account.owner == &program_id` matches
the program currently executing:

```rust
#[derive(Accounts)]
pub struct UpdateState<'info> {
    pub state: Account<'info, StateData>,   // Anchor checks owner
}
```

The bug appears when developers use:
- `AccountInfo<'info>` (no owner check)
- `UncheckedAccount<'info>` (no owner check, no discriminator check)
- `AccountLoader<'info, T>` without verifying owner separately
- Native programs (no Anchor) without manual `if account.owner != &program_id`

### Cross-program account ownership

Some accounts are correctly owned by **other** programs:
- SPL Token accounts: owned by `spl_token::ID`
- Sysvars: owned by `NativeLoader`
- System accounts (plain SOL): owned by `system_program::ID`
- ATA: owned by `spl_associated_token_account::ID` or directly by Token

The owner check needs to match the **expected** owner, not always the
calling program. This nuance distinguishes `owner-skip` from
`token-account-confusion` (where the issue is which Token program
variant — classic vs Token-2022).

## 2. Mainnet precedent and audit findings

### Direct precedent

Missing-owner-check is the textbook Solana smart contract vulnerability,
discussed at length in audit firm guidance:

- Neodyme blog: "Common Pitfalls in Solana Programs" lists "missing
  owner check" as #1 finding in nearly every Anchor-free Solana program
- Trail of Bits: their Anchor security guidelines explicitly warn about
  `AccountInfo<'info>` and `UncheckedAccount<'info>` requiring manual
  owner verification
- Sec3 / OtterSec audit reports — recurring finding across virtually
  all multi-account Solana protocols pre-mainnet
- Anza developer documentation explicitly identifies owner-check as a
  mandatory discipline for native programs

### Public mainnet incidents (account-confusion family)

- **Crema Finance (Jul 2022, $8.7M)** — missing account validation on
  tick array allowed attacker to substitute their own pseudo-tick-array
  account. Classic owner/account-type confusion
- **Loopscale (Apr 2024)** — partial root cause involved insufficient
  account validation in lending state reads
- **Various Anchor program post-mortems** — second most common cause
  after oracle manipulation

### solinv positioning

Like signer-skip, owner-skip is **the bug that audit firms catch
manually**. Bug bounty payouts when caught pre-mainnet by hunters using
fuzzers are in the same Critical tier ($100K-$500K range). Auto-catching
at audit-firm rate, free per check, is the economic argument.

## 3. Detection algorithm

### High-level pseudocode

```
for each instruction in program:
    for each account index with declared expected_owner:
        snapshot = ctx.snapshot()
        pre_hash = ctx.program_state_hash(program_id)

        // Create fake account with same data bytes but wrong owner
        real_account = ctx.get_account(ix.accounts[idx].pubkey)
        fake_pubkey = Pubkey::new_unique()
        ctx.set_account(fake_pubkey, Account {
            owner: NOT expected_owner,           // typically system_program
            data: real_account.data.clone(),     // preserve bytes for type
            lamports: real_account.lamports,
            ..
        })

        // Substitute fake in instruction accounts
        modified_accounts = ix.accounts.clone()
        modified_accounts[idx].pubkey = fake_pubkey

        result = ctx.send(ix.program, ix.data, modified_accounts)
        post_hash = ctx.program_state_hash(program_id)

        if result.success and post_hash != pre_hash:
            REPORT owner-skip violation

        ctx.revert_to(snapshot)
    end
end
```

### Why preserve data bytes

Without preserving the data bytes, the program may reject the fake
account at a *later* check (e.g., discriminator mismatch, malformed
struct). To isolate the owner-check failure, the fake account must
otherwise look valid. This gives the cleanest signal: if the only
difference is `owner`, success implies owner-check missing.

### Choice of fake owner

Default: `system_program::ID`. This is the most common scenario in
real exploits (attacker creates account via system_program, then passes
it to the vulnerable program). Alternative: any attacker-deployed
program ID — equivalent semantically, more realistic for some attack
scenarios but adds setup cost.

### Multi-pass: try each unexpected owner

solinv's owner-skip should iterate through several "wrong" owners:
1. `system_program::ID` (default attack)
2. `spl_token::ID` (interesting: substituting a token account)
3. `Pubkey::new_unique()` (random attacker-controlled program)

If ANY of these passes succeed → violation. Different unexpected owners
catch different bug patterns.

## 4. Capability trait + implementation

### Extended InstructionSpec

The existing `HasInstructionSet` trait's `InstructionSpec` extends with
ownership metadata:

```rust
// solinv-core/src/traits.rs

#[derive(Clone, Debug)]
pub struct InstructionSpec {
    pub program_id: Pubkey,
    pub name: String,
    pub accounts: Vec<AccountMeta>,
    pub signer_indices: Vec<usize>,
    pub optional_signer_indices: Vec<usize>,

    /// Per-account expected owner. Length must equal `accounts.len()`.
    /// `None` = no owner expectation (account can be anything, e.g.,
    /// arbitrary user wallet passed for fee payment).
    /// `Some(pk)` = account MUST be owned by `pk`; owner-skip invariant
    /// verifies the program checks this.
    pub expected_owners: Vec<Option<Pubkey>>,

    pub data_sample: Vec<u8>,
}
```

Anchor IDL auto-fill: every `Account<'info, T>` has `expected_owner =
Some(program_id)`. SPL Token accounts → `Some(spl_token::ID)`. Sysvars
→ `Some(NativeLoader::ID)`. `UncheckedAccount` / `AccountInfo` → user
must declare manually.

### Invariant function

```rust
// solinv-core/src/invariants/owner_skip.rs

use crate::traits::{HasContext, HasInstructionSet};
use crucible_fuzzer::fuzz_assert;
use solana_sdk::{account::Account, pubkey::Pubkey, system_program};

/// Detects missing `account.owner == expected_program` checks.
///
/// For each instruction with declared `expected_owners`, replaces the
/// target account with a fake account containing identical bytes but
/// owned by a non-expected program. If the instruction succeeds and
/// program state changes, report owner-skip violation.
pub fn owner_skip<F>(fixture: &mut F)
where
    F: HasInstructionSet + HasContext,
{
    let ixs = fixture.instructions();
    for ix in &ixs {
        for (idx, expected) in ix.expected_owners.iter().enumerate() {
            let Some(expected_owner) = expected else { continue };

            // Iterate through several "wrong" owners
            for wrong_owner in WRONG_OWNERS.iter() {
                if wrong_owner == expected_owner { continue; }

                let ctx = fixture.ctx_mut();
                let snapshot = ctx.snapshot();
                let pre_hash = ctx.program_state_hash(&ix.program_id);

                let real_pubkey = ix.accounts[idx].pubkey;
                let Some(real_account) = ctx.get_account(&real_pubkey)
                else {
                    ctx.revert_to(snapshot);
                    continue;
                };

                // Plant fake account
                let fake_pubkey = Pubkey::new_unique();
                ctx.set_account(fake_pubkey, Account {
                    owner: *wrong_owner,
                    data: real_account.data.clone(),
                    lamports: real_account.lamports,
                    executable: false,
                    rent_epoch: real_account.rent_epoch,
                });

                let mut accounts = ix.accounts.clone();
                accounts[idx] = AccountMeta {
                    pubkey: fake_pubkey,
                    is_signer: accounts[idx].is_signer,
                    is_writable: accounts[idx].is_writable,
                };

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
                    "owner-skip detected: instruction {} (program {}) \
                     succeeded with account {} owned by {} \
                     instead of expected {}",
                    ix.name,
                    ix.program_id,
                    idx,
                    wrong_owner,
                    expected_owner,
                );
            }
        }
    }
}

const WRONG_OWNERS: &[Pubkey] = &[
    system_program::ID,
    // spl_token::ID added at runtime (not const Pubkey)
    // attacker_program_id generated dynamically
];
```

### Usage from user harness

```rust
use solinv_fuzz::prelude::*;
use openhl_core::ID as OPENHL_ID;

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
                    // ...
                ],
                signer_indices: vec![0],
                optional_signer_indices: vec![],
                expected_owners: vec![
                    None,                  // trader = arbitrary wallet
                    Some(OPENHL_ID),       // position = our program
                    Some(OPENHL_ID),       // market = our program
                ],
                data_sample: vec![/* close_position ix data */],
            },
        ]
    }
}

#[invariant_test]
fn solinv_all(f: &mut OpenHLFixture) {
    solinv_core::invariants::signer_skip(f);
    solinv_core::invariants::owner_skip(f);
}
```

## 5. False-positive risks and mitigations

| Risk | Cause | Mitigation |
|---|---|---|
| **Wallet / fee-payer accounts** | Plain SOL accounts have `owner = system_program::ID` legitimately; replacing with another system-owned account is not a bug | `expected_owners[i] = None` for any account intended to be a user wallet |
| **Sysvar substitution** | Sysvars have specific owner (`NativeLoader`); flipping makes them invalid for runtime reasons, not just owner-check | Cover via separate `sysprogram-substitution` invariant. Mark sysvar indices with `Some(NativeLoader::ID)` but document overlap |
| **SPL Token accounts** | Owned by `spl_token::ID`, never the calling program. Calling program must check `owner == spl_token::ID` (or `spl_token_2022::ID`), not its own ID | `expected_owners[i] = Some(spl_token::ID)`. Distinct from owner-self assumption |
| **PDA accounts created mid-ix** | Account starts as system-owned, becomes program-owned via `system_instruction::allocate` + `assign` during ix | Skip account indices where instruction is the creator (declared via separate `creates_indices` field on InstructionSpec) |
| **CPI-target programs** | Account owned by a different program reached via CPI (e.g., metadata account for Metaplex CPI) | `expected_owners[i] = Some(metaplex_program::ID)` — declares the expected external owner; solinv checks against that |
| **Type-confusion cross-program** | Real account owned by genuine program X, attack substitutes account owned by attacker program Y with same data layout | Default to `WRONG_OWNERS` containing system_program + a random attacker pubkey; this case is caught |
| **Same-data different-owner success is intentional** | Some programs intentionally accept any owner and dispatch on data discriminator | Programmer error to write this; solinv reports as violation, programmer documents waiver via `#[solinv(ignore = "owner_skip")]` attribute on ix |

### Distinguishing owner-skip vs sysprogram-substitution

These two invariants overlap when the expected account is a sysvar.
Convention: if `expected_owner == NativeLoader::ID`, only the
`sysprogram-substitution` invariant fires (skip in owner-skip). Avoids
duplicate violation reports.

### Distinguishing owner-skip vs account-swap

owner-skip = wrong **owner program**, same data layout. account-swap =
wrong **account purpose** (e.g., user A's token account substituted for
user B's token account, both owned by SPL Token). Different attack
class, different invariant.

## 6. Severity classification

**Critical** baseline. Reasoning:

- Allows reading attacker-controlled state in place of legitimate state
- Combined with discriminator-skip → trivial type confusion → admin
  escalation, fund theft
- Routinely caught in audit; mainnet exploits in this family have
  caused multi-million-dollar losses (Crema $8.7M)
- Exploit complexity: low. Once discovered, weaponization is
  straightforward (deploy account with crafted bytes, call vulnerable
  ix)

Bug bounty reference: same tier as signer-skip ($150K-$1M Critical for
top-tier protocols).

Severity adjustment:
- State change is non-financial → **High** (still bad, but no direct
  fund loss vector)
- State change is read-only / metadata only → **Medium** (information
  disclosure or counter manipulation)
- Expected_owner is the calling program itself AND the data layout
  doesn't enable type confusion → **High** (less severe because the
  attacker can't easily craft a convincing fake)

## 7. Test fixture in openhl-solana

Plant owner-skip bug in `process_close_position`. This handler reads
the Position account to calculate PnL and transfer collateral back to
the trader. If the owner check is missing, an attacker can pass a
fake "Position" with arbitrary `entry_price` / `size_held`, claiming
infinite PnL.

```rust
// programs/openhl-core/src/lib.rs

// BEFORE (correct):
fn process_close_position<'a>(
    program_id: &Pubkey,
    accounts: &'a [AccountInfo<'a>],
    data: &[u8],
) -> ProgramResult {
    let position_ai = &accounts[1];

    if position_ai.owner != program_id {
        msg!("close_position: position account not owned by openhl-core");
        return Err(ProgramError::IllegalOwner);
    }

    let position = Position::try_from_slice(&position_ai.data.borrow())?;
    // ... use position.entry_price, position.size_held to compute PnL ...
}

// PLANTED BUG (for solinv validation):
fn process_close_position<'a>(
    program_id: &Pubkey,
    accounts: &'a [AccountInfo<'a>],
    data: &[u8],
) -> ProgramResult {
    let position_ai = &accounts[1];

    // BUG: owner check intentionally removed for solinv validation
    // (also remove discriminator check if testing both bugs simultaneously)

    let position = Position::try_from_slice(&position_ai.data.borrow())?;
    // ... attacker-controlled position data flows into PnL math ...
}
```

Expected solinv output when run against planted-bug version:

```
[VIOLATION] owner-skip detected
Instruction: ClosePosition
Program: openhl-core (8KxK...)
Account: 1 (position, pubkey GfHe...)
Wrong owner used in attack: 11111111111111111111111111111111 (system_program)
Expected owner: 8KxK... (openhl-core)
Tx outcome: Success (state changed: lamports moved 1000000 → 0)

Reproduction: see findings/2026-05-24-owner-skip-closepos.json
```

This is the **second acceptance test** for solinv-core (first being
signer-skip). Pass criterion: solinv detects within 30 seconds.

### Combined bug fixture

When both signer-skip AND owner-skip are planted simultaneously in the
same handler, solinv must report **both** violations independently
without one masking the other. This validates that invariants run in
isolation and don't have order dependencies.

## 8. References

### Audit firm guidance
- Neodyme: "Common Pitfalls in Solana Programs"
  https://neodyme.io/blog/common-pitfalls/
- Trail of Bits Anchor security guidelines
  https://github.com/trailofbits/publications
- Sec3 public audit reports
  https://www.sec3.dev/
- OtterSec audit retrospectives
  https://osec.io/

### Solana documentation
- AccountInfo::owner
  https://docs.rs/solana-program/latest/solana_program/account_info/struct.AccountInfo.html#structfield.owner
- Anchor Account constraint (owner verification)
  https://docs.rs/anchor-lang/latest/anchor_lang/accounts/account/struct.Account.html
- Anchor UncheckedAccount warning
  https://docs.rs/anchor-lang/latest/anchor_lang/accounts/unchecked_account/struct.UncheckedAccount.html

### Mainnet incidents (account-confusion family)
- Crema Finance post-mortem (Jul 2022, $8.7M)
  https://medium.com/@CremaFinance/
- Anchor security advisories
  https://github.com/coral-xyz/anchor/security/advisories

### Internal
- `docs/invariants/signer-skip.md` — template + shared traits (`HasContext`,
  `HasInstructionSet`)
- `docs/invariants/discriminator-skip.md` (TODO) — adjacent bug class;
  owner-skip + discriminator-skip together = type confusion
- `docs/invariants/account-swap.md` (TODO) — adjacent: wrong-account-of-same-owner
- `docs/research-crucible-integration.md` — TestContext API for
  `get_account`, `set_account`, `snapshot`, `revert_to`
