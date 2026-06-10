# Invariant: signer-skip

> **Severity**: Critical
> **Bug class**: Missing `is_signer` check on authorization-required account
> **Status**: Spec written 2026-05-24. Implementation: Phase 1 Days 16-18.

## 1. Bug class

A `signer-skip` vulnerability exists when a Solana program instruction
performs an authorization-required action (transfer funds, update
admin-only fields, close accounts, etc.) but fails to verify that the
account claimed as the authorizing party is actually a transaction
signer.

Solana's account model exposes `AccountInfo.is_signer: bool` for every
account passed to an instruction. This flag is set by the runtime when
the account's keypair signed the transaction. **The program code must
explicitly check this flag** — the runtime does not enforce
authorization semantics; it only validates that signers' signatures
match their pubkeys.

### Why this is Solana-specific (vs EVM)

EVM's `msg.sender` is implicit — every call has a guaranteed sender.
Solana has no `msg.sender` equivalent. Instead, instructions receive a
list of accounts, and the program must:

1. Identify which account in the list represents the "authority"
2. Check `account.is_signer` is `true` on that account
3. Optionally check the account's pubkey matches an expected admin pubkey

Skipping step 2 is the bug. The attacker constructs a transaction
including the victim's pubkey in the authority position, signs only
their own fee payer key, and the program proceeds as if authorization
was granted.

### Anchor specifics

Anchor's account constraint system provides `Signer<'info>` and
`#[account(signer)]` to enforce this declaratively:

```rust
#[derive(Accounts)]
pub struct UpdateAdmin<'info> {
    pub authority: Signer<'info>,   // Anchor enforces is_signer check
    // ...
}
```

The bug appears when developers:
- Use plain `AccountInfo<'info>` instead of `Signer<'info>`
- Use `UncheckedAccount<'info>` without manual verification
- Write native programs without Anchor and forget the check entirely

## 2. Mainnet precedent and audit findings

### Direct precedent (rare publicly)

Pure `signer-skip` is rarely the cause of headline mainnet exploits —
oracle/economic attacks dominate the top-loss list. But it is **the
single most common finding category** in pre-mainnet audit reports:

- Neodyme's "Hacking the Hackathon" series consistently flags missing
  signer checks as top finding in submitted projects
- Sec3 public audit summaries from 2023-2025 list "missing signer
  validation" in nearly every multi-instruction Anchor program
- OtterSec audit retrospectives identify it as the #1 vulnerability
  class caught pre-mainnet

### Related public mainnet incidents (signer family)

- **Wormhole bridge (Feb 2022, ~$320M)** — sysvar substitution attack
  on `verify_signatures`. Not pure signer-skip but same family of
  "trust the account claim without verification" bug
- **Crema Finance (Jul 2022, $8.7M)** — missing account validation on
  tick array, allowing attacker-controlled state to substitute for
  protocol state. Adjacent class
- **Various Anchor program audits** — too many to enumerate; signer
  skip is the #1 grep target on initial review

### solinv positioning

Auto-catching `signer-skip` at audit-firm rate ($50K-$200K per audit)
**without paying for audits** is the core economic argument. The bugs
are routinely caught by humans; the goal is automation at zero marginal
cost per check.

## 3. Detection algorithm

### High-level pseudocode

```
for each instruction in program:
    for each account marked signer-required (via IDL or capability trait):
        snapshot = ctx.snapshot()
        modified_accounts = ix.accounts.clone()
        modified_accounts[signer_idx].is_signer = false

        result = ctx.send_instruction(ix.program, ix.data, modified_accounts)

        if result.success and state_changed(snapshot, ctx.current_state()):
            REPORT signer-skip violation
        end

        ctx.revert_to(snapshot)
    end
end
```

### Required cheatcode

solinv needs the ability to **flip an account's `is_signer` flag** in a
synthetic instruction. LiteSVM's standard `TestContext.send()` constructs
the AccountMeta with signer flag from the actual signature presence;
solinv needs a lower-level API:

```rust
ctx.send_with_account_flags(
    program_id,
    ix_data,
    accounts,                  // Vec<AccountMeta>
    signer_override: HashMap<Pubkey, bool>,  // override is_signer per account
);
```

Whether this is provided by Crucible's `TestContext` or requires a thin
wrapper in `solinv-cheat` is a Phase 1 Days 6-10 design decision (need
to read Crucible's `TestContext` source).

### State-change comparison

"State changed" = any of:
- Lamports moved between accounts
- Account data byte-diff at any program-owned account
- New account created (lamports allocated for rent)
- Existing account closed (lamports drained to 0)

Lightweight check: hash all program-owned account data + lamport
balances pre and post, compare. Cheap, sufficient for detection.

## 4. Capability trait + implementation

### Trait

```rust
// solinv-core/src/traits.rs

use anchor_lang::prelude::Pubkey;
use anchor_lang::solana_program::instruction::AccountMeta;

/// Fixture supporting per-instruction introspection of signer requirements.
///
/// User fixtures implement this to expose their program's instruction set
/// to solinv invariants. Auto-implementable from Anchor IDL via macro.
pub trait HasInstructionSet {
    fn instructions(&self) -> Vec<InstructionSpec>;
}

#[derive(Clone, Debug)]
pub struct InstructionSpec {
    pub program_id: Pubkey,
    pub name: String,
    pub accounts: Vec<AccountMeta>,
    /// Indices into `accounts` that the IDL declares as `Signer<'info>`
    /// or that the capability trait implementor marks as signer-required.
    pub signer_indices: Vec<usize>,
    /// Indices that are OPTIONAL signers (instruction supports both
    /// signed and unsigned forms). Excluded from signer-skip detection.
    pub optional_signer_indices: Vec<usize>,
    /// Sample instruction data sufficient to exercise the auth path.
    /// Fuzzer mutates this; user provides at least one valid sample.
    pub data_sample: Vec<u8>,
}
```

### Invariant function

```rust
// solinv-core/src/invariants/signer_skip.rs

use crate::traits::HasInstructionSet;
use crucible_fuzzer::{fuzz_assert, TestContext};

/// Detects missing `is_signer` checks on authorization-required accounts.
///
/// For each instruction in the fixture's instruction set, for each
/// signer-required account, replay the instruction with `is_signer = false`
/// on that account. If the replay succeeds AND state changes occur,
/// report violation.
pub fn signer_skip<F>(fixture: &mut F)
where
    F: HasInstructionSet + HasContext,
{
    let ixs = fixture.instructions();
    for ix in &ixs {
        for &signer_idx in &ix.signer_indices {
            if ix.optional_signer_indices.contains(&signer_idx) {
                continue;  // Skip optional signers
            }

            let ctx = fixture.ctx_mut();
            let snapshot = ctx.snapshot();
            let pre_hash = ctx.program_state_hash(&ix.program_id);

            // Build accounts with is_signer = false on target index
            let mut accounts = ix.accounts.clone();
            accounts[signer_idx].is_signer = false;

            let result = ctx.send_with_account_overrides(
                ix.program_id,
                ix.data_sample.clone(),
                accounts,
            );

            let post_hash = ctx.program_state_hash(&ix.program_id);
            let state_changed = pre_hash != post_hash;

            ctx.revert_to(snapshot);

            fuzz_assert!(
                !(result.is_ok() && state_changed),
                "signer-skip detected: instruction {} (program {}) \
                 succeeded with is_signer=false on account {} ({})",
                ix.name,
                ix.program_id,
                signer_idx,
                ix.accounts[signer_idx].pubkey,
            );
        }
    }
}
```

### Supporting trait

```rust
pub trait HasContext {
    fn ctx(&self) -> &TestContext;
    fn ctx_mut(&mut self) -> &mut TestContext;
}
```

This is shared across all solinv invariants — define once in
`solinv-core/src/traits.rs`.

### Usage from user harness

```rust
use solinv_fuzz::prelude::*;

#[derive(Clone)]
struct OpenHLFixture {
    ctx: TestContext,
    market: Pubkey,
    trader: Pubkey,
    // ...
}

impl HasContext for OpenHLFixture { /* trivial */ }
impl HasInstructionSet for OpenHLFixture {
    fn instructions(&self) -> Vec<InstructionSpec> {
        vec![
            InstructionSpec {
                program_id: openhl_core::ID,
                name: "OpenPosition".into(),
                accounts: vec![
                    AccountMeta::new(self.trader, true),       // signer
                    AccountMeta::new(self.market, false),
                    // ...
                ],
                signer_indices: vec![0],   // trader is signer
                optional_signer_indices: vec![],
                data_sample: vec![/* tag + side + size + price */],
            },
            // ... more instructions ...
        ]
    }
}

#[invariant_test]
fn solinv_all(f: &mut OpenHLFixture) {
    solinv_core::invariants::signer_skip(f);
    // ... other invariants chained here ...
}
```

## 5. False-positive risks and mitigations

| Risk | Cause | Mitigation |
|---|---|---|
| **Optional signers flagged** | Instruction supports both signed and unsigned forms (e.g., crank with optional admin override) | Use `optional_signer_indices` field; user marks explicitly. Conservative default: any account in optional set is excluded |
| **Multi-sig schemes** | Instruction requires N-of-M signers; flipping 1 leaves M-1 signed → still succeeds, no violation reported | Either: (a) flip ALL signer accounts simultaneously; or (b) accept that multi-sig is correctly authorized by remaining signers (no bug). solinv should test BOTH all-flipped and one-flipped; one-flipped success is NOT a bug |
| **Custom auth via PDA/session key** | Instruction uses lookup table or session key instead of direct signer | False positive — user must exclude these instructions from `instructions()` list, or mark all "signers" as optional |
| **CPI-only auth** | Authorization granted by being CPI'd from a specific program, not by direct signer | solinv only fuzzes direct calls; will not exercise CPI auth paths. Out of scope for signer-skip invariant; covered by future `cpi-reentrancy` invariant |
| **Sysvar-account-shaped auth** | Authorization checks compare account pubkey to sysvar pubkey rather than checking signer | Different bug class (`sysprogram-substitution`). Not signer-skip |
| **Read-only success path** | Instruction returns Ok without state change even without auth (e.g., view-only ix) | `state_changed` filter handles this; no violation reported if no state change |

### Severity adjustment based on state change

- State change includes lamport movement → **Critical** (fund theft)
- State change includes admin/authority field update → **Critical** (privilege escalation)
- State change is non-financial (e.g., user profile metadata) → **High**
- State change is metadata only (e.g., emit log, increment counter) → **Medium**

solinv-core encodes this severity logic in the violation report.

## 6. Severity classification

**Critical** in baseline case. Downgrade only when:
- State change is non-financial AND
- Affected ix has no downstream economic effect

Bug bounty payout reference (Critical):
- Drift: $250K-$500K
- Marginfi: $150K-$250K
- Kamino: $250K-$1M
- Jupiter: $250K-$500K
- Solana Foundation: up to $1M

## 7. Test fixture in openhl-solana

Plant signer-skip bug in `OpenPosition` for validation:

```rust
// programs/openhl-core/src/lib.rs

// BEFORE (correct):
fn process_open_position<'a>(
    program_id: &Pubkey,
    accounts: &'a [AccountInfo<'a>],
    data: &[u8],
) -> ProgramResult {
    let trader_ai = &accounts[0];
    if !trader_ai.is_signer {
        msg!("open_position: trader must be signer");
        return Err(ProgramError::MissingRequiredSignature);
    }
    // ... rest of handler ...
}

// PLANTED BUG (for solinv validation):
fn process_open_position<'a>(
    program_id: &Pubkey,
    accounts: &'a [AccountInfo<'a>],
    data: &[u8],
) -> ProgramResult {
    let trader_ai = &accounts[0];
    // BUG: signer check intentionally removed for solinv validation
    // ... rest of handler proceeds without auth ...
}
```

Expected solinv output when run against planted-bug version:

```
[VIOLATION] signer-skip detected
Instruction: OpenPosition
Program: openhl-core (8KxK...)
Account: 0 (trader, pubkey GfHe...)
Tx outcome: Success (state changed)

Reproduction: see findings/2026-05-24-signer-skip-openpos.json
```

This bug fixture is the **first acceptance test** for the solinv-core
`signer-skip` invariant. Pass criterion: solinv detects this within
30 seconds of starting fuzz, before any other invariants fire.

## 8. References

### Audit firm guidance
- Neodyme: "Hacking the Hackathon" Solana security series
  https://neodyme.io/blog/
- Sec3 public audit reports
  https://www.sec3.dev/
- OtterSec audit retrospectives
  https://osec.io/
- Trail of Bits Anchor security guidelines
  https://github.com/trailofbits/publications

### Solana documentation
- AccountInfo::is_signer
  https://docs.rs/solana-program/latest/solana_program/account_info/struct.AccountInfo.html
- Anchor Signer constraint
  https://docs.rs/anchor-lang/latest/anchor_lang/accounts/signer/struct.Signer.html

### Adjacent precedent
- Wormhole post-mortem (Feb 2022)
  https://wormhole.com/security/incident-feb22
- Crema Finance post-mortem (Jul 2022)
  https://medium.com/@CremaFinance/

### Internal
- `docs/research-crucible-integration.md` — `TestContext` API for snapshot/revert
- `docs/research-medusa-patterns.md` — replayable failure artifacts schema
