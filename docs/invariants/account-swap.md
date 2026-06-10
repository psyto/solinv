# Invariant: account-swap

> **Severity**: Critical
> **Bug class**: Missing context-binding verification — accepting a legitimate account from the wrong context (wrong user / wrong market / wrong epoch)
> **Status**: Spec written 2026-05-24. Implementation: Phase 1 Day 25. Completes Critical tier.

## 1. Bug class

An `account-swap` vulnerability exists when a Solana program accepts
an account that passes all syntactic checks — correct owner, correct
discriminator, even correct PDA derivation — but the account belongs
to a **different context** than the one the instruction is operating
on. The program fails to verify the semantic relationship between
the account and other ix parameters (caller, target market, designated
epoch, etc.).

This is the **fourth-line defense** in the account-validation family:

1. signer-skip catches: no signer check (caller identity)
2. owner-skip catches: wrong owner program
3. discriminator-skip catches: wrong type within program
4. pda-forge catches: not a real PDA at all
5. **account-swap catches: real PDA, but for a different context**

### The semantic-relationship gap

Consider a perp DEX with per-user position PDAs derived from
`[b"position", trader, market_idx]`. The position account contains:

```rust
struct Position {
    discriminator: [u8; 8],
    trader: Pubkey,       // ← context binding to caller
    market: Pubkey,       // ← context binding to market
    size_held: i64,
    entry_price: u64,
    ...
}
```

A correct `process_close_position` handler verifies:

```rust
let position = Position::try_from_slice(&position_ai.data.borrow())?;
if position.trader != *trader_ai.key { return Err(IllegalOwner); }
if position.market != *market_ai.key { return Err(InvalidArgument); }
// ... close ...
```

The bug is omitting these binding checks. With signer + owner +
discriminator + PDA-derivation all in place, the attacker still needs
the program to verify "this position belongs to the trader making the
call AND for the market being closed against." Without that:

- Trader B can pass Trader A's position PDA → close A's position,
  drain A's collateral
- Position for market X can be closed against market Y's oracle →
  arbitrary PnL via oracle mismatch

### Why this is the hardest of the family

The first four invariants are **syntactic** — one comparison each
(`is_signer`, `account.owner`, `data[0..8]`, `find_program_address`).
account-swap is **semantic** — requires understanding which fields
within an account refer to which other accounts in the ix.

This means:
- User fixture must provide more context (alternate-context accounts)
- Detection requires constructing a "wrong context" substitute account
- False positive analysis is more nuanced (intentional shared contexts)

### Why Solana-specific

EVM contracts have storage tied to `msg.sender` implicitly (via mapping
keys). When `mapping(address => UserData) public users;` is read with
`users[msg.sender]`, Solidity guarantees the lookup matches the
caller. Solana has no implicit binding — every account passed must
be explicitly relationship-checked against the caller and context.

## 2. Mainnet precedent and audit findings

### Direct precedent

account-swap is one of the most common Solana audit findings, especially
in lending and DEX protocols where per-user state is held in per-user
PDAs:

- Trail of Bits and Neodyme audit reports include "missing
  user-account-binding verification" as a recurring critical finding
  in lending protocols
- Sec3 / OtterSec audit retrospectives flag this in nearly every
  multi-user Solana protocol pre-mainnet
- The coral-xyz/sealevel-attacks educational repo includes
  "swap-accounts" as a canonical CTF challenge

### Public mainnet incidents (context-binding family)

- **Various Solana lending protocols (multiple 2022-2024 audits)** —
  pre-mainnet findings of "user can liquidate any other user's
  position by passing target's position PDA" were caught in audit
  rather than mainnet
- **Sol Increment / Nirvana / similar yield protocols** — partial
  root causes involved insufficient user/vault binding verification
- **Crema Finance (Jul 2022, $8.7M)** — broader account-confusion
  family; some pre-conditions involved missing context binding

### solinv positioning

Like preceding invariants: audit-firm-rate detection, free per check.
account-swap is particularly valuable to automate because:

1. **Highest false-negative rate in manual review** — auditors must
   trace data flow across multiple ixs to spot missing bindings;
   automated cross-context substitution finds them mechanically
2. **Highest payout when found in mainnet** — context-binding bugs in
   active DeFi protocols typically rate Critical for direct fund-theft
3. **Most relevant to perp DEX / lending protocols** — solinv's
   primary target market for Phase 1 (Drift, Marginfi, Kamino, Jupiter)

## 3. Detection algorithm

### High-level pseudocode

```
for each instruction in program:
    for each account index with declared swap_alternates:
        snapshot = ctx.snapshot()
        pre_hash = ctx.program_state_hash(program_id)

        for each alt_pubkey in swap_alternates[idx]:
            // alt_pubkey is a real legitimate account in the fixture
            // (right owner, right discriminator, real PDA) representing
            // a DIFFERENT context (different user, market, etc.)

            modified_accounts = ix.accounts.clone()
            modified_accounts[idx].pubkey = alt_pubkey

            result = ctx.send(ix.program, ix.data, modified_accounts)
            post_hash = ctx.program_state_hash(program_id)

            if result.success and post_hash != pre_hash:
                REPORT account-swap violation

            ctx.revert_to(snapshot)
        end
    end
end
```

### Why use real alternate accounts

Unlike pda-forge (which uses `Pubkey::new_unique()` for "no PDA at
all"), account-swap requires a **legitimate** PDA from a different
context. This ensures:

- owner check passes (right owner)
- discriminator check passes (right type)
- PDA-forge check passes (real PDA from valid seeds)
- ONLY the context-binding check can catch this substitution

If the alternate account were synthetic, earlier invariants would
fire first, masking the account-swap violation. Real alternate
accounts isolate the binding check.

### Where alternate accounts come from

User fixture setup creates them. For openhl-solana:

```rust
// In OpenHLFixture::setup():
let trader_a = create_trader(&mut ctx);
let trader_b = create_trader(&mut ctx);
let market = create_market(&mut ctx);

let position_a = open_position(&mut ctx, &trader_a, &market);
let position_b = open_position(&mut ctx, &trader_b, &market);

// Now solinv can swap position_a for position_b in any ix
// that operates on trader_a's position.
```

The fixture provides these via the `swap_alternates` field per ix.

### Per-binding granularity

Each ix may swap multiple accounts. For `process_close_position`:

- Swap position_a → position_b (test trader binding)
- Swap market_x → market_y (test market binding, if multiple markets exist)

solinv tries each independently, reports independent violations.

### State-change detection (same as preceding invariants)

Pre/post program-owned account hash diff. If state changes AND ix
returns success → violation. Read-only ix with no state change is
not a violation even if binding is unverified (informational
disclosure may be tested via separate future invariant).

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
    pub expected_pda_seeds: Vec<Option<Vec<Vec<u8>>>>,
    pub creates_indices: Vec<usize>,

    /// Per-account alternate-context pubkeys to test substitution.
    /// Each entry is a real, legitimate account in the fixture (correct
    /// owner, discriminator, PDA derivation) but representing a
    /// DIFFERENT context — different user, market, epoch, etc.
    ///
    /// solinv substitutes each in turn and verifies the program rejects.
    /// Empty vec = no swap testing for that account index (e.g., the
    /// caller's own wallet, which has no "alternate context").
    pub swap_alternates: Vec<Vec<Pubkey>>,

    pub data_sample: Vec<u8>,
}
```

Anchor IDL does NOT auto-fill `swap_alternates` — semantic relationships
aren't IDL-introspectable. Users declare manually based on their
fixture setup.

### Invariant function

```rust
// solinv-core/src/invariants/account_swap.rs

use crate::traits::{HasContext, HasInstructionSet};
use crucible_fuzzer::fuzz_assert;
use solana_sdk::pubkey::Pubkey;

/// Detects missing context-binding verification on accounts that should
/// be tied to a specific caller / market / epoch / etc.
///
/// For each instruction with declared `swap_alternates`, substitutes
/// each alternate pubkey for the target account and observes whether
/// the instruction succeeds with state change. Each alternate is a
/// legitimate PDA from a different context — earlier invariants
/// (owner, discriminator, pda-forge) all pass, so only the missing
/// context-binding check can cause success.
pub fn account_swap<F>(fixture: &mut F)
where
    F: HasInstructionSet + HasContext,
{
    let ixs = fixture.instructions();
    for ix in &ixs {
        for (idx, alternates) in ix.swap_alternates.iter().enumerate() {
            for &alt_pubkey in alternates {
                let ctx = fixture.ctx_mut();
                let snapshot = ctx.snapshot();
                let pre_hash = ctx.program_state_hash(&ix.program_id);

                // Sanity: alt account must exist in fixture
                if ctx.get_account(&alt_pubkey).is_none() {
                    ctx.revert_to(snapshot);
                    continue;
                }

                let mut accounts = ix.accounts.clone();
                let real_pubkey = accounts[idx].pubkey;
                if real_pubkey == alt_pubkey {
                    ctx.revert_to(snapshot);
                    continue;  // Same account; not a swap
                }
                accounts[idx].pubkey = alt_pubkey;

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
                    "account-swap detected: instruction {} (program {}) \
                     succeeded with account {} swapped from {} to {} \
                     (different context, same shape)",
                    ix.name,
                    ix.program_id,
                    idx,
                    real_pubkey,
                    alt_pubkey,
                );
            }
        }
    }
}
```

### Usage from user harness

Fixture must create multiple contexts so swap candidates exist:

```rust
use solinv_fuzz::prelude::*;
use openhl_core::ID as OPENHL_ID;

#[derive(Clone)]
struct OpenHLFixture {
    ctx: TestContext,
    market_a: Pubkey,
    market_b: Pubkey,           // different market for market swap
    trader_a: Pubkey,
    trader_b: Pubkey,           // different trader for trader swap
    position_a_in_market_a: Pubkey,
    position_b_in_market_a: Pubkey,    // for trader swap
    position_a_in_market_b: Pubkey,    // for market swap
    vault_a: Pubkey,
    vault_b: Pubkey,
    // ...
}

impl OpenHLFixture {
    pub fn setup() -> Self {
        let mut ctx = TestContext::new();
        // Create two of each context-bound entity
        let market_a = create_market(&mut ctx);
        let market_b = create_market(&mut ctx);
        let trader_a = create_trader(&mut ctx);
        let trader_b = create_trader(&mut ctx);
        let position_a_in_market_a = open_position(&mut ctx, &trader_a, &market_a);
        let position_b_in_market_a = open_position(&mut ctx, &trader_b, &market_a);
        let position_a_in_market_b = open_position(&mut ctx, &trader_a, &market_b);
        // ...
        Self { ctx, market_a, /* ... */ }
    }
}

impl HasInstructionSet for OpenHLFixture {
    fn instructions(&self) -> Vec<InstructionSpec> {
        vec![
            // process_close_position called with (trader_a, position_a_in_market_a, market_a)
            InstructionSpec {
                program_id: OPENHL_ID,
                name: "ClosePosition".into(),
                accounts: vec![
                    AccountMeta::new(self.trader_a, true),
                    AccountMeta::new(self.position_a_in_market_a, false),
                    AccountMeta::new(self.market_a, false),
                ],
                signer_indices: vec![0],
                expected_owners: vec![
                    None,
                    Some(OPENHL_ID),
                    Some(OPENHL_ID),
                ],
                expected_discriminators: vec![
                    None,
                    Some(Position::DISCRIMINATOR),
                    Some(Market::DISCRIMINATOR),
                ],
                expected_pda_seeds: vec![
                    None,
                    Some(vec![
                        b"position".to_vec(),
                        self.trader_a.to_bytes().to_vec(),
                        self.market_a_idx.to_le_bytes().to_vec(),
                    ]),
                    None,
                ],
                creates_indices: vec![],
                swap_alternates: vec![
                    vec![],                              // trader: no swap (caller)
                    vec![
                        self.position_b_in_market_a,     // wrong trader
                        self.position_a_in_market_b,     // wrong market
                    ],
                    vec![self.market_b],                 // wrong market
                ],
                data_sample: vec![/* ... */],
                optional_signer_indices: vec![],
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
    solinv_core::invariants::account_swap(f);   // ← 5th of family
}
```

## 5. False-positive risks and mitigations

| Risk | Cause | Mitigation |
|---|---|---|
| **Intentional shared context** | Some ix legitimately accept any user (e.g., crank-style permissionless ix where any caller can operate on any account) | `swap_alternates[i] = vec![]` for those ix entries. User declares the intent |
| **Read-only ix with state change** | Counter increment for telemetry; not a real "bug" but state changes | Add severity downgrade rule: if only `last_accessed_slot` / counter fields changed, classify as Medium not Critical |
| **Permissionless settlement** | Ix designed for anyone to settle anyone's position (e.g., liquidation) | True positive in spirit, but expected behavior. User uses `swap_alternates[i] = vec![]` to suppress |
| **Multi-tenant program with shared resources** | Vault is intentionally shared across users; swap to "another user's vault" succeeds because there's only one vault per market | False positive: vault_a == vault_b (same vault). `swap_alternates` check excludes same-pubkey case (already in implementation) |
| **Lookup-based binding** | Program reads a separate lookup table to determine user, not the position's own `trader` field | True positive if lookup is also missing; if lookup correctly enforces binding, swap won't succeed (program reads from real lookup → real binding) |
| **CPI-mediated binding** | Binding enforced via CPI to another program (e.g., calling SPL Token to verify ownership) | True positive if SPL Token check is also bypassed; usually false positive (SPL Token does enforce) |
| **State change happens after binding check** | Program does some preliminary work (e.g., logs) then fails on binding check | `state_changed = true` triggers violation even if final state is unchanged. Workaround: hash only program-owned account data, not lamports/logs |

### Distinguishing account-swap from other invariants in the family

Five invariants total, fully orthogonal:

| Invariant | Substitute used | Catches |
|---|---|---|
| signer-skip | Same account, is_signer=false | Missing is_signer check |
| owner-skip | Same data, wrong owner | Missing owner check |
| discriminator-skip | Same data, corrupted disc | Missing discriminator check |
| pda-forge | Random pubkey, copied data | Missing PDA derivation check |
| **account-swap** | Real alternate PDA, alternate context | Missing context-binding check |

Each catches a distinct missing assertion. A program missing all five
reports five independent violations. The quintuple-bug fixture is the
**full contract** for the account-validation invariant family.

### Why account-swap can give false positives more than the others

Real-world programs sometimes WANT shared context (permissionless
ixs, crank-style settlement, multi-tenant shared resources). These
patterns look like account-swap "succeeded" but are intentional. solinv
errs on the side of reporting; user marks intent via empty
`swap_alternates`.

## 6. Severity classification

**Critical** baseline. Reasoning:

- Direct fund-theft path in lending protocols (close another user's
  position, drain their collateral)
- Direct vault-drainage path when vault is keyed per user
- Privilege escalation when admin/config is keyed per resource
- Exploit complexity: low. Attacker only needs to know another user's
  account pubkeys (often public via on-chain explorers)
- Mainnet precedent in lending family is well-documented

Bug bounty reference (Critical):
- Drift: $250K-$500K
- Marginfi: $150K-$250K
- Kamino: $250K-$1M
- Jupiter: $250K-$500K

Severity adjustment:
- State change is non-financial (e.g., closing inactive admin record)
  → **High**
- State change only affects metadata / telemetry → **Medium**
- ix is genuinely permissionless by design (user-declared) → not
  reported

## 7. Test fixture in openhl-solana

Plant account-swap bug in `process_close_position` — the missing
binding check on `position.trader == caller`. With this bug, trader B
can pass trader A's position PDA and close trader A's position.

```rust
// programs/openhl-core/src/lib.rs

// BEFORE (correct):
fn process_close_position<'a>(
    program_id: &Pubkey,
    accounts: &'a [AccountInfo<'a>],
    data: &[u8],
) -> ProgramResult {
    let trader_ai = &accounts[0];
    let position_ai = &accounts[1];
    let market_ai = &accounts[2];

    // ... signer / owner / discriminator / PDA checks ...

    let position = Position::try_from_slice(&position_ai.data.borrow())?;

    // CONTEXT BINDING checks:
    if &position.trader != trader_ai.key {
        msg!("close_position: position.trader mismatch");
        return Err(ProgramError::IllegalOwner);
    }
    if &position.market != market_ai.key {
        msg!("close_position: position.market mismatch");
        return Err(ProgramError::InvalidArgument);
    }

    // ... close position ...
}

// PLANTED BUG (for solinv validation):
fn process_close_position<'a>(
    program_id: &Pubkey,
    accounts: &'a [AccountInfo<'a>],
    data: &[u8],
) -> ProgramResult {
    let trader_ai = &accounts[0];
    let position_ai = &accounts[1];
    let market_ai = &accounts[2];

    // ... signer / owner / discriminator / PDA checks all in place ...

    let position = Position::try_from_slice(&position_ai.data.borrow())?;

    // BUG: context-binding checks removed
    // - missing: assert position.trader == *trader_ai.key
    // - missing: assert position.market == *market_ai.key

    // ... closes position for ANY trader's position, regardless of caller ...
}
```

Expected solinv output:

```
[VIOLATION] account-swap detected
Instruction: ClosePosition
Program: openhl-core (8KxK...)
Account: 1 (position)
Real pubkey: pos-A-market-A (3yQ7...)
Swapped to: pos-B-market-A (9hN2...) — different trader, same market
Tx outcome: Success (state changed: lamports moved 1000000 → 0)

Reproduction: see findings/2026-05-24-acct-swap-closepos.json
```

This is the **fifth and final acceptance test** for the
account-validation invariant family.

### Quintuple-bug fixture (full Critical-tier acceptance test)

Plant all five bugs simultaneously in `process_close_position`:

```rust
fn process_close_position<'a>(...) -> ProgramResult {
    let trader_ai = &accounts[0];
    // BUG 1 (signer-skip): is_signer check removed
    let position_ai = &accounts[1];
    // BUG 2 (owner-skip): owner check removed
    // BUG 3 (discriminator-skip): discriminator check removed
    // BUG 4 (pda-forge): PDA derivation check removed
    let position = Position::try_from_slice(&position_ai.data.borrow())?;
    // BUG 5 (account-swap): position.trader / position.market binding removed
    // ... process with arbitrary attacker-controlled state ...
}
```

solinv must report **five independent violations**. This validates
that all five Critical invariants:
- Run in isolation (snapshot/revert preserves cleanliness)
- Detect orthogonal bug classes (no false sharing)
- Compose cleanly (running all 5 in sequence produces 5 distinct reports)

This is the **end-state acceptance test for Critical tier**. Passing
it means Phase 1 Month 1's Days 16-25 implementation goal is met:
all 5 Critical invariants production-ready against openhl-solana.

## 8. References

### Audit firm guidance
- Trail of Bits Anchor security guidelines (context-binding patterns)
  https://github.com/trailofbits/publications
- Neodyme: "Common Pitfalls in Solana Programs" — user binding section
  https://neodyme.io/blog/common-pitfalls/
- coral-xyz/sealevel-attacks — "swap accounts" CTF challenge
  https://github.com/coral-xyz/sealevel-attacks
- Sec3 / OtterSec public audit reports — recurring finding category
  https://www.sec3.dev/ , https://osec.io/

### Solana / Anchor documentation
- Anchor `has_one` constraint (auto-binding verification)
  https://www.anchor-lang.com/docs/space-and-constraints
- Anchor `constraint` clause for custom binding checks

### Mainnet incidents (context-binding family)
- Various Solana lending protocol audit findings (Solend, Mango,
  Marinade ecosystem audits 2022-2024) — recurring patterns
- Crema Finance post-mortem (Jul 2022, $8.7M) — broader family

### Internal
- `docs/invariants/signer-skip.md` — caller-identity check, family member 1
- `docs/invariants/owner-skip.md` — owner-program check, family member 2
- `docs/invariants/discriminator-skip.md` — type check, family member 3
- `docs/invariants/pda-forge.md` — PDA-derivation check, family member 4
- `docs/research-crucible-integration.md` — TestContext API details
- `docs/research-summary.md` — Phase 1 implementation plan
