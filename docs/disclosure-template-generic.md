# Disclosure template — generic / direct-to-protocol

For protocols that run their own bounty programs (Drift, Marginfi,
Kamino, Jupiter, Phoenix, Mango, Solana Foundation, etc.) and accept
submissions via email / Discord / GitHub security advisory rather than
a managed platform. Use this as a plain markdown body to paste into
the protocol's submission form or attach as a `.md`.

Generic submissions don't have a forced taxonomy. Pick severity using
the protocol's stated criteria if published; otherwise default to the
mapping below. State the severity tier you're claiming up front so the
triage team can route the report.

| Invariant | Default severity | Reasoning |
|---|---|---|
| signer-skip | Critical | Authorization bypass — direct fund loss possible |
| owner-skip | Critical | Account-type confusion → arbitrary state mutation |
| discriminator-skip | Critical / High | Critical when struct overlap → priv-esc; High otherwise |
| pda-forge | Critical | Authority forgery |
| account-swap | High / Critical | High in DEX; Critical when canonical state is swapped |

Default severity assumes mainnet, no admin gating, no economic
preconditions. Adjust down where the attack requires a precondition the
protocol controls.

---

## Submission template

```markdown
# <Protocol> security disclosure: <invariant> in <handler>

**Severity**: <Critical/High/Medium> — <one sentence rationale>
**Reporter**: <handle / contact email>
**Date discovered**: <YYYY-MM-DD>
**Date reported**: <YYYY-MM-DD>
**Affected program**: `<program_id>` on Solana mainnet
**Affected version / commit**: `<git sha or program upgrade authority slot>`
**Tooling**: solinv invariant fuzzer (private), Crucible, LiteSVM

## Summary

<2-3 sentences. What's broken, what an attacker can do, what the user
impact is. No background, no story — judges skim this first.>

## Vulnerability

### Bug class

This is an `<invariant-name>` vulnerability: <one-line definition of
the class, e.g. "the program reads an account's data without verifying
the account is owned by the expected program">. Reference:
https://github.com/coral-xyz/sealevel-attacks (or OtterSec's Anchor
SECURITY.md if linkable).

### Location

`<file>:<line range>` — permalink:
https://github.com/<org>/<repo>/blob/<commit>/<path>#L<start>-L<end>

```rust
<3-10 lines quoting the vulnerable code, with the missing check
highlighted via a comment>
```

The corresponding check exists at `<other location>` (or "is missing
entirely from this program") — quote that for contrast if relevant.

## Impact

### Direct impact

- **Funds at risk**: <which accounts / TVL component>
- **Magnitude**: <amount, ideally with current $ figure>
- **State corruption**: <which fields, persistence>
- **Authorization bypassed**: <which roles>

### Composability impact

<If other protocols read from / interact with this state, list them.
Otherwise skip this section.>

### Pre-conditions

- Signer requirement: <none / fee payer only / specific keypair>
- Admin / privileged role: <none / specific role>
- Market state: <none / specific liquidity / specific pool config>
- Capital required: <SOL for fees only / capital lockup amount>

## Reproduction

### Environment

- Solana CLI: `<version>`
- LiteSVM / Crucible: `<version>`
- Test cluster: localnet fork from mainnet slot `<slot>`

### Steps

1. Clone repro: `git clone <repo>` (or paste inline below)
2. Build: `cargo build --release`
3. Run: `<command>`
4. Observe: `<expected violation message / state divergence>`

### Minimal action sequence

<Numbered list of on-chain instructions. Each step should be one ix
with explicit account list and arg values. This is the shrinker
output — keep it minimal.>

1. `<ix_name>(<args>)` — accounts: [`<a>`, `<b>`, …]
2. …

### Reproduction harness

<Inline the Rust file, or attach as a separate gist / file.>

```rust
use litesvm::LiteSVM;
use solana_sdk::{instruction::Instruction, pubkey::Pubkey, …};

fn main() {
    let mut svm = LiteSVM::new();
    svm.add_program_from_file(<program_id>, "<path-to-.so>").unwrap();

    // <fixture setup: keypairs, fund payer, initial state ix>

    // Attack
    let fake = <construct attacker account>;
    let ix = Instruction { /* … */ };
    let result = svm.send_transaction(<tx>);

    // Assert exploit succeeded (state mutated against invariant)
    assert!(result.is_ok(), "expected attack to succeed");
    let post = svm.get_account(&<target>).unwrap();
    assert_eq!(<assertion that proves exploit>, "state changed");
    println!("exploit succeeded: <impact summary>");
}
```

## Suggested fix

<Smallest correct diff. Cite the Anchor / native Solana idiom if
applicable.>

```diff
- pub <account>: AccountInfo<'info>,
+ pub <account>: Account<'info, <ExpectedType>>,
```

or

```diff
  pub fn handler(ctx: Context<…>) -> Result<()> {
+     require_keys_eq!(*ctx.accounts.<account>.owner, *ctx.program_id,
+         ErrorCode::WrongOwner);
      <existing body>
```

<2-3 sentences explaining why this fix is correct and complete.>

## Additional notes

- <Out-of-scope variants you noticed but didn't verify>
- <Suggested test additions to catch regressions>
- <Coordination preferences: embargo length, public disclosure timing>

## Contact

- <handle / email>
- PGP: <fingerprint or "available on request">
- Available for fix review and re-test: yes / no

---

By submitting this report I agree to <protocol's> responsible
disclosure policy as published at <link>.
```

---

## Worked example — escrow-demo owner-skip

(See `docs/implementation-day13-owner-skip-unmask-CRITICAL-COMPLETE.md`
for the original detection log. Below shows the template filled in.)

```markdown
# Escrow-demo security disclosure: owner-skip in unsafe_set_amount_from_source

**Severity**: Critical — unprivileged attacker can corrupt protocol-tracked balance state and drain vaults.
**Reporter**: psyto <saito.hiroyuki@gmail.com>
**Date discovered**: 2026-05-25
**Date reported**: <not submitted — example only>
**Affected program**: `Esrcw1111…` (escrow-demo planted-bug program)
**Affected version / commit**: `<commit of examples/escrow-demo at Day 13>`
**Tooling**: solinv invariant fuzzer (private), Crucible, LiteSVM

## Summary

The `unsafe_set_amount_from_source` handler in the escrow program reads
`source.data` without verifying `source.owner == &program_id`. An
attacker passes a system-owned account containing chosen bytes; the
program writes the attacker's `synthetic_amount` to `target.amount`.
This corrupts protocol-tracked balance state and enables unauthorized
withdrawals up to the vault's full balance.

## Vulnerability

### Bug class

This is an `owner-skip` vulnerability: the program reads an account's
data without verifying the account is owned by the expected program.
Reference: https://github.com/coral-xyz/sealevel-attacks (account-type
confusion).

### Location

`programs/escrow/src/lib.rs:147-159` (handler) and `:312-321` (account
context).

```rust
// :312-321
#[derive(Accounts)]
pub struct UnsafeSetAmountFromSource<'info> {
    pub source: AccountInfo<'info>,           // ← no owner check
    #[account(mut)]
    pub target: Account<'info, VaultState>,
}

// :147-159
pub fn unsafe_set_amount_from_source(ctx: Context<UnsafeSetAmountFromSource>) -> Result<()> {
    let data = ctx.accounts.source.data.borrow();
    let synthetic_amount = u64::from_le_bytes(data[0..8].try_into()?);
    ctx.accounts.target.amount = synthetic_amount;  // ← writes attacker-chosen value
    Ok(())
}
```

## Impact

### Direct impact

- **Funds at risk**: full vault balance per call (no rate limit)
- **Magnitude**: TVL-dependent; atomically drainable
- **State corruption**: `target.amount` set to attacker-chosen u64
- **Authorization bypassed**: none required — no signer, no admin

### Pre-conditions

- Signer requirement: fee payer only
- Admin / privileged role: none
- Market state: any non-empty vault
- Capital required: ~890 lamports (rent-exempt 32-byte system account)

## Reproduction

### Environment

- Solana CLI: 3.0
- LiteSVM: 0.9.0
- Crucible: v0.1.0

### Steps

```
cd examples/escrow-demo
crucible run escrow invariant_owner_skip_only --release
```

Expected output:
```
[owner-skip:Esrcw1111…] ix unsafe_set_amount_from_source succeeded
with account 0 owned by 11111111111111111111111111111111
instead of expected Esrcw1111…;
real pubkey 2RvPfFKU… → fake pubkey 13JpWEc…
```

Detection rate: 18,996 / 19,000 (~100%).

### Minimal action sequence (3 ix)

1. `init_vault(authority, mint_a, mint_b)` — accounts: [vault, vault_a_pda, vault_b_pda, authority, …]
2. `deposit(amount=1_000_000)` — establishes target.amount baseline
3. `unsafe_set_amount_from_source` — accounts: [fake_source, vault_target]; result: vault_target.amount overwritten

## Suggested fix

```diff
- pub source: AccountInfo<'info>,
+ pub source: Account<'info, VaultState>,
```

Anchor's typed `Account<'info, T>` enforces both the owner check
(`account.owner == &program_id`) and the discriminator check
(`account.data[0..8] == VaultState::DISCRIMINATOR`). This single change
closes the vulnerability completely.

Alternative (native Solana style):
```diff
  pub fn unsafe_set_amount_from_source(...) -> Result<()> {
+     require_keys_eq!(*ctx.accounts.source.owner, *ctx.program_id,
+         ErrorCode::WrongOwner);
      let data = ctx.accounts.source.data.borrow();
```

## Contact

- psyto <saito.hiroyuki@gmail.com>
- Available for fix review and re-test: yes
```
