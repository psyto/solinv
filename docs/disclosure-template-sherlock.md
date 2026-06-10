# Disclosure template — Sherlock

For Sherlock Watson submissions
(https://docs.sherlock.xyz/audits/watsons/judging). Sherlock's contest
format expects a specific markdown shape with required fields. This
template fills it in for Solana / solinv-style invariant findings.

Sherlock severity uses a 2-tier scale (**High** / **Medium**) in
contests; some private engagements add Low/Informational. The full
criteria are at
https://docs.sherlock.xyz/audits/judging/judging — read once before
submitting. Quick mapping for solinv invariants:

| Invariant | Sherlock tier | Notes |
|---|---|---|
| signer-skip | High | "Funds loss > $1k" criterion met by any drain-on-call ix |
| owner-skip | High | Same — account-type confusion almost always satisfies the funds-loss criterion |
| discriminator-skip | High (Medium if pure DoS) | High when it enables privilege escalation; Medium for unique-state corruption with no profit path |
| pda-forge | High | Authority forgery → funds loss is canonical Sherlock-High territory |
| account-swap | High / Medium | High when canonical vault/treasury is swapped; Medium for DEX user-controlled output (often dismissed as design) |

Sherlock judges aggressively dismiss findings that:
- Require admin/trusted-role compromise as precondition
- Are user-error or external-protocol issues
- Don't have a complete on-chain attack path

Frame impact in terms of an unprivileged external attacker.

---

## Submission template

```markdown
<watson handle> — <one-line title>

### Summary
One paragraph. The missing check (cite the invariant by name), the
attack vector, the bottom-line impact.

### Root Cause
File + permalink to the exact line(s) where the check is missing.
Quote the relevant 3-10 lines. Sherlock judges click these — broken
permalinks lose points.

In `<path>:<line>` the handler reads `<field>` from `<account>` without
verifying `<account>.owner == &program_id` (or `<account>.data[0..8]
== expected_discriminator`, etc.). The required check exists in
`<other handler that does it correctly>` but was omitted here.

### Internal pre-conditions
Conditions that must hold inside the protocol for the attack to work.
- Protocol must be in `<state>`
- `<account>` must be `<populated/empty/in some state>`
- No external assumptions here — keep external setup in "Attack Path"

### External pre-conditions
What the attacker needs from outside:
- An account owned by `<program>` with `<X bytes>` of attacker-chosen
  data — trivially fundable for ~`<lamports>`
- No oracle / no signer / no admin

If "none" — say so explicitly. Judges reward unconditional findings.

### Attack Path
Numbered list. Each step is one on-chain action. End with the bottom
line (state corrupted / funds drained / user locked).

1. Attacker creates `<fake account>` via `system_program::create_account`
   with `<bytes>` matching `<expected struct layout>`. Cost:
   `<lamports>`.
2. Attacker calls `<vulnerable ix>` passing `<fake account>` as
   `<account name>` and `<legitimate target>` as `<other name>`.
3. Program reads `<field>` from `<fake account>` without owner check,
   computes `<derived value>`, and writes to `<target.field>`.
4. Attacker calls `<follow-up ix>` which trusts `target.field` and
   transfers `<amount>` to attacker.

Loss: `<amount, denominated in protocol asset>` per call. No rate
limit / atomically drainable.

### Impact
Bottom-line one-liner: "Any unprivileged attacker can drain
`<vault/pool/treasury>` up to its full balance in a single tx" /
"Permanent freezing of `<user funds>` via `<state>` corruption".

Quantify if a TVL number is publicly visible. Sherlock's funds-loss
criterion is satisfied at >$1k; >$10k is uncontested High.

### PoC
Minimal runnable repro. Sherlock accepts forge tests for EVM and
LiteSVM / Crucible repros for Solana. Inline the harness:

```rust
// litesvm + raw ix construction; no Anchor IDL needed
use litesvm::LiteSVM;
use solana_sdk::{instruction::Instruction, …};

#[test]
fn poc_owner_skip() {
    let mut svm = LiteSVM::new();
    // … fixture setup …
    let fake = make_fake_account(&mut svm, /* bytes */);
    let ix = Instruction { /* … */ };
    let res = svm.send_transaction(/* tx using fake */);
    assert!(res.is_ok(), "attack should succeed — bug");
    assert_eq!(svm.get_account(&target).unwrap().data[…], attacker_chosen);
}
```

If using solinv: cite the `crucible run` invocation and paste the
shrunk action sequence and the violation message.

### Mitigation
Smallest correct fix. Cite the construct (Anchor `Account<'info, T>`,
`require_keys_eq!`, manual `if account.owner != …`, etc.) and show
the diff:

```diff
- pub source: AccountInfo<'info>,
+ pub source: Account<'info, VaultState>,
```

or

```diff
  pub fn handler(ctx: Context<…>) -> Result<()> {
+     require_keys_eq!(*ctx.accounts.source.owner, *ctx.program_id,
+         ErrorCode::WrongOwner);
      let data = ctx.accounts.source.data.borrow();
```
```

---

## Worked example — escrow-demo owner-skip

```markdown
psyto — owner-skip in unsafe_set_amount_from_source enables arbitrary target.amount overwrite

### Summary
The escrow program's `unsafe_set_amount_from_source` handler reads
`source.data` without verifying `source.owner == &program_id`. An
attacker passes a system-owned account with chosen bytes; the program
parses those bytes and writes the attacker's `synthetic_amount` to
`target.amount`, corrupting protocol-tracked balance and enabling
unauthorized withdrawals up to the vault's balance.

### Root Cause
`programs/escrow/src/lib.rs:147-159` (handler) and `:312-321`
(account context). The context declares `source: AccountInfo<'info>`
instead of `Account<'info, VaultState>`, bypassing Anchor's owner +
discriminator checks. The handler then trusts `source.data`:

```rust
let data = ctx.accounts.source.data.borrow();
let synthetic_amount = u64::from_le_bytes(data[0..8].try_into()?);
ctx.accounts.target.amount = synthetic_amount;
```

### Internal pre-conditions
- An initialized vault (`init_vault`) with at least one deposit on
  `target` (any non-zero `target.amount`).
- No admin / no signer beyond fee payer.

### External pre-conditions
- An attacker-funded account (~890 lamports rent-exempt for 32 bytes)
  with the first 8 bytes set to the attacker's chosen u64.

### Attack Path
1. Attacker calls `system_program::create_account` for `fake_source`,
   32 bytes, owned by `system_program`. Cost: 890 lamports.
2. Attacker writes 32 LE bytes encoding `synthetic_amount =
   u64::MAX` into `fake_source.data` (system-owned accounts allow
   the attacker to populate via prior tx).
3. Attacker calls `unsafe_set_amount_from_source` with
   `source = fake_source`, `target = vault_target`. Program reads
   attacker bytes, writes `u64::MAX` to `vault_target.amount`.
4. Attacker calls `withdraw(amount = vault.balance)`. Balance check
   passes (since `target.amount` was overwritten). Vault drained.

Loss: full vault balance per call. Atomically drainable.

### Impact
Any unprivileged attacker can drain the vault up to its full balance
in a single tx by overwriting protocol-tracked balance state. Funds
loss > $1k threshold is met for any non-empty vault.

### PoC
```
cd examples/escrow-demo
crucible run escrow invariant_owner_skip_only --release
```

solinv output:
```
[owner-skip:Esrcw1111…] ix unsafe_set_amount_from_source succeeded
with account 0 owned by 11111111111111111111111111111111
instead of expected Esrcw1111…;
real pubkey 2RvPfFKU… → fake pubkey 13JpWEc…
```

Detection: 18,996 / 19,000 executions (~100%). Shrunk action sequence
above (3 ix).

### Mitigation
```diff
- pub source: AccountInfo<'info>,
+ pub source: Account<'info, VaultState>,
```

Anchor's typed account enforces both owner and discriminator. If
keeping `AccountInfo` is required for some reason, add
`require_keys_eq!(*ctx.accounts.source.owner, *ctx.program_id,
ErrorCode::WrongOwner)` at the top of the handler.
```
