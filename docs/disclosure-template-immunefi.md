# Disclosure template — Immunefi

For Solana bug bounty submissions on [Immunefi](https://immunefi.com).
Fields below mirror Immunefi's submission form (as of 2026-05); the
boilerplate at the bottom is the worked example from solinv's Day 13
owner-skip detection on `examples/escrow-demo`.

Severity classification on Immunefi uses their **Smart Contract** scale
unless the project specifies otherwise — see
https://immunefi.com/immunefi-vulnerability-severity-classification-system-v2-3/.
Solinv invariants map to severity as follows; reference these in the
"Impact" section.

| Invariant | Default severity | Rationale |
|---|---|---|
| signer-skip | Critical | Direct unauthorized state mutation — bypass of authorization |
| owner-skip | Critical | Account-type confusion → arbitrary read of attacker-crafted data → privileged action |
| discriminator-skip | Critical / High | Critical when struct overlap enables privilege escalation; High otherwise |
| pda-forge | Critical | Authority forgery — bypass of program-derived authorization |
| account-swap | High / Critical | High in DEX/swap contexts; Critical when canonical state is swapped (vault, treasury, mint) |

Adjust **down** one tier if the attack requires a privileged precondition
the protocol already controls (e.g., admin-only ix). Adjust **up** if the
attack scales (atomically drainable, no rate limit).

---

## Submission form fields

### Title
`[Critical] <Protocol> — <invariant>: <one-line impact>`

Example: `[Critical] Escrow — owner-skip in unsafe_set_amount_from_source enables target.amount overwrite from attacker-owned source account`

### Project / Asset
- Project: `<bounty program name>`
- Asset in scope: `<program_id>` on `<chain>` (mainnet)
- Asset commit/version: `<git sha or program version>`

### Vulnerability type
`Smart Contract — <map invariant to Immunefi's taxonomy>`. Owner-skip
typically maps to "Theft of unclaimed yield" / "Direct theft of any user
funds" depending on the downstream action; signer-skip to "Permanent
freezing of funds" or "Direct theft" depending on the gated ix.

### Severity
Per the table above. Always justify in one sentence referencing
Immunefi's severity criteria (impact + likelihood).

### Bug description
One paragraph: the bug class (link the OtterSec Anchor SECURITY.md entry
if available), the missing check, and the specific line/function. Cite
the invariant by name — `owner-skip`, `discriminator-skip`, etc. —
and define it once if the project's security team may not be familiar
with the term. Avoid jargon dump.

### Impact
Concrete consequences for users / protocol:
- Funds lost: how much, from which account / role
- State corrupted: which fields, persisting how long
- Authorization bypassed: which roles
- Composability impact: whether other protocols are affected downstream

Quantify when possible. "Anyone with a system-owned account can set
arbitrary `target.amount` values, breaking all downstream balance
arithmetic and enabling unauthorized withdrawals up to the protocol's
TVL" is better than "loss of funds".

### Risk likelihood
- Preconditions: signer? admin? specific market state?
- Cost to attacker: gas, capital lockup, MEV positioning
- Detection probability: would a monitoring system notice in time to
  pause / circuit-break?

### Proof of concept
Provide all three layers:

1. **Annotated source location** — file + line range of the missing
   check in the vulnerable program. Use Immunefi's "code reference"
   field with a GitHub permalink.
2. **Reproduction harness** — gist or attachment of a minimal Rust
   binary that uses LiteSVM / Crucible to reproduce. solinv's
   `crucible run <fixture> <variant> --release` invocation goes here
   with the fixture source.
3. **Action sequence** — the shrunk N-step ix sequence from Crucible's
   shrinker, formatted as a numbered list of `Instruction { … }` calls.

The PoC must run end-to-end without manual edits. Bake fixture pubkeys
and slot pinning into the harness.

### Suggested fix
Pattern-match by invariant:
- signer-skip: `require!(ctx.accounts.signer.is_signer, ErrorCode::MissingSigner)` or Anchor's `Signer<'info>` constraint
- owner-skip: `require_keys_eq!(account.owner, &expected_program, ErrorCode::WrongOwner)` or Anchor's typed `Account<'info, T>`
- discriminator-skip: deserialize via Anchor's typed account or check the 8-byte sighash explicitly
- pda-forge: re-derive the PDA from canonical seeds and compare via `require_keys_eq!`; never trust attacker-supplied pubkeys for PDAs
- account-swap: equality assertion between the in-account pubkey field and the passed `AccountMeta`

Cite the upstream Anchor / Solana program library construct that
handles the check automatically when there is one.

### Disclosure timeline
- Discovered: `<date>`
- Reported: `<date you submit>`
- Embargo expectation: per program policy (usually 90 days post-fix
  or until paid out, whichever is later)

---

## Worked example — escrow-demo owner-skip (planted bug)

> This example would not actually be submitted (it's a planted bug in
> solinv's own acceptance test program). Use it as a structural model.

**Title**: `[Critical] Escrow — owner-skip in unsafe_set_amount_from_source allows arbitrary target.amount overwrite via attacker-owned source account`

**Severity**: Critical. Direct unauthorized mutation of protocol-tracked
balance with no privileged precondition; any caller with 0.001 SOL
for fees can execute.

**Bug description**: The `unsafe_set_amount_from_source` instruction in
the escrow program reads `source.data` to derive `synthetic_amount`
and writes that value to `target.amount`, but does not check that
`source.owner == &program_id`. This is an `owner-skip` vulnerability:
the program treats any account with the right byte layout as a
legitimate program-owned account.

**Impact**: An attacker can pass any account they control (owned by
`system_program` is easiest, since the bytes are attacker-controlled)
with arbitrary bytes laid out as the expected struct. The program
parses these bytes and writes the attacker's chosen `synthetic_amount`
to `target.amount`. Downstream balance arithmetic on `target` is then
arbitrary, enabling unauthorized withdrawals up to the vault's balance.

**Risk likelihood**: High. No signer, no admin, no specific market
state required. Cost ≈ network fee. Detection probability is low —
the ix appears as a normal program call in tx logs.

**PoC**:
1. Vulnerable line: `programs/escrow/src/lib.rs:147-159` (handler) and
   `programs/escrow/src/lib.rs:312-321` (account context, uses
   `AccountInfo<'info>` instead of `Account<'info, _>` for `source`).
2. Reproduction:
   ```
   cd examples/escrow-demo
   crucible run escrow invariant_owner_skip_only --release
   ```
   Expected output (truncated):
   ```
   [owner-skip:Esrcw1111…] ix unsafe_set_amount_from_source succeeded
   with account 0 owned by 11111111111111111111111111111111
   instead of expected Esrcw1111…;
   real pubkey 2RvPfFKU… → fake pubkey 13JpWEc…
   ```
   Detection rate: 18,996 violations / 19,000 executions (~100%).
3. Minimal action sequence (3 ix):
   1. `init_vault(authority, mint_a, mint_b)`
   2. `deposit(amount=1_000_000)` — establishes target.amount baseline
   3. `unsafe_set_amount_from_source` with `source` = attacker-owned
      account holding 32 LE bytes for `synthetic_amount =
      u64::MAX` → `target.amount` overwritten

**Suggested fix**: Replace `source: AccountInfo<'info>` with
`source: Account<'info, VaultState>` in the `UnsafeSetAmountFromSource`
account context. Anchor's typed account constraint enforces both the
owner check and the discriminator check. Alternatively (native style):
```rust
require_keys_eq!(*ctx.accounts.source.owner, *ctx.program_id,
    ErrorCode::WrongOwner);
```
at the top of the handler.
