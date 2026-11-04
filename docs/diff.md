# `solinv diff`: the account checks a change removes

An audited Anchor program is mostly clean. What breaks it later is a pull
request that drops a check: an `Account<'info, Vault>` loosened to
`UncheckedAccount` to get a test passing, a `Signer` turned into a plain
account, a `has_one` or `seeds` deleted in a refactor. Anchor enforces
the declaration, so when the declaration goes the check goes too, and
nothing else fails. `solinv diff` compares two versions of a program's
source, slot by slot, and names every check that is gone.

```bash
solinv diff --base-src <before> --head-src <after>            # text; exit 1 if a check is removed
solinv diff --base-src <before> --head-src <after> --format github   # Actions annotations
```

It reads source only — no build, no IDL, no Solana toolchain — so it runs
on any CI runner. `action.yml` wraps it for pull requests; see the
[README](../README.md#use-it-in-your-own-project). Live example:
[a demo pull request](https://github.com/psyto/solinv/pull/2) that makes
the change in [`examples/escrow-demo/diff/drop-a-check`](../examples/escrow-demo/diff/drop-a-check/lib.rs)
and fails with both findings on the line.

## What it reports

A slot is one field of a `#[derive(Accounts)]` struct, named by the
instruction whose handler takes that struct as its `Context<..>`
(composites by dotted path).

| Change | Reported as |
|---|---|
| typed account (`Account`, `AccountLoader`, `InterfaceAccount`, …) → `UncheckedAccount` / `AccountInfo` | removed: owner and type no longer checked |
| `Signer` or `#[account(signer)]` → neither, or made `Option<Signer>` | removed: no longer required to sign |
| `seeds`, `address` or `owner` constraint deleted | removed |
| `has_one = x` deleted | removed — or *moved* (warning) if another slot of the instruction now has it |
| `constraint = <expr>` deleted or replaced | removed, naming the expression — or *moved* (warning) |
| a check at the top level of the handler body deleted or changed: `require!`, `require_eq!` / `_neq` / `_gt` / `_gte`, `require_keys_eq!` / `_neq`, or `if <cond> { return Err(..) }` with no `else` | removed, naming it (`if !authority.is_signer` removed from the handler) — on the first account it names, or the instruction when it names only locals |
| …and an account it names now declares a check of the same kind instead — a signer check a `Signer`; a key check a `has_one`, `constraint`, `seeds`, `address` or `Program`/`Sysvar` type; an owner or discriminator check a typed account; a bump check `seeds` | warning: moved to a declaration — confirm it covers the same thing. Any other check (an amount, a slot) has no declared form and stays removed |
| vipers `assert_keys_eq!` / `assert_keys_neq!` deleted from an `impl Validate` the handler's `#[access_control(ctx.accounts.validate())]` runs (composites' `self.x.validate()` followed) | removed, naming the check — or *moved* (warning) |
| `close = <target>` deleted | removed: no longer emptied and handed back to the system program |
| `close` target changed | warning: that is where its lamports go |
| typed → a different typed type (`Account<Config>` → `Signer`) | warning: type changed |
| a slot wrapped in `Option<…>` | warning: now optional |
| a slot with checks gone from an instruction that remains | warning: renamed or removed, listing its checks |
| an instruction renamed — gone, with a new instruction sharing at least half of the two's slot names (programs, sysvars, `authority` and `payer` not counted), best match first, ties left unpaired | warning naming the new name; the two are compared slot by slot, so a check the rename dropped is still removed |
| an instruction gone with nothing that matches, and checks | warning: not compared, with how many checks it had |
| a new instruction with no signer that writes an account | warning: permissionless by design, or a missing authority check? |

Removals exit 1 (unless `--no-fail`); warnings do not. Annotations sit on
the line that declares the slot in the new version.

Constraints are compared by expression, with whitespace collapsed and the
`@ Error` dropped, so reformatting or renaming an error is not a change,
and swapping one check for another is. String literals in an expression
are kept, so `role == "admin"` → `role == "attacker"` is a change.
vipers key checks are compared with their arguments sorted and written
from the instruction's root (`assert_keys_eq!(common.bank.crate_mint,
common.crate_mint)`), so swapping the arguments is not a change; removing
the `#[access_control]` that runs them removes every one.

## Checked on

- The demo change above: both findings, at the line, exit 1 — locally and
  on the demo pull request.
- Jito tip-payment, tip-distribution and Raydium cp-swap compared with
  themselves: nothing reported.
- escrow-clean against the planted-bug escrow: three warnings, on exactly
  the three planted instructions that write state with no signer.
- [sealevel-attacks](sealevel-attacks.md): every fixed program turned
  into its insecure version — 11 of 11 classes where the check was
  declared, 9 of 11 where it was written in the handler; 0 removed
  checks in the 22 pairs the other way round, nor between the two fixed
  versions (`secure` → `recommended`: the handler checks become
  declarations, reported as moved).
- Cashio's real source, fixed (`7df6581`) against the version before the
  fix: `assert_keys_eq!(common.bank.crate_mint, common.crate_mint)` removed
  from `validate()`, in `print_cash` and `burn_cash` — the check its fix
  added. Cashio's code never had that check, so no pull request removed
  it; this shows that one written and later deleted would be named.

## Limits

It reads text, not types, line by line as rustfmt lays fields out:

- A check moved from an attribute into the handler body
  (`require_keys_eq!`) reads as removed. That is deliberate: a reviewer
  should look. Of the handler body only the top level is read: a check
  inside a loop, a `match`, an `if … else` chain, or a function the
  handler calls under another name (a helper `auth(&ctx)`) is not; a
  function of the same name taking the same `Context` (lib.rs delegating
  to `instructions::swap(ctx, …)`) is read as part of the instruction. A
  top-level `let x = &ctx.accounts.y;` is followed; a local built from an
  account's data (`let token = unpack(..)`) is not, so a check on it
  counts for the instruction, not the account. `if !x.is_signer {
  return Err }` and `require!(x.is_signer)` are different texts, so
  rewriting one as the other reads as a removal. The other code read is vipers' `assert_keys_eq!` /
  `assert_keys_neq!` in an `impl Validate` run by `#[access_control]`. A check inside an `if` counts as always run; a
  second `impl Validate` for the same struct anywhere in the source (a
  test module's included) leaves both unread. Rarer spellings —
  `self.x.to_account_info().key`, `<X as Validate>::validate(&self.x)` —
  are not normalised, so switching to one reads as a removal.
- A field typed by a type alias, a struct name defined twice, or a field
  type split over lines is not placed, so changes to it are not compared.
- A renamed instruction is paired by slot names alone: a rename that
  also renames most slots reads as one instruction gone (a warning) and
  one new, and an unrelated new instruction that happens to reuse half
  of a removed one's names is compared with it.
- Checks the IDL carries but the source does not spell (none in Anchor
  today) are out of reach; it compares source with source.
