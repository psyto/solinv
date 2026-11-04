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
| vipers `assert_keys_eq!` / `assert_keys_neq!` deleted from an `impl Validate` the handler's `#[access_control(ctx.accounts.validate())]` runs (composites' `self.x.validate()` followed) | removed, naming the check — or *moved* (warning) |
| typed → a different typed type (`Account<Config>` → `Signer`) | warning: type changed |
| a slot wrapped in `Option<…>` | warning: now optional |
| a slot with checks gone from an instruction that remains | warning: renamed or removed, listing its checks |
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
- Cashio's real source, fixed (`7df6581`) against the version before the
  fix: `assert_keys_eq!(common.bank.crate_mint, common.crate_mint)` removed
  from `validate()`, in `print_cash` and `burn_cash` — the check its fix
  added. Cashio's code never had that check, so no pull request removed
  it; this shows that one written and later deleted would be named.

## Limits

It reads text, not types, line by line as rustfmt lays fields out:

- A check moved from an attribute into the handler body
  (`require_keys_eq!`) reads as removed. That is deliberate: a reviewer
  should look. Handler bodies are not read; the one exception is vipers'
  `assert_keys_eq!` / `assert_keys_neq!` in an `impl Validate` run by
  `#[access_control]`. A check inside an `if` counts as always run; a
  second `impl Validate` for the same struct anywhere in the source (a
  test module's included) leaves both unread. Rarer spellings —
  `self.x.to_account_info().key`, `<X as Validate>::validate(&self.x)` —
  are not normalised, so switching to one reads as a removal.
- A field typed by a type alias, a struct name defined twice, or a field
  type split over lines is not placed, so changes to it are not compared.
- A whole instruction removed is not reported; its handler is gone with
  its checks.
- Checks the IDL carries but the source does not spell (none in Anchor
  today) are out of reach; it compares source with source.
