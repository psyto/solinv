# `solinv diff` on a native or Pinocchio program

A native or Pinocchio program has no `#[derive(Accounts)]` to compare: its account checks are
statements in its code. When `--base-src` has no accounts struct, `solinv diff` reads those
statements instead, fn by fn, and names a check a fn made in the base and no longer makes in the
head. Every finding is a **warning**: it is annotated on the pull request, and the job does not
fail on it — nor when such a program is deleted.

```bash
solinv diff --base-src <before>/src --head-src <after>/src
```

```
solinv diff: 0 removed check(s), 3 warning(s)
WARNING init_vault.admin_ai (lib.rs:232): `require_signer(admin_ai)?` is gone or its result is not propagated: `admin_ai` no longer has to sign
WARNING init_vault.vault_ai (lib.rs:232): `if &expected_vault != vault_ai.key() { return Err(..) }` is gone: `vault_ai`'s key is no longer compared with `expected_vault`
WARNING deposit.token_program_ai (lib.rs:316): `if token_program_ai.key() != &TOKEN_2022_PROGRAM_ID { return Err(..) }` is gone: `token_program_ai`'s key is no longer compared with `TOKEN_2022_PROGRAM_ID`
```

(psyto/princeps-solana's vault, with those three checks deleted by hand.)

## What it reads

A check is a condition that rejects the call — `if <cond> { return Err(..) }`, or
`if <cond> { .. } else { Err(..) }` on `!cond` — read as what it checks about which account:

| Written | Read as |
|---|---|
| `!a.is_signer()`, `!a.is_signer` | `a` signs |
| `!a.is_writable()`, `!a.executable()` | `a` is writable / a program |
| `a.owner() != id`, `*a.owner != id`, `!a.is_owned_by(id)`, `!a.owned_by(id)` | `a`'s owner is `id` |
| `a.key() != x`, `&x != a.key()`, `a.address() != x`, `!pubkey_eq(a.key(), x)`, `!cmp_pubkeys(..)`, `sol_memcmp(a.key, x, 32) != 0` | `a`'s key is `x` |

- The block may log first: `{ msg!(".."); return Err(..) }`, `sol_log(..)`, `solana_program::msg!`.
- Each `||` part is a check of its own; `!(p && q)` is `!p || !q`. A part joined by `&&` to
  anything but a flag is not read (`!a.is_signer() && !b.is_signer()` lets either sign).
- Spelling does not matter: `&`, `*`, `.as_ref()`, `.to_bytes()`, `Pubkey::new_from_array(..)`,
  `unsafe { .. }`, `likely(..)` / `unlikely(..)`, and `program_id` / `crate::ID` / `ID` for the
  program itself.
- A one-expression fn called in a condition is read through: `if !owner_ok(o, a.key)` with
  `fn owner_ok(x, y) -> bool { x == y }` is `a.key != o`.
- A helper the fn calls and propagates (`?`, `.unwrap()`, returned) counts as the checks it makes,
  on the arguments passed, to 4 calls deep: `require_signer(payer)?` is `payer` signs. A flag
  parameter (`if expect && !a.is_signer()`) counts when the call passes `true`. A helper handed an
  account's key (`require_admin(header.admin, a.key)`) checks that account.
- A helper that stops checking is named once, on itself, when it checks its parameter outright;
  when it checks only through a flag or a key it is handed, each call that still runs is named
  instead (`` `check(user,true)?` still runs, but no longer checks this ``).
- An account is named by its place in the slice when the fn binds it from one
  (`let vault = &accounts[1];`, `let [payer, vault, ..] = accounts`), so `read(&accounts[4])` and
  `let oracle = &accounts[4]; read(oracle)` are the same check.
- A `match` whose arms are enum variants (`Instruction::Deposit { .. } => { .. }`, or
  `=> process_deposit(accounts)?`) is compared arm by arm, each as its own instruction, with the
  checks the fn makes before the `match`.

A check moved into a helper, out of one into every caller, or from one spelling to another is not
reported. Nor is one on a fn or arm whose first statement now returns `Err` (the instruction was
turned off), or on an account the fn no longer takes at all: not a parameter, its place in the
slice not bound to a name (`let _oracle = &accounts[7]` does not count) nor indexed, and the slice
not handed on whole. When the same account is still compared, with one new
thing, it says so: `` `price_ai`'s owner is now compared with `PYTH_RECEIVER_PROGRAM_ID` instead of
`PYTH_PROGRAM_ID` ``.

## What it does not read

- Which account a variable holds, other than through its place in the slice. A fn renamed or
  moved to another module is not compared at all.
- A name it cannot resolve to one fn: another crate's helper, a fn two modules share, a method on
  a value of unknown type. Its checks are not counted, in either version.
- A fn's checks are one set. Outside instruction `match` arms, a check one branch drops and
  another branch still makes on the same account is not seen.
- Checks of data (a discriminator, a length, a field), of lamports, and anything written as
  `match` or `let .. else` rather than `if`.
- Nesting: a check inside `if flag { .. }` counts as made on every call.
- A `match` on a tag byte (`match data[0] { 0 => .., 1 => .. }`) is not split into arms: the fn's
  checks are one set, so a check one arm drops and another still makes is not seen.
- Given a directory explicitly, the CLI exits 1 when it finds neither an accounts struct, an
  entrypoint, nor a check it can read. The Action passes it only directories with an entrypoint
  outside comments (its comment stripping can be misled by `/*` or `//` inside a string).

## Measured on real histories

2026-11-06 · every first-parent commit that touches a `src` directory, compared with its parent,
as in [history-scan.md](history-scan.md):

```bash
solinv diff --base-src <parent>/<dir>/src --head-src <commit>/<dir>/src
```

| Repository | Commits | Reported | Commits flagged | Real loosenings |
|---|---|---|---|---|
| aeyakovenko/percolator-prog (to 69174f6, 2026-04-13; since rewritten as `v16_program.rs`) | 573 | 37 | 13 | 7 reports in 3 commits |
| solana-program/token (SPL Token and p-token) | 475 | 4 | 4 | 1 |
| psyto/princeps-solana | 22 | 1 | 1 | 1 |
| psyto/openhl-solana | 94 | 1 | 1 | 1 |
| **Total** | **1,164** | **43** | **19** | **10 reports in 6 commits** |

About 1 report in 4 is a real loosening, and 6 commits in 19. The real ones:

- percolator-prog 3a3225a: the owner checks of `WithdrawCollateral` and `TradeNoCpi`
  (`if Pubkey::new_from_array(owner) != *a_user.key`) commented out; restored later.
- percolator-prog bcbb5a6: `TradeCpi` no longer requires the LP owner to sign ("LP owner should
  not need to sign").
- percolator-prog c865a22: `ResolveMarket` stops propagating the oracle read, so any error from it
  — including a wrong oracle account — skips the settlement guard (meant for a stale oracle).
- token bf5d08f (p-token): `revoke` checks the delegate instead of the owner when the delegate
  signs ("self-revoke delegate").
- princeps-solana e6a097f: `close_repo` lets the lender close after expiry, so the borrower key
  check became `is_borrower || (expired && is_lender)`.
- openhl-solana 2fa82eb: `CreateSlab` initializes a slab the client created from a keypair instead
  of creating it at a PDA of the market, so the slab's key is no longer compared with that PDA
  (intended: it must now sign, be owned by the program, and be the right size).

The rest: an oracle migration that replaced the oracle key check with a feed id in its data (14 of
the 37, one commit), checks rewritten as Kani-provable struct predicates or a helper comparing a
field of the data instead, a variable renamed (`config` → `cfg`, `dest_account` →
`destination_account`), a check replaced by a PDA key check, a feature removed with the check
under it, an account left in place but no longer used while the slice is still handed on
(`expect_len(accounts, 8)`), and an intermediate commit whose call did not match its helper's
parameters.

An independent review then tried to break it with 27 base/head pairs (an authority account used
only to sign, a helper gutted to `Ok(())`, a trailing `return Err`, a `match` arm turned into a
call, a field name equal to an account name, non-ASCII text in a condition); each is a test in
`crates/solinv-static/tests/native_cases/`. Fixing the misses it found took the reports above
from 35 to 42 (8 real to 9).

Putting the action on openhl-solana then showed that a check whose block logs before it fails
(`{ msg!(".."); return Err(..) }`) was not read at all: 78 of the 192 account checks in its
`openhl-core`, and deleting `if !user_ai.is_signer { msg!(..); return Err(..) }` from `Deposit` was
not reported. v0.1.5 reads them (test `n03_logs_before_err`); the three histories above report
exactly the same with it.

Nothing else in the three histories was reported; what it misses there is not measured. Planted
removals: the unit tests in `crates/solinv-static/src/native.rs`, the three above on
princeps-solana's vault, and the `Deposit` signer check on openhl-solana's core.
