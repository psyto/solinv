# solinv diff on sealevel-attacks

2026-11-04 · solinv 06e3adf, re-run at the commit that fixed #9–#11 ·
[coral-xyz/sealevel-attacks](https://github.com/coral-xyz/sealevel-attacks) at 24555d0, the same
commit [epic-sec/epic](https://github.com/epic-sec/epic) scores against.

Each of the 11 classes has an `insecure` program and one or two fixed versions: `recommended`
(the check is declared through Anchor types and `#[account(...)]`) and `secure` (the check is
written in the handler). `solinv diff` answers "does this change remove a check", so each fixed
version was compared against `insecure`, as if a pull request turned one into the other:

```bash
solinv diff --base-src programs/<class>/<fixed>/src --head-src programs/<class>/insecure/src
```

## Result

| Class | recommended → insecure | secure → insecure |
|---|---|---|
| 0 signer-authorization | ✅ `Signer` → `AccountInfo` | ❌ |
| 1 account-data-matching | ✅ `Account` → `AccountInfo`; `constraint = authority.key == &token.owner` removed | ❌ |
| 2 owner-checks | ✅ `Account` → `AccountInfo` | ❌ |
| 3 type-cosplay | ✅ `Account` → `AccountInfo`; `has_one = authority` removed | ❌ |
| 4 initialization | ✅ `Account` → `AccountInfo`, with `init` renamed `initialize` in the same change: paired by their slots and compared ([#9](https://github.com/psyto/solinv/issues/9)) | ❌ |
| 5 arbitrary-cpi | ✅ `Program` → `AccountInfo` (plus signer and both token accounts) | ❌ |
| 6 duplicate-mutable-accounts | ✅ `constraint = user_a.key() != user_b.key()` removed | ❌ |
| 7 bump-seed-canonicalization | ✅ `seeds` removed | ❌ |
| 8 pda-sharing | ✅ `seeds` removed | ❌ |
| 9 closing-accounts | ✅ `close = destination` removed ([#10](https://github.com/psyto/solinv/issues/10)) | ❌ |
| 10 sysvar-address-checking | ✅ `Sysvar` → `AccountInfo` | ❌ |
| **Total** | **11 of 11** (9 of 11 at 06e3adf) | **0 of 11** ([#12](https://github.com/psyto/solinv/issues/12)) |

**False positives:** 0. Every pair was also compared the other way round, `insecure` →
`recommended` and `insecure` → `secure` (22 pairs), where the change adds checks; none reported
a removed check. Three of them report a rename (`initialize` → `init`, and two `secure` versions
that rename their instruction), as a warning.

## Reading it

- **A declared check that a change removes is what `diff` catches**, and it caught all 11
  classes in that form (9 before #9 and #10 were fixed). Each report names the slot and the check, and the line is the right one.
- **A check written in the handler is invisible.** In `secure` the checks are statements like
  `if !ctx.accounts.authority.is_signer { return Err(..) }`; deleting them reports nothing. Since
  #8 the vipers `assert_keys_eq!` form in `impl Validate` is read, but plain handler code is not
  ([#12](https://github.com/psyto/solinv/issues/12)).
- **This is not the same measurement as EPIC's.** EPIC scans each `insecure` program on its own and
  reports 2 of 11 classes caught. `diff` needs a before and an after, so its number says what a pull
  request that turns a fixed program into the insecure one would trip, not what solinv finds in
  code it sees for the first time.
- **The map, read from source alone** (`solinv idl --src`, no IDL, since these Anchor 0.20
  programs can't produce one with current Anchor — [#11](https://github.com/psyto/solinv/issues/11)):
  on each `insecure` program it marks the vulnerable account `U` or `t` in 10 of 11 classes; the
  one it cannot see is 8 pda-sharing, whose accounts are tied by `has_one` and whose flaw is in the
  seeds. On the `recommended` programs, the slots still marked are a closed account, its lamport
  destination, and two token accounts a CPI is handed — accounts the caller chooses.
- **The fuzz detectors were not run here.** It would need these programs built with an Anchor 0.20
  toolchain.
