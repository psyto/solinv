# solinv diff over open pull requests of public Anchor programs

2026-11-07 · solinv 0a774a7, then 60334bf · every open pull request updated since 2026-05-01, its
merge base compared with its head, for each program `src` it touches:

```bash
solinv diff --base-src <merge-base>/programs/<p>/src --head-src <pr-head>/programs/<p>/src
```

[history-scan.md](history-scan.md) asks whether solinv names a check that a merged pull request
dropped. This scan asks a different question: would it have caught something in work that is still
under review? It also checks what a team gets on the pull requests it is reviewing today.

## What was scanned

| Repository | Open PRs (updated since May) | PRs that touch a program |
|---|---|---|
| orca-so/whirlpools | 56 | 3 |
| 0dotxyz/marginfi-v2 | 19 (20 on the re-run) | 19 |
| Squads-Protocol/v4 | 12 | 4 |
| MeteoraAg/damm-v2 | 7 | 6 |
| helium/helium-program-library | 6 | 1 |
| openbook-dex/openbook-v2 | 4 | 2 |
| marinade-finance/liquid-staking-program | 4 | 0 |
| jito-foundation/stakenet | 3 | 3 |
| raydium-io/raydium-cp-swap | 3 | 3 |
| metaplex-foundation/mpl-bubblegum | 3 | 2 |
| raydium-io/raydium-clmm | 2 | 2 |
| MeteoraAg/dynamic-bonding-curve | 1 | 1 |
| blockworks-foundation/mango-v4 | 1 | 0 |
| **Total** | **121** | **46** |

Kamino's klend and kvault had no open pull requests: their development is not public.

## Found: no hole

Every report was read against its diff. None is a check dropped by mistake. Before the changes
below, 48 removals were reported, in 7 pull requests:

| Pull request | Removals | What it is |
|---|---|---|
| marginfi-v2 #668 (borrow orders) | 30 | `is_signer_authorized(&a, admin, authority.key(), false, false, true)` → `…, ALLOW_REBALANCE \| ALLOW_BORROW_ORDER)`: three bools folded into a bit set, with a new permission. Any keeper may now sign while the account is in a borrow order. The order's transaction shape is pinned through the instructions sysvar, and the borrowed tokens' destination is pinned to the owner's ATA. It is intended, and it is what a reviewer should judge. |
| marginfi-v2 #713 | 1 | `close_balance` no longer limits the bank to the standard asset tag (its commit: "Allow empty integration balance close"). The balance-is-empty checks remain. |
| openbook-v2 #296 (sunset) | 6 | Each owner or admin check kept, with `\|\| (JANITOR && janitor_active()?)` added, active after a fixed sunset date. It is intended. |
| raydium-clmm #203, raydium-cp-swap #81 | 6 | `is_supported_mint(m, init)` → `is_supported_mint(m, init, hook_enshrined)?`. The enshrinement account is checked by PDA address and owner. |
| raydium-cp-swap #79 | 4 | The swap handler's body moved into `swap_base_input_with_fee(ctx.accounts, ..)`. Every check is still there, word for word. |
| damm-v2 #237 | 1 | `create_token_badge` retired to `err!(DeprecatedEndpoint)`. |

## What changed in solinv

Each kind of report above became an issue, and the issues were worked by running solinv against
these pull requests:

- **The same call with other arguments** ([#20](https://github.com/psyto/solinv/issues/20)) is
  still a removal, but it now quotes the old and the new call. The first try made it a warning. An
  independent review then broke that rule ten ways, each a real loosening that would have passed:
  - a limit set to `0`: `check_slippage(out, min_out)` → `(out, 0)`;
  - the checked account swapped through a local: `is_owner(&a, ..)` → `(&g, ..)`;
  - a bool `| true`, a comparison nested in an argument, `Role::Admin` → `Role::User`.

  No reading of the text tells those apart from a refactor.
- **A check kept as one side of a new `||`** ([#22](https://github.com/psyto/solinv/issues/22))
  is still a removal, now said as *widened*, and it names only the added way through. This covers a
  `has_one` that became `constraint = x.f == f.key() || …`.
- **A fn the handler hands `ctx.accounts` itself to**
  ([#17](https://github.com/psyto/solinv/issues/17)) is read as part of the handler, one call
  deep. It must meet all of these:
  - the call runs on every path: at the top level, not after a `return Ok`, not under `#[cfg]`,
    not in a closure;
  - the fn has no early success of its own and does not rebind its parameter;
  - a bare name is the file's own top-level fn.

  Two rounds of review set each of these limits.
- **An instruction that now only fails** ([#21](https://github.com/psyto/solinv/issues/21)) has
  its removals folded into one warning. This needs every fn read as that instruction to fail. A
  `#[cfg]` variant, a mock or a test fn that fails does not count, and neither does a local fn of
  other accounts.
- A non-ASCII character in a handler check made `solinv diff` panic. It no longer does.

Re-run on the same pull requests (122 by then: one more marginfi pull request had been updated; it adds no report):

| | Before | After |
|---|---|---|
| Removals (fail CI) | 48 | 43 |
| …that say what changed (other arguments, widened) | 0 | 38 |
| Pull requests failing | 7 | 5 |

raydium-cp-swap #79 and damm-v2 #237 now pass. The mango-v4 #368 and #119 finds and openbook-v2
#96 ([history-scan.md](history-scan.md)) are still named on the pull request that made them.

## What this says

- On the open pull requests of well-reviewed programs, solinv found no mistake, and none was
  expected: those teams review closely. What solinv gives them is a list of the places where an
  account check changed meaning, each said in a sentence. The marginfi borrow-order permission and
  the openbook janitor are both such places.
- Most removals left are real changes of meaning that a person has to clear. solinv says what each
  one became; it does not decide whether that is all right.
