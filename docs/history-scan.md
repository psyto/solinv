# solinv diff over the merged history of public Anchor programs

2026-11-05 · solinv 55d0d88 · every first-parent commit on the default branch that touches a
program's `src`, compared with its parent:

```bash
solinv diff --base-src <parent>/programs/<p>/src --head-src <commit>/programs/<p>/src
```

A first-parent commit is one merged pull request (or one squash). To find removals that were
*mistakes*, the same history was also run the other way round (head → base: the checks each
commit *added*), and a removal was paired with a later addition of the same check on the same
instruction and account.

## What was scanned

| Repository | PRs touching programs | Since |
|---|---|---|
| blockworks-foundation/mango-v4 | 439 | 2022-01 |
| openbook-dex/openbook-v2 | 207 | 2023-04 |
| raydium-io/raydium-clmm | 138 | 2022-05 |
| 0dotxyz/marginfi-v2 | 95 | 2023-01 |
| jito-foundation/stakenet | 65 | 2023-12 |
| Kamino-Finance/klend | 57 | 2023-11 |
| orca-so/whirlpools | 57 | 2022-05 |
| raydium-io/raydium-cp-swap | 42 | 2023-12 |
| Squads-Protocol/v4 | 25 | 2022-12 |
| marinade-finance/liquid-staking-program | 8 | 2021-11 |
| **Total** | **1,133** | |

drift-labs/protocol-v2 (939 PRs) was still running when this was written and is not counted.

## Found: checks a pull request removed and an audit put back

Of the 7 removed-then-restored pairs, two are this, both in mango-v4, both named by `solinv diff` on the pull request that removed them:

| Removed in | Check | Restored in |
|---|---|---|
| [#368](https://github.com/blockworks-foundation/mango-v4/commit/93d33edb) "Perp: liq with token instruction", 2023-01-12 | `perp_liq_bankruptcy` was folded into the new `perp_liq_quote_and_bankruptcy`; the new struct's `group` lost `has_one = insurance_vault`. The instruction moves tokens out of `insurance_vault` with the group as authority | [#399](https://github.com/blockworks-foundation/mango-v4/commit/886a6696) "Perp audit: ix constraint fixes", 2023-01-19 |
| [#119](https://github.com/blockworks-foundation/mango-v4/commit/0b2e1e6e) "Mc/realloc 4", 2022-07-25 (on `main` with the 2022-08-04 merge) | `compute_account_data.account` changed to `AccountLoaderDynamic` and lost `has_one = group` | [ac580814](https://github.com/blockworks-foundation/mango-v4/commit/ac580814) "Audit: Fix some account constraints", 2022-08-11 |

The first is the case solinv's rename pairing ([#9](https://github.com/psyto/solinv/issues/9))
exists for: the check vanished while the instruction was renamed. We have not looked into whether
either change was ever deployed, and make no claim that it was exploitable — only that the check
was gone from `main` until an audit added it back.

## Found: loosenings to look at

- openbook-v2 [#96](https://github.com/openbook-dex/openbook-v2/pull/96) removed
  `constraint = token_deposit_account.mint == market_vault.mint` from `place_order`; #97 reverted
  the whole pull request two days later.
- stakenet [#48](https://github.com/jito-foundation/stakenet/pull/48) "Build IDL Anchor 0.30"
  turned 29 typed accounts (`Account<StakePool>` and others) into `AccountInfo`, with comments
  such as `CHECK: passing through, checks are done by spl-stake-pool` and `CHECK: TODO add
  validator list to config`; a later release gave `validator_list` an `address` constraint.
- raydium-cp-swap widened `address = admin` to `constraint = (admin || another owner)` twice, and
  Drift and stakenet titled such changes "allow whitelisted signer", "permissionless …", "Relax
  Constrant". These are intentional; they are what a reviewer should be shown.

## Noise: how many removals are real

Of 847 removals reported (Drift aside), 563 were declared checks and 284 handler checks.

**A random sample of 40 declared-check removals** (fixed seed), each read against its diff:

| Reading | Count |
|---|---|
| A real loosening, nothing equivalent added | 3 |
| A loosening the PR says is deliberate ("allow … during pause", "allow delegate …") | 2 |
| The same check written another way, moved, or a type whose loader now checks it | 29 |
| The account or instruction restructured (retired placeholder, two accounts merged) | 6 |
| solinv misread the source | 0 |

So about **1 report in 8 is a real loosening** on real pull requests (5 of 40; with a sample this
small, anywhere from about 1 in 25 to 1 in 4). The rest are true in the narrow sense — that
declaration is gone — but the guarantee survives elsewhere. A team putting this in CI should
expect most failures to be resolved by a reviewer saying "moved", which is what `--no-fail` and
the warning severity exist for, and what the next round of solinv work should cut down. The
commonest kinds:

- One relation written three ways: `has_one = f` on the holder, `address = X.load()?.f` on `f`,
  `constraint = X.load()?.f == f.key()`. Moving between them reads as a removal (11 of 40, often
  with an account renamed at the same time).
- A global gate replaced by a per-instruction one on the same account (`is_operational()` →
  `is_ix_enabled(IxGate::…)`; 5 of 40).
- A typed account made `UncheckedAccount` with its owner, discriminator and field checks moved
  into a function the handler calls (orca's sparse swap; 5 of 40).
- An account retired as a `/// CHECK: Deprecated … kept for compatibility` placeholder (5 of 40).

Two kinds of false removal found while reading are fixed:

- `#[account(signer)] AccountInfo` → `init` (no seeds) kept its signature: Anchor makes a non-PDA
  `init` / `init_if_needed` account sign (Marinade's anchor-0.27 upgrade).
- `owner` / `seeds` replaced by an `address` built from another account or a constant, or the
  reverse, is now a warning (stakenet's `address = get_validator_list(&config)?`). An address the
  caller passes, or a typed account in place of `owner`, is still a removal.

`x::id()` rewritten as `x::ID` (cp-swap's anchor-0.31 upgrade) is still a removal: Rust does not
make the two the same.
