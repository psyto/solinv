# Sanctum unstake ix inventory — Phase 4 N=2 target

Source: `~/src/sanctum-unstake-program/` (cloned from
`https://github.com/igneous-labs/sanctum-unstake-program` Day 44).
Build: `cargo build-sbf --tools-version v1.39` + macOS SDKROOT
incantation → `~/src/sanctum-unstake-program/target/deploy/unstake.so`
(753KB — ~6.5× bigger than Slumlord). Anchor 0.28.0.
On-chain program ID: `6KBz9djJAH3gRHscq9ujMpyZ5bCK9a27o3ybDtJLXowz`.
Mainnet deploy at commit `11aac05b22794e6c2c3366dbb7141f4c61845c24`.

## Audits

`audits/sec3-20230724.pdf` — one audit by Sec3 dated 2023-07-24.
Two-and-a-half years post-audit; reasonably-aged production code.
Code-quality posture similar to Slumlord (same igneous-labs team)
— pre-fuzz expectation is also 0 violations.

## Program shape

Anchor 0.28 — uses 8-byte sighash discriminator at `data[0..8]`,
Borsh-encoded args after. Per-ix validation via Anchor's account
context constraints (`#[account(seeds=…, has_one=…, mut, …)]`)
plus handler-body `validate(...)` helpers.

15 instructions covering 5 functional groups:

| Group | Instructions | Surface notes |
|---|---|---|
| Protocol fee management | `init_protocol_fee`, `set_protocol_fee` | Admin-only, low fuzz value |
| Pool lifecycle | `create_pool`, `set_fee`, `set_fee_authority`, `set_lp_token_metadata` | Admin-only, low fuzz value |
| LP token mechanics | `add_liquidity`, `remove_liquidity` | Math-heavy, high unchecked-math relevance |
| Stake account handling | `deactivate_stake_account`, `reclaim_stake_account` | Stake-program CPI, narrow surface |
| User-facing unstake | `unstake`, `unstake_wsol` | Highest user-facing surface, all 5 Critical applicable |
| Flash loan | `set_flash_loan_fee`, `take_flash_loan`, `repay_flash_loan` | Multi-ix tx pattern (like Slumlord's flash loan) |

## Selection for Phase 4 N=2 scaffold

Phase 4 plan §"Per-protocol budget" caps Anchor target at ~5-7 days
+ 1 day for campaigns. Scaffolding all 15 ix is out of scope. Pick
the top 2-3 by expected solinv-detection yield:

### Primary target: `unstake` + `unstake_wsol`

The most user-facing ix pair. Both apply all 5 Critical invariants
plus unchecked-math (token amount + fee math) plus cu-dos (stake
account iteration in remaining_accounts). User can submit either
flavor; both share most of the same account structure.

Account context: stake_account (mut, user-controlled), destination
(mut, where SOL flows), pool (mut, Anchor-protected), fee_account
(mut), protocol_fee_account (mut), stake_program, system_program,
clock, stake_history (last two = sysvars).

Highest-yield single target for Phase 4 N=2.

### Secondary target: `add_liquidity` + `remove_liquidity`

LP math has had historical bug surface in the Solana ecosystem
(Marinade share inflation, Saber precision loss). Anchor `Fee`
struct + `RemoveLiquidity` may have unchecked-math sub-surfaces.

If primary completes ahead of schedule, scaffold these as additional
data points.

### Skip (low expected yield)

- All admin ixs (init_protocol_fee, set_protocol_fee, set_fee,
  set_fee_authority, set_lp_token_metadata): admin-only, attacker
  can't reach. Already permission-gated by Anchor.
- Stake account handling (deactivate / reclaim): narrow surface;
  most validation handled by Solana stake program itself.
- Flash loan (take/repay/set_fee): would require multi-ix
  orchestration like Slumlord's Borrow+CheckRepaid pattern.
  Adds 1-2 days, marginal yield. Defer to N=3+ if reached.

## Solinv coverage analysis

| Invariant | Sanctum unstake surface | Expected outcome |
|---|---|---|
| **signer-skip** | `unstake` has stake_account_record/user authority signers. Anchor's `Signer<'info>` constraint enforces. | **0** by Anchor convention |
| **owner-skip** | Pool, fee_account, etc. all typed `Account<'info, T>` — Anchor auto-checks owner. | **0** by Anchor convention |
| **discriminator-skip** | All accounts use Anchor 8-byte sighash discriminators per Anchor 0.28. | **0** by Anchor convention |
| **pda-forge** | `pool` has `seeds = [...]` constraint per Anchor. | **0** by Anchor convention |
| **account-swap** | User-controlled `destination` is permissive (DEX-style); core protocol accounts have `has_one` constraints. | Likely **0** — would need a specific multi-context scenario |
| **unchecked-math** | LP math + fee math + protocol fee math. Anchor 0.28 ecosystem typically uses `checked_*` per audit guidance; Sec3 2023-07 audit would have flagged misses. | Likely **0** at the Bounded { 0, 10^18 } cap |
| **cu-dos** | `unstake` may iterate over remaining_accounts (rebate sources). Sec3 audit would have caught unbounded loops on user input. | Likely **0** at the 100K cu_budget cap |

Pre-fuzz estimate: **0 violations** — same shape as Slumlord
N=1. This is the **expected** outcome that closes the protocol-size
axis on Phase 4 (combined with N=1) per the stopping rule.

## What's expected, with honest framing

Sanctum unstake is **competently-coded production Anchor code by an
experienced team**, with one Sec3 audit (2.5 years old but the code
is still actively maintained per the commit hash mentioned in the
README). This is *protocol-size axis* testing — different scale
than Slumlord (753KB vs 115KB, 15 ix vs 4 ix) but same code-quality
class.

Per the Day 43 N=1 result log §"What this tests, what this doesn't":
> Sanctum's code-quality posture is the same as Slumlord. Testing
> the same axis twice gives a clean 2-trial dataset for the
> protocol-size axis but doesn't tell us about the code-quality
> axis. That's the explicit trade the user took at the Day 43
> sub-decision.

If N=2 returns 0 violations, the protocol-size axis is closed with
2 negatives. Phase 4 pivot binds at that point per the §"Stopping
rule":

> N=2, 0/2 violations across both → 2 independent negatives.
> Combined with Phase 2's 5 Critical / Phase 3's 2 High evidence
> on Raydium, this constitutes a *third axis* (protocol variety)
> all returning the same shape. **Pivot is binding — no further
> protocol scaffolds.** Move to option 2 (OSS) or 3 (pause).

If N=2 fires (unlikely per the pre-fuzz estimate), triage immediately
— it would be the first Phase 3/4 positive finding and worth a real
disclosure attempt.

## Reusable patterns from build

Same `SDKROOT + platform-tools v1.39` incantation as klend Day 17
and Slumlord Day 40. Anchor 0.28 builds cleanly under this stack.

## Next (Day 45-49)

Per the Phase 4 plan §"Per-protocol budget":

- Day 45: `examples/sanctum-unstake-fuzz/` scaffold + Cargo.toml
  workspace opt-out + skeleton main.rs with Anchor ix_sighash
  builder pattern (Day 15 refactor).
- Day 46: Fixture init — create_pool baseline + fund pool with
  add_liquidity to reach unstake reachability.
- Day 47: Wire 1-2 InstructionSpecs for `unstake` (+ maybe
  `add_liquidity`). Run smoke campaign.
- Day 48: Full Gate 1-style 5-7 invariant × 30s isolated campaigns
  per ix.
- Day 49: Result log + N=2 vs binding decision.

Per-protocol budget: 5 days for ≤2 ix Anchor scaffold matches the
Phase 4 plan's lower-end estimate. Slumlord pattern reuse + Anchor
0.28 maturity should keep this on track.
