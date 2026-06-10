# Phase 4 Day 46 — Sanctum unstake depth-gated finding

Date: 2026-05-26
Spec: Phase 4 protocol-variety stopping rule (2 protocol-size negatives close the axis).
Inventory: [docs/sanctum-unstake-ix-inventory.md](sanctum-unstake-ix-inventory.md)
Status: Phase 4 N=2 reached the same depth-gating shape as klend Day
25-27. Infrastructure proven, full attack surface gated by Anchor
0.28 + SPL Token CPI interaction in LiteSVM.

## What was attempted Day 46

Full N=2 scaffold per the Day 44 inventory plan:

1. Add `init_protocol_fee` builder + setup() call ✓ (Day 45)
2. Add `create_pool` builder + setup() call ✓
3. Add `set_fee` builder + `action_set_fee` ✓
4. Add `SetFee` InstructionSpec with full Anchor 0.28 account
   metadata (`expected_owners` / `expected_discriminators` /
   `expected_pda_seeds` covering Pool + Fee Anchor account types) ✓
5. Run smoke campaign to confirm reach ⚠️

Components 1-4 ship as committed code. Component 5 surfaced the
depth gate.

## Where it failed

`create_pool` returns `TxOutcome::ProgramError` with:

```
Program unpXTU2Ndrc7WWNyEhQWe4udTzSibLPi25SXv2xbCHQ failed:
Access violation in unknown section at address 0xFFFFFFFFFFFFFFFF
of size 32
```

The error originates inside Anchor 0.28's `#[account(init,
mint::authority = pool_sol_reserves, mint::decimals = SOL_DECIMALS)]`
constraint on the `lp_mint` field. That constraint generates CPI to
`spl_token::initialize_mint` after pre-creating the mint account.
The CPI doesn't complete cleanly in our LiteSVM setup.

Same depth-gating class as klend Day 25-27:

| Day | Target | Depth gate |
|---|---|---|
| klend Day 25-27 | klend `deposit_reserve_liquidity` | ReserveConfig fields (~10-15 fields) need sensible defaults to pass the handler's validate() path |
| Sanctum Day 46 | Sanctum `create_pool` | Anchor `init` + `mint::authority` CPI to spl_token::initialize_mint fails inside LiteSVM at toolchain-level memory access |

## What's proven

Component-level infrastructure that survives the gate:

- ✓ `unstake.so` builds (Day 44, 753KB) — Anchor 0.28 + macOS SDK
  + platform-tools v1.39 workaround confirmed reproducible
- ✓ Program ID double-declare resolved (lib.rs:6/9 — `local-testing`
  vs mainnet variant; the mainnet ID is what the .so carries
  without `--features local-testing`)
- ✓ Anchor 0.28 sighash builder pattern (`ix_sighash` +
  `account_disc`) ports cleanly from klend's Anchor 0.29
- ✓ `init_protocol_fee` ix completes successfully — first
  TxOutcome::Success on a Sanctum unstake ix
- ✓ Borsh wire format for `Fee { fee: FeeEnum::Flat { ratio:
  Rational { num: 0, denom: 10_000 } } }` is byte-correct (17
  bytes: `[0u8, num_le, denom_le]`)
- ✓ Account ordering for `CreatePool` (9 accounts) and `SetFee`
  (5 accounts) matches the program's `#[derive(Accounts)]` order
- ✓ Pool / Fee PDA derivations: `[pool_account.key()]` and
  `[pool_account.key(), b"fee"]` are correct seeds
- ✓ Harness builds clean + runs without panic with create_pool in
  the soft-fail path (1.4% edge coverage from init_protocol_fee +
  partial create_pool before the access violation)
- ✓ SetFee InstructionSpec metadata is well-formed — solinv
  invariants iterate over it correctly, attacking pubkeys / signer
  flags / pda seeds. They just never see Success because the
  underlying state was never initialized.

## What's not proven

- ❌ Full account-validation surface of any state-mutating ix
  on Sanctum unstake. Anchor constraint validation runs for
  `init_protocol_fee`, but `create_pool` / `set_fee` /
  `add_liquidity` / `unstake` never reach handler bodies.
- ❌ Per-ix CU consumption of state-mutating ixs (cu-dos
  detector has no data to compare against)
- ❌ Reachability of the `unstake` ix surface (which would also
  require delegated stake account fixturing — separate depth
  beyond the SPL Token CPI gate)

## Why I didn't fix it Day 46

The SPL Token CPI gate is a toolchain-level investigation. Probable
root causes (un-validated):

1. LiteSVM may bundle `spl-token` v0.6.x while Anchor 0.28 links
   against a different spl-token version → ABI mismatch on
   initialize_mint call
2. Rent sysvar may not be populated in LiteSVM's default state →
   spl_token::initialize_mint reads invalid memory at sysvar address
3. SPL Token program's loader version may differ in LiteSVM
   (BPF Loader v1 vs Upgradable Loader)

Each requires non-trivial digging:
- (1) → audit LiteSVM's spl_token bundling vs Anchor 0.28's
  expectations
- (2) → understand LiteSVM's sysvar handling + populate rent
- (3) → patch LiteSVM's program loading

Realistic estimate: 1-3 days of toolchain-level debugging, against
a target whose pre-fuzz expectation is already 0 violations and whose
parent stopping-rule data is already at "two negatives close the
axis" if interpreted pragmatically.

This is exactly the trade klend Day 27 surfaced: "iterate on depth"
vs "ship what you have + document the gate". klend chose the latter,
and the Day 28 retrospective endorsed it. Same call here.

## Honest read of the Phase 4 §"Stopping rule"

Strict reading:

> N=1, 0 violations → 1 data point, continue to N=2 (don't pivot
> on a single trial).
> N=2, 0/2 violations across both → 2 independent negatives ...
> Pivot is binding.

N=2 here is **not** "0 violations after extensive fuzzing of the
attack surface". It's "0 violations because the attack surface
wasn't reachable at fuzz depth". These are categorically different
data points.

Pragmatic reading: Combined with Phase 3's Raydium two-fail and
Slumlord N=1 clean negative, this is the **third** time the
existing solinv-fuzz toolkit has hit the same shape against the
existing protocol set:

| Trial | Target | Code-quality posture | Result |
|---|---|---|---|
| Phase 2 | Raydium SwapV2 | hardened production (Native) | 0 / 25K (Critical 5) |
| Phase 3 (Day 34) | Raydium SwapV2 | hardened production (Native) | 0 / 15K (unchecked-math) |
| Phase 3 (Day 38) | Raydium SwapV2 | hardened production (Native) | 0 / 25K (cu-dos) |
| Phase 4 (Day 43) | Slumlord | competent infra (Native) | 0 / 86K (5 invariants) |
| Phase 4 (Day 46) | Sanctum unstake | competent infra (Anchor) | depth-gated |

Five attempts. Three different invariant classes. Three different
protocols. Two different validation styles (Native helper +
Anchor constraints). All point the same direction: solinv-fuzz at
current capability doesn't surface findings on this class of
target.

## User decision point — Day 47

Strict reading wants:
- 1-3 days digging into LiteSVM + SPL Token CPI (option A1)
- OR move to a different N=2 target whose surface doesn't need
  SPL Token CPI (option A2 — e.g., back to candidate A from Day
  39 with explicit OSS-checked Colosseum 2025 winner)

Pragmatic reading wants:
- Bind the pivot now (option B — pivot to Day 38 §"Pivot options"
  1/2/3)

Both readings are defensible. The strict reading produces
*stronger* evidence at the cost of 1-2 more weeks. The pragmatic
reading produces *sufficient* evidence at the cost of less
certainty.

My recommendation: B. Three independent code-quality classes ×
three different invariant classes × five trials all returning the
same shape is empirically sufficient. The Day 46 depth-gating
**itself is a data point about solinv-fuzz capabilities at this
maturity level** — the framework doesn't easily reach Anchor 0.28
+ SPL Token CPI surfaces, which limits what protocols are
addressable in practice.

## Files added/changed today

- `examples/sanctum-unstake-fuzz/fuzz/sanctum-unstake/src/main.rs`
  — Day 46 CreatePool + SetFee + InstructionSpec wiring, with
  honest soft-fail handling around create_pool's known depth gate.
- `docs/phase4-day46-sanctum-unstake-depth-gated.md` (this doc).

## Cumulative Phase 4 schedule

| Day | Theme | Commit |
|---|---|---|
| 39 | Phase 4 plan + sequential kill criterion | `78d74df` |
| 39a | Lifinity eliminated, refreshed shortlist | `ba3cc97` |
| 40 | Slumlord N=1 target + .so build + inventory | `e90a229` |
| 41 | Slumlord N=1 scaffold | `58e9777` |
| 42 | Slumlord N=1 Borrow multi-ix + smoke | `564e240` |
| 43 | Slumlord N=1 clean negative (0/86K) | `c181619` |
| 44 | Sanctum N=2 target + .so build + inventory | `70eaee9` |
| 45 | Sanctum N=2 minimum-viable skeleton | `0ded2cf` |
| 46 | Sanctum N=2 CreatePool/SetFee wiring + depth-gating retrospective (this) | (pending) |

8 working days against the 5-7 day estimate per protocol. Slumlord
ran 5 days exactly; Sanctum 3 days to depth gate. Phase 4 total
is at "ahead of schedule on time, mixed on data quality".

The Day 47+ schedule depends on the user's pivot decision above.
If pragmatic (option B): write a Phase 4 closing retrospective +
move to Day 38 §"Pivot options". If strict (A1 or A2): commit
another 1-2 weeks to the strict reading.
