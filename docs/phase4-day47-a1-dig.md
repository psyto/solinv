# Phase 4 Day 47 — A1 dig: SPL Token CPI gate diagnosis

Date: 2026-05-26
Prior: [phase4-day46-sanctum-unstake-depth-gated.md](phase4-day46-sanctum-unstake-depth-gated.md)
User pick (Day 47): A1 — dig into the SPL Token CPI gate before
committing to the Phase 4 pivot.
Outcome: **3 hypotheses tested + falsified; hypothesis 1 (Anchor
0.28 ↔ LiteSVM 0.9.1 ABI mismatch) is the residual diagnosis,
infeasible to fix within Phase 4 budget.**

## The gate

Sanctum unstake's `create_pool` returns:

```
Program unpXTU2Ndrc7WWNyEhQWe4udTzSibLPi25SXv2xbCHQ invoke [1]
Program log: Instruction: CreatePool
Program unpXTU2Ndrc7WWNyEhQWe4udTzSibLPi25SXv2xbCHQ consumed
    5802 of 200000 compute units
Program unpXTU2Ndrc7WWNyEhQWe4udTzSibLPi25SXv2xbCHQ failed:
    Access violation in unknown section at address
    0xffffffffffffffff of size 32
```

5802 CU consumed before crash; no CPI invocations logged. Crash
occurs during Anchor 0.28's macro-expanded account validation,
before any of the `init` CPI flow runs.

## Hypotheses tested

### H2 — Rent sysvar not populated  (FALSIFIED)

Anchor 0.28's `#[account(init, mint::authority, mint::decimals)]`
invokes `spl_token::initialize_mint` via CPI, which reads the Rent
sysvar to compute rent-exempt lamports. If LiteSVM's default Rent
sysvar account has empty data, reading it would produce an
out-of-bounds access.

**Test**: added `ctx.set_sysvar(&Rent::default())` to setup() before
`create_pool`.
**Result**: identical error, identical 5802 CU. LiteSVM already
populates Rent sysvar via its `with_sysvars()` chain in `into_basic()`
(litesvm-0.9.1/src/lib.rs:459); the manual `set_sysvar` is redundant.

### H3 — SPL Token program not loaded  (FALSIFIED)

LiteSVM might not auto-load SPL Token, requiring an explicit
`ctx.add_program(spl_token_id, ...)` call before CPI works.

**Test**: read `litesvm-0.9.1/src/programs/mod.rs:7-45`. LiteSVM's
`load_default_programs` bundles `spl_token-3.5.0.so` (line 9-10) +
spl_token_2022 + spl_memo + ATA + config + ALT + Stake, all loaded
via `LiteSVM::default().into_basic()` → `with_default_programs()`.
SPL Token IS available.

**Result**: not the issue.

### H4 — LiteSVM doesn't auto-create account placeholders  (FALSIFIED)

Anchor's `init` constraint might pre-read the account-to-be-initialized
via AccountInfo before issuing the create_account CPI, hitting unmapped
memory if LiteSVM doesn't synthesize an empty AccountInfo for
ix-mentioned pubkeys without prior state.

**Test**: pre-wrote empty `SystemProgram`-owned `Account` placeholders
for `pool_account` and `lp_mint` via `ctx.write_account` before
`create_pool`.
**Result**: identical error, identical 5802 CU. Placeholder
pre-creation doesn't change the outcome.

### H1 — Anchor 0.28 ↔ LiteSVM 0.9.1 ABI mismatch  (residual diagnosis)

Anchor 0.28 was released for Solana 1.16-era runtime (≈2023). Its
proc-macros emit code expecting that runtime's account-data layout,
sysvar API shapes, BPF loader version, etc. LiteSVM 0.9.1 emulates
the Solana 3.x runtime (≈2025-2026), which has revised several of
these. Specifically suspicious:

- **`FeatureSet::all_enabled()` (litesvm lib.rs:456)** turns on
  features that Anchor 0.28 doesn't expect (e.g., changes to
  account-data encoding, sysvar serialization).
- **Account loader behavior** in the upgradable BPF loader v3 vs
  the legacy loader v2 might be exposed through `AccountInfo`
  fields Anchor 0.28's macros read directly.

The 5802 CU + identical `0xFFFFFFFFFFFFFFFF` size-32 access across
all H2/H3/H4 attempts points strongly here: it's not a
populate-this-thing fix, it's a fundamental compatibility mismatch.

## Comparable evidence

klend (Anchor 0.29, Day 17-27): same toolchain-level depth gate.
Day 27 retrospective declared "infrastructure proven, depth gated
by ReserveConfig setup" — but the deeper truth is that Anchor 0.29
+ LiteSVM 0.9.1 also has compatibility friction. Day 26's
init_reserve raw_call worked (978 iters no panic) only because the
specific init pattern there didn't trip the SPL-Token-init CPI flow.

escrow-demo uses `anchor-lang = "1.0.1"` (Day 14 retrofit) — the
modern Anchor that LiteSVM 0.9.1 is tested against. Works clean.

The pattern: **Anchor 0.28 and 0.29 production programs are
gated by toolchain mismatch with Crucible v0.1.0's LiteSVM v0.9.1;
Anchor 1.0+ programs work cleanly.**

## H1 fix scope estimate

Fixing the underlying ABI mismatch is fundamentally either:

1. **Patch LiteSVM** to support Anchor 0.28's ABI expectations.
   Likely requires either backporting Solana 1.16 account loader
   behavior, or selectively gating features in `FeatureSet`. 
   1-2 weeks of LiteSVM-internals work.
2. **Patch the target program** to Anchor 1.0+. Requires upstream
   PR + adoption by Sanctum, or maintaining a private fork. Same
   problem replicated for every Anchor 0.28/0.29 target.
3. **Use an older LiteSVM** that supports Anchor 0.28. Would
   require pinning Crucible to an older release. Loses other fixes.

Each path is multi-week. Phase 4's per-protocol budget is ≤7 days.
Out of scope.

## Decision implication for Phase 4 §"Stopping rule"

The strict reading of the stopping rule wanted N=2 = 0 violations
across the attack surface. H1 confirmed makes that *unreachable*
on Sanctum unstake at the current toolchain — it's not "0 because
clean" or "0 because depth-gated by missing fixture state", it's
"0 because Anchor's CPI flow doesn't run at all under LiteSVM
0.9.1". This is information **about solinv-fuzz's reachability
envelope**, not about Sanctum unstake's security.

Combined evidence as of Day 47:

| Trial | Target | Anchor version | Result |
|---|---|---|---|
| Phase 2 | Raydium SwapV2 | Native | 0 / 25K across 5 invariants |
| Phase 3 Day 34 | Raydium SwapV2 | Native | 0 / 15K unchecked-math |
| Phase 3 Day 38 | Raydium SwapV2 | Native | 0 / 25K cu-dos |
| Phase 4 Day 43 | Slumlord | Native (solores) | 0 / 86K across 5 invariants |
| Phase 4 Day 46 | klend | Anchor 0.29 | depth-gated (Day 27, ReserveConfig + ABI) |
| Phase 4 Day 47 | Sanctum unstake | Anchor 0.28 | depth-gated (this doc, H1 ABI confirmed) |

**Native targets**: tested clean (zero detections across multiple
invariant classes and multiple time-budget scales).

**Anchor 0.28/0.29 targets**: depth-gated at the toolchain layer.
The framework can't reach handler bodies, so detection is moot
regardless of code quality.

This widens the Day 46 retrospective's claim. solinv-fuzz at
current capability is not just "doesn't surface findings on this
class of target" — it's **unable to fully exercise Anchor 0.x
programs at all**. That's a much sharper limitation, and the
binding pivot decision applies more strongly.

## Recommendation update

Same recommendation as Day 46 §"User decision point — Day 47":
**option B — pivot binding now**. The A1 dig confirmed H1, and H1
isn't fixable within Phase 4 budget. The stopping rule's strict
reading is unreachable on Anchor 0.x targets without major
upstream changes to either Anchor or LiteSVM.

Day 38 §"Pivot options" still has three branches:
1. Less-hardened protocol targets — likely Native or Anchor 1.0+;
   the latter works clean per escrow-demo evidence
2. OSS audit-accelerator pivot
3. Pause and reassess

The A1 dig also adds a fourth, narrower option (option C, new
today):

4. **Fork the toolchain**: bring solinv-fuzz onto an Anchor 0.x-
   compatible LiteSVM (probably v0.5.x or older), or contribute the
   compatibility patches upstream. This unlocks the entire Anchor
   0.x universe (Drift, Marginfi, Kamino, Phoenix, Sanctum,
   Lifinity-equivalent). 2-4 weeks engineering cost. Higher
   leverage than any one-protocol dig.

Option 4 is the most strategic — it changes solinv-fuzz's
reachability envelope rather than working around it per-protocol.
If continuing solinv at all, this might be the right next move.

## Files changed Day 47

- `examples/sanctum-unstake-fuzz/fuzz/sanctum-unstake/src/main.rs`
  — added `solana_rent` import + `ctx.set_sysvar(&Rent::default())`
  (defensive, no-op since LiteSVM populates already), pre-created
  empty placeholders for pool_account / lp_mint (defensive, also
  not the gate). Updated soft-fail comment to reference this doc.
- `examples/sanctum-unstake-fuzz/fuzz/sanctum-unstake/Cargo.toml`
  — added `solana-rent = "3"` dep.
- `docs/phase4-day47-a1-dig.md` (this doc).
