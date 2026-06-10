# Phase 2 Day 27 — ReserveConfig byte-poke patch (status + deposit_limit)

Date: 2026-05-25
Status: ✅ ReserveConfigMirror added, post-init patch works mechanically. ⚠️ Baseline deposit STILL fails — config has more blocking fields. **Day 28 decision point**.
Schedule: 3-4 days ahead of Day 14 baseline.

## Goal (Day 26 Option B)

Patch 2 ReserveConfig fields (status: Hidden→Active, deposit_limit: 0→1e8)
post init_reserve. Expected: baseline `deposit_reserve_liquidity` succeeds
→ solinv attacks reach account-validation surface.

## What worked (mechanical infrastructure)

### ReserveConfigMirror with offset_of!

```rust
#[repr(C)]
struct ReserveConfigMirror {
    pub status: u8,                  // offset 0
    pub _filler: [u8; 159],          // 1..160
    pub deposit_limit: u64,          // 160 (8-aligned naturally)
    pub _tail: [u8; 776],            // 168..944
}
const _: () = assert!(size_of::<ReserveConfigMirror>() == 944);
```

Manual offset computation verified: ReserveConfig leading fields
through `borrow_factor_pct` total 160 bytes (per state/reserve.rs:
1532-1597 + ReserveFees=24 + BorrowRateCurve=[CurvePoint;11]=88).

### ReserveMirror extension

Replaced opaque `_tail [u8; 4968]` with structured tail:
```rust
struct ReserveMirror {
    // ... unchanged through collateral ...
    pub reserve_collateral_padding: [u8; 1200],   // offset 3648 (Day 27)
    pub config: ReserveConfigMirror,              // offset 4848 (944)
    pub _tail: [u8; 2824],                        // 5792..8616
}
const _: () = assert!(size_of::<ReserveMirror>() == 8616);
```

All static_asserts pass at `cargo check`.

### Post-init byte-poke pattern

```rust
let mut reserve_acc = ctx.read_account(&reserve)?;
write_u8_at(&mut reserve_acc.data, RES_OFFSET_CONFIG_STATUS, 0);
write_u64_at(&mut reserve_acc.data, RES_OFFSET_CONFIG_DEPOSIT_LIMIT, 100_000_000);
ctx.write_account(&reserve, reserve_acc)?;
```

Uses TestContext's `read_account` / `write_account` for round-trip
modification. No panic in 801-iteration smoke test — bytes round-trip
cleanly.

## What proved insufficient (depth still gated)

Smoke test (10s combined invariant):
- 801 executions, 0 panics ✓
- 0 crashes (solinv violations)
- **ok: 0/79278 (0%)** — baseline `deposit_reserve_liquidity` STILL fails

## Next-layer blockers (untested hypothesis)

After status=Active + deposit_limit=100M, deposit likely fails on:

1. `lending_operations::deposit_reserve_liquidity` math — needs
   non-zero `liquidation_threshold_pct`, `loan_to_value_pct`,
   `borrow_factor_pct` (else certain Fraction math fails)
2. `token_info.max_age_price_seconds = 0` — `refresh_reserve` might
   gate on this
3. `ReserveFees` all zero — possible div-by-zero in fee calc

Each additional field = ~30 min to find offset + add patch. Estimate
3-5 more fields needed = ~2-3 hrs additional work.

## Diminishing-returns analysis

| Day | Action | Outcome | Blocker found |
|---|---|---|---|
| 22 | scaffold | compiles | (none yet) |
| 23 | LendingMarket byte-poke | bytes valid | n/a |
| 24 | Reserve byte-poke | accepted | zero config |
| 25 | deposit ix wired | runs | refresh_reserve / deposit_limit |
| 26 | init_reserve raw_call | works | Hidden status + 0 limit |
| 27 | status + deposit_limit patch | works | more config (loan-to-value, etc.) |

**Each iteration takes 1 day and discovers 1-2 new blockers.** No
detections found at any depth. Confidence updated:

- klend fuzz depth gate is **ReserveConfig comprehensive setup**, not
  a single missing field
- Even with full depth unlocked, expected outcome is **0 detections**
  (Raydium SwapBaseInV2 precedent)
- Value of further iterations: marginal (confirm clean vs declare
  surface untested at depth)

## Day 28 decision (3 options)

### (A) Iterate 2-3 more config fields (~0.5 day)

- Add ReserveConfigMirror extensions for max_age_price_seconds,
  loan_to_value_pct, liquidation_threshold_pct, borrow_factor_pct
- Patch all 4-5 fields post-init
- Smoke test, then commit
- Risk: another blocker discovered = another day's iteration

### (B) Declare klend MVP done, write Phase 2 retrospective

- Phase 2 deliverables documented:
  - Raydium AMM: full coverage, surface clean (Day 18-21)
  - klend: infrastructure proven (scaffold + LendingMarket byte-poke
    + Reserve via init_reserve raw_call + ReserveConfigMirror with
    offset_of! patch pattern), depth gated by ReserveConfig setup
    complexity
- Day 28-30 → Phase 1 wrap-up:
  - Phase 2 retrospective doc (lessons learned)
  - Disclosure templates (for Phase 1 OSS posture)
  - README polish
  - Raydium Deposit/Withdraw extension (Day 21 deferred)

### (C) Hybrid: 1 more depth attempt + 1 day wrap-up

- Day 28: add 4-5 more config field patches (~3-4 hrs)
- Day 28 PM: if baseline succeeds, run regression (~2 hrs)
- Day 29-30: Phase 1 wrap-up either way

## Recommendation: **(B) declare klend MVP done**

Reasons:
- 5 days of klend work; 4-5 more config fields likely won't change
  the 0-detection outcome
- Phase 2 retrospective is valuable Phase 1 deliverable
- Honest framing: klend coverage is **infrastructure proven**, not
  "no bugs found" — important distinction for any future OSS publish
- Raydium SwapBaseInV2 already provided the clean-surface validation
- Day 21 deferred Raydium Deposit/Withdraw — could complete that
  with saved budget

(C) is reasonable if user prefers one more shot at klend depth before
declaring MVP done.

## Files changed Day 27

- `examples/klend-fuzz/fuzz/klend/src/main.rs`:
  - ReserveConfigMirror struct (~10 LOC) + static_assert
  - ReserveMirror restructure (replace _tail with structured tail)
  - 3 offset constants via offset_of! + compile-time assertion
    on _RC_OFFSET_DEPOSIT_LIMIT == 160
  - Post-init read+poke+write pattern in setup() (~10 LOC)
  - Total ~40 LOC delta
- `docs/phase2-day27-klend-config-patch.md` (this log)

## Schedule

Cumulative **3-4 days ahead** of Day 14 baseline. Day 28 decision
allocates remaining lead time.
