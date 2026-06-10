# Phase 5 Day 58 — cpi-reentrancy Gate 1 PASS

Date: 2026-06-09
Spec: [docs/invariants/cpi-reentrancy.md](invariants/cpi-reentrancy.md) §9
Impl: psyto/solinv@4820a9e (Day 58 cpi_reentrancy invariant)
Planted-bug fixture: `examples/escrow-demo/programs/escrow/src/lib.rs`
+ `unsafe_self_reentry` (outer) + `unsafe_inner_mutate` (inner CPI target)

## Result — Gate 1 PASS

Self-CPI re-entry detected end-to-end. 30-second campaign produced
18,999 violations at 642 exec/s.

```
[cpi-reentrancy:Esrcw11111111111111111111111111111111111111]
  program Esrcw11111111111111111111111111111111111111 re-entered at
  depths 1/2 (ix unsafe_self_reentry)
```

The depth pattern `1/2` confirms the detector observed the outer call
at depth 1 (`unsafe_self_reentry`) and the inner self-CPI at depth 2
(`unsafe_inner_mutate` via `invoke(&inner_ix, &[...])`).

## Setup

Planted bug shape (spec §1 sub-pattern #5 — "Self-CPI via
`invoke_signed`", here using plain `invoke` since the inner ix's
signer comes from the outer tx):

```
outer:        unsafe_self_reentry(ctx)
              ├─ read ctx.accounts.vault.amount
              ├─ build inner_ix targeting crate::ID with
              │  sighash = sha256("global:unsafe_inner_mutate")[..8]
              │  accounts = [vault (mut), depositor (signer)]
              ├─ invoke(&inner_ix, &[vault, depositor, escrow_program])
              │  └─ escrow re-enters: unsafe_inner_mutate(ctx, 12_345)
              │     └─ ctx.accounts.vault.amount = 12_345
              └─ Ok(())
```

Runtime log shape (excerpt from per-execution Crucible report):

```
Program Esrcw11111... invoke [1]
Program Esrcw11111... invoke [2]
Program Esrcw11111... success
Program Esrcw11111... success
```

solinv's `parse_cpi_events` + `detect_reentry` correctly identified
the cycle (same pid at stack positions corresponding to depths 1 and
2).

## Invocations

```bash
# Build escrow .so with the planted ix added
cd ~/src/solinv/examples/escrow-demo
cargo build-sbf --tools-version v1.52 --manifest-path programs/escrow/Cargo.toml

# Build the fuzz harness with the new variant
cd fuzz/escrow
cargo build --release --features invariant_cpi_reentrancy_only

# Run Gate 1
cd ~/src/solinv/examples/escrow-demo
crucible run escrow invariant_cpi_reentrancy_only --release --timeout 30
```

## Results

| Metric | Value |
|---|---:|
| Runtime | 30s |
| Executions | 19,000 |
| Crashes (violations) | **18,999** |
| Exec/sec | 642.3 |
| ok rate | 84.1% |
| Edges | 596/3,768 (15.8%) |
| Branches | 556/1,884 (29.5%) |
| Discovered actions | 5/7 |

The near-100% violation rate (18,999 / 19,000 = 99.99%) is expected:
the planted bug is structural (the cycle is unconditional in
`unsafe_self_reentry`), so every reachable invocation surfaces it.
The one non-violation execution likely never reached the planted
action within its sequence budget (action-discovery noise).

## Interpretation

### Detection-mechanism reading

The logs-based detector correctly extracted the CPI call tree from
`TxOutcome.logs`, walked the events maintaining the active stack,
and recognized that the escrow program ID appeared at two distinct
depths simultaneously. Detection algorithm exactly as specified
(spec §3) — no surprises, no false positives observed across the
campaign.

### Phase 2.5 framing reading

Gate 1 establishes implementation correctness — the v1 detector
fires on the canonical planted-bug shape per the §9 pre-commit. This
is the catalog-completion deliverable's correctness gate, not a
bug-yield metric.

Per spec §9 + §10, Gate 2 (production-target evidence on Raydium
AMM and/or Slumlord) is the next step. Under Phase 2.5 framing,
0 violations on hardened production targets is the **expected**
honest calibration data point — the detector's correctness is
already established here at Gate 1, so the production run measures
"do these specific protocols exhibit the pattern?", not "does the
detector work?".

### What Gate 1 does NOT prove

- The detector catches **all** re-entry shapes. Gate 1 covers the
  direct-cycle A→A shape (single-program self-CPI). Indirect A→B→A
  shapes (the harder mainnet cases, e.g., Mango v3) are tested
  structurally in the unit-test suite (`indirect_multi_hop_a_b_c_a_fires`)
  but not exercised end-to-end in Gate 1.
- False-positive rate on intentional re-entry patterns. The
  allowlist mechanism (`CpiReentrancyConfig.allowlist`) is unit-
  tested but not yet exercised on a real fixture that uses it.

Both are reasonable follow-ups under Phase 2.5; not gating on Gate 1.

## Files changed Day 58 (fixture + Gate 1)

- `examples/escrow-demo/programs/escrow/src/lib.rs` — added
  `unsafe_self_reentry` + `unsafe_inner_mutate` handlers +
  `UnsafeSelfReentry` + `UnsafeInnerMutate` Anchor account contexts.
  Sighash for inner-mutate hardcoded as `[158, 203, 192, 149, 204,
  238, 59, 124]` (sha256("global:unsafe_inner_mutate")[..8]) so the
  escrow SBF build pulls no hash crate.
- `examples/escrow-demo/fuzz/escrow/src/main.rs` — added
  `build_unsafe_self_reentry_ix` + `action_unsafe_self_reentry` +
  `self_reentry_spec` InstructionSpec literal (with
  `cpi_reentrancy: Some(CpiReentrancyConfig::default())`) +
  `invariant_cpi_reentrancy_only` `#[invariant_test]` fn.
- `examples/escrow-demo/fuzz/escrow/Cargo.toml` — added
  `invariant_cpi_reentrancy_only` cargo feature.
- `docs/phase5-day58-cpi-reentrancy-gate1.md` (this doc).

## Next

- **Gate 2** (Raydium) — Task #15. Phase 2.5 expected: 0 violations
  (catalog evidence). Same 2-minute × 4-parallel × 2-ix budget as
  the cu-dos / unchecked-math Gate 2 runs.
- Optional Gate 3 (Slumlord flash-loan borrower-callback shape) —
  the most-likely-positive production surface per spec §9 Gate 3.
