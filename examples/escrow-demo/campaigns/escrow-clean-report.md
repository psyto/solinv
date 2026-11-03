# Mutation campaign — escrow-clean

- **Gate**: PASS
- **Score**: 83.3% (5 killed / 6 reached)
- **Excluded from the denominator**: 0 not reached, 0 failed to build, 0 harness error (0% of 6 mutants produced no evidence)
- **Attribution**: 5 killed by the predicted invariant, 0 by another
- **Not covered by any v1 operator**: cu-dos, cpi-reentrancy, realloc-race, account-swap
- **Before excluding equivalent mutants**: 45.5% (5 killed / 11 reached)

## Pre-committed criterion

> precondition-skip 追加後。escrow-clean はベースラインで全11検出器が沈黙することを実測済み。前回 guard-drop 5件が生き残り、それを塞ぐために precondition-skip を作った。なお生き残るなら、宣言の網羅性かガードを偽にする状態への到達性の問題であり、いずれかを名指しして報告する

PASS requires score ≥ 0.80 over ≥ 6 reached mutants.

## Per invariant

| Invariant | Killed | Reached | Score | Not reached | Build failed | Harness error |
|---|---:|---:|---:|---:|---:|---:|
| precondition-skip | 3 | 4 | 75% | 0 | 0 | 0 |
| signer-skip | 2 | 2 | 100% | 0 | 0 | 0 |

## Survivors

Mutants that executed and that no invariant caught. Each is either a detector blind spot or a bug class the catalog does not model.

- `guard-drop@examples/escrow-demo/programs/escrow-clean/src/lib.rs:44#0`

## Excluded as equivalent

Mutants ruled incapable of producing incorrect behaviour, and so removed from the denominator. Each exclusion raises the score, so each one is stated with its argument — check them.

- `signer-type-weaken@examples/escrow-demo/programs/escrow-clean/src/lib.rs:121#0`
  - initialize carries `init, payer = depositor`, whose CreateAccount CPI requires the payer's signature at the runtime level. Weakening the Anchor type removes a check the CPI underneath re-imposes, so no incorrect behaviour is reachable.
- `signer-type-weaken@examples/escrow-demo/programs/escrow-clean/src/lib.rs:135#1`
  - deposit's body invokes a system transfer from the depositor, which the runtime rejects unless the depositor signed. The Anchor Signer constraint is redundant with that. Contrast withdraw and claim, which move lamports directly and where the same mutation IS killed.
- `checked-to-wrapping@examples/escrow-demo/programs/escrow-clean/src/lib.rs:87#1`
  - the subtraction is guarded by `amount <= vault.amount` two lines above, which this mutant leaves intact, so wrapping_sub never wraps.
- `checked-to-wrapping@examples/escrow-demo/programs/escrow-clean/src/lib.rs:60#0`
  - vault.amount accumulates real transferred lamports and the fixture funds accounts with 1e10; overflowing u64 needs ~1.8e19, so wrapping_add cannot wrap under any sequence this harness can generate. Fixture-relative, not absolute.
- `guard-drop@examples/escrow-demo/programs/escrow-clean/src/lib.rs:74#2`
  - dropping `amount > 0 && amount <= vault.amount` leaves the bound enforced anyway: the handler's `vault.amount.checked_sub(amount)` returns None and the ix errors. The surviving clause, amount > 0, is not redundant but cannot be exercised — the detector sends a fixed data_sample.
